package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/brand"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/install"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/share"
	"github.com/casea1/blackbox/internal/store"
)

// Status writes a plain summary of what this computer does and whether it
// is working: for a quick check by an administrator, or a support call.
func (a *App) Status(w io.Writer) error {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return err
	}
	now := a.now()
	s := st.State
	host := collect.LocalHost()
	p := func(label, format string, args ...any) {
		fmt.Fprintf(w, "  %-17s %s\n", label, fmt.Sprintf(format, args...))
	}
	var attention []string // problems that make "blackbox status" exit 4 (L10)

	fmt.Fprintf(w, "%s %s on %s\n\n", brand.Name, a.Version, host)
	switch a.Cfg.Role() {
	case "standalone":
		p("Role:", "standalone (reports on this computer only)")
	case "collector":
		p("Role:", "collector (reports on this computer and the computers that send to it)")
	case "sender":
		p("Role:", "sends to a collector (reports are produced on the collector)")
	}
	if s.LastCollect.IsZero() {
		p("Last collection:", "never (the scheduled task has not run yet)")
	} else {
		when := ago(now.Sub(s.LastCollect))
		if s.LastCollect.After(now.Add(clockSlack)) {
			when = "in the future: the clock was moved back" // not "just now" (T1)
		}
		p("Last collection:", "%s (%s)", stampLocal(s.LastCollect, a.loc()), when)
	}
	if bl := blockedNow(a.Cfg.DataDir, st); bl != nil {
		attention = append(attention, "collection is blocked")
		p("BLOCKED:", "%s", BlockedText(bl, a.loc()))
	}
	if !s.LastCheck.IsZero() {
		p("Settings checked:", "%s", stampLocal(s.LastCheck, a.loc()))
	}
	if s.ArchivedUntil.IsZero() {
		p("Log archive:", "none yet (the original logs are exported at every collection and archived once a day)")
	} else {
		where := "waiting in " + a.Cfg.ArchivesDir() + " for the next scheduled report"
		if !a.Cfg.MakesReports() {
			where = "sent to the collector"
			if n := lan.QueuedArchives(st); n > 0 {
				where = fmt.Sprintf("%d waiting to be sent to the collector", n)
			}
		}
		p("Log archive:", "original logs exported up to %s, archived once a day (%s)", stampLocal(s.ArchivedUntil, a.loc()), where)
	}

	for _, g := range s.LogGaps {
		attention = append(attention, "the saved original logs are incomplete")
		p("LOGS INCOMPLETE:", "%s had already overwritten its events from %s to %s when the original logs were saved. Make the log larger (blackbox check gives the size), or collect more often.",
			g.Source, stampLocal(g.From, a.loc()), stampLocal(g.To, a.loc()))
	}

	off := auditOffNow(st, now)
	for h, why := range off {
		if store.SystemKey(h) == store.SystemKey(host) {
			p("AUDITING OFF:", "%s — nothing is being recorded. Start it with: systemctl start auditd (and auditctl -e 1 if needed)", why)
		}
	}
	for _, l := range lostSince(st, s.LastWindowEnd, now) {
		p("Events lost:", "%s", LostText(l, a.loc(), a.Cfg.CollectEvery, store.SystemKey(l.Host) == store.SystemKey(host)))
		attention = append(attention, "events were lost to log rollover") // C6
	}
	// The clock moved back (T3, T1): a stored time in the future, or a
	// change noticed since the last report.
	if s.LastCollect.After(now.Add(clockSlack)) {
		attention = append(attention, "the clock was moved back")
		p("CLOCK MOVED BACK:", "the last collection is recorded at %s, %s ahead of the clock. Nothing collected is lost (reports follow collection order); check the time source.",
			stampLocal(s.LastCollect, a.loc()), roughAgo(s.LastCollect.Sub(now)))
	}
	for _, j := range s.ClockBack {
		attention = append(attention, "the clock was moved back")
		p("CLOCK MOVED BACK:", "noticed %s: the last collection had been recorded at %s, %s ahead. It is shown in the next report; check the time source.",
			stampLocal(j.Noticed, a.loc()), stampLocal(j.Was, a.loc()), roughAgo(j.Was.Sub(j.Noticed)))
	}

	if a.Cfg.SendTo != "" {
		fmt.Fprintln(w)
		p("Sending to:", "%s", a.Cfg.SendTo)
		if a.Cfg.ShareUser != "" {
			p("Share account:", "%s", a.Cfg.ShareUser)
		}
		waiting := lan.Queued(st)
		oldest := ""
		since := a.waitingSince(st)
		if !since.IsZero() {
			oldest = fmt.Sprintf("; the oldest waiting since %s (%s)", stampLocal(since, a.loc()), ago(now.Sub(since)))
		}
		switch snd := s.Send; {
		case snd == nil:
			p("Sent:", "nothing yet (sends after the next collection)")
		case snd.LastError != "":
			if !snd.FailingSince.IsZero() {
				p("SENDING FAILED:", "sending has failed since %s (%s), at every attempt", stampLocal(snd.FailingSince, a.loc()), ago(now.Sub(snd.FailingSince)))
			}
			p("Last attempt:", "%s — FAILED: %s", stampLocal(snd.LastAttempt, a.loc()), snd.LastError)
			p("Waiting to send:", "%d batch%s%s (kept safely here; sent when the collector can be reached, or now with: blackbox send)", waiting, es(waiting), oldest)
		default:
			if !snd.LastDelivered.IsZero() {
				p("Last delivered:", "%s (%s)", stampLocal(snd.LastDelivered, a.loc()), ago(now.Sub(snd.LastDelivered)))
			}
			p("Waiting to send:", "%d batch%s%s", waiting, es(waiting), oldest)
		}
		if kept := lan.Kept(st); len(kept) > 0 {
			p("Kept after delivery:", "%d batch%s (%d to %d), for %d days; if the collector reports some missing: %s",
				len(kept), es(len(kept)), kept[0], kept[len(kept)-1], a.Cfg.KeepSentDays, ResendCommand(kept[0], kept[len(kept)-1]))
		}
		switch snd := s.Send; {
		case !since.IsZero() && now.Sub(since) > SendStaleAfter:
			attention = append(attention, "data has waited more than a day to be sent")
			p("NOT SENT:", "data has been waiting to be sent for %s. It is kept here, never deleted; check that the collector can be reached (see Last attempt), then run: blackbox send", ago(now.Sub(since)))
		case snd != nil && snd.LastError != "" && !snd.FailingSince.IsZero() && now.Sub(snd.FailingSince) > SendStaleAfter:
			// Failing for a day even with nothing new to send (L12).
			attention = append(attention, "sending has failed for more than a day")
			p("NOT SENT:", "sending has failed since %s. Check that the collector can be reached (see Last attempt), then run: blackbox send", stampLocal(snd.FailingSince, a.loc()))
		}
	}
	if low := lowSpace(a.Cfg.DataDir); low != "" {
		attention = append(attention, "low disk space")
		p("LOW DISK SPACE:", "%s. Collected and queued data is never deleted to make room; free some space.", low)
	}
	if a.Cfg.MakesReports() {
		fmt.Fprintln(w)
		p("Reports:", "%s, saved in %s", a.Cfg.ReportAt.Describe(a.Cfg.ReportEvery), a.Cfg.ReportsDir())
		if !s.LastWindowEnd.IsZero() {
			p("Last report:", "period ending %s", stampLocal(s.LastWindowEnd, a.loc()))
			if next, due := nextReport(a.Cfg.ReportEvery, a.Cfg.ReportAt, s.LastWindowEnd, now, a.loc()); !due {
				p("Next report:", "after %s", stampLocal(next, a.loc()))
			} else {
				p("Next report:", "at the next scheduled run")
			}
		}
	}
	if a.Cfg.Inbox != "" {
		fmt.Fprintln(w)
		state := "OK"
		if !lan.IsInbox(a.Cfg.Inbox) {
			state = "NOT READY (created at the next scheduled run)"
		}
		waiting := 0
		if list, err := filepath.Glob(filepath.Join(a.Cfg.Inbox, "*.bbx")); err == nil {
			waiting = len(list)
		}
		// A shared inbox the firewall keeps closed (N2): reported, never changed.
		if runtime.GOOS == "windows" && install.InboxShared() {
			if open, err := share.SMBAllowedIn(); err == nil && !open {
				attention = append(attention, "the firewall blocks delivery")
				for i, l := range share.FirewallAdvice(share.SMBPort) {
					p(map[bool]string{true: "FIREWALL:"}[i == 0], "%s", l)
				}
			}
			if installed, open, err := share.SSHAllowedIn(); err == nil && installed && !open {
				attention = append(attention, "the firewall blocks SFTP delivery")
				for i, l := range share.FirewallAdvice(share.SSHPort) {
					p(map[bool]string{true: "FIREWALL:"}[i == 0], "%s", l)
				}
			}
		}
		bad := lan.Unreadable(a.Cfg.Inbox)
		for _, b := range bad {
			if name, _, _ := strings.Cut(b, " ("); strings.HasSuffix(name, ".bbx") {
				waiting-- // counted below as unreadable, not as waiting
			}
		}
		if len(bad) > 0 && state == "OK" {
			state = "PROBLEM"
		}
		p("Inbox:", "%s — %s; %d batch%s waiting to be imported", a.Cfg.Inbox, state, waiting, es(waiting))
		if len(bad) > 0 {
			p("", "%s", unreadableText(bad))
		}
		if rej, _ := filepath.Glob(filepath.Join(a.Cfg.Inbox, "rejected", "*")); len(rej) > 0 {
			p("", "%d file%s set aside in %s (see blackbox.log)", len(rej), map[bool]string{true: "s"}[len(rej) != 1], filepath.Join(a.Cfg.Inbox, "rejected"))
		}
	}
	if a.Cfg.Inbox != "" {
		fmt.Fprintln(w)
		a.writeSystems(w, st, now)
		// Batches that never arrived, unless accepted (L13b).
		for _, snd := range st.State.Senders {
			if len(snd.Missing) > 0 {
				attention = append(attention, "batches from "+snd.Host+" never arrived (see blackbox gaps)")
			}
		}
	}
	if len(attention) > 0 {
		return &NeedsAttention{What: attention}
	}
	return nil
}

// NeedsAttention is what Status returns when something needs looking at
// (L10): data waiting more than a day to be sent, or low disk space. The
// status itself was written; "blackbox status" exits 4 so scripts and
// monitoring can tell.
type NeedsAttention struct{ What []string }

func (e *NeedsAttention) Error() string { return "needs attention: " + strings.Join(e.What, "; ") }

// Systems writes the table of known computers.
func (a *App) Systems(w io.Writer) error {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return err
	}
	a.writeSystems(w, st, a.now())
	return nil
}

func (a *App) writeSystems(w io.Writer, st *store.Store, now time.Time) {
	var list []*store.System
	for _, s := range st.State.Systems {
		if s.Removed.IsZero() {
			list = append(list, s)
		}
	}
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	fmt.Fprintf(w, "Systems (%d)\n", len(list))
	if len(list) == 0 {
		fmt.Fprintln(w, "  none yet")
	} else {
		fmt.Fprintf(w, "  %-20s %-8s %-18s %-18s %s\n", "NAME", "OS", "LAST COLLECTION", "LAST RECEIVED", "NOTE")
	}
	self := store.SystemKey(collect.LocalHost())
	off := map[string]bool{}
	for h := range auditOffNow(st, now) {
		off[store.SystemKey(h)] = true
	}
	for _, s := range list {
		recv := stampLocal(s.LastReceived, a.loc())
		note := ""
		if store.SystemKey(s.Name) == self {
			recv, note = "-", "this computer"
		}
		if s.Via != "" {
			note = "via " + s.Via
		}
		switch {
		case s.LastRun.After(now.Add(clockSlack)):
			// T1b: recorded by a clock that was ahead.
			note = strings.TrimSpace(note + "  last collection is in the future: the clock was ahead")
		case !s.LastRun.IsZero() && now.Sub(s.LastRun) > silentAfter:
			note = strings.TrimSpace(note + "  NO DATA SINCE " + strings.ToUpper(ago(now.Sub(s.LastRun))))
		case store.SystemKey(s.Name) != self && !s.LastReceived.IsZero() && now.Sub(s.LastReceived) > 2*expectedSend:
			// Earlier than the silence above: a sender whose deliveries
			// are refused (or that is switched off) shows here first.
			note = strings.TrimSpace(note + "  no batch since " + stampLocal(s.LastReceived, a.loc()))
		}
		if off[store.SystemKey(s.Name)] {
			note = strings.TrimSpace("AUDITING OFF  " + note)
		}
		fmt.Fprintf(w, "  %-20s %-8s %-18s %-18s %s\n", s.Name, s.OS, stampLocal(s.LastRun, a.loc()), recv, note)
	}
	for _, snd := range st.State.Senders {
		for _, g := range snd.Missing {
			fmt.Fprintf(w, "  Missing: batches %d-%d from %s never arrived (noticed %s). %s\n",
				g.From, g.To, snd.Host, stampLocal(g.Noted, a.loc()), ResendAdvice(snd, g))
		}
		for _, g := range snd.Accepted {
			fmt.Fprintf(w, "  Accepted: batches %d-%d from %s will not arrive (%s, by %s on %s)\n",
				g.From, g.To, snd.Host, g.Reason, g.Who, stampLocal(g.When, a.loc()))
		}
		if snd.StartSeq > 1 && snd.Earlier != "" {
			fmt.Fprintf(w, "  %s: batches start at %d here; earlier ones went to %s\n", snd.Host, snd.StartSeq, snd.Earlier)
		}
	}
}

// expectedSend is how often a sender delivers: after each collection, by
// default every hour.
const expectedSend = time.Hour

// silentAfter matches the report's threshold for pointing out a computer
// that has stopped collecting.
const silentAfter = 36 * time.Hour

// RemoveSystem retires a computer: it is no longer listed, or reported as
// silent. Its past events stay in earlier reports. If it sends again, it
// is listed again.
func (a *App) RemoveSystem(name string) error {
	st, unlock, err := a.open()
	if err != nil {
		return err
	}
	defer unlock()
	s := st.State.Systems[store.SystemKey(name)]
	if s == nil {
		var names []string
		for _, x := range st.State.Systems {
			names = append(names, x.Name)
		}
		sort.Strings(names)
		return fmt.Errorf("no system named %q (known: %s)", name, strings.Join(names, ", "))
	}
	s.Removed = a.now()
	return st.Save()
}

// NextScheduled returns when the last scheduled report period ended (zero
// if no report has been produced yet) and when the next one is due (zero
// if it is due now: at the next scheduled run).
func (a *App) NextScheduled() (lastEnd, next time.Time, err error) {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	lastEnd = st.State.LastWindowEnd
	next, _ = nextReport(a.Cfg.ReportEvery, a.Cfg.ReportAt, lastEnd, a.now(), a.loc())
	return lastEnd, next, nil
}

// NextText says when the next scheduled report is due, in words.
func NextText(next time.Time) string {
	if next.IsZero() {
		return "at the next scheduled run"
	}
	return next.In(time.Local).Format("Monday 2 Jan 2006 15:04")
}

func nextReport(every string, at config.ReportAt, lastEnd, now time.Time, loc *time.Location) (time.Time, bool) {
	if _, due := DueWindowEnd(every, at, lastEnd, now, loc); due {
		return time.Time{}, true
	}
	return at.NextBoundary(every, now, loc), false
}

// BlockedText says collection is blocked by a run holding the lock
// (LOCK1), and what to do.
func BlockedText(b *store.Blocked, loc *time.Location) string {
	return fmt.Sprintf("Collection is blocked: a run has held the lock since %s (PID %d). %d scheduled run%s since %s collected nothing. "+
		"If that process is stuck, end it (Linux: sudo kill %d; Windows: taskkill /PID %d /F); the next run then collects what was missed.",
		stampLocal(b.Holder.Since, loc), b.Holder.PID, b.Refused, map[bool]string{true: "s"}[b.Refused != 1], stampLocal(b.First, loc), b.Holder.PID, b.Holder.PID)
}

// LostText describes events lost to rollover, with what to do about it:
// collect every 15 minutes, with the command (an upgrade keeps an hourly
// collect_every; only new installs collect every 15 minutes, C6), or, if
// it already does, a larger log. every is this computer's collect_every,
// local whether the log is this computer's.
func LostText(l LostLog, loc *time.Location, every time.Duration, local bool) string {
	return fmt.Sprintf("%s log on %s: %s events overwritten before they could be collected, since %s. %s",
		l.Channel, l.Host, commaNum(l.Count), stampLocal(l.Since, loc), LostAdvice(l.Host, every, local))
}

// LostAdvice is what to do about events lost to rollover (see LostText).
func LostAdvice(host string, every time.Duration, local bool) string {
	switch {
	case !local:
		return fmt.Sprintf("Collect every 15 minutes (on %s: blackbox config set collect_every 15m), or make the log larger.", host)
	case every > 15*time.Minute:
		return fmt.Sprintf("This computer collects every %s: collect every 15 minutes with: blackbox config set collect_every 15m. Or make the log larger.", everyWords(every))
	}
	return "Make the log larger (blackbox check gives the size the STIG requires)."
}

func everyWords(d time.Duration) string {
	if d%time.Hour == 0 {
		if d == time.Hour {
			return "hour"
		}
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d minutes", int(d.Minutes()))
}

func commaNum(n uint64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func stampLocal(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(loc).Format("2006-01-02 15:04")
}

func ago(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return "just now"
	case d < 2*time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func es(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

// Exists reports whether a data folder has been used (for messages).
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "state.json"))
	return err == nil
}

// unreadableText says which inbox files can't be read (L9): "1 file in
// the inbox can't be read (access denied): name".
func unreadableText(bad []string) string {
	if len(bad) == 1 {
		name, why, _ := strings.Cut(bad[0], " (")
		return fmt.Sprintf("1 file in the inbox can't be read (%s): %s", strings.TrimSuffix(why, ")"), name)
	}
	return fmt.Sprintf("%d files in the inbox can't be read: %s", len(bad), strings.Join(bad, ", "))
}
