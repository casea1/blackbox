// Package app ties collection, state and reporting together for the
// command-line tool.
package app

import (
	"errors"

	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/install"
	"github.com/casea1/blackbox/internal/inventory"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/scap"
	"github.com/casea1/blackbox/internal/selfaudit"
	"github.com/casea1/blackbox/internal/share"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

// App is a configured Blackbox instance.
type App struct {
	// final is set while the final report before sending is made (AR3).
	final bool

	Cfg     *config.Config
	Version string
	Now     func() time.Time
	Loc     *time.Location
	Logf    func(format string, args ...any)
	// LiveLogs reads this computer's own logs for a period (tests replace
	// it); nil uses the event logs.
	LiveLogs func(host string, from, to time.Time) ([]*event.Event, []string, error)
	// BootTime is when this computer last started (tests replace it).
	BootTime func() time.Time
	// QuietSend leaves the send result out of the log, for a caller that
	// says it in its own words (setup), so it isn't printed twice (L4).
	QuietSend bool
	// NoDeliver makes the data ready to send but leaves delivery to
	// blackbox-send.service (Linux, a folder the site mounted), so a
	// delivery problem never stops collection (L8).
	NoDeliver bool
	// Reschedule registers the collection task again (nil: the installed
	// one, install.RefreshSchedule); tests replace it.
	Reschedule func(every time.Duration) error
	// RecordSelf records a change Blackbox makes on a person's request
	// (nil: selfaudit.Record, the spool and the system log).
	RecordSelf func(dataDir string, c event.SelfChange, now time.Time) error
	// LogStates reads how far back each log reaches and whether it is full
	// (nil: archive.LogStates); tests replace it.
	LogStates func() []archive.LogState
	// Inventory reads this computer's hardware and accounts (nil:
	// inventory.Collect); tests replace it.
	Inventory func() *inventory.Inventory
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *App) loc() *time.Location {
	if a.Loc != nil {
		return a.Loc
	}
	return time.Local
}

func (a *App) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	}
}

// ReportsDir is where reports are written.
func (a *App) ReportsDir() string { return a.Cfg.ReportsDir() }

// pendingLogsDir holds each computer's daily archives of its original
// logs (this computer's own, and those received from senders) until a
// scheduled report takes them into its folder: archive_dir, or the
// archives folder in the data folder.
func (a *App) pendingLogsDir() string { return a.Cfg.ArchivesDir() }

// dataLogsDir is the archives folder in the data folder, where archives
// waited before archive_dir was set; any left there go into the next
// report too.
func (a *App) dataLogsDir() string { return filepath.Join(a.Cfg.DataDir, "archives") }

// waitingLogsDirs are the folders archives may be waiting in: archive_dir,
// the data folder's (before archive_dir was set) and the reports folder's
// (version 0.4).
func (a *App) waitingLogsDirs() []string {
	out := []string{a.pendingLogsDir()}
	for _, d := range []string{a.dataLogsDir(), a.legacyLogsDir()} {
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// scapReceivedDir is where a collector keeps the SCAP results senders
// deliver, by computer.
func (a *App) scapReceivedDir() string { return filepath.Join(a.Cfg.DataDir, "scap-received") }

// scapScans reads the SCAP results to show in a report: from the
// scap_results folder and, on a collector, those senders delivered.
func (a *App) scapScans() []*scap.Scan {
	dir := a.Cfg.ScapDir()
	if dir == "" {
		return nil
	}
	if dir == filepath.Join(a.Cfg.DataDir, "scap") {
		os.MkdirAll(dir, 0o750) // the default folder, ready for results
	}
	found, notes := scap.Find(dir, a.scapReceivedDir())
	for _, n := range notes {
		a.logf("SCAP results: %s", n)
	}
	out := make([]*scap.Scan, 0, len(found))
	for _, s := range found {
		out = append(out, s)
	}
	return out
}

// legacyLogsDir is where version 0.4 kept the daily archives; any left
// there go into the next report too.
func (a *App) legacyLogsDir() string { return filepath.Join(a.ReportsDir(), "archives") }

// piecesDir holds the original logs exported at each collection until
// they are packed into the day's archive (see package archive): in
// archive_dir when it is set, next to the archives.
func (a *App) piecesDir() string {
	if a.Cfg.ArchiveDir != "" {
		return filepath.Join(a.Cfg.ArchiveDir, ".exports")
	}
	return a.dataPiecesDir()
}

func (a *App) dataPiecesDir() string { return filepath.Join(a.Cfg.DataDir, "archive-pieces") }

// allPieces lists the exports waiting to be packed, those left in the
// data folder from before archive_dir was set first.
func (a *App) allPieces() ([]archive.Piece, error) {
	var out []archive.Piece
	if a.piecesDir() != a.dataPiecesDir() {
		old, err := archive.Pieces(a.dataPiecesDir())
		if err != nil {
			return nil, err
		}
		out = old
	}
	p, err := archive.Pieces(a.piecesDir())
	return append(out, p...), err
}

// saveLogPiece exports the original logs (see package archive) written
// since the last export, at every collection, while the logs still hold
// them (AR2). run is the collection just made, prevCollect the one before.
// What each log covers and what it overwrote before it could be saved are
// recorded with the piece and kept for status. After the clock was moved
// back, the export starts again at the first record written since the last
// one (AR1). If it fails, the same period is tried again.
func (a *App) saveLogPiece(st *store.Store, run *store.Run, prevCollect time.Time) {
	now := a.now()
	from := st.State.ArchivedUntil
	// The first export reaches back a week on purpose; what a log no
	// longer holds from before Blackbox was installed is not a gap.
	first := from.IsZero()
	if first {
		from = now.Add(-archive.FirstSpan)
	}
	var notes []string
	if from.After(now) {
		// The clock was moved back since the last export: everything
		// written since then was read by this collection.
		restart := now
		for _, c := range run.Channels {
			if !c.FirstTime.IsZero() && c.FirstTime.Before(restart) {
				restart = c.FirstTime
			}
		}
		if r := st.State.ArchiveRestart; r.IsZero() || restart.Before(r) {
			st.State.ArchiveRestart = restart
		}
	}
	if r := st.State.ArchiveRestart; !r.IsZero() {
		if r.Before(from) {
			notes = append(notes, fmt.Sprintf("The clock was moved back: the export before this one ran to %s, later than the clock showed afterwards. This part starts again at %s, the first record written since, so nothing is skipped; records stamped from %s to %s may also be in the part before.",
				stampUTC(st.State.ArchivedUntil), stampUTC(r), stampUTC(r), stampUTC(st.State.ArchivedUntil)))
			a.logf("the clock was moved back: the original logs are exported again from %s so nothing is skipped", r.In(a.loc()).Format("2006-01-02 15:04"))
		}
		from = r
	}
	if !from.Before(now) {
		st.State.ArchiveRestart = time.Time{}
		return
	}
	states := a.logStates()
	host := collect.LocalHost()
	lost := map[string]uint64{}
	for _, c := range run.Channels {
		if c.Gap != nil {
			lost[c.Channel] += c.Gap.Lost
		}
	}
	if first {
		// What collection already knew was overwritten in the period.
		if runs, err := st.ReadRuns(from); err == nil {
			for _, r := range runs {
				if r == run || !strings.EqualFold(r.Host, host) || r.Time.Equal(run.Time) {
					continue
				}
				for _, c := range r.Channels {
					if c.Gap != nil {
						lost[c.Channel] += c.Gap.Lost
					}
				}
			}
		}
	}
	var gaps []archive.Gap
	if !first {
		gaps = archive.GapsIn(states, from, now)
	}
	// A log this collection read nothing new from has nothing new to
	// export, if the last export came after the last collection.
	caughtUp := !first && st.State.ArchiveRestart.IsZero() && !st.State.ArchivedUntil.Before(prevCollect)
	known, fresh := map[string]bool{}, map[string]bool{}
	for _, c := range run.Channels {
		known[c.Channel] = true
		if c.Read > 0 || c.Gap != nil || c.Reset || c.Error != "" {
			fresh[c.Channel] = true
		}
	}
	skip := func(src string) bool { return caughtUp && known[src] && !fresh[src] }
	info := archive.Info{Host: host, OS: runtime.GOOS, From: from, To: now, Created: now, Notes: notes, Gaps: gaps,
		Logs: archive.Coverage(states, from, now, lost)}
	if _, err := archive.SavePiece(a.piecesDir(), info, nil, skip); err != nil {
		a.logf("exporting the original logs: %v; will try again next run", err)
		return
	}
	var kept []store.LogGap
	for _, g := range st.State.LogGaps {
		if now.Sub(g.Noted) < logGapsKept {
			kept = append(kept, g)
		}
	}
	for _, g := range gaps {
		a.logf("ORIGINAL LOGS INCOMPLETE: %s had already overwritten its events from %s to %s when it was saved", g.Source, g.From.In(a.loc()).Format("2006-01-02 15:04"), g.To.In(a.loc()).Format("2006-01-02 15:04"))
		kept = append(kept, store.LogGap{Source: g.Source, From: g.From, To: g.To, Noted: now})
	}
	st.State.LogGaps = kept
	st.State.ArchivedUntil = now
	st.State.ArchiveRestart = time.Time{}
}

func stampUTC(t time.Time) string { return t.UTC().Format("2006-01-02 15:04Z") }

// packLogs packs the exported pieces of the original logs into one
// archive: into the outbox on a sender, otherwise into the pending folder
// for the next report. Unless force is set it waits until the oldest
// piece is a day old.
func (a *App) packLogs(st *store.Store, force bool) {
	pieces, err := a.allPieces()
	if err != nil {
		a.logf("archiving the logs: %v", err)
		return
	}
	if len(pieces) == 0 || !(force || archive.PackDue(pieces, a.now())) {
		return
	}
	host := collect.LocalHost()
	dir := filepath.Join(a.pendingLogsDir(), archive.SafeName(host))
	if !a.Cfg.MakesReports() && !a.final {
		dir = lan.OutboxDir(st)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		a.logf("archiving the logs: %v", err)
		return
	}
	span := archive.Span(pieces)
	info, err := archive.Pack(filepath.Join(dir, archive.FileName(host, span.From, span.To)), host, runtime.GOOS, pieces, a.now())
	if err != nil {
		a.logf("archiving the logs: %v; will try again next run", err)
		return
	}
	for _, n := range info.Notes {
		a.logf("log archive: %s", n)
	}
}

// logGapsKept is how long status points out a gap in the saved original
// logs.
const logGapsKept = 14 * 24 * time.Hour

func (a *App) logStates() []archive.LogState {
	if a.LogStates != nil {
		return a.LogStates()
	}
	return archive.LogStates()
}

// bundleLogs combines, for each computer, the pending daily archives that
// end by end into one zip for the report folder. It returns them and the
// daily archives used, to remove once the report is written.
func (a *App) bundleLogs(end time.Time) (refs []report.ArchiveRef, used []string) {
	var list []archive.Stored
	for _, dir := range a.waitingLogsDirs() {
		l, err := archive.List(dir)
		if err != nil {
			a.logf("listing log archives in %s: %v", dir, err)
		}
		list = append(list, l...)
	}
	byHost := map[string][]archive.Stored{}
	var hosts []string
	for _, s := range list {
		if s.To.After(end) {
			continue // for the next report
		}
		k := strings.ToLower(s.Host)
		if byHost[k] == nil {
			hosts = append(hosts, k)
		}
		byHost[k] = append(byHost[k], s)
	}
	sort.Strings(hosts)
	for _, k := range hosts {
		days := byHost[k]
		name := "logs-" + archive.SafeName(days[0].Host) + ".zip"
		tmp := filepath.Join(a.pendingLogsDir(), "."+name)
		b, err := archive.Bundle(tmp, days)
		if err != nil {
			a.logf("original logs of %s: %v; they stay pending", days[0].Host, err)
			os.Remove(tmp)
			continue
		}
		fi, _ := os.Stat(tmp)
		var size uint64
		if fi != nil {
			size = uint64(fi.Size())
		}
		refs = append(refs, report.ArchiveRef{Host: days[0].Host, From: b.From, To: b.To, Name: name, Path: tmp, Bytes: size, SHA256: b.SHA256, Gaps: b.Gaps, Logs: b.Logs, Notes: b.Notes})
		for _, d := range days {
			used = append(used, d.Path)
		}
	}
	return refs, used
}

// open opens the data folder and takes the lock.
func (a *App) open() (*store.Store, func(), error) { return a.openWait(0) }

// openWait is open, waiting up to wait for a run in progress to finish.
// A scheduled run and a send started next to each other (the timer and
// blackbox-send.service, or the task and setup) then follow one another
// instead of the second failing; each run now also exports the original
// logs, so runs take longer.
func (a *App) openWait(wait time.Duration) (*store.Store, func(), error) {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return nil, nil, err
	}
	unlock, err := st.WaitLock(wait, func() { a.logf("waiting for the run in progress to finish") })
	if err != nil {
		return nil, nil, err
	}
	return st, unlock, nil
}

// runWait and sendWait are how long a scheduled run, and a send, wait
// for a run in progress.
var runWait, sendWait = 10 * time.Minute, 2 * time.Minute

// gather does what every run does before reporting: collect this
// system's logs, check its audit settings (daily, or now if force), and
// receive what other systems sent, if this is a collector.
func (a *App) gather(st *store.Store, forceCheck bool) error {
	a.noticeClock(st)
	prevCollect := st.State.LastCollect
	run, err := collect.Live(st, collect.Options{Version: a.Version, Now: a.now, Logf: a.Logf})
	if err != nil {
		return err
	}
	a.saveLogPiece(st, run, prevCollect)
	noteOwnName(st, run.Host, run.OS)
	st.NoteSystem(run.Host, run.OS, a.Version, "", run.Time, time.Time{}, a.now())
	if err := a.recordChecks(st, run.Host, forceCheck); err != nil {
		a.logf("audit settings check: %v", err)
	}
	a.receive(st)
	return st.Save()
}

// noteOwnName keeps the names this computer has collected under (W1b).
// The first time, its earlier names are taken from the computers whose
// data it collected itself (not delivered by another).
func noteOwnName(st *store.Store, host, osName string) {
	if host == "" {
		return
	}
	if len(st.State.OwnNames) == 0 {
		others := lan.OtherSystems(st, host)
		for k, sys := range st.State.Systems {
			if !others[k] && sys.Via == "" && sys.OS == osName && k != store.SystemKey(host) {
				st.State.OwnNames = append(st.State.OwnNames, sys.Name)
			}
		}
		sort.Strings(st.State.OwnNames)
	}
	for _, n := range st.State.OwnNames {
		if strings.EqualFold(n, host) {
			return
		}
	}
	st.State.OwnNames = append(st.State.OwnNames, host)
}

// farFuture is a period end no event time reaches.
var farFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// clockSlack is how far a stored time may be ahead of the clock before the
// clock counts as moved back (or an event as recorded with a clock ahead).
const clockSlack = 5 * time.Minute

// noticeClock records the clock having been moved back: the last
// collection is in the future (T3). On Windows the collection task is
// registered again, so its next run follows the corrected clock (T1).
func (a *App) noticeClock(st *store.Store) {
	now := a.now()
	was := st.State.LastCollect
	if was.IsZero() || !was.After(now.Add(clockSlack)) {
		return
	}
	st.State.ClockBack = append(st.State.ClockBack, store.ClockJump{Host: collect.LocalHost(), Noticed: now, Was: was})
	a.logf("the clock was moved back: the last collection was at %s, %s ahead of the clock now; nothing collected is lost (reports follow collection order)",
		was.In(a.loc()).Format("2006-01-02 15:04"), roughAgo(was.Sub(now)))
	if a.Cfg.CollectEvery > 0 {
		reschedule := a.Reschedule
		if reschedule == nil {
			reschedule = install.RefreshSchedule
		}
		if err := reschedule(a.Cfg.CollectEvery); err != nil {
			a.logf("re-registering the collection task after the clock change: %v", err)
		}
	}
}

func roughAgo(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	case d >= 2*time.Hour:
		return fmt.Sprintf("%.0f hours", d.Hours())
	}
	return fmt.Sprintf("%.0f minutes", d.Minutes())
}

// checkEvery is how often a system that is not producing a report checks
// its audit settings (a report always includes a fresh check).
const checkEvery = 20 * time.Hour

// checkDue says whether the audit settings should be checked again: daily,
// and after every restart, since settings such as auditd or the kernel's
// audit=1 often only take effect after one.
func checkDue(last, boot, now time.Time) bool {
	return now.Sub(last) >= checkEvery || (!boot.IsZero() && boot.After(last))
}

func (a *App) inventory() *inventory.Inventory {
	if a.Inventory != nil {
		return a.Inventory()
	}
	return inventory.Collect()
}

func (a *App) bootTime() time.Time {
	if a.BootTime != nil {
		return a.BootTime()
	}
	return bootTime()
}

// recordChecks checks this system's audit settings and keeps the result,
// so it reaches reports here or on the collector.
func (a *App) recordChecks(st *store.Store, host string, force bool) error {
	if !check.Supported {
		return nil
	}
	now := a.now()
	if !force && !checkDue(st.State.LastCheck, a.bootTime(), now) {
		return nil
	}
	rec := &store.CheckRecord{Time: now, Host: host, OS: runtime.GOOS, Results: check.Run(), Inventory: a.inventory()}
	if err := st.AppendChecks(rec); err != nil {
		return err
	}
	st.State.LastCheck = now
	return nil
}

// receive imports batches other systems have delivered to this
// collector's inbox.
func (a *App) receive(st *store.Store) {
	if a.Cfg.Inbox == "" {
		return
	}
	if !lan.IsInbox(a.Cfg.Inbox) {
		if err := lan.PrepareInbox(a.Cfg.Inbox, collect.LocalHost()); err != nil {
			a.logf("inbox %s is not available: %v", a.Cfg.Inbox, err)
			return
		}
	}
	res, err := lan.Import(st, a.Cfg.Inbox, lan.Dirs{Archives: a.pendingLogsDir(), Scap: a.scapReceivedDir()}, a.now(), a.Logf)
	if err != nil {
		a.logf("receiving from %s: %v", a.Cfg.Inbox, err)
	}
	if res.Batches > 0 {
		a.logf("received %d batch%s (%d records) from other systems", res.Batches, map[bool]string{true: "es"}[res.Batches != 1], res.Records)
	}
	if res.Already > 0 {
		// L11b: a batch sent again that was not missing.
		a.logf("%d batch%s already imported (sent again); nothing new in %s", res.Already, map[bool]string{true: "es"}[res.Already != 1], map[bool]string{true: "them", false: "it"}[res.Already != 1])
	}
	if res.Scap > 0 {
		a.logf("received %d SCAP scan result(s) from other systems", res.Scap)
	}
	if res.Archives > 0 {
		a.logf("received %d log archive(s) from other systems", res.Archives)
	}
}

// SendResult describes one attempt to send to the collector.
type SendResult struct {
	// FinalReport is the report made before this computer started sending,
	// of what it had as a computer that made reports (AR3).
	FinalReport              string
	Made, Delivered, Waiting int
	ArchivesDelivered        int
	ArchivesWaiting          int
	ScapDelivered            int
	Err                      error
}

// send batches new data and delivers what is waiting to the collector. A
// collector that cannot be reached is not an error for the run: the data
// waits in the outbox and goes next time.
func (a *App) send(st *store.Store) SendResult {
	var r SendResult
	host := collect.LocalHost()
	r.FinalReport = a.handover(st)
	lan.NoteVM(st, config.IsVirtualBoxShare(a.Cfg.SendTo))
	r.Made, r.Err = lan.Export(st, host, a.Version, a.now())
	// This computer's latest SCAP results go to the collector too.
	if dir := a.Cfg.ScapDir(); dir != "" && r.Err == nil {
		found, _ := scap.Find(dir)
		var files []string
		for _, s := range found {
			if store.SystemKey(s.Latest.Host) != store.SystemKey(host) {
				continue
			}
			files = append(files, s.Latest.File)
			if s.Previous != nil {
				files = append(files, s.Previous.File)
			}
		}
		if _, err := lan.QueueScap(st, files, a.now()); err != nil {
			a.logf("queueing SCAP results: %v", err)
		}
	}
	if r.Err == nil && a.NoDeliver {
		r.Waiting = lan.Queued(st)
		r.ArchivesWaiting = lan.QueuedArchives(st)
		return r
	}
	if r.Err == nil {
		dest, err := share.Destination(a.Cfg)
		if err != nil {
			r.Err = err
		} else {
			if changed, err := lan.NoteDestination(st, a.Cfg.SendTo, lan.InboxCollector(dest)); err != nil {
				a.logf("noting the new collector: %v", err)
			} else if changed {
				s := st.State.Send
				a.logf("sending to a different collector from batch %d; earlier batches went to %s", s.FirstSeq, s.Earlier)
			}
			r.Delivered, r.Err = lan.Deliver(st, dest, host, a.Cfg.KeepSentDays > 0)
			if r.Err == nil {
				r.ArchivesDelivered, r.Err = lan.DeliverArchives(st, dest)
			}
			if r.Err == nil {
				r.ScapDelivered, r.Err = lan.DeliverScap(st, dest)
			}
			if errors.Is(r.Err, lan.ErrNoInbox) {
				// Why, in the mount's own words (L6).
				r.Err = fmt.Errorf("%w (%s)", r.Err, share.Why(a.Cfg, dest))
			}
		}
	}
	r.Waiting = lan.Queued(st)
	r.ArchivesWaiting = lan.QueuedArchives(st)
	if _, err := lan.PruneSent(st, a.Cfg.KeepSentDays, a.now()); err != nil {
		a.logf("removing batches kept after delivery: %v", err)
	}
	if s := st.State.Send; s != nil {
		s.LastAttempt = a.now()
		s.LastError = ""
		if r.Err != nil {
			s.LastError = r.Err.Error()
			if s.FailingSince.IsZero() {
				s.FailingSince = a.now()
			}
		} else {
			s.FailingSince = time.Time{}
			if r.Waiting == 0 && r.ArchivesWaiting == 0 {
				s.LastDelivered = a.now()
			}
		}
		st.Save()
	}
	switch {
	case a.QuietSend:
	case r.Err != nil:
		a.logf("could not send to the collector: %v; %d batch(es) waiting, will retry next run", r.Err, r.Waiting)
	case r.Delivered > 0 || r.ArchivesDelivered > 0 || r.ScapDelivered > 0:
		a.logf("sent %s to the collector", sentText(r)) // SC2: SCAP results counted too
	}
	return r
}

// handover makes a final report when a computer that made reports (a
// collector or a standalone computer) starts sending to a collector
// (AR3, L14): everything it had collected and received and not yet
// reported, with every original log it held, its own and other
// computers'. Those stay in that report; from then on it sends only its
// own new data, so nothing is reported twice or filed under the wrong
// computer. It returns the report's folder ("" if none was needed).
func (a *App) handover(st *store.Store) string {
	s := st.State.Send
	var since time.Time
	if s != nil {
		since = s.Since
	}
	var pending []archive.Stored
	for _, d := range a.waitingLogsDirs() {
		l, _ := archive.List(d)
		pending = append(pending, l...)
	}
	reported := !st.State.LastGenerated.IsZero() && st.State.LastGenerated.After(since)
	received := false
	for _, snd := range st.State.Senders {
		if snd.LastReceived.After(since) {
			received = true
		}
	}
	// Switched from making reports: what was there is in the final report
	// and is not sent. A sender upgraded from a version without this
	// (Since not set) keeps sending what it has not sent yet; only
	// archives left pending from its time as a collector go in a report.
	switched := s == nil || (!since.IsZero() && reported)
	if !(switched && (reported || received)) && len(pending) == 0 {
		if s != nil && since.IsZero() {
			s.Since = a.now()
		}
		return ""
	}
	// After a switch its own original logs go in the final report too;
	// otherwise they go to the collector as usual.
	a.final = switched
	dir, err := a.report(st, a.now(), true)
	a.final = false
	if err != nil {
		a.logf("making the final report before sending to the collector: %v; will try again next run", err)
		return ""
	}
	if st.State.Send == nil {
		st.State.Send = &store.SendState{ID: store.NewID(), NextSeq: 1}
	}
	s = st.State.Send
	if switched {
		files, err := st.SpoolFiles()
		if err != nil {
			a.logf("final report: %v", err)
			return dir
		}
		if s.Offsets == nil {
			s.Offsets = map[string]int64{}
		}
		for _, f := range files {
			s.Offsets[f.Name] = f.Size
		}
	}
	s.Since = a.now()
	if err := st.Save(); err != nil {
		a.logf("saving state: %v", err)
	}
	a.logf("made a final report of what this computer had collected and received before sending to a collector, with the original logs it held: %s", dir)
	return dir
}

// sentText is "3 batches, 1 log archive and 2 SCAP results".
func sentText(r SendResult) string {
	var parts []string
	for _, p := range []struct {
		n          int
		one, other string
	}{{r.Delivered, "batch", "batches"}, {r.ArchivesDelivered, "log archive", "log archives"}, {r.ScapDelivered, "SCAP result", "SCAP results"}} {
		switch {
		case p.n == 1:
			parts = append(parts, "1 "+p.one)
		case p.n > 1:
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.other))
		}
	}
	switch len(parts) {
	case 0:
		return "nothing"
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// Scheduled is what the scheduled task runs: collect (and receive, on a
// collector), then send to the collector or produce a report if one is
// due. It returns the report folder ("" if none).
func (a *App) Scheduled() (string, error) {
	st, unlock, err := a.openWait(runWait)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := a.gather(st, false); err != nil {
		return "", err
	}
	if !a.Cfg.MakesReports() {
		a.packLogs(st, false)
		a.send(st)
		return "", nil
	}
	end, due := DueWindowEnd(a.Cfg.ReportEvery, a.Cfg.ReportAt, st.State.LastWindowEnd, a.now(), a.loc())
	if !due {
		a.packLogs(st, false)
		return "", nil
	}
	return a.report(st, end, true)
}

// ReportNow collects and produces a report up to now. With advance=false
// it is a manual report: the schedule and report chain are untouched,
// and the next scheduled report covers the same time again.
func (a *App) ReportNow(advance bool) (string, error) {
	st, unlock, err := a.open()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := a.gather(st, true); err != nil {
		return "", err
	}
	return a.report(st, a.now(), advance)
}

// SendNow collects and sends to the collector straight away (for example
// from a script that starts a virtual machine only for a short time).
func (a *App) SendNow() (SendResult, error) {
	if a.Cfg.SendTo == "" {
		return SendResult{}, fmt.Errorf("this computer is not set to send to a collector (send_to is empty)")
	}
	st, unlock, err := a.openWait(sendWait)
	if err != nil {
		return SendResult{}, err
	}
	defer unlock()
	if err := a.gather(st, false); err != nil {
		return SendResult{}, err
	}
	r := a.send(st)
	return r, r.Err
}

// ResendResult is what "blackbox send --resend" did.
type ResendResult struct {
	Sent    []uint64 // batches copied into the inbox again
	Missing []uint64 // no longer kept (older than keep_sent_days), or never made
}

// Resend copies batches from..to, kept after delivery, into the
// collector's inbox again (L11), and records that it did, like a setting
// change. The collector imports the ones that fill a gap.
func (a *App) Resend(from, to uint64) (ResendResult, error) {
	if a.Cfg.SendTo == "" {
		return ResendResult{}, fmt.Errorf("this computer is not set to send to a collector (send_to is empty)")
	}
	st, unlock, err := a.open()
	if err != nil {
		return ResendResult{}, err
	}
	dest, err := share.Destination(a.Cfg)
	if err != nil {
		unlock()
		return ResendResult{}, err
	}
	var r ResendResult
	r.Sent, r.Missing, err = lan.Resend(st, dest, collect.LocalHost(), from, to)
	if errors.Is(err, lan.ErrNoInbox) {
		err = fmt.Errorf("%w (%s)", err, share.Why(a.Cfg, dest))
	}
	unlock() // the record below opens the spool itself
	if len(r.Sent) > 0 {
		record := a.RecordSelf
		if record == nil {
			record = selfaudit.Record
		}
		c := event.SelfChange{Kind: "resent", New: seqRange(r.Sent), Old: a.Cfg.SendTo, Program: "blackbox send --resend"}
		if rerr := record(a.Cfg.DataDir, c, a.now()); rerr != nil {
			a.logf("batches were sent again, but recording it failed: %v", rerr)
		}
	}
	return r, err
}

// ResendCommand is the command a sender runs to fill a gap (L11).
func ResendCommand(from, to uint64) string {
	if to > from {
		return fmt.Sprintf("blackbox send --resend %d-%d", from, to)
	}
	return fmt.Sprintf("blackbox send --resend %d", from)
}

// seqRange is "214-219" for a run of batches, "214" for one, and
// "214-216, 219" when some are missing.
func seqRange(seqs []uint64) string {
	var parts []string
	for i := 0; i < len(seqs); {
		j := i
		for j+1 < len(seqs) && seqs[j+1] == seqs[j]+1 {
			j++
		}
		if j == i {
			parts = append(parts, fmt.Sprint(seqs[i]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", seqs[i], seqs[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// Collect only collects.
func (a *App) Collect() (*store.Run, error) {
	st, unlock, err := a.open()
	if err != nil {
		return nil, err
	}
	defer unlock()
	run, err := collect.Live(st, collect.Options{Version: a.Version, Now: a.now, Logf: a.Logf})
	if err == nil {
		st.NoteSystem(run.Host, run.OS, a.Version, "", run.Time, time.Time{}, a.now())
		err = st.Save()
	}
	return run, err
}

func (a *App) report(st *store.Store, end time.Time, advance bool) (string, error) {
	generated := a.now()
	prevEnd, prevGen := st.State.LastWindowEnd, st.State.LastGenerated
	since := prevEnd
	if !prevGen.IsZero() && prevGen.Before(since) {
		since = prevGen
	}
	// A day before the period is read as well, for detections that span
	// two reports.
	readFrom := since
	if !readFrom.IsZero() {
		readFrom = readFrom.Add(-contextSpan)
	}
	// Since the first report that records how far it read the spool, the
	// chain follows collection order (T3); before, collection times.
	positional := st.State.ReportedTo != nil
	var all []*event.Event
	var err error
	if positional {
		all, err = st.ReadEventsAfter(readFrom, st.State.ReportedTo)
	} else {
		all, err = st.ReadEvents(readFrom)
	}
	if err != nil {
		return "", err
	}
	marks, err := st.EventSizes()
	if err != nil {
		return "", err
	}
	// A manual report shows everything collected so far, whatever its
	// time says (T3b): after a clock correction, events can be stamped a
	// little after the moment the report is made.
	selEnd := end
	if !advance {
		selEnd = farFuture
	}
	var events []*event.Event
	if positional {
		events = SelectByCollection(all, prevEnd, prevGen, selEnd, generated)
	} else {
		events = SelectWindow(all, prevEnd, prevGen, selEnd, generated)
	}
	// Never a period that starts after it ends (T3): after the clock was
	// moved back, the previous period ended in what is now the future.
	windowStart := prevEnd
	clockBack := append([]store.ClockJump(nil), st.State.ClockBack...)
	if prevEnd.After(end) {
		windowStart = end
		for _, e := range events {
			if e.Time.Before(windowStart) {
				windowStart = e.Time
			}
		}
		if len(clockBack) == 0 {
			clockBack = append(clockBack, store.ClockJump{Host: collect.LocalHost(), Noticed: generated, Was: prevEnd})
		}
	}
	// The report's folder holds the original logs for its period: this
	// computer's are saved up to the end of the period first.
	var logs []report.ArchiveRef
	var usedLogs []string
	if advance {
		a.packLogs(st, true)
		logs, usedLogs = a.bundleLogs(generated)
		defer func() {
			for _, l := range logs {
				os.Remove(l.Path) // left only if the report was not written
			}
		}()
	}
	context := contextEvents(all, events, windowStart)
	runsSince := prevGen
	if runsSince.After(generated) {
		runsSince = windowStart // the previous report's time is in the future (T3)
	}
	runs, err := st.ReadRuns(runsSince)
	if err != nil {
		return "", err
	}
	// The latest audit settings check of each computer: a week's look-back
	// finds one even for a computer that checks only once a day.
	checkSince := prevEnd
	if !checkSince.IsZero() {
		checkSince = checkSince.AddDate(0, 0, -7)
	}
	latest, err := st.LatestChecks(checkSince, generated)
	if err != nil {
		return "", err
	}
	var sets []report.CheckSet
	for _, c := range latest {
		cs := report.NewCheckSet(c.Host, c.Time, c.Results)
		cs.Inventory = c.Inventory
		sets = append(sets, cs)
	}
	sort.Slice(sets, func(i, j int) bool { return strings.ToLower(sets[i].Host) < strings.ToLower(sets[j].Host) })

	scans := a.scapScans()
	r := report.Build(events, runs, report.Options{
		// The STIG compliance table shows once SCAP is in use: a folder
		// chosen in the settings, or any scan found.
		Scap: scans, ScapEnabled: len(scans) > 0 || (a.Cfg.ScapResults != "" && a.Cfg.ScapDir() != ""), ScapMaxAgeDays: a.Cfg.ScapMaxAgeDays,
		Site:        a.Cfg.SiteName,
		WindowStart: windowStart, WindowEnd: end, Generated: generated, Version: a.Version,
		ClockBack: clockJumps(clockBack),
		Source:    "Live collection", Location: a.loc(), InReportsDir: true, Interim: !advance, Period: a.Cfg.ReportEvery,
		History:      report.History(a.ReportsDir(), end, report.HistoryWeeks),
		ExcludeUsers: a.Cfg.ExcludeUsers, ExcludeProcesses: a.Cfg.ExcludeProcesses,
		KnownDevices: st.State.KnownDevices, CheckSets: sets,
		Context: context, Baseline: st.State.Baseline, BaselineHosts: st.State.BaselineHosts,
		WorkingHours: a.Cfg.WorkingHours,
		Archives:     logs, ArchivesKept: advance,
		Systems: systemsFor(st, prevEnd), Collector: a.Cfg.Inbox != "",
		LANWarnings:   append(lanWarnings(st, prevGen, generated, a.loc()), a.inboxWarnings()...),
		RetentionDays: a.Cfg.RetentionDays,
	})
	if advance {
		r.Removed = st.State.RemovedReports
	}
	if len(r.Hosts) == 0 {
		r.Hosts = []string{collect.LocalHost()}
	}
	name := report.DirName(end, a.Cfg.SiteName, r.Hosts, collect.LocalHost(), a.loc())
	if !advance {
		name += "_manual"
	} else if a.final {
		name += "_final"
	}
	dir := report.UniqueDir(a.ReportsDir(), name)
	if err := r.Write(dir); err != nil {
		return "", err
	}
	if advance {
		for _, p := range usedLogs {
			if err := os.Remove(p); err != nil {
				a.logf("removing a daily log archive now in the report: %v", err)
			}
		}
		st.State.LastWindowEnd = end
		st.State.LastGenerated = generated
		st.State.ReportedTo = marks
		st.State.ClockBack = nil // shown in this report
		for k, t := range r.NewDevices {
			st.State.KnownDevices[k] = t
		}
		report.UpdateBaseline(st.State.Baseline, st.State.BaselineHosts, r, generated)
		if err := st.Save(); err != nil {
			return dir, err
		}
		if err := st.Prune(a.Cfg.RetentionDays, generated); err != nil {
			a.logf("pruning old data: %v", err)
		}
		removed, err := pruneReports(a.ReportsDir(), a.Cfg.RetentionDays, generated)
		if err != nil {
			a.logf("pruning old reports: %v", err)
		}
		// Listed in the next scheduled report; this one listed the last.
		st.State.RemovedReports = removed
		if err := st.Save(); err != nil {
			a.logf("noting removed reports: %v", err)
		}
		for _, d := range a.waitingLogsDirs() {
			if err := archive.Prune(d, a.Cfg.RetentionDays, generated); err != nil {
				a.logf("pruning old log archives: %v", err)
			}
		}
	}
	if err := report.WriteIndex(a.ReportsDir(), a.Cfg.SiteName, a.Cfg.ReportAt.Describe(a.Cfg.ReportEvery), a.loc()); err != nil {
		a.logf("updating report index: %v", err)
	}
	return dir, nil
}

// contextSpan is how far before a report's period detections look.
const contextSpan = 24 * time.Hour

// contextEvents returns the events from the day before the period start
// that are not in the report itself (they were in the previous one).
func contextEvents(all, inReport []*event.Event, start time.Time) []*event.Event {
	if start.IsZero() {
		return nil
	}
	in := make(map[*event.Event]bool, len(inReport))
	for _, e := range inReport {
		in[e] = true
	}
	var out []*event.Event
	for _, e := range all {
		if !in[e] && !e.Time.Before(start.Add(-contextSpan)) && e.Time.Before(start) {
			out = append(out, e)
		}
	}
	return out
}

// systemsFor lists the computers to show in a report whose period starts
// at start: all known, except those retired before it.
func systemsFor(st *store.Store, start time.Time) []report.SystemInfo {
	// A name another computer says it had before is that computer, not
	// one of its own (W1b).
	former := map[string]bool{}
	for k, s := range st.State.Systems {
		for _, f := range s.Former {
			if store.SystemKey(f) != k {
				former[store.SystemKey(f)] = true
			}
		}
	}
	var out []report.SystemInfo
	for k, s := range st.State.Systems {
		if !s.Removed.IsZero() && !s.Removed.After(start) || former[k] {
			continue
		}
		out = append(out, report.SystemInfo{Name: s.Name, OS: s.OS, Version: s.Version, Via: s.Via,
			FirstSeen: s.FirstSeen, LastRun: s.LastRun, LastReceived: s.LastReceived, Former: s.Former, VM: s.VM})
	}
	return out
}

// lanWarnings describes problems noticed receiving from other computers
// since the previous report.
// inboxWarnings says which files in the inbox can't be read (L9).
func (a *App) inboxWarnings() []string {
	if a.Cfg.Inbox == "" {
		return nil
	}
	if bad := lan.Unreadable(a.Cfg.Inbox); len(bad) > 0 {
		return []string{unreadableText(bad) + ". Their events are not in this report; fix the file permissions so the next run imports them."}
	}
	return nil
}

func lanWarnings(st *store.Store, since, until time.Time, loc *time.Location) []string {
	var out []string
	ids := make([]string, 0, len(st.State.Senders))
	for id := range st.State.Senders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := st.State.Senders[id]
		for _, g := range s.Missing {
			if g.Noted.After(since) && !g.Noted.After(until) {
				what := fmt.Sprintf("batch %d", g.From)
				if g.To > g.From {
					what = fmt.Sprintf("batches %d to %d", g.From, g.To)
				}
				out = append(out, fmt.Sprintf("%s: %s sent by this computer never arrived (noticed %s). The events in them are missing from the reports; they may have been deleted from the inbox folder. %s",
					s.Host, what, g.Noted.In(loc).Format("2006-01-02 15:04"), ResendAdvice(s, g)))
			}
		}
		if s.ClockNoted.After(since) && !s.ClockNoted.After(until) {
			out = append(out, fmt.Sprintf("%s: its clock was %s ahead of this collector's (noticed %s). Event times from it may be wrong; check its time settings.",
				s.Host, s.ClockAhead, s.ClockNoted.In(loc).Format("2006-01-02 15:04")))
		}
	}
	return out
}

// ResendAdvice says how missing batches can be filled: "blackbox send
// --resend" on the sender, for the batches it says it still keeps (L13).
func ResendAdvice(snd *store.SenderState, g store.SeqGap) string {
	if snd.Kept == nil { // an older sender that does not say
		return fmt.Sprintf("To send them again, run on %s: %s (it keeps delivered batches for keep_sent_days, 14 days by default).", snd.Host, ResendCommand(g.From, g.To))
	}
	from, to := max(g.From, snd.Kept.From), min(g.To, snd.Kept.To)
	if snd.Kept.From == 0 || from > to {
		return fmt.Sprintf("%s no longer keeps them, so they cannot be sent again.", snd.Host)
	}
	text := fmt.Sprintf("To send them again, run on %s: %s", snd.Host, ResendCommand(from, to))
	if from != g.From || to != g.To {
		return text + " (it no longer keeps the others)."
	}
	return text + "."
}

// SelectWindow picks the events that belong in the report ending at end,
// given the previous report's window end and generation time. Every event
// lands in exactly one report:
//   - events that happened before end, and
//   - were not already in the previous report (collected after it was
//     generated, or happened after its window ended).
//
// Events from before the previous window that were collected late are
// included and marked Late.
func SelectWindow(all []*event.Event, prevEnd, prevGen, end, generated time.Time) []*event.Event {
	var out []*event.Event
	for _, e := range all {
		if !e.Time.Before(end) || e.Collected.After(generated) {
			continue // belongs to a later report
		}
		if !prevGen.IsZero() {
			already := !e.Collected.After(prevGen) && e.Time.Before(prevEnd)
			if already {
				continue
			}
			if e.Time.Before(prevEnd) {
				e.Late = true
			}
		}
		out = append(out, e)
	}
	return out
}

// SelectByCollection picks the events for a report by collection order
// (T3): an event belongs to this report unless the previous report read it
// (it is not Unreported) and showed it (it fell in that report's period,
// or was recorded with a clock ahead of that report's time). The clock
// can't make an event skip every report: an event collected after the
// previous report is in this one or, if it happened after this period
// ends, in the next. An event recorded with a clock ahead of now is shown
// now rather than when the clock catches up.
func SelectByCollection(all []*event.Event, prevEnd, prevGen, end, generated time.Time) []*event.Event {
	backwards := prevEnd.After(end)
	var out []*event.Event
	for _, e := range all {
		future := e.Time.After(generated.Add(clockSlack))
		if !e.Time.Before(end) && !future {
			continue // belongs to a later report
		}
		if !e.Unreported && (e.Time.Before(prevEnd) || (!prevGen.IsZero() && e.Time.After(prevGen.Add(clockSlack)))) {
			continue // in the previous report
		}
		if e.Unreported && e.Time.Before(prevEnd) && !backwards {
			e.Late = true
		}
		out = append(out, e)
	}
	return out
}

// clockJumps turns the stored clock changes into the report's.
func clockJumps(js []store.ClockJump) []report.ClockJump {
	var out []report.ClockJump
	for _, j := range js {
		out = append(out, report.ClockJump{Host: j.Host, Noticed: j.Noticed, Was: j.Was})
	}
	return out
}

// DueWindowEnd returns the end of the next scheduled report period and
// whether it is due. The first report is produced immediately; after
// that, periods end at the configured time (see config.ReportAt): each
// day, each week on the configured day, or on the 1st of each month.
func DueWindowEnd(every string, at config.ReportAt, lastEnd, now time.Time, loc *time.Location) (time.Time, bool) {
	if lastEnd.IsZero() {
		return now, true
	}
	b := at.LastBoundary(every, now, loc)
	if b.After(lastEnd) {
		return b, true
	}
	return time.Time{}, false
}

func pruneReports(dir string, days int, now time.Time) ([]string, error) {
	if days <= 0 {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var removed []string
	cut := now.AddDate(0, 0, -days)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cut) {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "manifest.sha256")); err != nil {
			continue // only remove folders Blackbox created
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return removed, err
		}
		removed = append(removed, e.Name())
	}
	return removed, nil
}

// Inputs are exported log files for a one-off report.
type Inputs struct {
	XML    []string // Windows: wevtutil / Event Viewer XML (any OS)
	EVTX   []string // Windows: .evtx (Windows only)
	Audit  []string // Linux: auditd logs (audit.log, rotated copies, .gz)
	Syslog []string // Linux: syslog, messages, kern.log, auth.log, secure, journalctl output
	Host   string   // Linux: host name when the logs do not say
	Passwd string   // Linux: /etc/passwd copy for turning user IDs into names
}

// Empty reports whether no files were given.
func (in Inputs) Empty() bool {
	return len(in.XML)+len(in.EVTX)+len(in.Audit)+len(in.Syslog) == 0
}

// ReportFromFiles builds a one-off report from exported logs.
//
// from and to (zero for no limit) keep only the events in that period
// (report --from/--to/--days, R9).
func (a *App) ReportFromFiles(in Inputs, outDir string, from, to time.Time) (string, error) {
	now := a.now()
	var events []*event.Event
	var runs []*store.Run
	var names []string
	for _, p := range in.XML {
		ev, run, err := collect.FromRaw(func(fn func(*winevt.Raw) error) error {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			return winevt.ParseStream(f, fn)
		}, p, now)
		if err != nil {
			return "", err
		}
		events, runs = append(events, ev...), append(runs, run)
		names = append(names, filepath.Base(p))
	}
	for _, p := range in.EVTX {
		ev, run, err := collect.FromRaw(func(fn func(*winevt.Raw) error) error { return winevt.ReadFile(p, fn) }, p, now)
		if err != nil {
			return "", err
		}
		events, runs = append(events, ev...), append(runs, run)
		names = append(names, filepath.Base(p))
	}
	if len(in.Audit)+len(in.Syslog) > 0 {
		ev, run, err := collect.LinuxFiles(in.Audit, in.Syslog, in.Host, in.Passwd, now)
		if err != nil {
			return "", err
		}
		events, runs = append(events, ev...), append(runs, run)
		for _, p := range append(append([]string{}, in.Audit...), in.Syslog...) {
			names = append(names, filepath.Base(p))
		}
	}
	if !from.IsZero() || !to.IsZero() {
		kept := events[:0]
		for _, e := range events {
			if (from.IsZero() || !e.Time.Before(from)) && (to.IsZero() || e.Time.Before(to)) {
				kept = append(kept, e)
			}
		}
		events = kept
	}
	end := to
	if end.IsZero() {
		end = now
		if len(events) > 0 {
			last := events[0].Time
			for _, e := range events {
				if e.Time.After(last) {
					last = e.Time
				}
			}
			end = last
		}
	}
	r := report.Build(events, runs, report.Options{
		Site:        a.Cfg.SiteName,
		WindowStart: from, WindowEnd: end, Generated: now, Version: a.Version,
		Source: "Exported log file" + plural(len(names)) + ": " + strings.Join(names, ", "), Location: a.loc(),
		ExcludeUsers: a.Cfg.ExcludeUsers, ExcludeProcesses: a.Cfg.ExcludeProcesses,
	})
	if outDir == "" {
		outDir = report.UniqueDir(".", "blackbox-report-"+now.In(a.loc()).Format("2006-01-02_1504"))
	}
	if err := r.Write(outDir); err != nil {
		return "", err
	}
	return outDir, nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Describe formats a collection run for the console.
func Describe(run *store.Run) string {
	var b strings.Builder
	for _, c := range run.Channels {
		status := fmt.Sprintf("read %d, kept %d", c.Read, c.Kept)
		switch {
		case c.Unavailable != "":
			status = "not enabled"
		case c.Error != "":
			status = "ERROR: " + c.Error
		}
		if c.Gap != nil {
			status += fmt.Sprintf(" — %d events LOST to log rollover", c.Gap.Lost)
		}
		if c.Reset {
			status += " — log was cleared"
		}
		fmt.Fprintf(&b, "  %-58s %s\n", c.Channel, status)
	}
	return b.String()
}
