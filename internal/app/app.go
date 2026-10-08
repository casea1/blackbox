// Package app ties collection, state and reporting together for the
// command-line tool.
package app

import (
	"errors"

	"fmt"
	"io/fs"
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
	"github.com/casea1/blackbox/internal/rollover"
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
	// ReportAlert writes a missing or changed scheduled report to the
	// system log (nil: selfaudit.ReportProblem); tests replace it.
	ReportAlert func(msg string) error
	// LogStates reads how far back each log reaches and whether it is full
	// (nil: archive.LogStates); tests replace it.
	LogStates func() []archive.LogState
	// Export exports the original logs for a piece (nil: by position,
	// archive.ByPosition); tests replace it.
	Export archive.ExportFunc
	// Inventory reads this computer's hardware and accounts (nil:
	// inventory.Collect); tests replace it.
	Inventory func() *inventory.Inventory
	// RunCheck checks the audit settings (nil: check.Run); tests
	// replace it.
	RunCheck func() []check.Result
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
	clears := a.noteClears(st, run, states, from)
	// cleared labels a gap in a log with a clear still open as the clear
	// (LC2b), with who and when; false when the clear's gap is recorded
	// already, so this one is dropped (LC2c). It is kept as recorded only
	// once the piece is saved.
	cleared := func(g *archive.Gap) bool {
		k := strings.ToLower(g.Source)
		c, ok := clears[k]
		if !ok || g.Reason != "" {
			return true
		}
		if c.Gap {
			return false
		}
		g.Cleared = clearedText(c)
		c.Gap = true
		clears[k] = c
		return true
	}
	if !first {
		// A log cleared since it last had a record exported reaches back
		// only to the clear: that is the clear (a High row), not an
		// overwrite (LC2). Its file keeps its size, so it still looks
		// full. The gap is labelled as the clear, with who and when
		// (LC2b).
		reset := map[string]bool{}
		for _, c := range run.Channels {
			if c.Reset && !c.Cleared {
				reset[strings.ToLower(c.Channel)] = true
			}
		}
		for _, g := range archive.GapsIn(states, from, now) {
			k := strings.ToLower(g.Source)
			if _, ok := st.State.ExportMarks[g.Source]; ok && runtime.GOOS == "windows" {
				continue // its gaps are found by record ID (AR9)
			}
			if _, ok := clears[k]; !ok && reset[k] {
				continue
			}
			if cleared(&g) {
				gaps = append(gaps, g)
			}
		}
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
	// Each log from where its last export ended, whatever the records'
	// times (AR8, AR9). A gap found by position after a clear is the
	// clear (LC2b).
	timeGap := map[string]bool{}
	for _, g := range gaps {
		timeGap[strings.ToLower(g.Source)] = true
	}
	pos := &archive.Positions{Marks: st.State.ExportMarks}
	byPos := archive.ByPosition(pos)
	export := a.Export
	if export == nil {
		export = func(dir string, from, to time.Time, skip func(string) bool) ([]archive.Source, []string, []archive.Gap) {
			s, n, all := byPos(dir, from, to, skip)
			// One gap per log: one found by time above stands.
			var g []archive.Gap
			for _, x := range all {
				if !timeGap[strings.ToLower(x.Source)] || x.Reason != "" {
					g = append(g, x)
				}
			}
			return s, n, g
		}
	}
	withClears := func(dir string, from, to time.Time, skip func(string) bool) ([]archive.Source, []string, []archive.Gap) {
		s, n, all := export(dir, from, to, skip)
		var g []archive.Gap
		for _, x := range all {
			if cleared(&x) {
				g = append(g, x)
			}
		}
		// LC2c: a clear seen since the last export is a gap whatever
		// the log's size. Windows truncates a cleared file, so a log
		// cleared well short of full does not wrap, and by position
		// its record numbers just start again: neither left a gap
		// above. Its events from the last export to the clear are not
		// in the saved logs.
		for _, k := range sortedKeys(clears) {
			c := clears[k]
			if c.Gap {
				continue
			}
			end := c.At
			if end.Before(from) {
				end = from // read late: cleared before the last export ended
			}
			if end.After(to) {
				end = to
			}
			x := archive.Gap{Source: c.Channel, From: from, To: end}
			cleared(&x)
			g = append(g, x)
		}
		return s, n, g
	}
	piece, err := archive.SavePiece(a.piecesDir(), info, withClears, skip)
	if err != nil {
		a.logf("exporting the original logs: %v; will try again next run", err)
		return
	}
	if st.State.ExportMarks == nil {
		st.State.ExportMarks = map[string]store.ExportMark{}
	}
	for k, m := range pos.Next {
		st.State.ExportMarks[k] = m
	}
	for k, c := range clears {
		if cur, ok := st.State.Clears[k]; ok && c.Gap && cur.At.Equal(c.At) {
			cur.Gap = true
			st.State.Clears[k] = cur
		}
	}
	gaps = piece.Info.Gaps
	var kept []store.LogGap
	for _, g := range st.State.LogGaps {
		if now.Sub(g.Noted) < logGapsKept {
			kept = append(kept, g)
		}
	}
	for _, g := range gaps {
		if g.Cleared != "" {
			a.logf("original logs: %s was cleared %s; its events before that are not in the saved original logs", g.Source, g.Cleared)
			c := clears[strings.ToLower(g.Source)]
			c.Gap = false
			kept = append(kept, store.LogGap{Source: g.Source, From: g.From, To: g.To, Noted: now, Cleared: &c})
			continue
		}
		if g.Reason != "" {
			a.logf("ORIGINAL LOGS INCOMPLETE: %s", g.Reason)
			kept = append(kept, store.LogGap{Source: g.Source, From: g.From, To: g.To, Noted: now, Reason: g.Reason})
			continue
		}
		a.logf("ORIGINAL LOGS INCOMPLETE: %s had already overwritten its events from %s to %s when it was saved%s", g.Source, g.From.In(a.loc()).Format("2006-01-02 15:04"), g.To.In(a.loc()).Format("2006-01-02 15:04"), recordsNote(g.Records))
		kept = append(kept, store.LogGap{Source: g.Source, From: g.From, To: g.To, Noted: now, Records: g.Records})
	}
	st.State.LogGaps = kept
	st.State.ArchivedUntil = now
	st.State.ArchiveRestart = time.Time{}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// noteClears keeps the logs this run found cleared (LC2b), and forgets
// those that have since had a record exported: a later gap in them is an
// overwrite again. It returns the clears still open, before this run's
// gaps use them.
func (a *App) noteClears(st *store.Store, run *store.Run, states []archive.LogState, from time.Time) map[string]store.LogClear {
	for _, c := range run.Channels {
		if !c.Cleared {
			continue
		}
		if st.State.Clears == nil {
			st.State.Clears = map[string]store.LogClear{}
		}
		at := c.ClearedAt
		if at.IsZero() {
			at = from // some time since the last export
		}
		st.State.Clears[strings.ToLower(c.Channel)] = store.LogClear{Channel: c.Channel, At: at, By: c.ClearedBy}
	}
	for _, s := range states {
		k := strings.ToLower(s.Source)
		if c, ok := st.State.Clears[k]; ok && !s.Oldest.IsZero() && s.Oldest.After(c.At) && !s.Oldest.After(from) {
			delete(st.State.Clears, k) // a record since the clear is in an earlier export
		}
	}
	for k, c := range st.State.Clears {
		if a.now().Sub(c.At) > logGapsKept {
			delete(st.State.Clears, k)
		}
	}
	out := map[string]store.LogClear{}
	for k, c := range st.State.Clears {
		out[k] = c
	}
	return out
}

func recordsNote(r string) string {
	if r == "" {
		return ""
	}
	return " (" + r + ")"
}

// clearedText is "by claude at 2026-10-07 16:24Z".
func clearedText(c store.LogClear) string {
	who := c.By
	if who == "" {
		who = "someone"
	}
	return "by " + who + " at " + stampUTC(c.At)
}

// runsCovering are Blackbox's runs from an hour before the earliest event
// on, for telling Blackbox's own activity from a person's (AR2c). runs,
// read since the last scheduled report was made, miss the run that made
// it: the original logs a run exports are written during that run, before
// the report is made, so a manual report straight after would show them
// as a person's writes.
func runsCovering(st *store.Store, events []*event.Event, runs []*store.Run, since time.Time) []*store.Run {
	if len(events) == 0 {
		return runs
	}
	// A run starts before what it writes: from an hour before the
	// earliest event, or before since if that is earlier.
	first := events[0].Time
	for _, e := range events {
		if e.Time.Before(first) {
			first = e.Time
		}
	}
	first = first.Add(-time.Hour)
	if !first.Before(since) {
		first = since.Add(-time.Hour)
	}
	more, err := st.ReadRuns(first)
	if err != nil {
		return runs
	}
	return more
}

// packFailing is packing the original logs failing here, for a report.
func packFailing(st *store.Store) *report.PackFailing {
	f := st.State.PackFailing
	if f == nil {
		return nil
	}
	return &report.PackFailing{Host: collect.LocalHost(), Since: f.Since, Reason: f.Reason}
}

func stampUTC(t time.Time) string { return t.UTC().Format("2006-01-02 15:04Z") }

// packLogs packs the exported pieces of the original logs into one
// archive: into the outbox on a sender, otherwise into the pending folder
// for the next report. Unless force is set it waits until the oldest
// piece is a day old.
func (a *App) packLogs(st *store.Store, force bool) {
	// Packing failing is kept in the state, so status and reports say
	// so until it works again (AR5).
	failed := func(err error) {
		if st.State.PackFailing == nil {
			st.State.PackFailing = &store.PackFailure{Since: a.now()}
		}
		st.State.PackFailing.Reason = err.Error()
		a.logf("ORIGINAL LOGS NOT ARCHIVED since %s: %v; will try again next run", st.State.PackFailing.Since.In(a.loc()).Format("2006-01-02 15:04"), err)
		if err := st.Save(); err != nil {
			a.logf("saving the state: %v", err)
		}
	}
	pieces, err := a.allPieces()
	if err != nil {
		failed(err)
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
		failed(err)
		return
	}
	span := archive.Span(pieces)
	info, err := archive.Pack(filepath.Join(dir, archive.FileName(host, span.From, span.To)), host, runtime.GOOS, pieces, a.now())
	if err != nil {
		failed(err)
		return
	}
	st.State.PackFailing = nil
	for _, n := range info.Notes {
		a.logf("log archive: %s", n)
	}
	// An export lost before packing is a gap status points out, like an
	// overwritten one (AR5).
	for _, g := range info.Gaps {
		if g.Reason != "" {
			st.State.LogGaps = addLogGap(st.State.LogGaps, store.LogGap{Source: g.Source, From: g.From, To: g.To, Noted: a.now(), Reason: g.Reason})
		}
	}
	// A sender, or a run with no report due, saves nothing after this.
	if err := st.Save(); err != nil {
		a.logf("saving the state: %v", err)
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

// waitingLogs is what of the original logs waits for the next scheduled
// report, for a manual report to say (UI5): the daily archives and the
// exports not yet packed, their period, size and computers, and when the
// scheduled report that takes them is due.
func (a *App) waitingLogs(st *store.Store) *report.WaitingLogs {
	w := &report.WaitingLogs{Dir: a.pendingLogsDir()}
	hosts := map[string]bool{}
	span := func(from, to time.Time, host string, size uint64) {
		if w.From.IsZero() || from.Before(w.From) {
			w.From = from
		}
		if to.After(w.To) {
			w.To = to
		}
		hosts[strings.ToLower(host)] = true
		w.Bytes += size
	}
	for _, dir := range a.waitingLogsDirs() {
		l, _ := archive.List(dir)
		for _, s := range l {
			span(s.From, s.To, s.Host, uint64(s.Bytes))
		}
	}
	pieces, _ := a.allPieces()
	for _, p := range pieces {
		var size uint64
		filepath.WalkDir(p.Dir, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if fi, err := d.Info(); err == nil {
					size += uint64(fi.Size())
				}
			}
			return nil
		})
		host := p.Info.Host
		if host == "" {
			host = collect.LocalHost()
		}
		span(p.Info.From, p.Info.To, host, size)
	}
	w.Systems = len(hosts)
	w.Next, _ = nextReport(a.Cfg.ReportEvery, a.Cfg.ReportAt, st.State.LastWindowEnd, a.now(), a.loc())
	return w
}

// bundleLogs combines, for each computer, the pending daily archives that
// end by end into one zip for the report folder. It returns them, the
// daily archives used, to remove once the report is written, and those
// left out because they failed their check, to set aside then (AR7).
func (a *App) bundleLogs(end time.Time) (refs []report.ArchiveRef, used []string, left []report.LeftOutLogs) {
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
		// One that fails its check does not hold back the others (AR7).
		for _, l := range b.LeftOut {
			a.logf("ORIGINAL LOGS NOT IN REPORT: %s (%s): %s; it is set aside", filepath.Base(l.Path), days[0].Host, l.Reason)
			left = append(left, report.LeftOutLogs{Host: days[0].Host, From: l.From, To: l.To, Reason: l.Reason,
				SetAside: setAsidePath(l.Path)})
		}
		if b.SHA256 == "" {
			continue // none of them passed
		}
		fi, _ := os.Stat(tmp)
		var size uint64
		if fi != nil {
			size = uint64(fi.Size())
		}
		refs = append(refs, report.ArchiveRef{Host: days[0].Host, From: b.From, To: b.To, Name: name, Path: tmp, Bytes: size, SHA256: b.SHA256, Gaps: b.Gaps, Logs: b.Logs, Notes: b.Notes, Changed: b.Changed})
		for _, d := range days {
			if !leftOut(b.LeftOut, d.Path) {
				used = append(used, d.Path)
			}
		}
	}
	return refs, used, left
}

func leftOut(l []archive.LeftOut, path string) bool {
	for _, x := range l {
		if x.Path == path {
			return true
		}
	}
	return false
}

// setAsidePath is where a daily archive that failed its check is moved:
// a set-aside folder next to it, which is not read as pending (AR7).
func setAsidePath(path string) string {
	return filepath.Join(filepath.Dir(path), "set-aside", filepath.Base(path))
}

// setAside moves a daily archive left out of a report aside; it says
// where it is.
func setAside(path string) string {
	dst := setAsidePath(path)
	err := os.MkdirAll(filepath.Dir(dst), 0o750)
	if err == nil {
		err = os.Rename(path, dst)
	}
	if err != nil {
		return path + " (it could not be moved: " + err.Error() + ")"
	}
	return dst
}

// recentLeftOut are the archives left out of scheduled reports in the
// last logGapsKept, for a manual report (AR7).
func (a *App) recentLeftOut(st *store.Store) []report.LeftOutLogs {
	var out []report.LeftOutLogs
	for _, l := range st.State.LeftOut {
		if a.now().Sub(l.Noted) < logGapsKept {
			out = append(out, report.LeftOutLogs{Report: l.Report, Host: l.Host, From: l.From, To: l.To, Reason: l.Reason, SetAside: l.SetAside})
		}
	}
	return out
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
	opt := a.liveOptions()
	run, err := collect.Live(st, opt)
	if err != nil {
		return err
	}
	a.collected(opt)
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

// turnover is how fast this computer's logs were seen turning over since
// the last report, as status says it, for the size check (LOG1d).
func turnover(st *store.Store, now time.Time, every time.Duration) func(string) (rollover.Loss, bool) {
	self := store.SystemKey(collect.LocalHost())
	seen := map[string]rollover.Loss{}
	for _, l := range lostSince(st, st.State.LastWindowEnd, now, every) {
		if store.SystemKey(l.Host) == self && l.Held > 0 {
			seen[strings.ToLower(l.Channel)] = l.Loss
		}
	}
	return func(log string) (rollover.Loss, bool) {
		l, ok := seen[strings.ToLower(log)]
		return l, ok
	}
}

// CheckTurnover is turnover for blackbox check, from the data folder (nil
// if it can't be read).
func (a *App) CheckTurnover() func(string) (rollover.Loss, bool) {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return nil
	}
	return turnover(st, a.now(), a.Cfg.CollectEvery)
}

// recordChecks checks this system's audit settings and keeps the result,
// so it reaches reports here or on the collector.
func (a *App) recordChecks(st *store.Store, host string, force bool) error {
	_, err := a.checkNow(st, host, force)
	return err
}

// checkNow is recordChecks, returning what it recorded (nil when no check
// was due, or checks are not supported here).
func (a *App) checkNow(st *store.Store, host string, force bool) (*store.CheckRecord, error) {
	if !check.Supported && a.RunCheck == nil {
		return nil, nil
	}
	now := a.now()
	if !force && !checkDue(st.State.LastCheck, a.bootTime(), now) {
		return nil, nil
	}
	run := a.RunCheck
	if run == nil {
		run = check.Run
	}
	check.Turnover = turnover(st, now, a.Cfg.CollectEvery)
	rec := &store.CheckRecord{Time: now, Host: host, OS: runtime.GOOS, Results: run(), Inventory: a.inventory()}
	if err := st.AppendChecks(rec); err != nil {
		return rec, err
	}
	st.State.LastCheck = now
	return rec, nil
}

// RecordCheck checks the audit settings now and keeps the result with
// this computer's inventory, as a collection does (UX10b). Setup calls it
// at every install and upgrade, so the settings an upgrade or a change of
// settings left are what status and the next report show, not a check
// made up to a day before by the earlier version. It returns the results
// to show, even when they could not be kept.
func (a *App) RecordCheck() ([]check.Result, error) {
	st, unlock, err := a.openWait(sendWait)
	if err != nil {
		run := a.RunCheck
		if run == nil {
			run = check.Run
		}
		return run(), err
	}
	defer unlock()
	rec, err := a.checkNow(st, collect.LocalHost(), true)
	if serr := st.Save(); err == nil {
		err = serr
	}
	if rec == nil {
		return nil, err
	}
	return rec.Results, err
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
		a.noteBlocked(err)
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
	a.verifyReports(st)
	end, due := DueWindowEnd(a.Cfg.ReportEvery, a.Cfg.ReportAt, st.State.LastWindowEnd, a.now(), a.loc())
	if !due {
		a.packLogs(st, false)
		// Reports deleted since the last one drop off the index, and
		// missing scheduled ones show, without waiting for a report.
		a.refreshIndex(st)
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
	opt := a.liveOptions()
	run, err := collect.Live(st, opt)
	if err == nil {
		a.collected(opt)
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
	// Inbox conflicts recorded since the last report are High rows (SEC1).
	events = append(events, lan.ConflictEvents(st, prevGen, generated)...)
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
	var leftLogs []report.LeftOutLogs
	if advance {
		a.packLogs(st, true)
		logs, usedLogs, leftLogs = a.bundleLogs(generated)
		defer func() {
			for _, l := range logs {
				os.Remove(l.Path) // left only if the report was not written
			}
		}()
	}
	var waiting *report.WaitingLogs
	if !advance {
		waiting = a.waitingLogs(st)
		leftLogs = a.recentLeftOut(st)
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
	ownRuns := runsCovering(st, events, runs, runsSince)
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
		ClockBack: clockJumps(clockBack), MissingReports: reportProblems(st),
		Source: "Live collection", Location: a.loc(), InReportsDir: true, Interim: !advance, Period: a.Cfg.ReportEvery,
		History:      report.History(a.ReportsDir(), end, report.HistoryWeeks),
		ExcludeUsers: a.Cfg.ExcludeUsers, ExcludeProcesses: a.Cfg.ExcludeProcesses,
		KnownDevices: st.State.KnownDevices, CheckSets: sets,
		Context: context, Baseline: st.State.Baseline, BaselineHosts: st.State.BaselineHosts,
		WorkingHours: a.Cfg.WorkingHours,
		Archives:     logs, ArchivesKept: advance, Waiting: waiting, OwnRuns: ownRuns, PackFailing: packFailing(st), LeftOut: leftLogs,
		Systems: systemsFor(st, prevEnd, a.Cfg.Inbox != ""), Collector: a.Cfg.Inbox != "",
		LANWarnings:   append(lanWarnings(st, prevGen, generated, a.loc()), a.inboxWarnings()...),
		RetentionDays: a.Cfg.RetentionDays, Overdue: a.overdueLogs(generated, notOverdue(usedLogs, leftLogs)),
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
		var keptLeft []store.LeftOutLogs
		for _, l := range st.State.LeftOut {
			if generated.Sub(l.Noted) < logGapsKept {
				keptLeft = append(keptLeft, l)
			}
		}
		for _, l := range leftLogs {
			// Out of the pending folder, so the next report does not try
			// it again, and kept for the administrator (AR7).
			src := filepath.Join(filepath.Dir(filepath.Dir(l.SetAside)), filepath.Base(l.SetAside))
			keptLeft = append(keptLeft, store.LeftOutLogs{Report: filepath.Base(dir), Host: l.Host, From: l.From, To: l.To,
				Reason: l.Reason, SetAside: setAside(src), Noted: generated})
		}
		st.State.LeftOut = keptLeft
		for _, p := range usedLogs {
			if err := os.Remove(p); err != nil {
				a.logf("removing a daily log archive now in the report: %v", err)
			}
		}
		st.State.LastWindowEnd = end
		st.State.LastGenerated = generated
		st.State.ReportedTo = marks
		noteReport(st, dir, windowStart, end, generated)
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
		removed, err := pruneReports(a.ReportsDir(), a.Cfg.RetentionDays, generated, st.State.Reports)
		if err != nil {
			a.logf("pruning old reports: %v", err)
		}
		// Listed in the next scheduled report; this one listed the last.
		st.State.RemovedReports = removed
		markRemoved(st, a.ReportsDir(), removed, generated)
		if err := st.Save(); err != nil {
			a.logf("noting removed reports: %v", err)
		}
		// Archives still waiting in archive_dir are never pruned: they are
		// in no report yet, and may be the only copy (RET1).
	}
	a.refreshIndex(st)
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
//
// A computer that no longer receives (a collector made standalone or a
// sender) leaves out the computers that sent to it and sent nothing this
// period (ROLE1): they are not its systems any more.
func systemsFor(st *store.Store, start time.Time, collector bool) []report.SystemInfo {
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
		if !collector && k != store.SystemKey(collect.LocalHost()) && !s.LastReceived.After(start) {
			continue
		}
		out = append(out, report.SystemInfo{Name: s.Name, OS: s.OS, Version: s.Version, Via: s.Via,
			FirstSeen: s.FirstSeen, LastRun: s.LastRun, LastReceived: s.LastReceived, Former: s.Former, VM: s.VM,
			Removed: s.Removed, RemovedBy: s.RemovedBy})
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
	var out []string
	if bad := lan.Unreadable(a.Cfg.Inbox); len(bad) > 0 {
		out = append(out, unreadableText(bad)+". Their events are not in this report; fix the file permissions so the next run imports them.")
	}
	// SEC2: files set aside are in no report until sent again.
	if rej := lan.Rejected(a.Cfg.Inbox); len(rej) > 0 {
		out = append(out, fmt.Sprintf("%d file%s in the inbox could not be used and %s set aside in %s; their data is not in this report: %s",
			len(rej), map[bool]string{true: "s"}[len(rej) != 1], map[bool]string{true: "were", false: "was"}[len(rej) != 1],
			filepath.Join(a.Cfg.Inbox, "rejected"), strings.Join(rej, "; ")))
	}
	return out
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
		if retiredSender(st, s) {
			continue // SEC1d
		}
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

// addLogGap adds g unless the same gap is already listed: a pack can
// name one export's gap twice, and status should say it once.
func addLogGap(gaps []store.LogGap, g store.LogGap) []store.LogGap {
	for _, o := range gaps {
		if o.Source == g.Source && o.Reason == g.Reason && o.From.Equal(g.From) && o.To.Equal(g.To) {
			return gaps
		}
	}
	return append(gaps, g)
}
