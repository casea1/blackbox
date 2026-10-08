//go:build !windows

package app

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
)

// auditFixture points the collector's log paths at an audit.log in base
// holding one record per time given, and returns its path.
func auditFixture(t *testing.T, base string, times ...time.Time) string {
	t.Helper()
	audit := filepath.Join(base, "audit.log")
	t.Cleanup(func(a string, s, au []string) func() {
		return func() { collect.AuditLog, collect.SystemLogs, collect.AuthLogs = a, s, au }
	}(collect.AuditLog, collect.SystemLogs, collect.AuthLogs))
	// An empty system log, so the export never falls back to this
	// machine's own systemd journal.
	syslog := filepath.Join(base, "syslog")
	os.WriteFile(syslog, nil, 0o644)
	collect.AuditLog, collect.SystemLogs, collect.AuthLogs = audit, []string{syslog}, nil
	writeAudit(t, audit, times...)
	return audit
}

func writeAudit(t *testing.T, audit string, times ...time.Time) {
	t.Helper()
	var b strings.Builder
	for i, at := range times {
		fmt.Fprintf(&b, "type=SYSCALL msg=audit(%d.000:%d): rec%02d\n", at.Unix(), i+1, i)
	}
	if err := os.WriteFile(audit, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	// Written "now" as far as the export can tell.
	last := times[len(times)-1].Add(time.Hour)
	os.Chtimes(audit, last, last)
}

// zipText reads one file of a zip.
func zipText(t *testing.T, path, name string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == name {
			r, _ := f.Open()
			b, _ := io.ReadAll(r)
			r.Close()
			return string(b)
		}
	}
	t.Fatalf("%s has no %s", path, name)
	return ""
}

func auditRun(at time.Time, read int, lost uint64, first time.Time) *store.Run {
	cr := store.ChannelRun{Channel: collect.AuditLog, Read: read, FirstTime: first}
	if lost > 0 {
		cr.Gap = &store.Gap{Lost: lost}
	}
	return &store.Run{Time: at, Host: collect.LocalHost(), Channels: []store.ChannelRun{cr}}
}

// AR2: the original logs are exported at every collection, so a log that
// rolls over within the day loses only what it had overwritten before the
// last collection; the archive and the report say, for each log, how far
// back it actually reaches and how many events it overwrote first.
func TestOriginalLogsExportedEachCollection(t *testing.T) {
	base := t.TempDir()
	day := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	at := func(h, m int) time.Time { return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }
	audit := auditFixture(t, base, at(4, 8), at(11, 50), at(12, 10))

	st, _ := store.Open(filepath.Join(base, "data"))
	now := at(12, 0)
	var states []archive.LogState
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: 15 * time.Minute}, Loc: time.UTC,
		Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return states }}

	// The first export reaches back a week, but the Security log (here the
	// audit log) had rolled over: it holds nothing before 04:08, and the
	// collection already knew 94,565 events were overwritten.
	states = []archive.LogState{{Source: audit, Oldest: at(4, 8), Wraps: true}}
	a.saveLogPiece(st, auditRun(now, 3, 94565, at(4, 8)), time.Time{})
	if !st.State.ArchivedUntil.Equal(now) {
		t.Fatalf("archived until %v", st.State.ArchivedUntil)
	}

	// 12:15: one new record, exported at once.
	prev := now
	now = at(12, 15)
	a.saveLogPiece(st, auditRun(now, 1, 0, at(12, 10)), prev)

	// 12:30: nothing new; the log is left out of the export.
	prev, now = now, at(12, 30)
	a.saveLogPiece(st, auditRun(now, 0, 0, time.Time{}), prev)

	// 12:45: Windows Update ran; the log rolled over and overwrote 500
	// events written after the 12:30 export.
	writeAudit(t, audit, at(12, 40), at(12, 44))
	states = []archive.LogState{{Source: audit, Oldest: at(12, 40), Wraps: true}}
	prev, now = now, at(12, 45)
	a.saveLogPiece(st, auditRun(now, 2, 500, at(12, 40)), prev)

	pieces, _ := archive.Pieces(a.piecesDir())
	if len(pieces) != 4 || len(pieces[2].Info.Files) != 0 || len(pieces[3].Info.Gaps) != 1 {
		t.Fatalf("pieces: %+v", pieces)
	}

	a.packLogs(st, true)
	if p, _ := archive.Pieces(a.piecesDir()); len(p) != 0 {
		t.Errorf("pieces left after packing: %d", len(p))
	}
	list, _ := archive.List(a.pendingLogsDir())
	if len(list) != 1 {
		t.Fatalf("archives: %+v", list)
	}
	info, err := archive.Verify(list[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.From.Equal(day.Add(12*time.Hour).AddDate(0, 0, -7)) || !info.To.Equal(at(12, 45)) {
		t.Errorf("archive period %v – %v", info.From, info.To)
	}
	got := zipText(t, list[0].Path, "audit.log")
	for _, want := range []string{"rec00", "rec01", "rec02"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit.log misses %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "\n") != 5 {
		t.Errorf("audit.log has %d lines, want 5 (3 + 2, nothing twice):\n%s", strings.Count(got, "\n"), got)
	}
	if len(info.Logs) != 1 || !info.Logs[0].From.Equal(at(4, 8)) || info.Logs[0].Overwritten != 94565+500 {
		t.Errorf("coverage: %+v", info.Logs)
	}
	if len(info.Gaps) != 1 || !info.Gaps[0].From.Equal(at(12, 30)) || !info.Gaps[0].To.Equal(at(12, 40)) {
		t.Errorf("gaps: %+v", info.Gaps)
	}

	st.Save()
	var b bytes.Buffer
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) || !strings.Contains(b.String(), "LOGS INCOMPLETE:") ||
		!strings.Contains(b.String(), "the audit log had already overwritten its events from 2026-10-05 12:30 to 2026-10-05 12:40") {
		t.Errorf("status (%v):\n%s", err, b.String())
	}

	refs, _, _ := a.bundleLogs(now)
	if len(refs) != 1 || len(refs[0].Gaps) != 1 || len(refs[0].Logs) != 1 {
		t.Fatalf("bundle: %+v", refs)
	}
	r := report.Build(nil, nil, report.Options{WindowEnd: now, Location: time.UTC, Archives: refs, ArchivesKept: true})
	if !strings.Contains(strings.Join(r.Health.Warnings, "\n"), "the original logs are incomplete: "+audit+" had already overwritten its events from") {
		t.Errorf("report warnings: %v", r.Health.Warnings)
	}
	dir := filepath.Join(base, "report")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, want := range []string{
		"Covers from 5 Oct 04:08; 95,065 events were overwritten before they could be exported; Missing 5 Oct 12:30 – 5 Oct 12:40: overwritten before it was saved",
		audit + ": covers from 5 Oct 04:08",
	} {
		if !strings.Contains(string(html), want) {
			t.Errorf("the Original logs page does not say %q", want)
		}
	}
	sum, _ := os.ReadFile(filepath.Join(dir, "summary.json"))
	if !strings.Contains(string(sum), `"overwritten": 95065`) {
		t.Errorf("summary.json has no coverage:\n%s", sum)
	}
}

// AR1: the clock runs 3 hours fast, the logs are exported, the clock is
// corrected. What is written after the correction is stamped before the
// end of the last export, and must still be exported, with a note.
func TestOriginalLogsAfterClockMovedBack(t *testing.T) {
	base := t.TempDir()
	day := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	at := func(h, m int) time.Time { return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }
	// Stamped by the fast clock (06:50, 06:58), then after the correction
	// (03:50 the log clear, 03:55 a settings change).
	audit := auditFixture(t, base, at(6, 50), at(6, 58))

	st, _ := store.Open(filepath.Join(base, "data"))
	st.State.ArchivedUntil = at(6, 45)
	st.State.LastCollect = at(6, 45)
	now := at(7, 0) // really 04:00
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: 15 * time.Minute}, Loc: time.UTC,
		Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return nil }}
	a.saveLogPiece(st, auditRun(now, 2, 0, at(6, 50)), at(6, 45))
	if !st.State.ArchivedUntil.Equal(at(7, 0)) {
		t.Fatalf("archived until %v", st.State.ArchivedUntil)
	}

	// The clock is set back 3 hours; the log clear and settings change
	// are stamped 03:50 and 03:55, before the end of the last export.
	writeAudit(t, audit, at(6, 50), at(6, 58), at(3, 50), at(3, 55))
	now = at(4, 0)
	a.saveLogPiece(st, auditRun(now, 2, 0, at(3, 50)), at(7, 0))
	if !st.State.ArchivedUntil.Equal(at(4, 0)) || !st.State.ArchiveRestart.IsZero() {
		t.Fatalf("archived until %v, restart %v", st.State.ArchivedUntil, st.State.ArchiveRestart)
	}

	// The next collection carries on from there.
	writeAudit(t, audit, at(6, 50), at(6, 58), at(3, 50), at(3, 55), at(4, 5))
	now = at(4, 15)
	a.saveLogPiece(st, auditRun(now, 1, 0, at(4, 5)), at(4, 0))

	a.packLogs(st, true)
	list, _ := archive.List(a.pendingLogsDir())
	if len(list) != 1 {
		t.Fatalf("archives: %+v", list)
	}
	info, err := archive.Verify(list[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	got := zipText(t, list[0].Path, "audit.log")
	for _, want := range []string{"rec00", "rec01", "rec02", "rec03", "rec04"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit.log misses %s (the stretch after the clock change was skipped):\n%s", want, got)
		}
	}
	if !info.From.Equal(at(3, 50)) || !info.To.Equal(at(4, 15)) {
		t.Errorf("archive period %v – %v", info.From, info.To)
	}
	notes := strings.Join(info.Notes, "\n")
	if !strings.Contains(notes, "The clock was moved back") || !strings.Contains(notes, "starts again at 2026-10-05 03:50Z") {
		t.Errorf("notes: %q", info.Notes)
	}

	refs, _, _ := a.bundleLogs(now)
	r := report.Build(nil, nil, report.Options{WindowEnd: now, Location: time.UTC, Archives: refs, ArchivesKept: true})
	dir := filepath.Join(base, "report")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	if !strings.Contains(string(html), "The clock was moved back: the export before this one ran to 2026-10-05 07:00Z") {
		t.Error("the Original logs page does not explain the clock change")
	}
}

// With archive_dir set (a larger volume), the exports and the archives
// waiting for the next report go there; those already waiting in the data
// folder still go into the next report.
func TestArchiveDirElsewhere(t *testing.T) {
	base := t.TempDir()
	day := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	auditFixture(t, base, day.Add(11*time.Hour), day.Add(11*time.Hour+30*time.Minute))
	st, _ := store.Open(filepath.Join(base, "data"))
	now := day.Add(12 * time.Hour)
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: 15 * time.Minute}, Loc: time.UTC,
		Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return nil }}
	// Waiting from before archive_dir was set.
	pendingLogs(t, a, "OLD-HOST", now.Add(-time.Hour))

	a.Cfg.ArchiveDir = filepath.Join(base, "bigdisk", "logs")
	a.saveLogPiece(st, auditRun(now, 2, 0, day.Add(11*time.Hour)), time.Time{})
	if p, _ := archive.Pieces(filepath.Join(a.Cfg.ArchiveDir, ".exports")); len(p) != 1 {
		t.Fatalf("exports not in archive_dir: %d", len(p))
	}
	a.packLogs(st, true)
	list, _ := archive.List(a.Cfg.ArchiveDir)
	if len(list) != 1 || list[0].Host != archive.SafeName(collect.LocalHost()) {
		t.Fatalf("archives in archive_dir: %+v", list)
	}
	refs, used, _ := a.bundleLogs(now)
	if len(refs) != 2 || len(used) != 2 {
		t.Errorf("bundled %d archives (%d used), want this computer's and the one left in the data folder", len(refs), len(used))
	}
}

// UI5: a manual report keeps no original logs; its Original logs page says
// where they wait (archive_dir), the period and size so far, and which
// scheduled report will hold them. The logs stay where they are.
func TestManualReportSaysWhereLogsWait(t *testing.T) {
	base := t.TempDir()
	day := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	auditFixture(t, base, day.Add(5*time.Hour), day.Add(6*time.Hour))
	st, _ := store.Open(filepath.Join(base, "data"))
	now := day.Add(6*time.Hour + 44*time.Minute)
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: filepath.Join(base, "reports"), ArchiveDir: filepath.Join(base, "bigdisk"),
		ReportEvery: "daily", ReportAt: config.DefaultReportAt, CollectEvery: 15 * time.Minute}, Version: "test", Loc: time.UTC,
		Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return nil }}
	st.State.LastWindowEnd, st.State.LastGenerated = day, day.Add(5*time.Minute)
	pendingLogs(t, a, "ubuntu-server", day) // a daily archive from a sender
	st.State.ArchivedUntil = day            // exported up to midnight, then since
	a.saveLogPiece(st, auditRun(now, 2, 0, day.Add(5*time.Hour)), day)

	dir, err := a.report(st, now, false)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	h := string(html)
	for _, want := range []string{"Where the original logs are", "they wait in " + a.Cfg.ArchiveDir,
		"So far they cover 2026-10-04 00:00 to 2026-10-05 06:44", "from 2 systems", "The scheduled report due Tue 6 Oct 00:00 holds them",
		"Waiting in " + a.Cfg.ArchiveDir + " for the next scheduled report",
		"5 Oct 00:00 – 06:44", "the raw Windows and Linux logs wait for the next scheduled report"} {
		if !strings.Contains(h, want) {
			t.Errorf("manual report lacks %q", want)
		}
	}
	if strings.Contains(h, "made without keeping the original logs") || strings.Contains(h, "Hashes verified") {
		t.Error("the manual report still shows the empty archive page")
	}
	if p, _ := archive.Pieces(a.piecesDir()); len(p) != 1 {
		t.Errorf("the manual report moved the waiting exports: %d left", len(p))
	}
	if l, _ := archive.List(a.pendingLogsDir()); len(l) != 1 {
		t.Errorf("the manual report moved the waiting archives: %d left", len(l))
	}
}

// AR2c, as on the Windows 11 VM on 7 Oct: a hand-run "blackbox run" made
// the scheduled report at 13:53:04, then went on exporting the original
// logs; the Event Log service's writes of the pieces (4663 at 13:53:08,
// collected by the next run) were High rows in a manual report made
// after, because it read only the runs since 13:53:04. They are
// Blackbox's own, whenever the report is made; another write stays.
func TestManualReportAfterRunDropsExportWrites(t *testing.T) {
	base := t.TempDir()
	st, _ := store.Open(filepath.Join(base, "data"))
	at := func(h, m, s int) time.Time { return time.Date(2026, 10, 7, h, m, s, 0, time.UTC) }
	now := at(14, 0, 0)
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: filepath.Join(base, "reports"), ReportEvery: "daily", ReportAt: config.DefaultReportAt, CollectEvery: 15 * time.Minute},
		Version: "test", Loc: time.UTC, Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return nil }}
	host := collect.LocalHost()
	st.AppendRun(&store.Run{Time: at(13, 53, 0), Host: host, Duration: 6, Version: "0.19.0"})
	st.AppendRun(&store.Run{Time: at(13, 58, 0), Host: host, Duration: 5, Version: "0.19.0"})
	st.State.LastWindowEnd, st.State.LastGenerated = at(0, 0, 0), at(13, 53, 4)
	write := func(sec int, name string, piece bool) *event.Event {
		e := &event.Event{Time: at(13, 53, sec), Host: host, Category: event.CatIntegrity, Severity: event.SevHigh, Action: "blackbox_files_changed",
			User: host + `\tester`, Process: `C:\Windows\System32\svchost.exe`, Target: `C:\ProgramData\Blackbox\archive-pieces\000011\` + name,
			Summary: host + `\tester changed C:\ProgramData\Blackbox\archive-pieces\000011\` + name + " (using svchost.exe)."}
		if piece {
			e.Fields = map[string]string{event.ExportPieceFlag: "1"}
		}
		return e
	}
	evs := []*event.Event{write(8, "Security.evtx", true), write(8, "System.evtx", true), write(8, "Application.evtx", true), write(8, "Microsoft-Windows-PowerShell-Operational.evtx", true),
		write(30, "notes.txt", false)} // not a piece: someone else
	evs[4].Process = `C:\Windows\System32\notepad.exe`
	st.AppendEvents(at(13, 58, 0), evs)
	st.Save()

	dir, err := a.report(st, now, false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "summary.json"))
	var s report.Summary
	json.Unmarshal(b, &s)
	if s.High != 1 || s.Events != 1 {
		t.Errorf("manual report: %d events, %d high; want only the notepad write: %s", s.Events, s.High, b)
	}
}

// LC2, LC2b: a log cleared since the last export reaches back only to the
// clear, and its file keeps its size: that part is labelled as the clear
// (who and when), not an overwrite, and status gives no "LOGS INCOMPLETE"
// or size advice for it. Also when the log stayed empty at the run that
// read the clear, and its first record came only by the next run.
func TestClearedLogIsNotAGap(t *testing.T) {
	base := t.TempDir()
	day := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	at := func(h, m int) time.Time { return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }
	audit := auditFixture(t, base, at(5, 0), at(6, 10))
	st, _ := store.Open(filepath.Join(base, "data"))
	now := at(6, 0)
	var states []archive.LogState
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: 15 * time.Minute}, Loc: time.UTC,
		Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return states }}
	states = []archive.LogState{{Source: audit, Oldest: at(5, 0), Wraps: true}}
	a.saveLogPiece(st, auditRun(now, 1, 0, at(5, 0)), time.Time{})

	// 06:17: cleared by claude. The log now starts at 06:17 and is still
	// "full".
	prev := now
	now = at(6, 30)
	states = []archive.LogState{{Source: audit, Oldest: at(6, 17), Wraps: true}}
	run := auditRun(now, 1, 0, at(6, 17))
	run.Channels[0].Cleared, run.Channels[0].ClearedAt, run.Channels[0].ClearedBy = true, at(6, 16), "claude"
	st.AppendRun(run)
	a.saveLogPiece(st, run, prev)
	if len(st.State.LogGaps) != 1 || st.State.LogGaps[0].Cleared == nil || st.State.LogGaps[0].Cleared.By != "claude" {
		t.Errorf("the clear is not labelled: %+v", st.State.LogGaps)
	}
	pieces, _ := archive.Pieces(a.piecesDir())
	if g := pieces[len(pieces)-1].Info.Gaps; len(g) != 1 || g[0].Cleared != "by claude at 2026-10-07 06:16Z" {
		t.Errorf("piece gaps: %+v", g)
	}
	st.Save()
	var b bytes.Buffer
	if err := a.Status(&b); err != nil || strings.Contains(b.String(), "LOGS INCOMPLETE") || strings.Contains(b.String(), "larger") || strings.Contains(b.String(), "EVENTS LOST") ||
		!strings.Contains(b.String(), "Log cleared:      "+audit+" was cleared by claude at 2026-10-07 06:16;") { // local (TZ1)
		t.Errorf("status (%v):\n%s", err, b.String())
	}

	// LC2b, LC2c: cleared at 06:40; the run at 06:45 reads the clear
	// while the log is empty: the clear is the gap at once (06:30, the
	// last export, to 06:40). Its first record comes at 06:50; the 07:00
	// run, which has no clear in it, finds the log still "full" from
	// 06:50, which is not an overwrite and not a second clear.
	st.State.LogGaps = nil
	prev, now = now, at(6, 45)
	states = []archive.LogState{{Source: audit, Wraps: true}}
	run = auditRun(now, 0, 0, time.Time{})
	run.Channels[0].Cleared, run.Channels[0].ClearedAt, run.Channels[0].ClearedBy = true, at(6, 40), "claude"
	st.AppendRun(run)
	a.saveLogPiece(st, run, prev)
	if len(st.State.LogGaps) != 1 || st.State.LogGaps[0].Cleared == nil || !st.State.LogGaps[0].Cleared.At.Equal(at(6, 40)) ||
		!st.State.LogGaps[0].From.Equal(at(6, 30)) || !st.State.LogGaps[0].To.Equal(at(6, 40)) {
		t.Fatalf("the clear read with the log empty is not a gap: %+v", st.State.LogGaps)
	}
	prev, now = now, at(7, 0)
	states = []archive.LogState{{Source: audit, Oldest: at(6, 50), Wraps: true}}
	run = auditRun(now, 1, 0, at(6, 50))
	st.AppendRun(run)
	a.saveLogPiece(st, run, prev)
	if len(st.State.LogGaps) != 1 {
		t.Fatalf("a second gap after the clear: %+v", st.State.LogGaps)
	}
	pieces, _ = archive.Pieces(a.piecesDir())
	if g := pieces[len(pieces)-1].Info.Gaps; len(g) != 0 {
		t.Errorf("the 07:00 piece has gaps: %+v", g)
	}
	// Once a record since the clear has been exported, a gap is an
	// overwrite again.
	st.State.LogGaps = nil
	prev, now = now, at(7, 15)
	states = []archive.LogState{{Source: audit, Oldest: at(6, 50), Wraps: true}}
	a.saveLogPiece(st, auditRun(now, 1, 0, at(7, 5)), prev)
	if len(st.State.Clears) != 0 {
		t.Errorf("clear kept after a record since it was exported: %+v", st.State.Clears)
	}
	prev, now = now, at(7, 30)
	states = []archive.LogState{{Source: audit, Oldest: at(7, 20), Wraps: true}}
	a.saveLogPiece(st, auditRun(now, 1, 0, at(7, 20)), prev)
	if len(st.State.LogGaps) != 1 || st.State.LogGaps[0].Cleared != nil {
		t.Errorf("an overwrite after the clear: %+v", st.State.LogGaps)
	}
}

// LOG1b: an incomplete PowerShell log is its own, lower line (status
// does not exit 4 for it alone), a gap within one minute reads "at about",
// and "collect more often" is said only when it would help.
func TestLogsIncompleteSplit(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	at := time.Date(2026, 10, 7, 6, 17, 0, 0, time.UTC)
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: 15 * time.Minute}, Loc: time.UTC,
		Now: func() time.Time { return at.Add(time.Hour) }}
	st.State.LogGaps = []store.LogGap{{Source: "Microsoft-Windows-PowerShell/Operational", From: at, To: at.Add(20 * time.Second), Noted: at}}
	st.Save()
	var b bytes.Buffer
	if err := a.Status(&b); err != nil {
		t.Errorf("status exits for the PowerShell log alone: %v\n%s", err, b.String())
	}
	if !strings.Contains(b.String(), "Logs incomplete:") || !strings.Contains(b.String(), "at about 2026-10-07 06:17") ||
		strings.Contains(b.String(), "from 2026-10-07 06:17 to 2026-10-07 06:17") || strings.Contains(b.String(), "collect more often") {
		t.Errorf("status:\n%s", b.String())
	}
	// The Security log's gap still makes it exit 4; collecting hourly,
	// collecting more often is offered.
	a.Cfg.CollectEvery = time.Hour
	st.State.LogGaps = append(st.State.LogGaps, store.LogGap{Source: "Security", From: at.Add(-time.Hour), To: at, Noted: at})
	st.Save()
	b.Reset()
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) || !strings.Contains(b.String(), "LOGS INCOMPLETE:  the Security log had already overwritten its events from 2026-10-07 05:17 to 2026-10-07 06:17") ||
		!strings.Contains(b.String(), "or collect more often") {
		t.Errorf("status (%v):\n%s", err, b.String())
	}
}

// AR5: while the exports cannot be packed, status says so and exits 4,
// and the report says why; once packing works, an export lost in the
// meantime is a gap with its reason, and packing goes on without it.
func TestPackFailingAndLostExport(t *testing.T) {
	base := t.TempDir()
	now := time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC)
	st, _ := store.Open(filepath.Join(base, "data"))
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: 15 * time.Minute}, Loc: time.UTC,
		Now: func() time.Time { return now }}
	export := func(dir string, from, to time.Time, skip func(string) bool) ([]archive.Source, []string, []archive.Gap) {
		var out []archive.Source
		for _, n := range []string{"Security.evtx", "Application.evtx"} {
			p := filepath.Join(dir, n)
			os.WriteFile(p, []byte(n+from.Format("1504")), 0o644)
			out = append(out, archive.Source{Name: n, Source: strings.TrimSuffix(n, ".evtx"), Path: p})
		}
		return out, nil, nil
	}
	for i := 0; i < 2; i++ {
		from := now.Add(time.Duration(i-2) * time.Hour)
		if _, err := archive.SavePiece(a.piecesDir(), archive.Info{Host: collect.LocalHost(), From: from, To: from.Add(time.Hour), Created: from.Add(time.Hour)}, export, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Something in the way of the archive folder.
	block := filepath.Join(a.pendingLogsDir(), archive.SafeName(collect.LocalHost()))
	os.MkdirAll(filepath.Dir(block), 0o750)
	os.WriteFile(block, []byte("x"), 0o644)

	a.packLogs(st, true)
	st, _ = store.Open(st.Dir) // what was saved
	f := st.State.PackFailing
	if f == nil || !f.Since.Equal(now) || f.Reason == "" {
		t.Fatalf("pack failure not kept: %+v", f)
	}
	var b bytes.Buffer
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) || !strings.Contains(b.String(), "ORIGINAL LOGS NOT ARCHIVED since 2026-10-07 13:00: ") {
		t.Errorf("status (%v):\n%s", err, b.String())
	}
	// Later failures keep when it started.
	now = now.Add(time.Hour)
	a.packLogs(st, true)
	if !st.State.PackFailing.Since.Equal(now.Add(-time.Hour)) {
		t.Errorf("failing since %v", st.State.PackFailing.Since)
	}
	r := report.Build(nil, nil, report.Options{WindowEnd: now, Location: time.UTC, PackFailing: packFailing(st), ArchivesKept: true})
	if w := strings.Join(r.Health.Warnings, "\n"); !strings.Contains(w, "ORIGINAL LOGS NOT ARCHIVED: ") || !strings.Contains(w, "have not been archived since 2026-10-07 13:00") {
		t.Errorf("report warnings: %s", w)
	}
	dir := filepath.Join(base, "report")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	if html, _ := os.ReadFile(filepath.Join(dir, "report.html")); !strings.Contains(string(html), "have not been archived since") {
		t.Error("Original logs page does not say packing fails")
	}

	// Fixed; meanwhile one export was deleted.
	os.Remove(block)
	pieces, _ := archive.Pieces(a.piecesDir())
	os.Remove(filepath.Join(pieces[0].Dir, "Security.evtx"))
	a.packLogs(st, true)
	st, _ = store.Open(st.Dir)
	if st.State.PackFailing != nil {
		t.Errorf("still failing: %+v", st.State.PackFailing)
	}
	if p, _ := archive.Pieces(a.piecesDir()); len(p) != 0 {
		t.Errorf("pieces left: %d", len(p))
	}
	if len(st.State.LogGaps) != 1 || st.State.LogGaps[0].Source != "Security" || !strings.Contains(st.State.LogGaps[0].Reason, "was missing") {
		t.Fatalf("gaps: %+v", st.State.LogGaps)
	}
	b.Reset()
	if err := a.Status(&b); !errors.As(err, &na) || strings.Contains(b.String(), "NOT ARCHIVED") || !strings.Contains(b.String(), "LOGS INCOMPLETE:  Security.evtx, exported for 2026-10-07 11:00 to 2026-10-07 12:00,") { // local (TZ1)
		t.Errorf("status (%v):\n%s", err, b.String())
	}
	refs, _, _ := a.bundleLogs(now)
	r = report.Build(nil, nil, report.Options{WindowEnd: now, Location: time.UTC, Archives: refs, ArchivesKept: true})
	if w := strings.Join(r.Health.Warnings, "\n"); !strings.Contains(w, "the original logs are incomplete: Security.evtx") {
		t.Errorf("report warnings: %s", w)
	}
}

// LOG1c: one "Logs incomplete" line per log, with the count, the latest
// part and the same advice as its "Events lost" line: a log too small for
// how fast it is written is not told to collect more often.
func TestLogsIncompleteOneLinePerLog(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	at := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: time.Hour}, Loc: time.UTC,
		Now: func() time.Time { return at.Add(8 * time.Hour) }}
	ps := "Microsoft-Windows-PowerShell/Operational"
	for i := 0; i < 6; i++ {
		from := at.Add(time.Duration(i) * time.Hour)
		st.State.LogGaps = append(st.State.LogGaps, store.LogGap{Source: ps, From: from, To: from.Add(10 * time.Minute), Noted: from})
		// The log turned over after holding 9 minutes of events.
		st.AppendRun(&store.Run{Time: from.Add(10 * time.Minute), Host: collect.LocalHost(), Channels: []store.ChannelRun{{Channel: ps, MaxSizeBytes: 15 << 20,
			OldestTime: from.Add(time.Minute), Gap: &store.Gap{Lost: 100}}}})
	}
	st.Save()
	var b bytes.Buffer
	a.Status(&b)
	out := b.String()
	if n := strings.Count(out, "Logs incomplete:"); n != 1 {
		t.Errorf("%d lines for one log:\n%s", n, out)
	}
	if !strings.Contains(out, "the PowerShell log had already overwritten some of its events 6 times when the original logs were saved, since 2026-10-07 09:00; the latest from 2026-10-07 14:00 to 2026-10-07 14:10.") ||
		!strings.Contains(out, "collecting more often would not help") || strings.Contains(out, "collect more often (blackbox config set") {
		t.Errorf("status:\n%s", out)
	}
	// STAT2: the size advice is given once, on the Logs incomplete line;
	// the Events lost line points to it. The size is a stable step.
	if n := strings.Count(out, "Make it at least"); n != 1 || strings.Count(out, "wevtutil") != 1 ||
		!strings.Contains(out, "Make it at least 1 GB") || !strings.Contains(out, "What to do: see Logs incomplete above.") {
		t.Errorf("advice %d times:\n%s", n, out)
	}
}

// AR7: at a scheduled report, a daily archive that fails its check (here
// a sender's, damaged) is left out and set aside; the others, its own
// computer's other day included, go into the report. Status says so and
// exits 4, the report says why on Overview, Original logs and Audit
// health, and the next report does not try it again.
func TestArchiveLeftOutOfReport(t *testing.T) {
	base := t.TempDir()
	st, _ := store.Open(filepath.Join(base, "data"))
	end := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	now := end.Add(time.Minute)
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: filepath.Join(base, "reports"), ReportEvery: "daily", ReportAt: config.DefaultReportAt, Inbox: filepath.Join(base, "inbox")},
		Version: "test", Loc: time.UTC, Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return nil }}
	for _, h := range []string{"WIN11", "WS-07"} {
		st.AppendEvents(end.Add(-time.Hour), []*event.Event{{Time: end.Add(-time.Hour), Collected: end.Add(-time.Hour), Host: h, OS: "windows",
			Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", User: "claude", Summary: "claude logged on."}})
	}
	pendingLogs(t, a, "WIN11", end)
	pendingLogs(t, a, "WS-07", end.Add(-24*time.Hour))
	bad := pendingLogs(t, a, "WS-07", end)
	os.WriteFile(bad, []byte("damaged"), 0o644)

	dir, err := a.report(st, end, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"logs-WIN11.zip", "logs-WS-07.zip"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s not in the report: %v", n, err)
		}
	}
	aside := filepath.Join(filepath.Dir(bad), "set-aside", filepath.Base(bad))
	if _, err := os.Stat(aside); err != nil {
		t.Errorf("the bad archive was not set aside: %v", err)
	}
	if l, _ := archive.List(a.pendingLogsDir()); len(l) != 0 {
		t.Errorf("archives still pending: %+v", l)
	}
	if len(st.State.LeftOut) != 1 || st.State.LeftOut[0].Report != filepath.Base(dir) || st.State.LeftOut[0].Host != "WS-07" || st.State.LeftOut[0].SetAside != aside {
		t.Fatalf("left out: %+v", st.State.LeftOut)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	// Overview's line, and the warning on Original logs (UI-R1; was an Audit health card).
	for _, want := range []string{"Original logs not in this report", "not a readable zip file", "It was set aside in "} {
		if !strings.Contains(string(html), want) {
			t.Errorf("the report does not say %q", want)
		}
	}
	if strings.Contains(string(html), "Original logs archived") {
		t.Error(`the report says "Original logs archived"`)
	}
	var b bytes.Buffer
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) || !strings.Contains(b.String(), "ORIGINAL LOGS NOT IN REPORT "+filepath.Base(dir)+": WS-07's logs for 2026-10-07 00:00 to 2026-10-08 00:00: not a readable zip file") {
		t.Errorf("status (%v):\n%s", err, b.String())
	}
	// A manual report afterwards says so too.
	now = now.Add(time.Hour)
	man, err := a.report(st, now, false)
	if err != nil {
		t.Fatal(err)
	}
	if html, _ := os.ReadFile(filepath.Join(man, "report.html")); !strings.Contains(string(html), "Original logs left out of a report") || strings.Contains(string(html), "Original logs archived") {
		t.Error("the manual report does not say original logs were left out")
	}
	// The next scheduled report does not try it again.
	now = end.Add(24*time.Hour + time.Minute)
	if _, err := a.report(st, end.Add(24*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if len(st.State.LeftOut) != 1 {
		t.Errorf("left out again: %+v", st.State.LeftOut)
	}
}

// AR8, AR9: the original logs are exported by position. A record written
// in the same second as an export, after it, and records stamped while
// the clock was set back (before the last export's end) are in the next
// piece; nothing is recorded missing.
func TestExportByPositionNotTime(t *testing.T) {
	base := t.TempDir()
	day := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	at := func(h, m, s int) time.Time {
		return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(s)*time.Second)
	}
	audit := auditFixture(t, base, at(11, 50, 0))
	add := func(when time.Time, serial int, what string) {
		f, _ := os.OpenFile(audit, os.O_APPEND|os.O_WRONLY, 0o644)
		fmt.Fprintf(f, "type=SYSCALL msg=audit(%d.%03d:%d): %s\n", when.Unix(), when.Nanosecond()/1e6, serial, what)
		f.Close()
	}
	st, _ := store.Open(filepath.Join(base, "data"))
	now := at(12, 0, 0)
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: 15 * time.Minute}, Loc: time.UTC,
		Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return nil }}
	a.saveLogPiece(st, auditRun(now, 1, 0, at(11, 50, 0)), time.Time{})

	add(at(12, 0, 0).Add(400*time.Millisecond), 2, "same-second") // after the cut, in its second
	add(at(11, 40, 0), 3, "clock-back-logon")                     // stamped before the last export's end
	add(at(11, 40, 5), 4, "clock-change")
	prev := now
	now = at(12, 15, 0)
	a.saveLogPiece(st, auditRun(now, 3, 0, at(11, 40, 0)), prev)

	pieces, _ := archive.Pieces(a.piecesDir())
	if len(pieces) != 2 {
		t.Fatalf("pieces: %d", len(pieces))
	}
	b, _ := os.ReadFile(filepath.Join(pieces[1].Dir, "audit.log"))
	for _, want := range []string{"same-second", "clock-back-logon", "clock-change"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the second piece misses %s:\n%s", want, b)
		}
	}
	if strings.Contains(string(b), "rec00") {
		t.Errorf("exported twice:\n%s", b)
	}
	if len(pieces[1].Info.Gaps) != 0 || len(st.State.LogGaps) != 0 {
		t.Errorf("gaps: %+v %+v", pieces[1].Info.Gaps, st.State.LogGaps)
	}
	if m := st.State.ExportMarks[audit]; m.Serial != 4 || m.Offset == 0 {
		t.Errorf("mark: %+v", m)
	}
}
