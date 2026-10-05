//go:build !windows

package app

import (
	"archive/zip"
	"bytes"
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
		!strings.Contains(b.String(), audit+" had already overwritten its events from 2026-10-05 12:30 to 2026-10-05 12:40") {
		t.Errorf("status (%v):\n%s", err, b.String())
	}

	refs, _ := a.bundleLogs(now)
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

	refs, _ := a.bundleLogs(now)
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
	refs, used := a.bundleLogs(now)
	if len(refs) != 2 || len(used) != 2 {
		t.Errorf("bundled %d archives (%d used), want this computer's and the one left in the data folder", len(refs), len(used))
	}
}
