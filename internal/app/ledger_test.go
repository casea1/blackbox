package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// A scheduled report deleted, moved or changed after it was written is
// pointed out (status exits 4, the next report says so, the index lists
// it) until a person accepts it; removal under retention_days is not.
func TestReportLedger(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	reports := t.TempDir()
	now := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	mk := func(name string) string {
		d := filepath.Join(reports, name)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "manifest.sha256"), []byte("abc  report.html\n"), 0o644)
		os.WriteFile(filepath.Join(d, "summary.json"), []byte(`{"window_start":"2026-09-30T00:00:00Z","window_end":"2026-10-07T00:00:00Z"}`), 0o644)
		return d
	}
	week1, week2, week3 := mk("2026-09-30_CI"), mk("2026-10-07_CI"), mk("2026-10-14_CI")
	for i, d := range []string{week1, week2, week3} {
		to := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC).AddDate(0, 0, 7*i)
		noteReport(st, d, to.AddDate(0, 0, -7), to, to)
	}
	st.Save()
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: reports, ReportEvery: "weekly", ReportAt: config.DefaultReportAt}, Version: "test", Loc: time.UTC,
		Now: func() time.Time { return now }, Logf: func(string, ...any) {}}
	var recorded []event.SelfChange
	a.RecordSelf = func(dir string, c event.SelfChange, now time.Time) error { recorded = append(recorded, c); return nil }

	if p := reportProblems(st); len(p) != 0 {
		t.Fatalf("reports in place: %+v", p)
	}
	os.RemoveAll(week1)                                                              // deleted
	os.WriteFile(filepath.Join(week2, "manifest.sha256"), []byte("edited\n"), 0o644) // changed
	os.RemoveAll(week3)
	markRemoved(st, reports, []string{"2026-10-14_CI"}, now) // retention_days
	st.Save()

	p := reportProblems(st)
	if len(p) != 2 || p[0].Problem != "missing" || p[1].Problem != "changed" {
		t.Fatalf("problems: %+v", p)
	}
	var b bytes.Buffer
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) || !strings.Contains(err.Error(), "a scheduled report is missing") {
		t.Fatalf("status = %v\n%s", err, b.String())
	}
	if !strings.Contains(b.String(), "REPORT MISSING:") || !strings.Contains(b.String(), "2026-09-30_CI") || !strings.Contains(b.String(), "REPORT CHANGED:") ||
		strings.Contains(b.String(), "2026-10-14_CI") {
		t.Errorf("status:\n%s", b.String())
	}
	h, _ := a.Health()
	if len(h.MissingReports) != 2 {
		t.Errorf("health: %+v", h.MissingReports)
	}

	// The index lists what is in the folder now, and the missing report.
	a.refreshIndex(st)
	idx, _ := os.ReadFile(filepath.Join(reports, "index.html"))
	if !strings.Contains(string(idx), "Missing: deleted or moved") || !strings.Contains(string(idx), "Changed after it was written") {
		t.Errorf("index does not list the missing and changed reports")
	}

	if err := a.AcceptReport("2026-09-30_CI", ""); err == nil {
		t.Error("accepted without a reason")
	}
	if err := a.AcceptReport("2026-09-30_CI", "moved to the archive drive"); err != nil {
		t.Fatal(err)
	}
	st, _ = store.Open(st.Dir)
	if p := reportProblems(st); len(p) != 1 || p[0].Name != "2026-10-07_CI" {
		t.Errorf("after accepting one: %+v", p)
	}
	if len(recorded) != 1 || recorded[0].Kind != "report_accepted" || recorded[0].New != "missing" || recorded[0].Old != "moved to the archive drive" {
		t.Errorf("recorded: %+v", recorded)
	}
	b.Reset()
	a.Reports(&b)
	if !strings.Contains(b.String(), "accepted as missing") || !strings.Contains(b.String(), "CHANGED") || !strings.Contains(b.String(), "removed under retention_days") {
		t.Errorf("blackbox reports:\n%s", b.String())
	}

	// LEDGER2: the accepted report stays on the index, muted, with who,
	// when and why.
	a.refreshIndex(st)
	idx, _ = os.ReadFile(filepath.Join(reports, "index.html"))
	if !strings.Contains(string(idx), "Accepted as moved by ") || !strings.Contains(string(idx), " on 8 Oct 2026: moved to the archive drive") ||
		!strings.Contains(string(idx), `class="trail mute"`) {
		t.Errorf("index does not keep the accepted report")
	}
}

// LEDGER1: every run checks that each file of a scheduled report is there
// at its size; once a day each is hashed against the manifest. Status
// names the file.
func TestReportLedgerFiles(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	reports := t.TempDir()
	now := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	d := filepath.Join(reports, "2026-10-07_CI")
	os.MkdirAll(d, 0o755)
	files := map[string]string{"report.html": "<html>", "logs-WS-07.zip": "zipdata", "summary.json": "{}"}
	var manifest strings.Builder
	for _, n := range []string{"logs-WS-07.zip", "report.html", "summary.json"} {
		os.WriteFile(filepath.Join(d, n), []byte(files[n]), 0o644)
		sum, _ := fileSHA256(filepath.Join(d, n))
		manifest.WriteString(sum + "  " + n + "\n")
	}
	os.WriteFile(filepath.Join(d, "manifest.sha256"), []byte(manifest.String()), 0o644)
	noteReport(st, d, now.AddDate(0, 0, -7), now, now)
	if r := st.State.Reports[0]; r.Files["logs-WS-07.zip"] != 7 || len(r.Files) != 3 {
		t.Fatalf("sizes: %+v", r.Files)
	}
	st.Save()
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: reports, ReportEvery: "weekly", ReportAt: config.DefaultReportAt}, Version: "test", Loc: time.UTC,
		Now: func() time.Time { return now }, Logf: func(string, ...any) {}, ReportAlert: func(string) error { return nil }}
	status := func() string {
		var b bytes.Buffer
		a.Status(&b)
		return b.String()
	}

	// Same size, different bytes: only the daily hash finds it.
	os.WriteFile(filepath.Join(d, "logs-WS-07.zip"), []byte("zipDATA"), 0o644)
	if p := reportProblems(st); len(p) != 0 {
		t.Fatalf("found before the daily check: %+v", p)
	}
	a.verifyReports(st) // not a day yet
	if p := reportProblems(st); len(p) != 0 {
		t.Fatalf("hashed before a day: %+v", p)
	}
	now = now.Add(25 * time.Hour)
	a.verifyReports(st)
	st, _ = store.Open(st.Dir) // kept
	if p := reportProblems(st); len(p) != 1 || p[0].What != "logs-WS-07.zip was changed (its SHA-256 no longer matches the manifest)" {
		t.Fatalf("after the daily check: %+v", p)
	}
	if s := status(); !strings.Contains(s, "REPORT CHANGED:") || !strings.Contains(s, "logs-WS-07.zip was changed") {
		t.Errorf("status:\n%s", s)
	}
	// Put back: the next daily check clears it.
	os.WriteFile(filepath.Join(d, "logs-WS-07.zip"), []byte("zipdata"), 0o644)
	now = now.Add(25 * time.Hour)
	a.verifyReports(st)
	if p := reportProblems(st); len(p) != 0 {
		t.Fatalf("restored: %+v", p)
	}

	// Deleted, or a different size: found at once.
	os.Remove(filepath.Join(d, "logs-WS-07.zip"))
	if p := reportProblems(st); len(p) != 1 || p[0].Problem != "changed" || p[0].What != "logs-WS-07.zip is missing" {
		t.Fatalf("deleted: %+v", p)
	}
	if s := status(); !strings.Contains(s, "logs-WS-07.zip is missing") {
		t.Errorf("status:\n%s", s)
	}
	os.WriteFile(filepath.Join(d, "logs-WS-07.zip"), []byte("zip"), 0o644)
	if p := reportProblems(st); len(p) != 1 || p[0].What != "logs-WS-07.zip was changed (its size differs)" {
		t.Fatalf("resized: %+v", p)
	}
}

// LEDGER1b: a report recorded by 0.19 has no file list. A file moved out
// of it is noticed at once (from its manifest), not at the next daily
// hash; the list is filled in from the manifest; and blackbox reports
// exits 4 like status.
func TestLedgerOldRecord(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	reports := t.TempDir()
	now := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	d := filepath.Join(reports, "2026-10-06_0000_4-systems")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "report.html"), []byte("<html>"), 0o644)
	os.WriteFile(filepath.Join(d, "logs-WIN11-TEST.zip"), []byte("zipdata"), 0o644)
	os.WriteFile(filepath.Join(d, "manifest.sha256"), []byte("aa  report.html\nbb  logs-WIN11-TEST.zip\n"), 0o644)
	sum, _ := manifestHash(d)
	to := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	st.State.Reports = []store.ReportRecord{{Dir: d, From: to.AddDate(0, 0, -1), To: to, Made: to, Manifest: sum, Verified: now}} // as 0.19 kept it
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: reports, ReportEvery: "daily", ReportAt: config.DefaultReportAt}, Version: "test", Loc: time.UTC,
		Now: func() time.Time { return now }, Logf: func(string, ...any) {}, ReportAlert: func(string) error { return nil }}

	var b bytes.Buffer
	if err := a.Reports(&b); err != nil {
		t.Fatalf("in place: %v\n%s", err, b.String())
	}
	a.verifyReports(st) // the first run after the upgrade: hashed less than a day ago
	if f := st.State.Reports[0].Files; len(f) != 2 || f["logs-WIN11-TEST.zip"] != 7 {
		t.Fatalf("file list not filled in from the manifest: %+v", f)
	}
	st.Save()
	os.Rename(filepath.Join(d, "logs-WIN11-TEST.zip"), filepath.Join(reports, "moved.zip"))
	if p := reportProblems(st); len(p) != 1 || p[0].What != "logs-WIN11-TEST.zip is missing" {
		t.Fatalf("moved file: %+v", p)
	}
	// Not yet filled in (no run since the upgrade): still noticed.
	st.State.Reports[0].Files = nil
	if p := reportProblems(st); len(p) != 1 || p[0].What != "logs-WIN11-TEST.zip is missing" {
		t.Fatalf("moved file, no list: %+v", p)
	}
	st.Save()
	b.Reset()
	var na *NeedsAttention
	if err := a.Reports(&b); !errors.As(err, &na) || !strings.Contains(b.String(), "CHANGED: logs-WIN11-TEST.zip is missing") {
		t.Errorf("blackbox reports (%v):\n%s", err, b.String())
	}
}

// LEDGER4: a scheduled report found missing or changed is written to the
// system log (Application event 101 on Windows, ident blackbox on Linux)
// once, not at every run; again only if it is fixed and then goes wrong
// again, or goes from changed to missing. A failed write is tried again.
func TestReportProblemSystemLog(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	reports := t.TempDir()
	now := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	d := filepath.Join(reports, "2026-10-07_CI")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "report.html"), []byte("<html>"), 0o644)
	sum, _ := fileSHA256(filepath.Join(d, "report.html"))
	os.WriteFile(filepath.Join(d, "manifest.sha256"), []byte(sum+"  report.html\n"), 0o644)
	noteReport(st, d, now.Add(-9*time.Hour).AddDate(0, 0, -7), now.Add(-9*time.Hour), now)
	var logged []string
	fail := false
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: reports, ReportEvery: "weekly", ReportAt: config.DefaultReportAt}, Version: "test", Loc: time.UTC,
		Now: func() time.Time { return now }, Logf: func(string, ...any) {},
		ReportAlert: func(msg string) error {
			if fail {
				return errors.New("no syslog")
			}
			logged = append(logged, msg)
			return nil
		}}
	a.verifyReports(st)
	if len(logged) != 0 {
		t.Fatalf("logged for a report in place: %q", logged)
	}
	os.WriteFile(filepath.Join(d, "report.html"), []byte("<html>!"), 0o644)
	fail = true
	a.verifyReports(st)
	fail = false
	for i := 0; i < 3; i++ {
		a.verifyReports(st)
	}
	if len(logged) != 1 || !strings.HasPrefix(logged[0], "REPORT CHANGED: The scheduled report for 2026-10-01 00:00 to 2026-10-08 00:00 (2026-10-07_CI) was changed after it was written: report.html was changed (its size differs).") ||
		!strings.HasSuffix(logged[0], "\". Folder: "+d) {
		t.Fatalf("logged: %q", logged)
	}
	if st2, _ := store.Open(st.Dir); st2.State.Reports[0].Alerted != "changed" {
		t.Error("not kept in the ledger")
	}
	os.RemoveAll(d)
	a.verifyReports(st)
	a.verifyReports(st)
	if len(logged) != 2 || !strings.HasPrefix(logged[1], "REPORT MISSING: ") {
		t.Fatalf("logged: %q", logged)
	}
	// Accepted: nothing more, and no repeat.
	if err := a.AcceptReport("2026-10-07_CI", "moved to the archive drive"); err != nil {
		t.Fatal(err)
	}
	st, _ = store.Open(st.Dir)
	a.RecordSelf = func(string, event.SelfChange, time.Time) error { return nil }
	a.verifyReports(st)
	if len(logged) != 2 {
		t.Fatalf("logged after accepting: %q", logged)
	}
}
