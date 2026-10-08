package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The index lists the report folders there now (a deleted one drops off at
// the next rebuild), and a missing scheduled report in its place, never as
// the latest.
func TestIndexMissingReports(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, end time.Time, manual bool) {
		d := filepath.Join(dir, name)
		os.MkdirAll(d, 0o755)
		s := `{"window_start":"` + end.AddDate(0, 0, -7).Format(time.RFC3339) + `","window_end":"` + end.Format(time.RFC3339) + `","interim":` + map[bool]string{true: "true", false: "false"}[manual] + `}`
		os.WriteFile(filepath.Join(d, "summary.json"), []byte(s), 0o644)
	}
	end := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	mk("2026-09-30_CI", end.AddDate(0, 0, -7), false)
	mk("2026-10-05_CI_manual", end.AddDate(0, 0, -2), true)
	if err := WriteIndex(dir, "CI", "weekly", time.UTC, nil); err != nil {
		t.Fatal(err)
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	if !strings.Contains(string(idx), "2026-10-05_CI_manual/report.html") {
		t.Fatal("the manual report is not listed")
	}
	os.RemoveAll(filepath.Join(dir, "2026-10-05_CI_manual"))
	missing := []MissingReport{{Name: "2026-10-07_CI", From: end.AddDate(0, 0, -7), To: end, Problem: "missing"}}
	if err := WriteIndex(dir, "CI", "weekly", time.UTC, missing); err != nil {
		t.Fatal(err)
	}
	idx, _ = os.ReadFile(filepath.Join(dir, "index.html"))
	h := string(idx)
	if strings.Contains(h, "2026-10-05_CI_manual") {
		t.Error("a deleted manual report is still listed")
	}
	if !strings.Contains(h, "Missing: deleted or moved") || strings.Contains(h, "2026-10-07_CI/report.html") {
		t.Error("the missing scheduled report is not shown as missing")
	}
	if !strings.Contains(h, `href="2026-09-30_CI/report.html">Open the latest report`) {
		t.Error("the latest report should be the newest one still there")
	}
}

// The next report says an earlier scheduled report is missing: on the
// Overview checklist and in Audit health's gaps.
func TestReportShowsMissingReports(t *testing.T) {
	end := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	m := MissingReport{Name: "2026-09-30_CI", From: end.AddDate(0, 0, -21), To: end.AddDate(0, 0, -14), Problem: "missing"}
	r := Build(nil, nil, Options{WindowStart: end.AddDate(0, 0, -7), WindowEnd: end, Location: time.UTC, Source: "Live collection",
		MissingReports: []MissingReport{m}, Systems: []SystemInfo{{Name: "WIN11-COL", OS: "windows", LastRun: end}}})
	found := false
	for _, l := range r.overview(nil).Checks {
		if l.Title == "Earlier reports missing or changed" && l.Level == "bad" && strings.Contains(l.What, "2026-09-30_CI") {
			found = true
		}
	}
	if !found {
		t.Errorf("overview: %+v", r.overview(nil).Checks)
	}
	// UI-R1: on Original logs, not Audit health.
	ok := false
	for _, f := range r.logsPage().Failing {
		if strings.Contains(f, "Earlier reports missing or changed") && strings.Contains(f, "2026-09-30_CI") && strings.Contains(f, "blackbox reports accept") {
			ok = true
		}
	}
	if !ok {
		t.Errorf("original logs: %q", r.logsPage().Failing)
	}
}
