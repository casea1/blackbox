package report

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// ASSESS1: a report folder explains itself to someone who receives only
// the folder (README.txt, in the manifest), and events.csv times carry
// their offset and a UTC column.
func TestReportFolderForAnAssessor(t *testing.T) {
	loc := time.FixedZone("PDT", -7*3600)
	end := time.Date(2026, 10, 7, 7, 0, 0, 0, time.UTC)
	ev := &event.Event{Time: end.Add(-time.Hour), Host: "WIN11-TEST", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo,
		Action: "logon", User: "claude", Summary: "claude logged on."}
	r := Build([]*event.Event{ev}, nil, Options{Location: loc, WindowStart: end.Add(-24 * time.Hour), WindowEnd: end, Generated: end, Version: "0.22.0"})
	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(filepath.Join(dir, "README.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sha256sum -c manifest.sha256", "Get-FileHash", "Get-WinEvent -Path", "ausearch -if audit.log", "Time zone: times in the report and in events.csv are PDT (UTC-07:00)"} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("README.txt lacks %q:\n%s", want, readme)
		}
	}
	if m, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256")); !strings.Contains(string(m), "  README.txt\n") {
		t.Error("README.txt is not in the manifest")
	}
	zr, err := zip.OpenReader(filepath.Join(dir, "events.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	f, _ := zr.File[0].Open()
	b, _ := io.ReadAll(f)
	f.Close()
	lines := strings.Split(string(b), "\n")
	if !strings.HasSuffix(strings.TrimSpace(lines[0]), ",time_utc") || !strings.HasPrefix(lines[1], "2026-10-06 23:00:00 -07:00,") || !strings.Contains(lines[1], ",2026-10-07 06:00:00Z") {
		t.Errorf("events.csv:\n%s\n%s", lines[0], lines[1])
	}
}

// AR10: a computer's zip that doesn't line up with the period says where
// it starts and that the rest is in the next scheduled report.
func TestArchiveCoverageAgainstPeriod(t *testing.T) {
	start := time.Date(2026, 10, 6, 7, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	r := Build(nil, nil, Options{Location: time.UTC, WindowStart: start, WindowEnd: end, Generated: end, ArchivesKept: true,
		Archives: []ArchiveRef{{Host: "ubuntu-server", Name: "logs-ubuntu-server.zip", From: start.Add(-7 * time.Hour), To: end.Add(-7*time.Hour + time.Minute)}}})
	r.archiveState = map[string]archiveState{}
	lp := r.logsPage()
	if len(lp.Archives) != 1 {
		t.Fatalf("archives: %+v", lp.Archives)
	}
	notes := strings.Join(lp.Archives[0].Notes, "\n")
	if !strings.Contains(notes, "Starts at 2026-10-06 00:00, before this period") || !strings.Contains(notes, "Ends at 2026-10-07 00:01: its logs from then to the end of this period (2026-10-07 07:00) are in the next scheduled report") ||
		!strings.Contains(lp.Archives[0].Coverage, "the rest in the next report") {
		t.Errorf("notes: %s / %q", notes, lp.Archives[0].Coverage)
	}
}
