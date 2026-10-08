package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/store"
)

// VER2: the ledger records how many files a scheduled report has, and a
// file added to it afterwards (anywhere in the folder) makes it CHANGED.
// A listed file the daily check can't read is not verified.
func TestLedgerAddedAndUnreadable(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	reports := t.TempDir()
	now := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	d := filepath.Join(reports, "2026-10-07_CI")
	os.MkdirAll(filepath.Join(d, "data"), 0o755)
	var manifest strings.Builder
	for _, n := range []string{"data/logons-20261006.js", "report.html", "summary.json"} {
		os.WriteFile(filepath.Join(d, filepath.FromSlash(n)), []byte(n), 0o644)
		sum, _ := fileSHA256(filepath.Join(d, filepath.FromSlash(n)))
		manifest.WriteString(sum + "  " + n + "\n")
	}
	os.WriteFile(filepath.Join(d, "manifest.sha256"), []byte(manifest.String()), 0o644)
	noteReport(st, d, now.AddDate(0, 0, -7), now, now)
	if n := st.State.Reports[0].FileCount; n != 4 {
		t.Fatalf("file count %d, want 4", n)
	}
	st.Save()
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: reports, ReportEvery: "weekly", ReportAt: config.DefaultReportAt}, Version: "test", Loc: time.UTC,
		Now: func() time.Time { return now }, Logf: func(string, ...any) {}}

	// Windows adds desktop.ini by itself: not a change.
	os.WriteFile(filepath.Join(d, "desktop.ini"), []byte("x"), 0o644)
	if p := reportProblems(st); len(p) != 0 {
		t.Fatalf("desktop.ini: %+v", p)
	}
	os.MkdirAll(filepath.Join(d, "extra", "sub"), 0o755)
	os.WriteFile(filepath.Join(d, "extra", "sub", "report.html"), []byte("<h1>forged</h1>"), 0o644)
	p := reportProblems(st)
	if len(p) != 1 || p[0].Problem != "changed" || p[0].What != "extra/sub/report.html was added after the report was written (it is not in the manifest)" {
		t.Fatalf("added: %+v", p)
	}
	var b bytes.Buffer
	a.Status(&b)
	if !strings.Contains(b.String(), "extra/sub/report.html was added") {
		t.Errorf("status:\n%s", b.String())
	}
	os.RemoveAll(filepath.Join(d, "extra"))
	if p := reportProblems(st); len(p) != 0 {
		t.Fatalf("removed again: %+v", p)
	}

	// A listed file that can't be read (here a folder in its place).
	os.Remove(filepath.Join(d, "summary.json"))
	os.Mkdir(filepath.Join(d, "summary.json"), 0o755)
	now = now.Add(25 * time.Hour)
	a.verifyReports(st)
	if bad := st.State.Reports[0].Bad; !strings.HasPrefix(bad, "summary.json could not be read, so it is not verified") {
		t.Errorf("daily check of an unreadable file: Bad = %q", bad)
	}
}
