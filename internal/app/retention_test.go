package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
)

// reportFolder makes a report folder in dir with a manifest and, unless
// end is zero, a summary.json ending its period at end; its modified
// date is set to modified.
func reportFolder(t *testing.T, dir, name string, end, modified time.Time) string {
	t.Helper()
	p := filepath.Join(dir, name)
	os.MkdirAll(p, 0o750)
	os.WriteFile(filepath.Join(p, "manifest.sha256"), []byte("x"), 0o640)
	if !end.IsZero() {
		b, _ := json.Marshal(report.Summary{WindowEnd: end, Generated: end})
		os.WriteFile(filepath.Join(p, "summary.json"), b, 0o640)
	}
	os.Chtimes(p, modified, modified)
	return p
}

// A9, RET1: reports are aged by their period end (the ledger's, or
// summary.json's), not the folder's modified date: a folder restored
// from a backup with an old date is kept, one with no readable period
// end is kept, and only report folders (with a manifest) are removed.
// Pruning says which it removed, so the next report can list them.
func TestPruneReportsByPeriodEnd(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	old, recent := now.AddDate(0, 0, -40), now.AddDate(0, 0, -3)
	reportFolder(t, dir, "old", old, recent)        // copied lately, period long over
	reportFolder(t, dir, "restored", recent, old)   // restored from a backup
	reportFolder(t, dir, "noend", time.Time{}, old) // no summary.json
	ledgered := reportFolder(t, dir, "ledger", recent, recent)
	os.MkdirAll(filepath.Join(dir, "notreport"), 0o750)
	os.Chtimes(filepath.Join(dir, "notreport"), old, old)
	// The ledger's period end comes first.
	ledger := []store.ReportRecord{{Dir: ledgered, From: old.AddDate(0, 0, -7), To: old}}

	removed, err := pruneReports(dir, 30, now, ledger)
	if err != nil || strings.Join(removed, ",") != "ledger,old" {
		t.Errorf("removed %v %v", removed, err)
	}
	for _, n := range []string{"restored", "noend", "notreport"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s removed: %v", n, err)
		}
	}
}

// RET1: original logs in no report are never removed under
// retention_days. Waiting (or set aside) longer than that, status says so
// and exits 4, and the report says so on Audit health and Original logs;
// archives within retention_days are not pointed out.
func TestOverdueLogsKeptAndRaised(t *testing.T) {
	base := t.TempDir()
	st, _ := store.Open(filepath.Join(base, "data"))
	end := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	now := end.Add(time.Minute)
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: filepath.Join(base, "reports"), ReportEvery: "daily", ReportAt: config.DefaultReportAt,
		RetentionDays: 30, Inbox: filepath.Join(base, "inbox")},
		Version: "test", Loc: time.UTC, Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return nil }}
	st.AppendEvents(end.Add(-time.Hour), []*event.Event{{Time: end.Add(-time.Hour), Collected: end.Add(-time.Hour), Host: "WIN11", OS: "windows",
		Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", User: "claude", Summary: "claude logged on."}})

	// A sender's day set aside 60 days ago (AR7), another waiting 50 days,
	// and one recent.
	aside := pendingLogs(t, a, "WS-07", end.AddDate(0, 0, -60))
	moved := setAsidePath(aside)
	os.MkdirAll(filepath.Dir(moved), 0o750)
	if err := os.Rename(aside, moved); err != nil {
		t.Fatal(err)
	}
	waiting := pendingLogs(t, a, "WS-08", end.AddDate(0, 0, -50))
	pendingLogs(t, a, "WIN11", end)

	var b bytes.Buffer
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) {
		t.Errorf("status does not exit 4: %v\n%s", err, b.String())
	}
	for _, want := range []string{
		"ORIGINAL LOGS NEVER REPORTED: WS-07: original logs from 2026-08-08 00:00 to 2026-08-09 00:00 have waited 60 days and were never put in a report",
		"WS-08: original logs from 2026-08-18 00:00 to 2026-08-19 00:00 have waited 50 days",
		"retention_days = 30 does not remove them",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("status missing %q:\n%s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "WIN11: original logs") {
		t.Errorf("a recent archive pointed out:\n%s", b.String())
	}

	// The scheduled report takes the waiting ones (WS-08's too) and
	// removes nothing in no report.
	dir, err := a.report(st, end, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(moved); err != nil {
		t.Errorf("the set-aside archive was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "logs-WS-08.zip")); err != nil {
		t.Errorf("WS-08's waiting logs not in the report: %v", err)
	}
	if _, err := os.Stat(waiting); err == nil {
		t.Error("WS-08's archive still waiting after the report took it")
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, want := range []string{"Original logs never put in a report", "have waited 60 days and were never put in a report"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("the report does not say %q", want)
		}
	}
	if strings.Contains(string(html), "WS-08: original logs from") {
		t.Error("the report calls logs it holds never reported")
	}
	b.Reset()
	if err := a.Status(&b); !errors.As(err, &na) || !strings.Contains(b.String(), "WS-07: original logs from") || strings.Contains(b.String(), "WS-08: original logs") {
		t.Errorf("status after the report (%v):\n%s", err, b.String())
	}

	// Without retention_days nothing is pointed out.
	a.Cfg.RetentionDays = 0
	if got := a.overdueLogs(now, nil); len(got) != 0 {
		t.Errorf("overdue with no retention: %+v", got)
	}
}
