//go:build !windows

package app

import (
	"bytes"
	"errors"
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

// A full log that would overwrite unsaved events before the next run is
// saved early, not at the next daily save; what it had already lost is
// recorded in the archive, shown by status (exit 4) and in the report.
func TestOriginalLogsSavedEarlyAndGapsFlagged(t *testing.T) {
	base := t.TempDir()
	audit := filepath.Join(base, "audit.log")
	os.WriteFile(audit, []byte("type=SYSCALL msg=audit(1791158400.000:9): x\n"), 0o644)
	defer func(a string, s, au []string) { collect.AuditLog, collect.SystemLogs, collect.AuthLogs = a, s, au }(collect.AuditLog, collect.SystemLogs, collect.AuthLogs)
	collect.AuditLog, collect.SystemLogs, collect.AuthLogs = audit, []string{filepath.Join(base, "none")}, nil

	st, _ := store.Open(filepath.Join(base, "data"))
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	saved := now.Add(-2 * time.Hour) // the last save: not due again for a day
	st.State.ArchivedUntil = saved
	var states []archive.LogState
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", CollectEvery: 15 * time.Minute}, Loc: time.UTC,
		Now: func() time.Time { return now }, LogStates: func() []archive.LogState { return states }}

	// A full log that still holds days: nothing early.
	states = []archive.LogState{{Source: "Security", Oldest: now.Add(-72 * time.Hour), Wraps: true}}
	a.archiveLogs(st, now, false)
	if !st.State.ArchivedUntil.Equal(saved) {
		t.Fatal("saved early with a log that holds days")
	}

	// A full log that has already overwritten 40 minutes past the last save.
	states = []archive.LogState{{Source: audit, Oldest: saved.Add(40 * time.Minute), Wraps: true}}
	a.archiveLogs(st, now, false)
	if !st.State.ArchivedUntil.Equal(now) {
		t.Fatalf("not saved early: archived until %v", st.State.ArchivedUntil)
	}
	list, _ := archive.List(a.pendingLogsDir())
	if len(list) != 1 {
		t.Fatalf("archives: %+v", list)
	}
	info, err := archive.Verify(list[0].Path)
	if err != nil || len(info.Gaps) != 1 || !info.Gaps[0].From.Equal(saved) || !info.Gaps[0].To.Equal(saved.Add(40*time.Minute)) {
		t.Fatalf("archive gaps: %+v %v", info.Gaps, err)
	}

	var b bytes.Buffer
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) || !strings.Contains(b.String(), "LOGS INCOMPLETE:") ||
		!strings.Contains(b.String(), audit+" had already overwritten its events from 2026-10-05 10:00 to 2026-10-05 10:40") {
		t.Errorf("status (%v):\n%s", err, b.String())
	}

	refs, _ := a.bundleLogs(now)
	if len(refs) != 1 || len(refs[0].Gaps) != 1 {
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
	if !strings.Contains(string(html), "Missing 5 Oct 10:00 – 5 Oct 10:40: overwritten before it was saved") {
		t.Error("the Original logs page does not show the gap")
	}
}
