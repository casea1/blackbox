package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// FIX1: blackbox fixes writes the fix list alone: no report folder, the
// schedule untouched, and no events or people in it.
func TestFixListWritesOnlyTheList(t *testing.T) {
	base := t.TempDir()
	st, _ := store.Open(filepath.Join(base, "data"))
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: filepath.Join(base, "reports"), ReportEvery: "daily", ReportAt: config.DefaultReportAt},
		Version: "test", Loc: time.UTC}
	at := time.Date(2026, 10, 5, 6, 0, 0, 0, time.UTC)
	st.AppendEvents(at, []*event.Event{{Time: at, Collected: at, Host: "WIN11-TEST", OS: "windows",
		Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_cleared", User: "claude", Summary: "The Security log was cleared by claude."}})
	st.State.LastWindowEnd, st.State.LastGenerated = at.Add(-time.Hour), at.Add(-time.Hour)
	a.Now = func() time.Time { return at.Add(time.Minute) }
	out := filepath.Join(base, "fixes.html")
	a.fixesOut = out
	if _, err := a.report(st, a.now(), false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), "Fix list") {
		t.Fatalf("fix list: %v", err)
	}
	if strings.Contains(string(b), "claude") {
		t.Error("the fix list names a person")
	}
	if entries, _ := os.ReadDir(filepath.Join(base, "reports")); len(entries) != 0 {
		t.Errorf("a report was written too: %v", entries)
	}
	if !st.State.LastGenerated.Equal(at.Add(-time.Hour)) {
		t.Error("the schedule moved")
	}
}
