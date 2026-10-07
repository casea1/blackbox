package app

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/store"
)

// LOCK1: a scheduled run refused because a run holds the lock is noted;
// status says collection is blocked and exits 4, the status icon shows
// it, and the next collection records the gap with its run.
func TestBlockedCollection(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 10, 7, 13, 16, 0, 0, time.UTC)
	st.State.LastCollect = now.Add(-31 * time.Minute)
	st.Save()
	unlock, err := st.Lock() // the run that hangs
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", ReportAt: config.DefaultReportAt, CollectEvery: 15 * time.Minute},
		Now: func() time.Time { return now }, Loc: time.UTC, Logf: func(string, ...any) {}}
	defer func(w time.Duration) { runWait = w }(runWait)
	runWait = 10 * time.Millisecond

	for i := 0; i < 2; i++ {
		if _, err := a.Scheduled(); !errors.Is(err, store.ErrBusy) {
			t.Fatalf("scheduled run while the lock is held: %v", err)
		}
		now = now.Add(15 * time.Minute)
	}
	bl := readBlocked(st.Dir)
	if bl == nil || bl.Refused != 2 || bl.Holder.PID != os.Getpid() || !bl.First.Equal(now.Add(-30*time.Minute)) {
		t.Fatalf("blocked record = %+v", bl)
	}

	var b bytes.Buffer
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) || !strings.Contains(err.Error(), "collection is blocked") {
		t.Fatalf("status = %v, want exit 4 for blocked collection\n%s", err, b.String())
	}
	want := fmt.Sprintf("Collection is blocked: a run has held the lock since %s (PID %d)", stampLocal(bl.Holder.Since, time.UTC), os.Getpid())
	if !strings.Contains(b.String(), want) || !strings.Contains(b.String(), "2 scheduled runs since") {
		t.Errorf("status does not say collection is blocked (%q):\n%s", want, b.String())
	}
	h, _ := a.Health()
	if h.Blocked == nil || h.Blocked.Holder.PID != os.Getpid() {
		t.Errorf("health blocked = %+v", h.Blocked)
	}

	// The run ends: no longer blocked, and the next collection carries
	// the gap.
	unlock()
	unlock = nil
	b.Reset()
	if err := a.Status(&b); err != nil || strings.Contains(b.String(), "BLOCKED") {
		t.Errorf("after the lock is free, status = %v:\n%s", err, b.String())
	}
	opt := a.liveOptions()
	if opt.Blocked == nil || opt.Blocked.Refused != 2 {
		t.Fatalf("next collection's options carry %+v", opt.Blocked)
	}
	a.collected(opt)
	if readBlocked(st.Dir) != nil {
		t.Error("the blocked record is kept after a collection recorded it")
	}
}
