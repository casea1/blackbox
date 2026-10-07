package gui

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/app"
)

// TRAY2: the menu opens without waiting for the status to be read (it
// took 8 seconds on the Server 2025 VM); the read runs in the background,
// one at a time, and updates what the next menu shows.
func TestMenuDoesNotWaitForStatus(t *testing.T) {
	initUI()
	tr := &tray{window: newWindow("Blackbox status", 0, 0, 0)}
	defer tr.close()
	var reads atomic.Int32
	release := make(chan struct{})
	tr.readHealth = func() (app.Health, error) {
		reads.Add(1)
		<-release
		return app.Health{LastCollect: time.Now(), Every: 15 * time.Minute}, nil
	}
	tr.view = trayView{Status: "Collecting every 15 minutes · last 14:05"}

	start := time.Now()
	m := tr.openMenu()
	took := time.Since(start)
	pDestroyMenu.Call(m)
	if took > 500*time.Millisecond {
		t.Errorf("the menu took %v to build while the status was being read", took)
	}
	m = tr.openMenu() // clicked again while the read runs
	pDestroyMenu.Call(m)
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		tr.mu.Lock()
		done := !tr.reading
		h := tr.lastHealth
		tr.mu.Unlock()
		if done {
			if h.LastCollect.IsZero() {
				t.Error("the status read was not kept")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the status read never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := reads.Load(); n != 1 {
		t.Errorf("%d status reads for two clicks during one read, want 1", n)
	}
	if !strings.HasPrefix(tr.view.Status, "Collecting") {
		t.Errorf("view: %+v", tr.view)
	}
}
