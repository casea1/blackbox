package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/app"
	"github.com/casea1/blackbox/internal/store"
)

// S1: the reports folder exists after setup, even when no report is made
// (an upgrade), so "Open reports folder" opens it.
func TestEnsureDir(t *testing.T) {
	d := filepath.Join(t.TempDir(), "Blackbox", "reports")
	if err := ensureDir(d); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		t.Errorf("reports folder not made: %v", err)
	}
	if err := ensureDir(d); err != nil {
		t.Errorf("an existing folder: %v", err)
	}
}

// S14: setup run while the scheduled run holds the lock is not a
// connection problem.
func TestSentLinesBusy(t *testing.T) {
	busy := fmt.Errorf("%w (lock file x)", store.ErrBusy)
	got := strings.Join(sentLines(app.SendResult{}, busy, `\\C\inbox`, false), "\n")
	if !strings.Contains(got, "A collection was already running, so this computer's events go to the collector at the next run") || strings.Contains(got, "could not be reached") {
		t.Errorf("busy: %s", got)
	}
	got = strings.Join(sentLines(app.SendResult{Waiting: 2}, errors.New("no inbox"), `\\C\inbox`, false), "\n")
	if !strings.Contains(got, "could not be reached yet: no inbox") || !strings.Contains(got, "2 batches waiting") {
		t.Errorf("unreachable: %s", got)
	}
}

// AR3: setup says when a final report was made before sending.
func TestSentLinesFinalReport(t *testing.T) {
	got := strings.Join(sentLines(app.SendResult{FinalReport: "/r/2026-10-05_final", Delivered: 1}, nil, "x", true), "\n")
	if !strings.Contains(got, "Its final report") || !strings.Contains(got, "/r/2026-10-05_final") || !strings.Contains(got, "Sent 1 batch to x") {
		t.Errorf("%s", got)
	}
}

// AR3b: a computer that made reports but none since it last sent makes no
// final report; setup says its events were sent to the collector instead.
func TestSentLinesForwarded(t *testing.T) {
	got := strings.Join(sentLines(app.SendResult{Delivered: 3}, nil, "x", true), "\n")
	if !strings.Contains(got, "no final report was needed") || strings.Contains(got, "Its final report") || !strings.Contains(got, "Sent 3 batches to x") {
		t.Errorf("%s", got)
	}
	if got := strings.Join(sentLines(app.SendResult{Delivered: 3}, nil, "x", false), "\n"); strings.Contains(got, "final report") {
		t.Errorf("a computer that was a sender already: %s", got)
	}
}
