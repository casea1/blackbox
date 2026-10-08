package app

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
)

// SEC1: a cloned sender (one sender ID, two computers) is kept and is a
// High detection in the next report, saying what to run.
func TestClonedSenderIsADetection(t *testing.T) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	in := t.TempDir()
	lan.PrepareInbox(in, "COL")
	st, _ := store.Open(t.TempDir())
	ev := func(h string) [][]byte { return [][]byte{[]byte(`{"host":"` + h + `","summary":"x"}`)} }
	reviewBatch(t, in, &lan.Batch{Header: lan.Header{Sender: "WS-01", SenderID: "same", Seq: 5, Created: at}, Events: ev("WS-01")})
	lan.Import(st, in, lan.Dirs{}, at, nil)
	reviewBatch(t, in, &lan.Batch{Header: lan.Header{Sender: "WS-02", SenderID: "same", Seq: 5, Created: at}, Events: ev("WS-02")})
	lan.Import(st, in, lan.Dirs{}, at.Add(time.Minute), nil)
	evs := lan.ConflictEvents(st, at.Add(-time.Hour), at.Add(time.Hour))
	r := report.Build(evs, nil, report.Options{WindowEnd: at.Add(time.Hour), Location: time.UTC})
	found := false
	for _, f := range r.Findings {
		if f.Severity == event.SevHigh {
			found = true
		}
	}
	if len(evs) != 1 || !strings.Contains(evs[0].Summary, "blackbox send --new-id") || !found {
		t.Errorf("conflicts %d, findings %+v", len(evs), r.Findings)
	}
}
