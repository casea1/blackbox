package app

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/store"
)

func reviewBatch(t *testing.T, dir string, b *lan.Batch) {
	t.Helper()
	data, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s_%s_%d.bbx", b.Sender, b.SenderID, b.Seq)), data, 0o644)
}

// REVIEW-9: a sender whose batches say it was formerly called DC01 makes
// the real DC01 vanish from the collector's systems list.
func TestReviewFormerNameHidesSystem(t *testing.T) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	in := t.TempDir()
	lan.PrepareInbox(in, "COL")
	st, _ := store.Open(t.TempDir())
	run := func(h string) []byte {
		return []byte(fmt.Sprintf(`{"time":%q,"host":%q,"os":"windows","version":"0.21.0"}`, at.Format(time.RFC3339), h))
	}
	reviewBatch(t, in, &lan.Batch{Header: lan.Header{Sender: "DC01", SenderID: "dc", Seq: 1, Created: at}, Runs: [][]byte{run("DC01")}})
	if _, err := lan.Import(st, in, lan.Dirs{}, at, nil); err != nil {
		t.Fatal(err)
	}
	before := systemsFor(st, at.Add(-time.Hour), true)
	reviewBatch(t, in, &lan.Batch{Header: lan.Header{Sender: "WS-66", SenderID: "ws", Seq: 1, Created: at, Former: []string{"DC01"}}, Runs: [][]byte{run("WS-66")}})
	if _, err := lan.Import(st, in, lan.Dirs{}, at.Add(time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	after := systemsFor(st, at.Add(-time.Hour), true)
	names := func(l any) string { return fmt.Sprintf("%+v", l) }
	t.Logf("before: %d systems; after: %d systems", len(before), len(after))
	found := false
	for _, s := range after {
		if s.Name == "DC01" {
			found = true
		}
	}
	if !found {
		t.Errorf("DC01 is gone from the systems list: %s", names(after))
	}
}

// REVIEW-10: a cloned sender (same data folder, so same sender ID) has
// its batches dropped as duplicates of the original's.
func TestReviewClonedSenderIDCollision(t *testing.T) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	in := t.TempDir()
	lan.PrepareInbox(in, "COL")
	st, _ := store.Open(t.TempDir())
	ev := func(h string) []byte { return []byte(fmt.Sprintf(`{"host":%q,"summary":"x"}`, h)) }
	reviewBatch(t, in, &lan.Batch{Header: lan.Header{Sender: "WS-01", SenderID: "same", Seq: 5, Created: at}, Events: [][]byte{ev("WS-01")}})
	lan.Import(st, in, lan.Dirs{}, at, nil)
	reviewBatch(t, in, &lan.Batch{Header: lan.Header{Sender: "WS-02", SenderID: "same", Seq: 5, Created: at}, Events: [][]byte{ev("WS-02")}})
	res, err := lan.Import(st, in, lan.Dirs{}, at.Add(time.Minute), nil)
	evs, _ := st.ReadEvents(time.Time{})
	t.Logf("err=%v batches=%d already=%d events=%d rejected=%v", err, res.Batches, res.Already, len(evs), res.Rejected)
	if len(evs) != 2 {
		t.Errorf("WS-02's batch was discarded as a duplicate of WS-01's without warning")
	}
}
