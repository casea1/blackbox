package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/inventory"
)

func TestSpoolAndState(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	if err := s.AppendEvents(now, []*event.Event{{Time: now, Summary: "a"}, {Time: now, Summary: "b"}}); err != nil {
		t.Fatal(err)
	}
	s.State.Bookmarks[BookmarkKey("ws-07", "Security")] = Bookmark{RecordID: 42}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	// A torn final line (power loss mid-write) must not break reading.
	f, _ := os.OpenFile(filepath.Join(dir, "spool", "events-2026-09-29.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"time":"2026-09-29T10:0`)
	f.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.State.Bookmarks["WS-07|Security"].RecordID != 42 {
		t.Error("bookmark not persisted")
	}
	ev, err := s2.ReadEvents(time.Time{})
	if err != nil || len(ev) != 2 {
		t.Fatalf("read %d events, err %v", len(ev), err)
	}
}

func TestLock(t *testing.T) {
	s, _ := Open(t.TempDir())
	unlock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock(); err == nil {
		t.Error("second lock should fail")
	}
	unlock()
	if u, err := s.Lock(); err != nil {
		t.Error("lock after unlock should succeed")
	} else {
		u()
	}
}

func TestWaitLock(t *testing.T) {
	lockPoll = 10 * time.Millisecond
	s, _ := Open(t.TempDir())
	unlock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WaitLock(30*time.Millisecond, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("WaitLock on a held lock = %v, want ErrBusy", err)
	}
	waited := false
	go func() { time.Sleep(50 * time.Millisecond); unlock() }()
	u, err := s.WaitLock(5*time.Second, func() { waited = true })
	if err != nil {
		t.Fatal(err)
	}
	u()
	if !waited {
		t.Error("waiting callback was not called")
	}
}

// The inventory read with a settings check is kept with it, and an older
// record without one still reads.
func TestCheckRecordInventory(t *testing.T) {
	st, _ := Open(t.TempDir())
	at := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	inv := &inventory.Inventory{Model: "OptiPlex 7090", Serial: "7XK2PQ3", Drives: []inventory.Drive{{Serial: "S5GX"}},
		Accounts: []inventory.Account{{Name: "localadmin", ID: "…1001", Enabled: true, Admin: true}}}
	if err := st.AppendChecks(&CheckRecord{Time: at, Host: "WS-07", Inventory: inv}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendChecks(&CheckRecord{Time: at, Host: "OLD-PC"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.LatestChecks(time.Time{}, at.Add(time.Hour))
	if err != nil || got["WS-07"] == nil || got["WS-07"].Inventory == nil || got["WS-07"].Inventory.Serial != "7XK2PQ3" ||
		got["WS-07"].Inventory.Accounts[0].ID != "…1001" || got["OLD-PC"] == nil || got["OLD-PC"].Inventory != nil {
		t.Errorf("latest checks: %+v", got)
	}
}

// SEC1e: Reload reads what another run saved since the store was opened,
// so a caller that waited for the lock does not save an older copy.
func TestReloadReadsLaterSave(t *testing.T) {
	dir := t.TempDir()
	waiter, _ := Open(dir)
	run, _ := Open(dir)
	run.State.Senders["id"] = &SenderState{Host: "ubuntu-server", LastSeq: 472}
	if err := run.Save(); err != nil {
		t.Fatal(err)
	}
	if waiter.State.Senders["id"] != nil {
		t.Fatal("the waiter's copy changed by itself")
	}
	if err := waiter.Reload(); err != nil {
		t.Fatal(err)
	}
	if s := waiter.State.Senders["id"]; s == nil || s.LastSeq != 472 || waiter.State.Bookmarks == nil {
		t.Errorf("after reload: %+v", waiter.State)
	}
	os.WriteFile(filepath.Join(dir, "state.json"), []byte("{"), 0o640)
	if err := waiter.Reload(); err == nil {
		t.Error("a damaged state.json was read")
	}
}
