package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/inventory"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/store"
)

// SEC1e: the collector's upgrade starts a collection (the scheduled task
// is run at once), which imports what waited in the 0.23 sender folders
// and pins the sender's key, while setup records the audit settings check
// (RecordCheck), waiting for that run to finish. Setup used to save the
// state it read before waiting, which undid the import: the next batch
// then showed a false gap, a resend imported the batch a second time, and
// the key was pinned only at the next delivery (SEC1f). It reads the
// state again once it has the lock.
func TestUpgradeCheckKeepsRunsImport(t *testing.T) {
	in := t.TempDir()
	if err := lan.PrepareInbox(in, "COLLECTOR"); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 8, 5, 30, 0, 0, time.UTC)

	// A 0.24 sender delivering into its 0.23 folder.
	ubu, _ := store.Open(t.TempDir())
	ubu.State.Send = &store.SendState{ID: store.NewID(), NextSeq: 472, Folder: "UBUNTU-SERVER"}
	folder := filepath.Join(in, "UBUNTU-SERVER")
	os.MkdirAll(folder, 0o750)
	os.WriteFile(filepath.Join(folder, "BLACKBOX-SENDER.txt"), []byte("Blackbox sender folder\r\n"), 0o644)
	at := t0
	deliver := func() {
		t.Helper()
		at = at.Add(time.Minute)
		if err := ubu.AppendEvents(at, []*event.Event{{Time: at, Collected: at, Host: "ubuntu-server", OS: "linux",
			Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "logon"}}); err != nil {
			t.Fatal(err)
		}
		if err := ubu.AppendRun(&store.Run{Time: at, Host: "ubuntu-server", OS: "linux", Version: "test"}); err != nil {
			t.Fatal(err)
		}
		lan.Export(ubu, "ubuntu-server", "test", at)
		if n, err := lan.Deliver(ubu, in, "ubuntu-server", true); err != nil || n != 1 {
			t.Fatalf("deliver: %d %v", n, err)
		}
	}
	deliver() // 472, waiting in the folder at the upgrade

	// The collector, as 0.23 left it: it imported 471 through the folder.
	dir := t.TempDir()
	col, _ := store.Open(dir)
	id := ubu.State.Send.ID
	col.State.Senders[id] = &store.SenderState{Host: "ubuntu-server", LastSeq: 471, FirstSeen: t0, LastReceived: t0,
		Names: []string{"ubuntu-server"}, Folder: "UBUNTU-SERVER"}
	col.State.InboxFolders = map[string]*store.InboxFolder{"UBUNTU-SERVER": {Account: "bb-ubuntu", Hosts: []string{"ubuntu-server"}, Added: t0}}
	if err := col.Save(); err != nil {
		t.Fatal(err)
	}

	// Setup moves the files out of the folders.
	if n := lan.MigrateSenderFolders(nil, in, t.Logf); n != 1 {
		t.Fatalf("moved %d", n)
	}
	// The collection the upgrade started holds the lock...
	run, _ := store.Open(dir)
	unlock, err := run.Lock()
	if err != nil {
		t.Fatal(err)
	}
	// ...while setup records the check, and waits for it.
	waiting := make(chan struct{}, 1)
	a := &App{Cfg: &config.Config{DataDir: dir}, Now: func() time.Time { return at },
		RunCheck:  func() []check.Result { return nil },
		Inventory: func() *inventory.Inventory { return nil },
		Logf: func(f string, args ...any) {
			if strings.Contains(f, "waiting for the run") {
				select {
				case waiting <- struct{}{}:
				default:
				}
			}
		}}
	done := make(chan error)
	go func() { _, err := a.RecordCheck(); done <- err }()
	select {
	case <-waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("setup did not wait for the run")
	}
	res, err := lan.Import(run, in, lan.Dirs{}, at.Add(time.Minute), t.Logf)
	if err != nil || res.Batches != 1 {
		t.Fatalf("the run's import: %+v %v", res, err)
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatalf("record check: %v", err)
	}

	st, _ := store.Open(dir)
	snd := st.State.Senders[id]
	if snd.LastSeq != 472 || len(snd.Missing) != 0 || snd.KeyFP == "" {
		t.Fatalf("the run's import was undone: %+v", snd)
	}
	if k := st.State.SenderKeys["UBUNTU-SERVER"]; k == nil || k.FP != snd.KeyFP {
		t.Errorf("the key pinned at the upgrade was lost: %+v", k)
	}
	if !st.State.LastCheck.Equal(at) {
		t.Errorf("setup's check was not kept: %v", st.State.LastCheck)
	}

	// The next batch (473): no gap. Resending 472: already imported.
	deliver()
	if res, _ := lan.Import(st, in, lan.Dirs{}, at.Add(time.Minute), t.Logf); res.Batches != 1 || len(st.State.Senders[id].Missing) != 0 {
		t.Fatalf("next batch: %+v, missing %v", res, st.State.Senders[id].Missing)
	}
	if sent, _, err := lan.Resend(ubu, in, "ubuntu-server", 472, 472); err != nil || len(sent) != 1 {
		t.Fatalf("resend: %v %v", sent, err)
	}
	if res, _ := lan.Import(st, in, lan.Dirs{}, at.Add(2*time.Minute), t.Logf); res.Batches != 0 || res.Already != 1 {
		t.Errorf("resend of 472: %+v, want already imported", res)
	}
}
