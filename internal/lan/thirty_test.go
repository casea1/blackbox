package lan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// DESIGN1: the owner's network, simulated. Thirty senders, 15 Windows
// and 15 Linux, all delivering into one drop-only inbox (as with one
// shared delivery account, the account says nothing), over three rounds.
// Among them:
//   - one cloned with its data folder (same sender ID and key, another
//     name): both kept, High rows, nothing merged;
//   - one reinstalled (a new data folder: new ID, new key): held with a
//     High row until rekey, then imported;
//   - one not upgraded (unsigned, 0.23 names): accepted, listed as
//     unsigned.
//
// Every event every computer collected is imported exactly once, and no
// sender has a missing batch.
func TestThirtySenders(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	type sender struct {
		host, os string
		st       *store.Store
		unsigned bool
	}
	var senders []*sender
	for i := 1; i <= 30; i++ {
		s := &sender{host: fmt.Sprintf("WIN-%02d", i), os: "windows"}
		if i > 15 {
			s.host, s.os = fmt.Sprintf("ubu-ws-%02d", i), "linux"
		}
		st, err := store.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s.st = st
		senders = append(senders, s)
	}
	senders[29].unsigned = true // ubu-ws-30 is still on 0.23
	want := map[string]int{}    // events collected, by computer
	round := func(r int, at time.Time) ImportResult {
		for _, s := range senders {
			n := 1 + (len(s.host)+r)%3
			collect(t, s.st, s.host, s.os, n, at)
			want[s.host] += n
			if _, err := Export(s.st, s.host, "0.24.0", at); err != nil {
				t.Fatal(err)
			}
			if s.unsigned {
				// 0.23: unsigned, under its old name, by its own hand.
				list, _ := outbox(s.st)
				for _, name := range list {
					data, _ := os.ReadFile(filepath.Join(OutboxDir(s.st), name))
					seq := strings.TrimLeft(strings.TrimSuffix(name, batchExt), "0")
					os.WriteFile(filepath.Join(in, fmt.Sprintf("%s_%s_%010s%s", s.host, s.st.State.Send.ID, seq, batchExt)), data, 0o640)
					os.Remove(filepath.Join(OutboxDir(s.st), name))
				}
				continue
			}
			if _, err := Deliver(s.st, in, s.host, true); err != nil {
				t.Fatal(err)
			}
		}
		res, err := Import(col, in, Dirs{}, at.Add(time.Minute), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := round(1, t0); res.Batches != 30 || len(res.Rejected) != 0 || len(res.Held) != 0 {
		t.Fatalf("round 1: %+v", res)
	}
	// WIN-07 is cloned with its data folder: WIN-07-COPY.
	clone, _ := store.Open(copyDir(t, senders[6].st.Dir))
	senders = append(senders, &sender{host: "WIN-07-COPY", os: "windows", st: clone})
	// ubu-ws-20 is reinstalled: a new data folder.
	re, _ := store.Open(t.TempDir())
	senders[19].st = re
	res := round(2, t0.Add(time.Hour))
	if res.Batches != 30 || len(res.Held) != 1 || len(res.Rejected) != 0 {
		t.Fatalf("round 2: %+v", res)
	}
	highs := map[string]bool{}
	for _, c := range ConflictEvents(col, t0.Add(30*time.Minute), t0.Add(2*time.Hour)) {
		if c.Severity == event.SevHigh {
			highs[c.Host] = true
		}
	}
	if !highs["ubu-ws-20"] || !highs["WIN-07-COPY"] {
		t.Errorf("High rows for the reinstalled and the cloned computer: %v", highs)
	}
	if res := round(3, t0.Add(2*time.Hour)); res.Batches != 30 || len(res.Held) != 1 {
		t.Fatalf("round 3: %+v", res)
	}
	if n, err := SetKey(col, in, "ubu-ws-20", Rekey, "admin", "reinstalled", t0.Add(3*time.Hour)); err != nil || n != 2 {
		t.Fatalf("rekey: %d %v", n, err)
	}
	if res, _ := Import(col, in, Dirs{}, t0.Add(3*time.Hour), nil); res.Batches != 2 || len(res.Rejected) != 0 {
		t.Fatalf("after rekey: %+v", res)
	}

	// Every event once.
	evs, _ := col.ReadEvents(time.Time{})
	got := map[string]int{}
	for _, e := range evs {
		got[e.Host]++
	}
	for h, n := range want {
		if got[h] != n {
			t.Errorf("%s: %d events imported, %d collected", h, got[h], n)
		}
	}
	if len(got) != len(want) {
		t.Errorf("computers: %d, want %d", len(got), len(want))
	}
	for id, s := range col.State.Senders {
		if len(s.Missing) != 0 {
			t.Errorf("%s (%s) has missing batches: %+v", s.Host, id, s.Missing)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(in, "*.bbx")); len(left) != 0 {
		t.Errorf("left in the inbox: %v", left)
	}
	// Signed or not, as each is.
	for _, s := range senders {
		k := col.State.SenderKeys[store.SystemKey(s.host)]
		if (k == nil) != s.unsigned {
			t.Errorf("%s: pinned %v, unsigned %v", s.host, k != nil, s.unsigned)
		}
	}
	if k := col.State.SenderKeys["WIN-07-COPY"]; k == nil || k.SharedWith != "WIN-07" {
		t.Errorf("clone's key: %+v", k)
	}
}
