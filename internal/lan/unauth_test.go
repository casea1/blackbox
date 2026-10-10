package lan

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// unauthBatch writes an unsigned batch file for sender id that decodes
// as far as its header (which names that sender and seq) and then fails:
// its first record is not valid.
func unauthBatch(t *testing.T, dir, host, id string, seq uint64) {
	t.Helper()
	hdr, err := json.Marshal(Header{Kind: batchKind, Format: batchFormat, Sender: host, SenderID: id, Seq: seq, Created: t0})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(hdr)
	gz.Write([]byte("\nnot a record\n"))
	gz.Close()
	if err := os.WriteFile(filepath.Join(dir, InboxName(host, id, seq)), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// SEC4: a malformed, unsigned delivery under a pinned sender's ID and a
// far-ahead number is set aside, and changes nothing about that sender:
// not its last number, its missing batches or its key, also after the
// state is read back from disk.
func TestUnauthenticatedBatchLeavesSenderState(t *testing.T) {
	for _, dirs := range []Dirs{{}, {RequireSigned: true}} {
		in := inbox(t)
		colDir := t.TempDir()
		col, _ := store.Open(colDir)
		ws := system(t, "WS-09", "windows", 2, t0)
		Export(ws, "WS-09", "test", t0)
		if n, err := Deliver(ws, in, "WS-09", true); err != nil || n != 1 {
			t.Fatalf("deliver: %d %v", n, err)
		}
		if res, _ := Import(col, in, dirs, t0.Add(time.Minute), t.Logf); res.Batches != 1 {
			t.Fatalf("signed import: %+v", res)
		}
		id := ws.State.Send.ID
		before := *col.State.Senders[id]
		before.Missing = append([]store.SeqGap(nil), before.Missing...)
		if before.LastSeq != 1 || before.KeyFP == "" {
			t.Fatalf("after the signed batch: %+v", before)
		}

		unauthBatch(t, in, "WS-09", id, 9000)
		res, err := Import(col, in, dirs, t0.Add(2*time.Minute), t.Logf)
		if err != nil || len(res.Rejected) != 1 || res.Batches != 0 {
			t.Fatalf("malformed batch: %+v %v", res, err)
		}
		reloaded, err := store.Open(colDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range []*store.Store{col, reloaded} {
			got := st.State.Senders[id]
			if got == nil || got.LastSeq != before.LastSeq || !reflect.DeepEqual(got.Missing, before.Missing) || got.KeyFP != before.KeyFP {
				t.Errorf("require_signed=%v: sender state changed by an unauthenticated delivery: %+v (was %+v)", dirs.RequireSigned, got, before)
			}
		}
	}
}

// SEC4: a batch whose signature checks out but whose contents can't be
// imported is still its sender's: its number is noted as missing, so a
// resend can fill it.
func TestAuthenticatedBadBatchNotesGap(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	k, _, err := EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	put := func(seq uint64, ev string) {
		b := &Batch{Header: Header{Sender: "WS-01", SenderID: "abc", Seq: seq, Created: t0}, Events: [][]byte{[]byte(ev)}}
		plain, _ := b.Bytes()
		signed, err := SignBatch(plain, k, t0)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(in, InboxName("WS-01", "abc", seq)), signed, 0o644)
	}
	put(1, `{"host":"WS-01","summary":"x"}`)
	if res, _ := Import(col, in, Dirs{}, t0, t.Logf); res.Batches != 1 {
		t.Fatalf("first batch: %+v", res)
	}
	put(3, `{"host":"WS-01","time":5}`)
	if res, _ := Import(col, in, Dirs{}, t0.Add(time.Minute), t.Logf); len(res.Rejected) != 1 {
		t.Fatalf("bad batch: %+v", res)
	}
	s := col.State.Senders["abc"]
	if s == nil || s.LastSeq != 3 || len(s.Missing) != 1 || s.Missing[0].From != 2 || s.Missing[0].To != 3 {
		t.Errorf("signed but unimportable batch 3: %+v", s)
	}
}
