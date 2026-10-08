package lan

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// senderFolder makes a sender's own folder in the inbox, as "blackbox
// inbox add" does (without the permissions, which need an account).
func senderFolder(t *testing.T, col *store.Store, in, name, host string) string {
	t.Helper()
	dir, err := PrepareSenderFolder(col, in, name, "bb-"+strings.ToLower(name), host, t0)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// SEC1: each sender delivers into its own folder, and what a folder holds
// must be from its computer. One sender can't write as another, in its
// own folder, in another's or in the shared inbox folder.
func TestSenderCannotWriteAsAnother(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	dcDir := senderFolder(t, col, in, "DC01", "DC01")
	wsDir := senderFolder(t, col, in, "WS-02", "")

	// Each sender finds its own folder and delivers there.
	dc := system(t, "DC01", "windows", 2, t0)
	send(t, dc, "DC01", in, t0)
	if dc.State.Send.Folder != "DC01" {
		t.Fatalf("DC01 delivered to %q", dc.State.Send.Folder)
	}
	ws := system(t, "WS-02", "windows", 1, t0)
	send(t, ws, "WS-02", in, t0)
	if ws.State.Send.Folder != "WS-02" {
		t.Fatalf("WS-02 delivered to %q", ws.State.Send.Folder)
	}
	res, err := Import(col, in, Dirs{}, t0.Add(time.Minute), t.Logf)
	if err != nil || res.Batches != 2 || len(res.Rejected) != 0 {
		t.Fatalf("import: %+v %v", res, err)
	}
	if f := col.State.InboxFolders["WS-02"]; f == nil || len(f.Hosts) != 1 || f.Hosts[0] != "WS-02" {
		t.Errorf("WS-02's folder did not learn its computer: %+v", f)
	}

	// WS-02 writes batches claiming to be DC01: in its own folder, in
	// DC01's folder (if its permissions were wrong) and in the inbox.
	forged := func(dir, name string, seq uint64) {
		b := &Batch{Header: Header{Sender: "DC01", SenderID: dc.State.Send.ID, Seq: seq, Created: t0},
			Events: [][]byte{[]byte(`{"host":"DC01","summary":"forged"}`)}}
		writeBatch(t, dir, b)
		_ = name
	}
	forged(wsDir, "own", 2)
	forged(in, "shared", 3)
	wsAsDC := &Batch{Header: Header{Sender: "WS-02", SenderID: ws.State.Send.ID, Seq: 2, Created: t0},
		Events: [][]byte{[]byte(`{"host":"WS-02","summary":"x"}`)}}
	writeBatch(t, dcDir, wsAsDC)
	res, _ = Import(col, in, Dirs{}, t0.Add(time.Hour), t.Logf)
	if res.Batches != 0 || len(res.Rejected) != 3 {
		t.Fatalf("forged batches: %+v", res)
	}
	for _, r := range res.Rejected {
		if !strings.Contains(r, "set aside") {
			t.Errorf("not set aside: %s", r)
		}
	}
	evs, _ := col.ReadEvents(time.Time{})
	for _, e := range evs {
		if e.Summary == "forged" {
			t.Errorf("a forged event was imported: %+v", e)
		}
	}
	// Each rejected file has a note saying why and who wrote it.
	notes, _ := filepath.Glob(filepath.Join(in, "rejected", "*"+whyExt))
	if len(notes) != 3 {
		t.Errorf("notes: %v", notes)
	}
	if got := Rejected(in); len(got) != 3 || !strings.Contains(strings.Join(got, "\n"), "delivers through") {
		t.Errorf("Rejected: %v", got)
	}
}

// writeRaw writes a batch whose records are given as raw JSON lines, with
// a valid end marker: an envelope that is intact but whose records are
// not what Blackbox writes.
func writeRaw(t *testing.T, dir string, h Header, lines ...string) {
	t.Helper()
	h.Kind, h.Format = batchKind, batchFormat
	head, _ := json.Marshal(h)
	all := string(head) + "\n"
	for _, l := range lines {
		all += l + "\n"
	}
	sum := sha256.Sum256([]byte(all))
	end, _ := json.Marshal(record{End: &trailer{Records: len(lines), SHA256: hex.EncodeToString(sum[:])}})
	f, err := os.Create(filepath.Join(dir, InboxName(h.Sender, h.SenderID, h.Seq)))
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	z.Write([]byte(all + string(end) + "\n"))
	z.Close()
	f.Close()
}

// SEC2: a batch whose records can't be used is set aside with a note, the
// import carries on, and its number is a gap until it is sent again.
func TestBadBatchesSetAside(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	h := func(seq uint64) Header { return Header{Sender: "WS-03", SenderID: "w3", Seq: seq, Created: t0} }
	writeRaw(t, in, h(1), `{"event":{"host":"WS-03","summary":"ok"}}`)
	writeRaw(t, in, h(2), `{"event":"not an event"}`)
	writeRaw(t, in, h(3), `{"event":{"host":"WS-03","time":"yesterday"}}`)
	writeRaw(t, in, h(4), `{"other":{"x":1}}`)
	writeRaw(t, in, h(5), `{"event":{"host":"WS-03","summary":"ok"}}`)
	res, err := Import(col, in, Dirs{}, t0, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if res.Batches != 2 || len(res.Rejected) != 3 {
		t.Fatalf("import: %+v", res)
	}
	snd := col.State.Senders["w3"]
	if len(snd.Missing) != 1 || snd.Missing[0].From != 2 || snd.Missing[0].To != 4 || snd.LastSeq != 5 {
		t.Errorf("gaps: %+v, last %d", snd.Missing, snd.LastSeq)
	}
	rej := strings.Join(Rejected(in), "\n")
	for _, want := range []string{"event 1 can't be read", "of no known type"} {
		if !strings.Contains(rej, want) {
			t.Errorf("rejected reasons lack %q:\n%s", want, rej)
		}
	}
	// Sent again, it fills its gap.
	writeRaw(t, in, h(3), `{"event":{"host":"WS-03","summary":"ok"}}`)
	Import(col, in, Dirs{}, t0.Add(time.Hour), t.Logf)
	if snd := col.State.Senders["w3"]; len(snd.Missing) != 2 {
		t.Errorf("after resending 3: %+v", snd.Missing)
	}
}

// SEC3b: an oversized batch file is refused before it is read.
func TestOversizedBatchRefused(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	p := filepath.Join(in, InboxName("WS-04", "w4", 1))
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxBatchFile + 1); err != nil {
		t.Skip("cannot make a large sparse file:", err)
	}
	f.Close()
	res, _ := Import(col, in, Dirs{}, t0, nil)
	if len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0], "larger than any batch") {
		t.Errorf("import: %+v", res)
	}
}

// SEC1: a different batch under a number already imported is kept and
// raised, and so is a former name that is another live computer.
func TestConflictsRaised(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	ev := func(s string) [][]byte { return [][]byte{[]byte(`{"host":"DC01","summary":"` + s + `"}`)} }
	writeBatch(t, in, &Batch{Header: Header{Sender: "DC01", SenderID: "dc", Seq: 1, Created: t0}, Events: ev("a")})
	Import(col, in, Dirs{}, t0, nil)
	writeBatch(t, in, &Batch{Header: Header{Sender: "DC01", SenderID: "dc", Seq: 1, Created: t0}, Events: ev("b")})
	res, _ := Import(col, in, Dirs{}, t0.Add(time.Minute), nil)
	if res.Batches != 1 || res.Already != 0 {
		t.Fatalf("different batch 1: %+v", res)
	}
	// The same batch again is a duplicate.
	writeBatch(t, in, &Batch{Header: Header{Sender: "DC01", SenderID: "dc", Seq: 1, Created: t0}, Events: ev("a")})
	if res, _ := Import(col, in, Dirs{}, t0.Add(2*time.Minute), nil); res.Already != 1 {
		t.Errorf("same batch 1 again: %+v", res)
	}
	writeBatch(t, in, &Batch{Header: Header{Sender: "WS-66", SenderID: "ws", Seq: 1, Created: t0, Former: []string{"DC01", "OLD-NAME"}}, Events: ev("c")})
	Import(col, in, Dirs{}, t0.Add(3*time.Minute), nil)
	cs := ConflictEvents(col, t0.Add(-time.Hour), t0.Add(time.Hour))
	if len(cs) != 2 || !strings.Contains(cs[0].Summary, "Two different batches 1 from DC01") ||
		!strings.Contains(cs[1].Summary, "WS-66 says it was formerly called DC01") || cs[0].Severity != "high" {
		for _, c := range cs {
			t.Logf("%s %s", c.Severity, c.Summary)
		}
		t.Errorf("conflicts: %d", len(cs))
	}
	if f := col.State.Senders["ws"].Former; len(f) != 0 {
		t.Errorf("former names taken: %v", f)
	}
}

// SEC1: a different archive for a period already filed is kept next to it
// and raised; an archive whose host is ".." is refused (SEC3a).
func TestArchiveClashKeptAndRaised(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	arch := t.TempDir()
	from, to := t0, t0.Add(24*time.Hour)
	fakeArchive(t, in, "archive_a_x.zip", "DC01", from, to, "ONE")
	fakeArchive(t, in, "archive_a_y.zip", "DC01", from, to, "ONE")
	res, _ := Import(col, in, Dirs{Archives: arch}, t0, nil)
	fakeArchive(t, in, "archive_b_z.zip", "DC01", from, to, "TWO")
	res, _ = Import(col, in, Dirs{Archives: arch}, t0.Add(time.Hour), nil)
	if res.Archives != 1 {
		t.Fatalf("import: %+v", res)
	}
	list, _ := filepath.Glob(filepath.Join(arch, "DC01", "*.zip"))
	if len(list) != 2 {
		t.Errorf("filed: %v", list)
	}
	if cs := ConflictEvents(col, t0, t0.Add(2*time.Hour)); len(cs) != 1 || !strings.Contains(cs[0].Summary, "Two different original-log archives from DC01") {
		t.Errorf("conflicts: %+v", cs)
	}
	fakeArchive(t, in, "archive_c_d.zip", ".", from, to, "x")
	if res, _ := Import(col, in, Dirs{Archives: arch}, t0, nil); len(res.Rejected) != 1 {
		t.Errorf("host \".\": %+v", res)
	}
}

// SEC1: first_seq is taken only close to the next batch expected.
func TestFirstSeqWindow(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	st.State.Senders = map[string]*store.SenderState{}
	importBatch(st, &Batch{Header: Header{Sender: "A", SenderID: "a", Seq: 10, FirstSeq: 10}, Sum: "1"}, "", "", t0)
	importBatch(st, &Batch{Header: Header{Sender: "A", SenderID: "a", Seq: 15, FirstSeq: 15}, Sum: "2"}, "", "", t0)
	if s := st.State.Senders["a"]; len(s.Missing) != 0 || s.LastSeq != 15 {
		t.Errorf("first_seq within the window: %+v", s)
	}
	importBatch(st, &Batch{Header: Header{Sender: "A", SenderID: "a", Seq: 500, FirstSeq: 500}, Sum: "3"}, "", "", t0)
	if s := st.State.Senders["a"]; len(s.Missing) != 1 || s.Missing[0].From != 16 || s.Missing[0].To != 499 {
		t.Errorf("a jump is a gap: %+v", s.Missing)
	}
}

// SEC1: on the sender, a file already in the inbox under the next name
// counts as delivered only if it is the same; otherwise the batch goes
// under a new name.
func TestDeliverNeverTakesAnotherFile(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-05", "windows", 1, t0)
	Export(ws, "WS-05", "test", t0)
	name := InboxName("WS-05", ws.State.Send.ID, 1)
	os.WriteFile(filepath.Join(in, name), []byte("someone else's"), 0o644)
	if n, err := Deliver(ws, in, "WS-05", false); err != nil || n != 1 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(in, AgainName(name, 2))); err != nil {
		t.Errorf("not delivered under a new name: %v", err)
	}
	col, _ := store.Open(t.TempDir())
	res, _ := Import(col, in, Dirs{}, t0, nil)
	if res.Batches != 1 || len(res.Rejected) != 1 {
		t.Errorf("import: %+v", res)
	}
}

// SEC1: a SCAP result whose contents don't match the hash in its name is
// refused.
func TestScapHashChecked(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	os.WriteFile(filepath.Join(in, "scap_x_0123456789abcdef.xml.gz"), gzipBytes(t, "<x/>"), 0o644)
	res, _ := Import(col, in, Dirs{Scap: t.TempDir()}, t0, nil)
	if len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0], "do not match the hash") {
		t.Errorf("import: %+v", res)
	}
}

// SEC1: a cloned computer gets a new ID: waiting batches are renumbered
// under it.
func TestNewID(t *testing.T) {
	ws := system(t, "WS-06", "windows", 1, t0)
	Export(ws, "WS-06", "test", t0)
	old := ws.State.Send.ID
	o, id, err := NewID(ws)
	if err != nil || o != old || id == old {
		t.Fatalf("new id: %s %s %v", o, id, err)
	}
	list, _ := outbox(ws)
	data, _ := os.ReadFile(filepath.Join(OutboxDir(ws), list[0]))
	b, err := Decode(strings.NewReader(string(data)))
	if err != nil || b.SenderID != id || b.Seq != 1 || ws.State.Send.NextSeq != 2 {
		t.Errorf("renumbered batch: %+v %v", b, err)
	}
}
