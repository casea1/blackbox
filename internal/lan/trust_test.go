package lan

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// legacyFolder makes a sender's own folder in the inbox as 0.23's
// "blackbox inbox add" did, and records it.
func legacyFolder(t *testing.T, col *store.Store, in, name, host string) string {
	t.Helper()
	dir := filepath.Join(in, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, legacyMarker), []byte("Blackbox sender folder\r\nComputer: "+host+"\r\n"), 0o644)
	if col.State.InboxFolders == nil {
		col.State.InboxFolders = map[string]*store.InboxFolder{}
	}
	col.State.InboxFolders[strings.ToUpper(name)] = &store.InboxFolder{Account: "bb-" + strings.ToLower(name), Hosts: []string{host}, Added: t0}
	return dir
}

// DESIGN1, SEC1c: at the collector's upgrade, what waits in a 0.23
// sender's own folder is imported under the same rules as the inbox, and
// the folder is removed. The sender's import record is kept by sender
// ID: batches 431-433, imported from the shared folder before the switch,
// are imported once, never listed as missing, and not imported again
// when sent again; 434, waiting in the folder, is not refused.
func TestSenderFoldersMigrated(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	ev := func(n uint64) [][]byte {
		return [][]byte{[]byte(fmt.Sprintf(`{"host":"ubuntu-server","summary":"batch %d"}`, n))}
	}
	batch := func(seq uint64) *Batch {
		return &Batch{Header: Header{Sender: "ubuntu-server", SenderID: "u1", Seq: seq, Created: t0}, Events: ev(seq)}
	}
	for seq := uint64(431); seq <= 433; seq++ {
		writeBatch(t, in, batch(seq))
	}
	// Seen before from 430 on.
	col.State.Senders["u1"] = &store.SenderState{Host: "ubuntu-server", LastSeq: 430, FirstSeen: t0}
	res, err := Import(col, in, Dirs{}, t0, t.Logf)
	if err != nil || res.Batches != 3 {
		t.Fatalf("shared folder: %+v %v", res, err)
	}
	// 0.23: the sender moved to its own folder; 434 waits there.
	dir := legacyFolder(t, col, in, "ubuntu-server", "ubuntu-server")
	writeBatch(t, dir, batch(434))
	other := filepath.Join(in, "not-a-sender-folder")
	os.MkdirAll(other, 0o750)
	os.WriteFile(filepath.Join(other, "x.bbx"), []byte("x"), 0o644)

	// The collector is upgraded.
	res, err = Import(col, in, Dirs{}, t0.Add(time.Hour), t.Logf)
	if err != nil || res.Batches != 1 || len(res.Rejected) != 0 {
		t.Fatalf("after the upgrade: %+v %v", res, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the 0.23 sender folder is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(other, "x.bbx")); err != nil {
		t.Errorf("a folder that is not a sender's was touched: %v", err)
	}
	if col.State.InboxFolders != nil {
		t.Errorf("0.23 folder record kept: %+v", col.State.InboxFolders)
	}
	// 431-433 sent again (send --resend after the move).
	for seq := uint64(431); seq <= 433; seq++ {
		writeBatch(t, in, batch(seq))
	}
	res, _ = Import(col, in, Dirs{}, t0.Add(2*time.Hour), t.Logf)
	if res.Batches != 0 || res.Already != 3 || len(res.Rejected) != 0 {
		t.Errorf("431-433 again: %+v", res)
	}
	s := col.State.Senders["u1"]
	if len(s.Missing) != 0 || s.LastSeq != 434 {
		t.Errorf("record: missing %+v, last %d", s.Missing, s.LastSeq)
	}
	evs, _ := col.ReadEvents(time.Time{})
	seen := map[string]int{}
	for _, e := range evs {
		seen[e.Summary]++
	}
	for seq := 431; seq <= 434; seq++ {
		if n := seen[fmt.Sprintf("batch %d", seq)]; n != 1 {
			t.Errorf("batch %d imported %d times", seq, n)
		}
	}
}

// DESIGN1: a sender writes each file straight under its final name, so
// the collector may find one half written. It is left alone for 10
// minutes after it was last written, then refused as incomplete; the
// complete copy the sender delivers again is imported.
func TestPartialFileWaitsThenRefused(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	b := &Batch{Header: Header{Sender: "WS-09", SenderID: "w9", Seq: 1, Created: t0},
		Events: [][]byte{[]byte(`{"host":"WS-09","summary":"x"}`)}}
	data, _ := b.Bytes()
	for _, cut := range []int{0, 5, len(data) / 2, len(data) * 3 / 4} {
		p := filepath.Join(in, fmt.Sprintf("WS-09_w9_0000000001_%012d.bbx", cut))
		os.WriteFile(p, data[:cut], 0o640)
		os.Chtimes(p, t0, t0)
	}
	arch := fakeArchive(t, t.TempDir(), "a.zip", "WS-09", t0, t0.Add(time.Hour), "logs")
	zip, _ := os.ReadFile(arch)
	pa := filepath.Join(in, "archive_w9_WS-09_x_0123456789ab.zip")
	os.WriteFile(pa, zip[:len(zip)/2], 0o640)
	os.Chtimes(pa, t0, t0)
	ps := filepath.Join(in, "scap_w9_0123456789abcdef_0123456789ab.xml.gz")
	gz := gzipBytes(t, "<x/>")
	os.WriteFile(ps, gz[:len(gz)-4], 0o640)
	os.Chtimes(ps, t0, t0)

	dirs := Dirs{Archives: t.TempDir(), Scap: t.TempDir()}
	res, err := Import(col, in, dirs, t0.Add(9*time.Minute), t.Logf)
	if err != nil || res.Batches != 0 || len(res.Rejected) != 0 {
		t.Fatalf("still being written: %+v %v", res, err)
	}
	if left, _ := filepath.Glob(filepath.Join(in, "*_*")); len(left) != 6 {
		t.Errorf("files left alone: %v", left)
	}
	res, _ = Import(col, in, dirs, t0.Add(11*time.Minute), t.Logf)
	if len(res.Rejected) != 6 {
		t.Fatalf("after 10 minutes: %+v", res)
	}
	for _, r := range res.Rejected {
		if !strings.Contains(r, "set aside") {
			t.Errorf("not set aside: %s", r)
		}
	}
	if why := strings.Join(Rejected(in), "\n"); strings.Count(why, "incomplete") < 5 {
		t.Errorf("reasons:\n%s", why)
	}
	// The complete batch, delivered again, fills the gap.
	writeBatch(t, in, b)
	res, _ = Import(col, in, dirs, t0.Add(time.Hour), t.Logf)
	if res.Batches != 1 || len(col.State.Senders["w9"].Missing) != 0 {
		t.Errorf("delivered again: %+v %+v", res, col.State.Senders["w9"])
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
	importBatch(st, &Batch{Header: Header{Sender: "A", SenderID: "a", Seq: 10, FirstSeq: 10}, Sum: "1"}, "", t0)
	importBatch(st, &Batch{Header: Header{Sender: "A", SenderID: "a", Seq: 15, FirstSeq: 15}, Sum: "2"}, "", t0)
	if s := st.State.Senders["a"]; len(s.Missing) != 0 || s.LastSeq != 15 {
		t.Errorf("first_seq within the window: %+v", s)
	}
	importBatch(st, &Batch{Header: Header{Sender: "A", SenderID: "a", Seq: 500, FirstSeq: 500}, Sum: "3"}, "", t0)
	if s := st.State.Senders["a"]; len(s.Missing) != 1 || s.Missing[0].From != 16 || s.Missing[0].To != 499 {
		t.Errorf("a jump is a gap: %+v", s.Missing)
	}
}

// DESIGN1: the sender never looks in the inbox. Each delivery has a
// name of its own (HOST_SENDERID_SEQ_RANDOM.bbx), made only if no file has
// it, so a file someone else put there under the batch's name is never
// taken for it, overwritten or read.
func TestDeliverNeverTakesAnotherFile(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-05", "windows", 1, t0)
	Export(ws, "WS-05", "test", t0)
	planted := filepath.Join(in, InboxName("WS-05", ws.State.Send.ID, 1))
	os.WriteFile(planted, []byte("someone else's"), 0o644)
	if n, err := Deliver(ws, in, "WS-05", false); err != nil || n != 1 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	if b, _ := os.ReadFile(planted); string(b) != "someone else's" {
		t.Error("the planted file was changed")
	}
	got, _ := filepath.Glob(filepath.Join(in, "WS-05_"+ws.State.Send.ID+"_0000000001_*.bbx"))
	if len(got) != 1 || len(filepath.Base(got[0])) != len("WS-05_"+ws.State.Send.ID+"_0000000001_0123456789ab.bbx") {
		t.Fatalf("delivered as %v", got)
	}
	col, _ := store.Open(t.TempDir())
	res, _ := Import(col, in, Dirs{}, t0, nil)
	if res.Batches != 1 || len(res.Rejected) != 1 {
		t.Errorf("import: %+v", res)
	}
}

// DESIGN1: a name already taken (someone made that file first) is
// retried under a new random part.
func TestDropRetriesTakenName(t *testing.T) {
	in := t.TempDir()
	src := filepath.Join(t.TempDir(), "b")
	os.WriteFile(src, []byte("batch"), 0o640)
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		name, err := drop(src, in, "H_id_0000000001", batchExt, nil)
		if err != nil || seen[name] {
			t.Fatalf("drop %d: %s %v", i, name, err)
		}
		seen[name] = true
		if id, seq, ok := parseInboxName(name); !ok || id != "id" || seq != 1 {
			t.Errorf("%s parses as %s %d %v", name, id, seq, ok)
		}
	}
	if err := writeNew(filepath.Join(in, "taken"), func(*os.File) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(filepath.Join(in, "taken"), func(*os.File) error { return nil }); !errors.Is(err, fs.ErrExist) {
		t.Errorf("O_EXCL: %v", err)
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
