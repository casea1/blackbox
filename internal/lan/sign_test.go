package lan

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/store"
)

// DESIGN1: a signed batch keeps its content hash (what "already
// imported" compares), and any change to what is signed is caught.
func TestSignedBatchRoundTrip(t *testing.T) {
	k, made, err := EnsureKey(t.TempDir())
	if err != nil || !made {
		t.Fatal(made, err)
	}
	b := &Batch{Header: Header{Sender: "WS-01", SenderID: "abc", Seq: 7, Created: t0},
		Events: [][]byte{[]byte(`{"host":"WS-01","summary":"x"}`)}}
	plain, _ := b.Bytes()
	signed, err := SignBatch(plain, k, t0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(signed))
	if err != nil || got.Sig == nil {
		t.Fatalf("decode: %+v %v", got, err)
	}
	unsigned, _ := Decode(bytes.NewReader(plain))
	if got.Sum != unsigned.Sum {
		t.Error("signing changed the batch's hash")
	}
	pub, err := verifyBatch(got)
	if err != nil || Fingerprint(pub) != k.Fingerprint() {
		t.Fatalf("verify: %v", err)
	}
	// The same signature on another batch number, or another computer.
	for _, change := range []func(*Batch){
		func(b *Batch) { b.Seq = 8 },
		func(b *Batch) { b.Sender = "DC01" },
		func(b *Batch) { b.SenderID = "other" },
		func(b *Batch) { b.Sum = strings.Repeat("0", 64) },
		func(b *Batch) { b.Sig.Time = b.Sig.Time.Add(time.Second) },
	} {
		c := *got
		sig := *got.Sig
		c.Sig = &sig
		change(&c)
		if _, err := verifyBatch(&c); err == nil {
			t.Errorf("a changed batch verified: %+v", c.Header)
		}
	}
	// The key file is the account's alone.
	if p := KeyProblem(filepath.Dir(KeyPath(t.TempDir()))); p != "" {
		t.Errorf("no key: %s", p)
	}
}

// DESIGN1: the key file is checked: readable by others is a problem.
func TestKeyProblem(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := EnsureKey(dir); err != nil {
		t.Fatal(err)
	}
	if p := KeyProblem(dir); p != "" {
		t.Fatalf("a new key: %s", p)
	}
	if fi, _ := os.Stat(KeyPath(dir)); fi.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Errorf("mode %v", fi.Mode())
	}
	if os.PathSeparator == '/' {
		os.Chmod(KeyPath(dir), 0o644)
		if p := KeyProblem(dir); !strings.Contains(p, "other accounts can read it") {
			t.Errorf("mode 0644: %q", p)
		}
	}
}

// signedImport delivers what st has waiting into in and imports it.
func deliverAndImport(t *testing.T, st, col *store.Store, host, in string, dirs Dirs, at time.Time) ImportResult {
	t.Helper()
	send(t, st, host, in, at)
	res, err := Import(col, in, dirs, at.Add(time.Minute), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// DESIGN1: the first signed delivery pins the computer to its key; a
// different key (a reinstall) is held with a High row until rekey, and
// then imported.
func TestKeyPinnedThenChangeHeld(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	ws := system(t, "WS-01", "windows", 2, t0)
	if res := deliverAndImport(t, ws, col, "WS-01", in, Dirs{}, t0); res.Batches != 1 {
		t.Fatalf("first: %+v", res)
	}
	k := col.State.SenderKeys["WS-01"]
	wk, _ := LoadKey(ws.Dir)
	if k == nil || k.FP != wk.Fingerprint() || k.Held {
		t.Fatalf("pinned: %+v", k)
	}
	if cs := ConflictEvents(col, t0, t0.Add(time.Hour)); len(cs) != 1 || cs[0].Severity != "info" || !strings.Contains(cs[0].Summary, "New sender: WS-01") {
		t.Errorf("new sender note: %+v", cs)
	}
	// Reinstalled: a new data folder, so a new sender ID and a new key.
	re := system(t, "WS-01", "windows", 3, t0.Add(time.Hour))
	res := deliverAndImport(t, re, col, "WS-01", in, Dirs{}, t0.Add(time.Hour))
	if res.Batches != 0 || len(res.Held) != 1 || len(res.Rejected) != 0 {
		t.Fatalf("new key: %+v", res)
	}
	k = col.State.SenderKeys["WS-01"]
	rk, _ := LoadKey(re.Dir)
	if k.NewFP != rk.Fingerprint() || !strings.Contains(KeyChangeText(k), "blackbox senders rekey WS-01") {
		t.Errorf("key change: %+v", k)
	}
	if cs := ConflictEvents(col, t0.Add(30*time.Minute), t0.Add(2*time.Hour)); len(cs) != 1 || cs[0].Severity != "high" || !strings.Contains(cs[0].Summary, "is now signing with a different key") {
		t.Errorf("High row: %+v", cs)
	}
	if h := Held(in); len(h) != 1 {
		t.Errorf("held: %v", h)
	}
	// Held again at the next run, not imported.
	collect(t, re, "WS-01", "windows", 1, t0.Add(2*time.Hour))
	if res := deliverAndImport(t, re, col, "WS-01", in, Dirs{}, t0.Add(2*time.Hour)); res.Batches != 0 || len(res.Held) != 1 {
		t.Fatalf("still held: %+v", res)
	}
	n, err := SetKey(col, in, "ws-01", Rekey, "admin", "reinstalled", t0.Add(3*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("rekey: %d %v", n, err)
	}
	res, _ = Import(col, in, Dirs{}, t0.Add(3*time.Hour), t.Logf)
	if res.Batches != 2 || len(res.Rejected) != 0 || len(res.Held) != 0 {
		t.Fatalf("after rekey: %+v", res)
	}
	if k := col.State.SenderKeys["WS-01"]; k.FP != rk.Fingerprint() || k.NewFP != "" || len(k.Changes) != 1 || k.Changes[0].Who != "admin" {
		t.Errorf("rekeyed: %+v", k)
	}
	if s := col.State.Senders[re.State.Send.ID]; s == nil || s.LastSeq != 2 || len(s.Missing) != 0 {
		t.Errorf("reinstalled sender: %+v", s)
	}
}

// DESIGN1: with new_senders = hold, a new computer's deliveries wait
// until it is approved.
func TestNewSenderHeldUntilApproved(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	ws := system(t, "WS-02", "linux", 1, t0)
	dirs := Dirs{HoldNew: true, Archives: t.TempDir()}
	res := deliverAndImport(t, ws, col, "WS-02", in, dirs, t0)
	if res.Batches != 0 || len(res.Held) != 1 || !col.State.SenderKeys["WS-02"].Held {
		t.Fatalf("held: %+v", res)
	}
	if _, err := SetKey(col, in, "WS-02", Rekey, "a", "", t0); err == nil {
		t.Error("rekey of a computer that has not changed its key")
	}
	if n, err := SetKey(col, in, "WS-02", Approve, "admin", "new workstation", t0.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("approve: %d %v", n, err)
	}
	if res, _ := Import(col, in, dirs, t0.Add(time.Hour), t.Logf); res.Batches != 1 {
		t.Errorf("after approval: %+v", res)
	}
}

// DESIGN1: unsigned deliveries (senders before 0.24) are taken from a
// computer that has never signed, refused once it has (no downgrade),
// and refused from all with require_signed = yes.
func TestUnsignedOnlyUntilSigned(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	old := func(host, id string, seq uint64) *Batch {
		return &Batch{Header: Header{Sender: host, SenderID: id, Seq: seq, Created: t0},
			Events: [][]byte{[]byte(fmt.Sprintf(`{"host":%q,"summary":"%d"}`, host, seq))}}
	}
	writeBatch(t, in, old("OLD-PC", "o1", 1))
	if res, _ := Import(col, in, Dirs{}, t0, t.Logf); res.Batches != 1 {
		t.Fatalf("unsigned from a computer never signed: %+v", res)
	}
	if s := col.State.Senders["o1"]; s.Unsigned.IsZero() || s.KeyFP != "" {
		t.Errorf("not noted unsigned: %+v", s)
	}
	writeBatch(t, in, old("OLD-PC", "o1", 2))
	if res, _ := Import(col, in, Dirs{RequireSigned: true}, t0.Add(time.Minute), t.Logf); len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0], "require_signed") {
		t.Errorf("require_signed: %+v", res)
	}
	// WS-03 signs; then an unsigned file claiming to be from it is refused,
	// and its number is not counted missing (it is not WS-03's).
	ws := system(t, "WS-03", "windows", 1, t0)
	deliverAndImport(t, ws, col, "WS-03", in, Dirs{}, t0)
	writeBatch(t, in, old("WS-03", ws.State.Send.ID, 2))
	writeBatch(t, in, old("WS-03", "forged", 1))
	res, _ := Import(col, in, Dirs{}, t0.Add(time.Hour), t.Logf)
	if res.Batches != 0 || len(res.Rejected) != 2 {
		t.Fatalf("downgrade: %+v", res)
	}
	for _, r := range res.Rejected {
		if !strings.Contains(r, "it is not signed, but") {
			t.Errorf("reason: %s", r)
		}
	}
	if s := col.State.Senders[ws.State.Send.ID]; len(s.Missing) != 0 || s.LastSeq != 1 {
		t.Errorf("a refused forgery made a gap: %+v", s)
	}
}

// DESIGN1: a file signed with another key under a pinned computer's
// name is held, never imported; a signature that does not match is
// refused; a forged archive or SCAP result is refused or held.
func TestForgedDeliveries(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	arch := t.TempDir()
	dc := system(t, "DC01", "windows", 1, t0)
	deliverAndImport(t, dc, col, "DC01", in, Dirs{Archives: arch}, t0)
	evil, _, _ := EnsureKey(t.TempDir())
	b := &Batch{Header: Header{Sender: "DC01", SenderID: dc.State.Send.ID, Seq: 2, Created: t0},
		Events: [][]byte{[]byte(`{"host":"DC01","summary":"forged"}`)}}
	plain, _ := b.Bytes()
	signed, _ := SignBatch(plain, evil, t0)
	os.WriteFile(filepath.Join(in, "DC01_"+dc.State.Send.ID+"_0000000002-aaaaaaaaaaaa.bbx"), signed, 0o640)
	// A real signature moved onto other content.
	dk, _ := LoadKey(dc.Dir)
	b2 := &Batch{Header: Header{Sender: "DC01", SenderID: dc.State.Send.ID, Seq: 3, Created: t0},
		Events: [][]byte{[]byte(`{"host":"DC01","summary":"real"}`)}}
	p2, _ := b2.Bytes()
	s2, _ := SignBatch(p2, dk, t0)
	b4 := &Batch{Header: Header{Sender: "DC01", SenderID: dc.State.Send.ID, Seq: 4, Created: t0},
		Events: [][]byte{[]byte(`{"host":"DC01","summary":"forged"}`)}}
	p4, _ := b4.Bytes()
	s4, _ := SignBatch(p4, dk, t0)
	sigOf := func(b []byte) []byte {
		t := mustGunzip(t, b)
		i := bytes.Index(t, []byte(`"sig":"`))
		return t[i : i+bytes.IndexByte(t[i+7:], '"')+8]
	}
	s2 = bytes.Replace(mustGunzip(t, s4), sigOf(s4), sigOf(s2), 1)
	os.WriteFile(filepath.Join(in, "DC01_"+dc.State.Send.ID+"_0000000004-bbbbbbbbbbbb.bbx"), gzipBytes(t, string(s2)), 0o640)
	// An archive for DC01 signed by the attacker's key.
	src := fakeArchive(t, t.TempDir(), "a.zip", "DC01", t0, t0.Add(time.Hour), "forged")
	name := "archive_x_DC01_a-cccccccccccc.zip"
	data, _ := os.ReadFile(src)
	os.WriteFile(filepath.Join(in, name), data, 0o640)
	sig, _ := makeSig(evil, filepath.Join(in, name), "archive", "DC01", "x", archiveWhat(t0, t0.Add(time.Hour)), t0)
	os.WriteFile(filepath.Join(in, name+sigExt), sig, 0o640)
	// The same archive, unsigned (DC01 signs).
	os.WriteFile(filepath.Join(in, "archive_y_DC01_a-dddddddddddd.zip"), data, 0o640)

	res, _ := Import(col, in, Dirs{Archives: arch}, t0.Add(time.Hour), t.Logf)
	if res.Batches != 0 || res.Archives != 0 || len(res.Held) != 2 || len(res.Rejected) != 2 {
		t.Fatalf("forged: %+v", res)
	}
	all := strings.Join(res.Rejected, "\n")
	if !strings.Contains(all, "does not match its contents") || !strings.Contains(all, "it is not signed, but DC01") {
		t.Errorf("reasons:\n%s", all)
	}
	evs, _ := col.ReadEvents(time.Time{})
	for _, e := range evs {
		if e.Summary == "forged" || e.Summary == "real" {
			t.Errorf("imported: %+v", e)
		}
	}
	if list, _ := archive.List(arch); len(list) != 0 {
		t.Errorf("archives filed: %+v", list)
	}
}

func mustGunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := gunzip(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// copyDir copies a data folder, as cloning a computer does.
func copyDir(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o750)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0o600)
	})
	return to
}

// DESIGN1: one key on two computers (a computer cloned with its data
// folder) is a High row; neither is merged into the other, and both
// computers' batches are kept. send --new-id gives the copy a new key.
func TestSameKeyOnTwoComputers(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	ws := system(t, "WS-04", "windows", 1, t0)
	deliverAndImport(t, ws, col, "WS-04", in, Dirs{}, t0)
	clone, err := store.Open(copyDir(t, ws.Dir))
	if err != nil {
		t.Fatal(err)
	}
	collect(t, clone, "WS-04-COPY", "windows", 1, t0.Add(time.Hour))
	res := deliverAndImport(t, clone, col, "WS-04-COPY", in, Dirs{}, t0.Add(time.Hour))
	if res.Batches != 1 || len(res.Held) != 0 {
		t.Fatalf("clone: %+v", res)
	}
	found := false
	for _, c := range ConflictEvents(col, t0, t0.Add(2*time.Hour)) {
		if c.Severity == "high" && strings.Contains(c.Summary, "sign with the same key") {
			found = true
		}
	}
	if !found || col.State.SenderKeys["WS-04-COPY"].SharedWith != "WS-04" {
		t.Errorf("no High row for one key on two computers: %+v", col.State.SenderKeys)
	}
	before, _ := LoadKey(clone.Dir)
	if _, _, err := NewID(clone); err != nil {
		t.Fatal(err)
	}
	after, _ := LoadKey(clone.Dir)
	if before.Fingerprint() == after.Fingerprint() {
		t.Error("send --new-id kept the key")
	}
}

// DESIGN1, SEC1c: a sender upgraded mid-stream. Batches 1-2 were
// delivered unsigned by 0.23 and wait in the inbox, 3 waits in its 0.23
// folder, 4 waits in its outbox, made by 0.23; after the upgrade it
// makes 5 and delivers 4-5 signed. All five are imported once, with no
// gap and nothing refused; sent again, all are "already imported".
func TestUpgradeMidStream(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	ws := system(t, "WS-05", "linux", 1, t0)
	for i := 1; i <= 4; i++ {
		if i > 1 {
			collect(t, ws, "WS-05", "linux", 1, t0.Add(time.Duration(i)*time.Hour))
		}
		Export(ws, "WS-05", "0.23.0", t0.Add(time.Duration(i)*time.Hour))
	}
	list, _ := outbox(ws)
	folder := legacyFolder(t, col, in, "WS-05", "WS-05")
	for i, name := range list[:3] {
		data, _ := os.ReadFile(filepath.Join(OutboxDir(ws), name))
		dir := in
		if i == 2 {
			dir = folder
		}
		os.WriteFile(filepath.Join(dir, InboxName("WS-05", ws.State.Send.ID, uint64(i+1))), data, 0o640)
		os.MkdirAll(SentDir(ws), 0o750)
		os.Rename(filepath.Join(OutboxDir(ws), name), filepath.Join(SentDir(ws), name))
	}
	// Upgraded: 5 is made, and 4-5 go signed.
	collect(t, ws, "WS-05", "linux", 1, t0.Add(5*time.Hour))
	Export(ws, "WS-05", "0.24.0", t0.Add(5*time.Hour))
	if n, err := Deliver(ws, in, "WS-05", true); err != nil || n != 2 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	res, err := Import(col, in, Dirs{}, t0.Add(6*time.Hour), t.Logf)
	if err != nil || res.Batches != 5 || len(res.Rejected) != 0 || len(res.Held) != 0 {
		t.Fatalf("import: %+v %v", res, err)
	}
	s := col.State.Senders[ws.State.Send.ID]
	if s.LastSeq != 5 || len(s.Missing) != 0 || s.KeyFP == "" {
		t.Errorf("record: %+v", s)
	}
	// Sent again after the upgrade: signed now, and already imported.
	sent, _, err := Resend(ws, in, "WS-05", 1, 5)
	if err != nil || len(sent) != 5 {
		t.Fatalf("resend: %v %v", sent, err)
	}
	res, _ = Import(col, in, Dirs{}, t0.Add(7*time.Hour), t.Logf)
	if res.Batches != 0 || res.Already != 5 || len(res.Rejected) != 0 {
		t.Errorf("sent again: %+v", res)
	}
	evs, _ := col.ReadEvents(time.Time{})
	if len(evs) != 5 {
		t.Errorf("%d events, want 5 (one per batch, none twice)", len(evs))
	}
}

// SEC1f: an unsigned copy of a batch already imported signed (the copy a
// sender keeps in outbox\sent, replayed into the inbox) is "already
// imported", not refused. An unsigned batch claiming that signed sender
// that is not an exact copy (other content, or a number not imported) is
// still refused, and makes no gap.
func TestUnsignedCopyOfImportedBatch(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	ws := system(t, "WS-09", "windows", 2, t0)
	Export(ws, "WS-09", "test", t0)
	if n, err := Deliver(ws, in, "WS-09", true); err != nil || n != 1 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	if res, _ := Import(col, in, Dirs{}, t0.Add(time.Minute), t.Logf); res.Batches != 1 {
		t.Fatalf("signed import: %+v", res)
	}
	id := ws.State.Send.ID
	kept, err := os.ReadFile(filepath.Join(SentDir(ws), outboxName(1)))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := Decode(bytes.NewReader(kept)); err != nil || b.Sig != nil {
		t.Fatalf("the kept copy should be unsigned: %v %+v", err, b)
	}
	replay := filepath.Join(in, fmt.Sprintf("WS-09_%s_0000000001-0123456789ab.bbx", id))
	os.WriteFile(replay, kept, 0o644)
	res, _ := Import(col, in, Dirs{}, t0.Add(time.Hour), t.Logf)
	if res.Already != 1 || res.Batches != 0 || len(res.Rejected) != 0 {
		t.Fatalf("unsigned copy: %+v, want already imported", res)
	}
	if _, err := os.Stat(replay); err == nil {
		t.Error("the copy was left in the inbox")
	}

	// Not an exact copy: refused as before, with no gap.
	writeBatch(t, in, &Batch{Header: Header{Sender: "WS-09", SenderID: id, Seq: 1, Created: t0},
		Events: [][]byte{[]byte(`{"host":"WS-09","summary":"other"}`)}})
	writeBatch(t, in, &Batch{Header: Header{Sender: "WS-09", SenderID: id, Seq: 2, Created: t0},
		Events: [][]byte{[]byte(`{"host":"WS-09","summary":"new"}`)}})
	res, _ = Import(col, in, Dirs{}, t0.Add(2*time.Hour), t.Logf)
	if res.Already != 0 || res.Batches != 0 || len(res.Rejected) != 2 {
		t.Fatalf("unsigned, not a copy: %+v", res)
	}
	for _, r := range res.Rejected {
		if !strings.Contains(r, "it is not signed, but") {
			t.Errorf("reason: %s", r)
		}
	}
	if s := col.State.Senders[id]; len(s.Missing) != 0 || s.LastSeq != 1 || len(col.State.InboxConflicts) != 1 {
		t.Errorf("after the refusals: %+v, conflicts %+v", s, col.State.InboxConflicts)
	}
}

// SEC1f: a file in the inbox that is not a delivery (anything but a
// batch, log archive, SCAP result, their signatures and the marker) is
// set aside in inbox/rejected with a note once it has not changed for 10
// minutes, never deleted. A recent one is left for now.
func TestStrayFilesSetAside(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	old := t0.Add(-time.Hour)
	for _, n := range []string{"probe2.txt", ".hidden", "notes.txt.sig", "desktop.ini"} {
		p := filepath.Join(in, n)
		os.WriteFile(p, []byte("x"), 0o644)
		os.Chtimes(p, old, old)
	}
	recent := filepath.Join(in, "new.txt")
	os.WriteFile(recent, []byte("x"), 0o644)
	os.Chtimes(recent, t0.Add(-time.Minute), t0.Add(-time.Minute))
	os.MkdirAll(filepath.Join(in, "someone-elses"), 0o750)
	res, err := Import(col, in, Dirs{}, t0, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 4 {
		t.Fatalf("set aside: %v", res.Rejected)
	}
	for _, n := range []string{"probe2.txt", ".hidden", "notes.txt.sig", "desktop.ini"} {
		if _, err := os.Stat(filepath.Join(in, rejectedDir, n)); err != nil {
			t.Errorf("%s not set aside: %v", n, err)
		}
		why, err := os.ReadFile(filepath.Join(in, rejectedDir, n+whyExt))
		if err != nil || !strings.Contains(string(why), "not a Blackbox delivery") {
			t.Errorf("%s: note %q %v", n, why, err)
		}
	}
	for _, p := range []string{recent, filepath.Join(in, MarkerFile), filepath.Join(in, "someone-elses")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was moved: %v", p, err)
		}
	}
	if got := Rejected(in); len(got) != 4 {
		t.Errorf("Rejected lists %v", got)
	}
	// Ten minutes on, the recent one goes too.
	if res, _ := Import(col, in, Dirs{}, t0.Add(10*time.Minute), t.Logf); len(res.Rejected) != 1 {
		t.Errorf("later: %v", res.Rejected)
	}
}
