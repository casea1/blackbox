package lan

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/store"
)

func writeBatch(t *testing.T, dir string, b *Batch) string {
	t.Helper()
	data, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("%s_%s_%d.bbx", b.Sender, b.SenderID, b.Seq)
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// REVIEW-1: one batch whose envelope is valid but whose event line is not
// an Event object stops Import for every batch after it, every run.
func TestReviewPoisonBatchBlocksInbox(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	writeBatch(t, in, &Batch{Header: Header{Sender: "EVIL", SenderID: "a0", Seq: 1, Created: t0},
		Events: [][]byte{[]byte(`"not an event"`)}})
	good := writeBatch(t, in, &Batch{Header: Header{Sender: "DC01", SenderID: "zz", Seq: 1, Created: t0},
		Events: [][]byte{[]byte(`{"host":"DC01","summary":"real"}`)}})
	for run := 1; run <= 3; run++ {
		res, err := Import(col, in, Dirs{}, t0.Add(time.Duration(run)*time.Hour), nil)
		t.Logf("run %d: err=%v batches=%d rejected=%v", run, err, res.Batches, res.Rejected)
	}
	if _, err := os.Stat(filepath.Join(in, good)); err == nil {
		t.Errorf("DC01's good batch is still waiting in the inbox after 3 runs")
	}
}

// REVIEW-2: a forged batch with a sender's ID and a huge first_seq makes
// every later genuine batch from that sender a "duplicate": it is deleted
// unimported and no gap is recorded.
func TestReviewFirstSeqHijack(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	ev := []byte(`{"host":"DC01","summary":"real"}`)
	writeBatch(t, in, &Batch{Header: Header{Sender: "DC01", SenderID: "dc", Seq: 1, Created: t0}, Events: [][]byte{ev}})
	if _, err := Import(col, in, Dirs{}, t0, nil); err != nil {
		t.Fatal(err)
	}
	const big = 1 << 62
	writeBatch(t, in, &Batch{Header: Header{Sender: "DC01", SenderID: "dc", Seq: big, FirstSeq: big, Created: t0}})
	Import(col, in, Dirs{}, t0.Add(time.Minute), nil)
	// The real sender carries on with batches 2..4.
	for s := uint64(2); s <= 4; s++ {
		writeBatch(t, in, &Batch{Header: Header{Sender: "DC01", SenderID: "dc", Seq: s, Created: t0}, Events: [][]byte{ev}})
	}
	res, err := Import(col, in, Dirs{}, t0.Add(time.Hour), nil)
	evs, _ := col.ReadEvents(time.Time{})
	snd := col.State.Senders["dc"]
	t.Logf("err=%v batches=%d already=%d events stored=%d lastSeq=%d missing=%v", err, res.Batches, res.Already, len(evs), snd.LastSeq, snd.Missing)
	left, _ := filepath.Glob(filepath.Join(in, "*.bbx"))
	if len(evs) != 4 {
		t.Errorf("genuine batches 2-4 were discarded (%d events stored, %d .bbx left in inbox, %d gaps recorded)", len(evs), len(left), len(snd.Missing))
	}
}

func fakeArchive(t *testing.T, dir, name, host string, from, to time.Time, content string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "Security.evtx")
	os.WriteFile(src, []byte(content), 0o644)
	// A fixed time: the zip records it, so two archives of the same content
	// are the same bytes even when made either side of a second.
	os.Chtimes(src, from, from)
	p := filepath.Join(dir, name)
	if _, err := archive.Write(p, archive.Info{Host: host, OS: "windows", From: from, To: to, Created: to},
		[]archive.Source{{Name: "Security.evtx", Source: "Security", Path: src}}); err != nil {
		t.Fatal(err)
	}
	return p
}

// REVIEW-3: any inbox writer can file archives as any host, and the first
// archive filed for a host+period wins: the genuine one arriving later is
// deleted as a "duplicate" without its contents being compared.
func TestReviewArchiveSpoofFirstWins(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	arch := t.TempDir()
	from, to := t0, t0.Add(24*time.Hour)
	fakeArchive(t, in, "archive_attacker_x.zip", "DC01", from, to, "FORGED")
	res, _ := Import(col, in, Dirs{Archives: arch}, t0, nil)
	t.Logf("forged: archives=%d rejected=%v", res.Archives, res.Rejected)
	genuine := fakeArchive(t, in, "archive_dcid_DC01_x.zip", "DC01", from, to, "GENUINE EVTX")
	res, _ = Import(col, in, Dirs{Archives: arch}, t0.Add(time.Hour), nil)
	t.Logf("genuine: archives=%d rejected=%v", res.Archives, res.Rejected)
	_, gerr := os.Stat(genuine)
	filed := filepath.Join(arch, "DC01", archive.FileName("DC01", from, to))
	cs, _ := archive.Contents(filed)
	t.Logf("genuine still in inbox: %v; filed %s", gerr == nil, filed)
	// The archive's files are compressed: look inside every archive filed
	// for DC01 (a second, different one is filed as …-2.zip).
	genuineKept := false
	all, _ := filepath.Glob(filepath.Join(arch, "DC01", "*.zip"))
	for _, z := range all {
		if r, err := zip.OpenReader(z); err == nil {
			for _, f := range r.File {
				if rc, err := f.Open(); err == nil {
					b, _ := io.ReadAll(rc)
					rc.Close()
					genuineKept = genuineKept || bytes.Contains(b, []byte("GENUINE"))
				}
			}
			r.Close()
		}
	}
	if !genuineKept && gerr != nil {
		t.Errorf("the genuine DC01 archive was deleted; DC01's filed archive is the forged one (%d infos)", len(cs))
	}
}

// REVIEW-4: an archive whose archive.json says host ".." is filed outside
// the archives folder, where List never sees it (never bundled or pruned).
func TestReviewArchiveDotDotHost(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	base := t.TempDir()
	arch := filepath.Join(base, "archives")
	fakeArchive(t, in, "archive_x_y.zip", "..", t0, t0.Add(time.Hour), "x")
	res, err := Import(col, in, Dirs{Archives: arch}, t0, nil)
	t.Logf("err=%v archives=%d rejected=%v", err, res.Archives, res.Rejected)
	m, _ := filepath.Glob(filepath.Join(base, "*.zip"))
	l, _ := archive.List(arch)
	if len(m) > 0 {
		t.Errorf("archive filed outside the archives folder: %v (List sees %d)", m, len(l))
	}
}
