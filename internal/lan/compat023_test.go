package lan

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/store"
)

// The 0.23 collector's name rules, copied from v0.23.0 as fixed fixtures
// (internal/lan/receive.go parseInboxName and importArchive, and
// internal/lan/scap.go importScap). They must not be changed: they are
// what a collector that has not been upgraded yet runs (DESIGN1, upgrade
// order A + C: senders first, then the collector).

// v023ParseInboxName is parseInboxName from v0.23.0, unchanged.
func v023ParseInboxName(n string) (id string, seq uint64, ok bool) {
	parts := strings.Split(strings.TrimSuffix(n, batchExt), "_")
	if len(parts) < 3 {
		return "", 0, false
	}
	last, _, _ := strings.Cut(parts[len(parts)-1], "-")
	seq, err := strconv.ParseUint(last, 10, 64)
	if err != nil || seq == 0 {
		return "", 0, false
	}
	return parts[len(parts)-2], seq, parts[len(parts)-2] != ""
}

// v023ScapName is how v0.23.0's importScap reads a SCAP result's name:
// the sender ID and the hash its contents must start with.
func v023ScapName(name string) (id, sum string) {
	rest := strings.TrimSuffix(strings.TrimPrefix(name, scapPrefix), scapExt)
	id, sum, _ = strings.Cut(rest, "_")
	sum, _, _ = strings.Cut(sum, "-")
	return id, sum
}

// v023ArchiveID is how v0.23.0's importArchive reads an archive's name.
func v023ArchiveID(name string) string {
	id, _, _ := strings.Cut(strings.TrimPrefix(name, archivePrefix), "_")
	return id
}

// DESIGN1 (owner's answer C): what a 0.24 sender delivers is named
// HOST_SENDERID_SEQ-RANDOM.bbx, which a 0.23 collector reads as the same
// sender and batch number, so senders can be upgraded before the
// collector. Log archives and SCAP results carry their random part the
// same way.
func TestNewNamesReadBy023Collector(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-05", "windows", 3, t0)
	Export(ws, "WS-05", "test", t0)
	id := ws.State.Send.ID
	if n, err := Deliver(ws, in, "WS-05", false); err != nil || n != 1 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	got, _ := filepath.Glob(filepath.Join(in, "*.bbx"))
	if len(got) != 1 {
		t.Fatalf("delivered: %v", got)
	}
	name := filepath.Base(got[0])
	prefix := "WS-05_" + id + "_0000000001-"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+12+len(batchExt) {
		t.Fatalf("named %s, want %sRANDOM.bbx", name, prefix)
	}
	if gid, seq, ok := v023ParseInboxName(name); !ok || gid != id || seq != 1 {
		t.Errorf("0.23 reads %s as %q %d %v", name, gid, seq, ok)
	}
	if gid, seq, ok := parseInboxName(name); !ok || gid != id || seq != 1 {
		t.Errorf("0.24 reads %s as %q %d %v", name, gid, seq, ok)
	}

	src := filepath.Join(t.TempDir(), "x")
	os.WriteFile(src, []byte("x"), 0o640)
	sum := "0123456789abcdef"
	scapName, err := drop(src, in, scapPrefix+id+"_"+sum, scapExt, []byte("sig"))
	if err != nil {
		t.Fatal(err)
	}
	if gid, gsum := v023ScapName(scapName); gid != id || gsum != sum {
		t.Errorf("0.23 reads %s as %q %q", scapName, gid, gsum)
	}
	archName, err := drop(src, in, archivePrefix+id+"_logs-WS-05_20261008T0000Z", archiveExt, []byte("sig"))
	if err != nil {
		t.Fatal(err)
	}
	if gid := v023ArchiveID(archName); gid != id {
		t.Errorf("0.23 reads %s as %q", archName, gid)
	}
}

// DESIGN1: the 0.24 collector reads its own senders' names and those of
// senders not upgraded yet (HOST_ID_SEQ.bbx, and HOST_ID_SEQ-N.bbx for a
// batch delivered again), and nothing looser.
func TestParseInboxNameOldAndNew(t *testing.T) {
	for _, c := range []struct {
		name string
		id   string
		seq  uint64
		ok   bool
	}{
		{"WS-05_0123456789abcdef_0000000431-0123456789ab.bbx", "0123456789abcdef", 431, true},
		{"WS-05_0123456789abcdef_0000000431.bbx", "0123456789abcdef", 431, true},
		{"WS-05_0123456789abcdef_0000000431-2.bbx", "0123456789abcdef", 431, true},
		{"WS-05_0123456789abcdef_431.bbx", "0123456789abcdef", 431, true},
		{"WS-05_0123456789abcdef_0000000431-2-0123456789ab.bbx", "0123456789abcdef", 431, true}, // moved out of a 0.23 folder
		{"WS-05_0123456789abcdef_0000000000-0123456789ab.bbx", "", 0, false},
		{"WS-05_0123456789abcdef_x-0123456789ab.bbx", "", 0, false},
		{"WS-05__0000000001-0123456789ab.bbx", "", 0, false},
		{"0123456789abcdef_0000000001.bbx", "", 0, false},
		{"A_B_0123456789abcdef_0000000001.bbx", "", 0, false},
	} {
		id, seq, ok := parseInboxName(c.name)
		if ok != c.ok || ok && (id != c.id || seq != c.seq) {
			t.Errorf("%s: %q %d %v, want %q %d %v", c.name, id, seq, ok, c.id, c.seq, c.ok)
		}
	}
	for i := 0; i < 50; i++ {
		n := migratedName("WS-05_0123456789abcdef_0000000007.bbx")
		if id, seq, ok := parseInboxName(n); !ok || id != "0123456789abcdef" || seq != 7 {
			t.Fatalf("migrated as %s: %q %d %v", n, id, seq, ok)
		}
	}
}

// DESIGN1: a sender upgraded while the collector is still 0.23 keeps
// delivering into the folder 0.23 gave it (a 0.23 collector refuses a
// file in the inbox itself from a computer that has a folder). Once the
// 0.24 collector has moved the folder's files into the inbox and removed
// it, the sender delivers into the inbox.
func TestSenderUpgradedFirstUses023Folder(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	folder := legacyFolder(t, col, in, "WS-05", "WS-05")
	ws := system(t, "WS-05", "windows", 1, t0)
	Export(ws, "WS-05", "test", t0)
	ws.State.Send.Folder = "WS-05"
	if n, err := Deliver(ws, in, "WS-05", true); err != nil || n != 1 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	if got, _ := filepath.Glob(filepath.Join(folder, "*.bbx")); len(got) != 1 {
		t.Fatalf("not in the 0.23 folder: %v", got)
	} else if _, _, ok := v023ParseInboxName(filepath.Base(got[0])); !ok {
		t.Errorf("0.23 can't read %s", got[0])
	}
	if got, _ := filepath.Glob(filepath.Join(in, "*.bbx")); len(got) != 0 {
		t.Errorf("in the inbox itself: %v", got)
	}

	// The collector is upgraded: its next import empties and removes the folder.
	res, err := Import(col, in, Dirs{}, t0, t.Logf)
	if err != nil || res.Batches != 1 {
		t.Fatalf("import: %+v %v", res, err)
	}
	if _, err := os.Stat(folder); err == nil {
		t.Fatal("the 0.23 folder is still there")
	}
	collect(t, ws, "WS-05", "windows", 1, t0.Add(time.Hour))
	Export(ws, "WS-05", "test", t0.Add(time.Hour))
	if n, err := Deliver(ws, in, "WS-05", true); err != nil || n != 1 {
		t.Fatalf("deliver after the upgrade: %d %v", n, err)
	}
	if got, _ := filepath.Glob(filepath.Join(in, "*.bbx")); len(got) != 1 {
		t.Errorf("not in the inbox: %v", got)
	}
	res, _ = Import(col, in, Dirs{}, t0.Add(time.Hour), t.Logf)
	if res.Batches != 1 || len(res.Rejected) != 0 || len(col.State.Senders[ws.State.Send.ID].Missing) != 0 {
		t.Errorf("import after the upgrade: %+v %+v", res, col.State.Senders[ws.State.Send.ID])
	}

	// A recorded folder name is a name, never a path.
	for _, f := range []string{"..", ".", "../x", "a/b"} {
		ws.State.Send.Folder = f
		if d := deliveryDir(ws, in); d != in {
			t.Errorf("folder %q: delivers into %s", f, d)
		}
	}
}

// DESIGN1: a sender upgraded before the collector signs what it drops into
// its 0.23 folder; at the collector's upgrade each archive and SCAP result
// is moved out with its NAME.sig and imported as signed, and a signature
// a 0.23 collector left behind (it imported the file and ignored the
// .sig) is removed, not refused.
func TestSignedDeliveriesThrough023Folder(t *testing.T) {
	in := inbox(t)
	col, _ := store.Open(t.TempDir())
	folder := legacyFolder(t, col, in, "WS-07", "WS-07")
	ws := system(t, "WS-07", "windows", 1, t0)
	Export(ws, "WS-07", "test", t0)
	ws.State.Send.Folder = "WS-07"

	logFile := filepath.Join(t.TempDir(), "Security.evtx")
	os.WriteFile(logFile, []byte("pretend evtx"), 0o644)
	from, to := t0.Add(-24*time.Hour), t0
	if _, err := archive.Write(filepath.Join(OutboxDir(ws), archive.FileName("WS-07", from, to)),
		archive.Info{Host: "WS-07", OS: "windows", From: from, To: to, Created: to},
		[]archive.Source{{Name: "Security.evtx", Source: "Security", Path: logFile}}); err != nil {
		t.Fatal(err)
	}
	files := []string{"../../testdata/scap/scc/Sessions/2026-09-29_100000/Results/SCAP/XML/WS-07_SCC-5.10_2026-09-29_100000_XCCDF-Results_MS_Windows_11_STIG.xml"}
	if n, err := QueueScap(ws, files, t0); err != nil || n != 1 {
		t.Fatalf("queued %d %v", n, err)
	}
	if n, err := Deliver(ws, in, "WS-07", true); err != nil || n != 1 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	if n, err := DeliverArchives(ws, in); err != nil || n != 1 {
		t.Fatalf("archives: %d %v", n, err)
	}
	if n, err := DeliverScap(ws, in, "WS-07"); err != nil || n != 1 {
		t.Fatalf("scap: %d %v", n, err)
	}
	id := ws.State.Send.ID
	for _, pat := range []string{"*.bbx", "*.zip", "*.zip.sig", "*.xml.gz", "*.xml.gz.sig"} {
		got, _ := filepath.Glob(filepath.Join(folder, pat))
		if len(got) != 1 {
			t.Fatalf("%s in the 0.23 folder: %v", pat, got)
		}
		n := filepath.Base(got[0])
		switch pat {
		case "*.bbx":
			if gid, seq, ok := v023ParseInboxName(n); !ok || gid != id || seq != 1 {
				t.Errorf("0.23 reads %s as %q %d %v", n, gid, seq, ok)
			}
		case "*.zip":
			if gid := v023ArchiveID(n); gid != id {
				t.Errorf("0.23 reads %s as %q", n, gid)
			}
		case "*.xml.gz":
			if gid, sum := v023ScapName(n); gid != id || len(sum) != 16 {
				t.Errorf("0.23 reads %s as %q %q", n, gid, sum)
			}
		}
	}
	if got, _ := filepath.Glob(filepath.Join(in, "*.*")); len(got) != 1 { // the marker
		t.Errorf("in the inbox itself: %v", got)
	}
	// What a 0.23 collector leaves: the signature of an archive it imported.
	for _, p := range []string{filepath.Join(folder, "archive_"+id+"_old-0123456789ab.zip.sig"), filepath.Join(in, "archive_"+id+"_older-0123456789ab.zip.sig")} {
		os.WriteFile(p, []byte("sig"), 0o640)
		os.Chtimes(p, t0, t0)
	}

	dirs := Dirs{Archives: t.TempDir(), Scap: t.TempDir()}
	res, err := Import(col, in, dirs, t0.Add(time.Minute), t.Logf)
	if err != nil || res.Batches != 1 || res.Archives != 1 || res.Scap != 1 || len(res.Rejected) != 0 || len(res.Held) != 0 {
		t.Fatalf("import at the upgrade: %+v %v", res, err)
	}
	if _, err := os.Stat(folder); err == nil {
		t.Error("the 0.23 folder is still there")
	}
	if k := col.State.SenderKeys["WS-07"]; k == nil || k.FP == "" {
		t.Errorf("not pinned: %+v", k)
	}
	res, _ = Import(col, in, dirs, t0.Add(20*time.Minute), t.Logf)
	if len(res.Rejected) != 0 {
		t.Errorf("left-over signatures refused: %+v", res.Rejected)
	}
	if got, _ := filepath.Glob(filepath.Join(in, "*.sig")); len(got) != 0 {
		t.Errorf("signatures left: %v", got)
	}
	if got, _ := filepath.Glob(filepath.Join(in, rejectedDir, "*")); len(got) != 0 {
		t.Errorf("rejected: %v", got)
	}
}

// import023 imports what waits in a 0.23 sender folder as a 0.23
// collector did: the record is the sender ID's, and the signature (which
// 0.23 does not know) is not looked at.
func import023(t *testing.T, col *store.Store, folder string, now time.Time) {
	t.Helper()
	got, _ := filepath.Glob(filepath.Join(folder, "*.bbx"))
	for _, g := range got {
		f, err := os.Open(g)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Decode(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := importBatch(col, b, "", now); err != nil {
			t.Fatal(err)
		}
		os.Remove(g)
	}
}

// SEC1e: batches waiting in a 0.23 sender folder when the collector is
// upgraded are imported once. The next batch shows no gap, and sending
// them again ("blackbox send --resend") says "already imported", whether
// the folder held one batch or several, and whether the sender's record
// already existed (it delivered through the folder to 0.23 before) or
// not. The key is pinned at that first import (SEC1f).
func TestUpgradeWaitingBatchesNoFalseGap(t *testing.T) {
	for _, c := range []struct {
		name    string
		before  int // batches the 0.23 collector imported from the folder
		waiting int // batches waiting in the folder at the upgrade
	}{
		{"one waiting, record existed", 2, 1},
		{"several waiting, record existed", 1, 3},
		{"several waiting, no record yet", 0, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := inbox(t)
			col, _ := store.Open(t.TempDir())
			folder := legacyFolder(t, col, in, "UBUNTU-SERVER", "ubuntu-server")
			ubu := system(t, "ubuntu-server", "linux", 1, t0)
			ubu.State.Send = &store.SendState{ID: store.NewID(), NextSeq: 1, Folder: "UBUNTU-SERVER"}
			at := t0
			deliver := func() {
				t.Helper()
				at = at.Add(time.Hour)
				collect(t, ubu, "ubuntu-server", "linux", 1, at)
				Export(ubu, "ubuntu-server", "test", at)
				if n, err := Deliver(ubu, in, "ubuntu-server", true); err != nil || n != 1 {
					t.Fatalf("deliver: %d %v", n, err)
				}
			}
			// The sender, upgraded first, delivers into its 0.23 folder;
			// the 0.23 collector imports some, and the rest wait.
			for i := 0; i < c.before; i++ {
				deliver()
				import023(t, col, folder, at)
			}
			for i := 0; i < c.waiting; i++ {
				deliver()
			}
			last := uint64(c.before + c.waiting)

			// The collector's upgrade: setup empties the folders, then its
			// first run imports what was in them.
			if n := MigrateSenderFolders(nil, in, t.Logf); n != c.waiting {
				t.Fatalf("moved %d, want %d", n, c.waiting)
			}
			res, err := Import(col, in, Dirs{}, at.Add(time.Minute), t.Logf)
			if err != nil || res.Batches != c.waiting || len(res.Rejected) != 0 || len(res.Held) != 0 {
				t.Fatalf("import at the upgrade: %+v %v", res, err)
			}
			id := ubu.State.Send.ID
			snd := col.State.Senders[id]
			if snd == nil || snd.LastSeq != last || len(snd.Missing) != 0 || snd.KeyFP == "" {
				t.Fatalf("after the upgrade: %+v", snd)
			}
			if k := col.State.SenderKeys["UBUNTU-SERVER"]; k == nil || k.FP != snd.KeyFP {
				t.Errorf("key not pinned at the upgrade: %+v", k)
			}

			// The next batch, into the inbox itself: no gap.
			deliver()
			res, _ = Import(col, in, Dirs{}, at.Add(time.Minute), t.Logf)
			if res.Batches != 1 || len(res.Rejected) != 0 {
				t.Fatalf("next batch: %+v", res)
			}
			if snd := col.State.Senders[id]; snd.LastSeq != last+1 || len(snd.Missing) != 0 {
				t.Fatalf("false gap after the next batch: %+v", snd.Missing)
			}

			// Sent again: already imported, not imported a second time.
			from := uint64(c.before + 1)
			if sent, _, err := Resend(ubu, in, "ubuntu-server", from, last); err != nil || len(sent) != c.waiting {
				t.Fatalf("resend: %v %v", sent, err)
			}
			res, _ = Import(col, in, Dirs{}, at.Add(2*time.Minute), t.Logf)
			if res.Batches != 0 || res.Already != c.waiting || len(res.Rejected) != 0 {
				t.Errorf("resend imported again: %+v", res)
			}
		})
	}
}
