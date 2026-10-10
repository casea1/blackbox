package lan

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/scap"
	"github.com/casea1/blackbox/internal/store"
)

var t0 = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)

// system is a data folder with some collected data, like one computer.
func system(t *testing.T, host, osName string, n int, at time.Time) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	collect(t, st, host, osName, n, at)
	return st
}

// collect adds n events, a run and a check, as one collection would.
func collect(t *testing.T, st *store.Store, host, osName string, n int, at time.Time) {
	t.Helper()
	var evs []*event.Event
	for i := 0; i < n; i++ {
		evs = append(evs, &event.Event{Time: at.Add(-time.Duration(i) * time.Minute), Collected: at, Host: host, OS: osName,
			Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "logon"})
	}
	if err := st.AppendEvents(at, evs); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendRun(&store.Run{Time: at, Host: host, OS: osName, Version: "test",
		Channels: []store.ChannelRun{{Channel: "Security", Read: n, Kept: n}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendChecks(&store.CheckRecord{Time: at, Host: host, OS: osName,
		Results: []check.Result{{Area: "Audit policy", Item: "Logon", Status: check.Pass}}}); err != nil {
		t.Fatal(err)
	}
}

func inbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := PrepareInbox(dir, "COLLECTOR"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func send(t *testing.T, st *store.Store, host, dir string, at time.Time) int {
	t.Helper()
	if _, err := Export(st, host, "test", at); err != nil {
		t.Fatal(err)
	}
	n, err := Deliver(st, dir, host, false)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBatchRoundTripAndTamperDetection(t *testing.T) {
	b := &Batch{Header: Header{Sender: "WS-01", SenderID: "abc", Seq: 7, Created: t0},
		Events: [][]byte{[]byte(`{"host":"WS-01","summary":"one"}`)}, Runs: [][]byte{[]byte(`{"host":"WS-01"}`)}}
	data, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 7 || got.Sender != "WS-01" || len(got.Events) != 1 || len(got.Runs) != 1 || string(got.Events[0]) != `{"host":"WS-01","summary":"one"}` {
		t.Fatalf("round trip lost data: %+v", got)
	}

	// Cut short: no trailer.
	if _, err := Decode(bytes.NewReader(data[:len(data)/2])); err == nil {
		t.Error("a truncated batch was accepted")
	}
	// Altered contents with the original trailer.
	b.Events[0] = []byte(`{"host":"WS-01","summary":"two"}`)
	altered, _ := b.Bytes()
	if _, err := Decode(bytes.NewReader(spliceTrailer(t, altered, data))); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("altered batch: got %v, want a checksum error", err)
	}
	if _, err := Decode(strings.NewReader("hello")); err == nil {
		t.Error("a non-batch file was accepted")
	}
}

// spliceTrailer puts the original batch's trailer on the altered batch.
func spliceTrailer(t *testing.T, altered, original []byte) []byte {
	t.Helper()
	lines := func(b []byte) []string {
		raw, err := gunzip(b)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	a, o := lines(altered), lines(original)
	a[len(a)-1] = o[len(o)-1]
	return gzipBytes(t, strings.Join(a, "\n")+"\n")
}

func TestSendAndImport(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-01", "windows", 3, t0)
	vm := system(t, "ubuntu-vm", "linux", 2, t0)
	if n := send(t, ws, "WS-01", in, t0); n != 1 {
		t.Fatalf("sent %d batches, want 1", n)
	}
	send(t, vm, "ubuntu-vm", in, t0)
	if Queued(ws) != 0 {
		t.Error("outbox not emptied after delivery")
	}

	col, _ := store.Open(t.TempDir())
	now := t0.Add(30 * time.Minute)
	res, err := Import(col, in, Dirs{}, now, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if res.Batches != 2 || len(res.Rejected) != 0 {
		t.Fatalf("imported %+v", res)
	}
	evs, _ := col.ReadEvents(time.Time{})
	if len(evs) != 5 {
		t.Fatalf("collector has %d events, want 5", len(evs))
	}
	for _, e := range evs {
		if !e.Collected.Equal(now) {
			t.Errorf("received event should count as collected on arrival, got %v", e.Collected)
		}
	}
	runs, _ := col.ReadRuns(time.Time{})
	if len(runs) != 2 || !runs[0].Received.Equal(now) {
		t.Errorf("runs not imported with their arrival time: %+v", runs)
	}
	checks, _ := col.LatestChecks(time.Time{}, now)
	if len(checks) != 2 || checks["UBUNTU-VM"] == nil {
		t.Errorf("audit checks not imported: %v", checks)
	}
	sys := col.State.Systems["UBUNTU-VM"]
	if sys == nil || sys.OS != "linux" || !sys.LastRun.Equal(t0) || !sys.LastReceived.Equal(now) {
		t.Errorf("system registry: %+v", sys)
	}
	left, _ := filepath.Glob(filepath.Join(in, "*.bbx"))
	if len(left) != 0 {
		t.Errorf("imported batches left in the inbox: %v", left)
	}

	// Next hour: only new data travels.
	collect(t, ws, "WS-01", "windows", 1, t0.Add(time.Hour))
	send(t, ws, "WS-01", in, t0.Add(time.Hour))
	res, _ = Import(col, in, Dirs{}, now.Add(time.Hour), t.Logf)
	if res.Records != 3 { // 1 event, 1 run, 1 check
		t.Errorf("second import had %d records, want 3 (nothing re-sent)", res.Records)
	}
}

func TestDuplicateDeliveryAndMissingBatch(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-01", "windows", 1, t0)
	Export(ws, "WS-01", "test", t0) // batch 1
	collect(t, ws, "WS-01", "windows", 1, t0.Add(time.Hour))
	Export(ws, "WS-01", "test", t0.Add(time.Hour)) // batch 2
	collect(t, ws, "WS-01", "windows", 1, t0.Add(2*time.Hour))
	Export(ws, "WS-01", "test", t0.Add(2*time.Hour)) // batch 3
	if _, err := Deliver(ws, in, "WS-01", false); err != nil {
		t.Fatal(err)
	}
	id := ws.State.Send.ID
	one := delivered(t, in, "WS-01", id, 1)
	saved, _ := os.ReadFile(one)
	os.Remove(delivered(t, in, "WS-01", id, 2)) // lost in transit

	col, _ := store.Open(t.TempDir())
	if _, err := Import(col, in, Dirs{}, t0.Add(3*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	s := col.State.Senders[id]
	if s == nil || s.LastSeq != 3 || len(s.Missing) != 1 || s.Missing[0].From != 2 || s.Missing[0].To != 2 {
		t.Fatalf("missing batch not recorded: %+v", s)
	}
	// Batch 1 delivered again (e.g. the sender crashed before removing it).
	os.WriteFile(one, saved, 0o644)
	res, _ := Import(col, in, Dirs{}, t0.Add(4*time.Hour), nil)
	evs, _ := col.ReadEvents(time.Time{})
	if res.Records != 0 || len(evs) != 2 {
		t.Errorf("duplicate batch imported again: %d records, %d events", res.Records, len(evs))
	}
}

func TestDeliverNeedsInboxMarker(t *testing.T) {
	ws := system(t, "WS-01", "windows", 1, t0)
	Export(ws, "WS-01", "test", t0)
	// An unmounted share looks like an empty local folder.
	empty := t.TempDir()
	if _, err := Deliver(ws, empty, "WS-01", false); !errors.Is(err, ErrNoInbox) {
		t.Fatalf("got %v, want ErrNoInbox", err)
	}
	if Queued(ws) != 1 {
		t.Error("batch should stay queued until the inbox is reachable")
	}
	entries, _ := os.ReadDir(empty)
	if len(entries) != 0 {
		t.Error("wrote into a folder that is not an inbox")
	}
}

func TestRejectsBadFiles(t *testing.T) {
	in := inbox(t)
	os.WriteFile(filepath.Join(in, "WS-01_abc_0000000001.bbx"), []byte("not a batch"), 0o644)
	os.WriteFile(filepath.Join(in, "notes.bbx"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(in, ".WS-01_abc_0000000002.bbx.partial"), []byte("x"), 0o644) // still being copied
	col, _ := store.Open(t.TempDir())
	res, err := Import(col, in, Dirs{}, t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 2 {
		t.Errorf("rejected %v, want the two bad files", res.Rejected)
	}
	if _, err := os.Stat(filepath.Join(in, ".WS-01_abc_0000000002.bbx.partial")); err != nil {
		t.Error("a file still being copied must be left alone")
	}
	if _, err := os.Stat(filepath.Join(SetAsideDir(col.Dir), "notes.bbx")); err != nil {
		t.Error("bad file not set aside")
	}
}

func TestInterruptedImportIsUndone(t *testing.T) {
	col, _ := store.Open(t.TempDir())
	col.AppendEvents(t0, []*event.Event{{Time: t0, Host: "A", Summary: "kept"}})
	name := "events-" + t0.Format("2006-01-02") + ".jsonl"
	if err := col.BeginImport([]string{name, "runs-" + t0.Format("2006-01-02") + ".jsonl"}); err != nil {
		t.Fatal(err)
	}
	col.AppendRaw(name, [][]byte{[]byte(`{"host":"B","summary":"half an import"}`)})
	col.AppendRaw("runs-"+t0.Format("2006-01-02")+".jsonl", [][]byte{[]byte(`{"host":"B"}`)})
	// Crash here. Opening to read changes nothing; the next run, which
	// takes the lock, undoes the partial import.
	reader, _ := store.Open(col.Dir)
	if reader.State.Pending == nil {
		t.Fatal("a reader must not undo an import that may still be running")
	}
	again, err := store.Open(col.Dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := again.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	evs, _ := again.ReadEvents(time.Time{})
	if len(evs) != 1 || evs[0].Summary != "kept" {
		t.Errorf("after recovery: %d events", len(evs))
	}
	if _, err := os.Stat(filepath.Join(col.Dir, "spool", "runs-"+t0.Format("2006-01-02")+".jsonl")); !os.IsNotExist(err) {
		t.Error("file created by the interrupted import should be removed")
	}
	if again.State.Pending != nil {
		t.Error("pending import not cleared")
	}
}

func TestExportCrashRewritesSameBatch(t *testing.T) {
	ws := system(t, "WS-01", "windows", 2, t0)
	Export(ws, "WS-01", "test", t0)
	// Simulate a crash after the batch was written but before state was
	// saved: reload the old state.
	ws.State.Send.NextSeq = 1
	ws.State.Send.Offsets = map[string]int64{}
	if _, err := Export(ws, "WS-01", "test", t0); err != nil {
		t.Fatal(err)
	}
	if Queued(ws) != 1 || ws.State.Send.NextSeq != 2 {
		t.Errorf("queued %d, next %d: the batch should be rewritten, not duplicated", Queued(ws), ws.State.Send.NextSeq)
	}
}

func TestLargeHistorySplitsIntoBatches(t *testing.T) {
	ws := system(t, "WS-01", "windows", maxBatchLines+10, t0)
	n, err := Export(ws, "WS-01", "test", t0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("made %d batches, want 2", n)
	}
}

func TestLogArchivesAreDeliveredAndFiled(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-01", "windows", 1, t0)
	send(t, ws, "WS-01", in, t0) // gives the sender its ID

	logFile := filepath.Join(t.TempDir(), "Security.evtx")
	os.WriteFile(logFile, []byte("pretend evtx"), 0o644)
	from, to := t0.Add(-24*time.Hour), t0
	os.MkdirAll(OutboxDir(ws), 0o750)
	if _, err := archive.Write(filepath.Join(OutboxDir(ws), archive.FileName("WS-01", from, to)),
		archive.Info{Host: "WS-01", OS: "windows", From: from, To: to, Created: to},
		[]archive.Source{{Name: "Security.evtx", Source: "Security", Path: logFile}}); err != nil {
		t.Fatal(err)
	}
	if QueuedArchives(ws) != 1 {
		t.Fatal("archive not queued")
	}
	if n, err := DeliverArchives(ws, in); n != 1 || err != nil || QueuedArchives(ws) != 0 {
		t.Fatalf("delivered %d: %v", n, err)
	}

	col, _ := store.Open(t.TempDir())
	archives := filepath.Join(t.TempDir(), "archives")
	res, err := Import(col, in, Dirs{Archives: archives}, t0, t.Logf)
	if err != nil || res.Archives != 1 || len(res.Rejected) != 0 {
		t.Fatalf("import: %+v %v", res, err)
	}
	list, _ := archive.List(archives)
	if len(list) != 1 || list[0].Host != "WS-01" || !list[0].To.Equal(to) {
		t.Fatalf("filed: %+v", list)
	}

	// A damaged archive is set aside, not filed.
	os.WriteFile(filepath.Join(in, "archive_abc_WS-02_x.zip"), []byte("not a zip"), 0o640)
	old := t0.Add(-time.Hour) // not one still being written (DESIGN1)
	os.Chtimes(filepath.Join(in, "archive_abc_WS-02_x.zip"), old, old)
	res, _ = Import(col, in, Dirs{Archives: archives}, t0, nil)
	if res.Archives != 0 || len(res.Rejected) != 1 {
		t.Fatalf("damaged archive: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(SetAsideDir(col.Dir), "archive_abc_WS-02_x.zip")); err != nil {
		t.Error("damaged archive not in rejected")
	}
}

// R8: a batch that arrives after a later one (out of order) is imported,
// and its gap is cleared.
func TestLateBatchFillsTheGap(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-01", "windows", 1, t0)
	Export(ws, "WS-01", "test", t0) // batch 1
	collect(t, ws, "WS-01", "windows", 1, t0.Add(time.Hour))
	Export(ws, "WS-01", "test", t0.Add(time.Hour)) // batch 2
	collect(t, ws, "WS-01", "windows", 1, t0.Add(2*time.Hour))
	Export(ws, "WS-01", "test", t0.Add(2*time.Hour)) // batch 3
	if _, err := Deliver(ws, in, "WS-01", false); err != nil {
		t.Fatal(err)
	}
	id := ws.State.Send.ID
	two := delivered(t, in, "WS-01", id, 2)
	held, _ := os.ReadFile(two)
	os.Remove(two) // delayed

	col, _ := store.Open(t.TempDir())
	Import(col, in, Dirs{}, t0.Add(3*time.Hour), nil)
	if s := col.State.Senders[id]; len(s.Missing) != 1 {
		t.Fatalf("gap not noted: %+v", s)
	}
	os.WriteFile(two, held, 0o644) // arrives late
	res, err := Import(col, in, Dirs{}, t0.Add(4*time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := col.State.Senders[id]
	evs, _ := col.ReadEvents(time.Time{})
	if res.Records == 0 || len(s.Missing) != 0 || s.LastSeq != 3 || len(evs) != 3 {
		t.Errorf("late batch: %d records, missing %v, last %d, %d events", res.Records, s.Missing, s.LastSeq, len(evs))
	}
}

func TestFillGap(t *testing.T) {
	g := fillGap([]store.SeqGap{{From: 2, To: 6}}, 4)
	if len(g) != 2 || g[0].To != 3 || g[1].From != 5 {
		t.Errorf("split: %+v", g)
	}
	if g := fillGap([]store.SeqGap{{From: 2, To: 2}}, 2); len(g) != 0 {
		t.Errorf("filled: %+v", g)
	}
}

// L1: a batch that can't be read is set aside, and the others are still
// imported.
func TestUnreadableBatchDoesNotBlockImport(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-01", "windows", 3, t0)
	send(t, ws, "WS-01", in, t0)
	// A dangling link stands in for a file the collector can't read.
	bad := filepath.Join(in, "AAA_0123456789abcdef_0000000001.bbx")
	if err := os.Symlink(filepath.Join(in, "gone"), bad); err != nil {
		t.Skip("symlinks not available:", err)
	}
	col, _ := store.Open(t.TempDir())
	res, err := Import(col, in, Dirs{}, t0.Add(time.Minute), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if res.Batches != 1 || len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0], "not a regular file") {
		t.Errorf("import: %+v", res)
	}
}

// §6: a sender's SCAP results go to the collector once each, and are filed
// under the computer they are for.
func TestScapResultsTravel(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-07", "windows", 1, t0)
	send(t, ws, "WS-07", in, t0) // gives the sender its ID
	files := []string{"../../testdata/scap/scc/Sessions/2026-09-29_100000/Results/SCAP/XML/WS-07_SCC-5.10_2026-09-29_100000_XCCDF-Results_MS_Windows_11_STIG.xml"}
	if n, err := QueueScap(ws, files, t0); err != nil || n != 1 {
		t.Fatalf("queued %d %v", n, err)
	}
	if n, _ := QueueScap(ws, files, t0); n != 0 {
		t.Error("the same result queued twice")
	}
	if n, err := DeliverScap(ws, in, "WS-07"); err != nil || n != 1 || QueuedScap(ws) != 0 {
		t.Fatalf("delivered %d %v", n, err)
	}
	col, _ := store.Open(t.TempDir())
	scapDir := filepath.Join(t.TempDir(), "scap-received")
	res, err := Import(col, in, Dirs{Scap: scapDir}, t0, t.Logf)
	if err != nil || res.Scap != 1 || len(res.Rejected) != 0 {
		t.Fatalf("import %+v %v", res, err)
	}
	got, _ := filepath.Glob(filepath.Join(scapDir, "WS-07", "scap_*.xml.gz"))
	if len(got) != 1 {
		t.Fatalf("filed: %v", got)
	}
	r, err := scap.ReadFile(got[0])
	if err != nil || r[0].Host != "WS-07" || len(r[0].Open) != 3 {
		t.Errorf("filed result: %+v %v", r, err)
	}
}

// L11: delivered batches are kept, resent on request to fill a gap the
// collector reports, and removed after keep_sent_days.
func TestKeptBatchesResendFillsGap(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-01", "windows", 1, t0)
	for i := 1; i <= 3; i++ {
		if i > 1 {
			collect(t, ws, "WS-01", "windows", 1, t0.Add(time.Duration(i-1)*time.Hour))
		}
		Export(ws, "WS-01", "test", t0.Add(time.Duration(i-1)*time.Hour))
	}
	if n, err := Deliver(ws, in, "WS-01", true); err != nil || n != 3 {
		t.Fatalf("deliver: %d, %v", n, err)
	}
	if q := Queued(ws); q != 0 {
		t.Errorf("kept batches counted as waiting: %d", q)
	}
	if k := Kept(ws); len(k) != 3 || k[0] != 1 || k[2] != 3 {
		t.Fatalf("kept: %v", k)
	}
	if _, ok := OldestQueued(ws); ok {
		t.Error("kept batches counted as waiting to send")
	}
	id := ws.State.Send.ID
	os.Remove(delivered(t, in, "WS-01", id, 2)) // lost on the collector

	col, _ := store.Open(t.TempDir())
	Import(col, in, Dirs{}, t0.Add(3*time.Hour), nil)
	if s := col.State.Senders[id]; len(s.Missing) != 1 {
		t.Fatalf("gap not noted: %+v", s)
	}
	from, to, err := ParseRange("1-4")
	if err != nil {
		t.Fatal(err)
	}
	sent, missing, err := Resend(ws, in, "WS-01", from, to)
	if err != nil || len(sent) != 3 || len(missing) != 1 || missing[0] != 4 {
		t.Fatalf("resend: sent %v, missing %v, %v", sent, missing, err)
	}
	if _, err := Import(col, in, Dirs{}, t0.Add(4*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	s := col.State.Senders[id]
	evs, _ := col.ReadEvents(time.Time{})
	if len(s.Missing) != 0 || len(evs) != 3 {
		t.Errorf("after resend: missing %v, %d events (want 3: batches 1 and 3 not imported twice)", s.Missing, len(evs))
	}

	// Removed after keep_sent_days, counted from delivery.
	if n, _ := PruneSent(ws, 14, time.Now()); n != 0 {
		t.Errorf("pruned %d batches delivered today", n)
	}
	old := time.Now().AddDate(0, 0, -15)
	os.Chtimes(filepath.Join(SentDir(ws), outboxName(1)), old, old)
	if n, _ := PruneSent(ws, 14, time.Now()); n != 1 || len(Kept(ws)) != 2 {
		t.Errorf("prune: removed %d, kept %v", n, Kept(ws))
	}
	if n, _ := PruneSent(ws, 0, time.Now()); n != 2 {
		t.Errorf("keep_sent_days 0 should remove all kept batches, removed %d", n)
	}
}

func TestParseRange(t *testing.T) {
	for in, want := range map[string][2]uint64{"214-219": {214, 219}, "214": {214, 214}, " 7 - 9 ": {7, 9}} {
		if a, b, err := ParseRange(in); err != nil || a != want[0] || b != want[1] {
			t.Errorf("%q: %d-%d %v", in, a, b, err)
		}
	}
	for _, bad := range []string{"", "x", "9-7", "0", "1-", "-3"} {
		if _, _, err := ParseRange(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
