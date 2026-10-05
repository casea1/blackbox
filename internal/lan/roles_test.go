package lan

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

func inboxOf(t *testing.T, collector string) string {
	t.Helper()
	dir := t.TempDir()
	if err := PrepareInbox(dir, collector); err != nil {
		t.Fatal(err)
	}
	return dir
}

// L13: a sender moved to another collector says which batch is the first
// there, so the new collector does not count the earlier ones (delivered
// to the old collector) as missing. A batch made for the old collector but
// not delivered yet goes to the new one, marked too.
func TestNewCollectorNoFalseGap(t *testing.T) {
	old, nu := inboxOf(t, "WIN-498EC8UMUEL"), inboxOf(t, "WIN11-COL")
	ubu := system(t, "ubuntu-server", "linux", 2, t0)
	for i := 0; i < 3; i++ {
		if i > 0 {
			collect(t, ubu, "ubuntu-server", "linux", 2, t0.Add(time.Duration(i)*time.Hour))
		}
		if _, err := NoteDestination(ubu, "//WIN-498EC8UMUEL/BlackboxInbox", InboxCollector(old)); err != nil {
			t.Fatal(err)
		}
		send(t, ubu, "ubuntu-server", old, t0.Add(time.Duration(i)*time.Hour))
	}
	// Batch 4 is made while the old collector can't be reached.
	collect(t, ubu, "ubuntu-server", "linux", 2, t0.Add(3*time.Hour))
	Export(ubu, "ubuntu-server", "test", t0.Add(3*time.Hour))

	changed, err := NoteDestination(ubu, "//WIN11-COL/BlackboxInbox", InboxCollector(nu))
	if err != nil || !changed {
		t.Fatalf("destination change not noticed: %v", err)
	}
	if s := ubu.State.Send; s.FirstSeq != 4 || s.Earlier != "WIN-498EC8UMUEL" {
		t.Fatalf("send state: first %d, earlier %q", s.FirstSeq, s.Earlier)
	}
	if _, err := Deliver(ubu, nu, "ubuntu-server", true); err != nil {
		t.Fatal(err)
	}
	collect(t, ubu, "ubuntu-server", "linux", 2, t0.Add(4*time.Hour))
	send(t, ubu, "ubuntu-server", nu, t0.Add(4*time.Hour))

	col, _ := store.Open(t.TempDir())
	if _, err := Import(col, nu, Dirs{}, t0.Add(5*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	snd := col.State.Senders[ubu.State.Send.ID]
	if snd == nil || len(snd.Missing) != 0 || snd.LastSeq != 5 || snd.StartSeq != 4 || snd.Earlier != "WIN-498EC8UMUEL" {
		t.Fatalf("collector: %+v", snd)
	}
	// It says which batches it keeps: 4, kept after delivery (5 was
	// still being made when its header was written).
	if snd.Kept == nil || snd.Kept.From != 4 || snd.Kept.To != 4 {
		t.Errorf("kept: %+v", snd.Kept)
	}

	// The same folder, the same collector: nothing changes.
	if changed, _ := NoteDestination(ubu, `\\win11-col\BlackboxInbox\`, "WIN11-COL"); changed || ubu.State.Send.FirstSeq != 4 {
		t.Error("the same destination counted as a new one")
	}
}

// L14: a computer that was a collector and now sends passes on only its
// own data, not what other computers delivered to it.
func TestFormerCollectorSendsOnlyItsOwn(t *testing.T) {
	ubu := system(t, "ubuntu-server", "linux", 3, t0)
	in := inboxOf(t, "WIN-498EC8UMUEL")
	send(t, ubu, "ubuntu-server", in, t0)
	srv := system(t, "WIN-498EC8UMUEL", "windows", 2, t0)
	if _, err := Import(srv, in, Dirs{}, t0.Add(time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	// Now a sender.
	nu := inboxOf(t, "WIN11-COL")
	send(t, srv, "WIN-498EC8UMUEL", nu, t0.Add(time.Hour))
	entries, _ := os.ReadDir(nu)
	var got []*Batch
	for _, e := range entries {
		if filepath.Ext(e.Name()) == batchExt {
			data, _ := os.ReadFile(filepath.Join(nu, e.Name()))
			b, err := Decode(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, b)
		}
	}
	if len(got) != 1 || len(got[0].Events) != 2 || len(got[0].Runs) != 1 || len(got[0].Checks) != 1 {
		t.Fatalf("batches: %d, first has %d events, %d runs, %d checks", len(got), len(got[0].Events), len(got[0].Runs), len(got[0].Checks))
	}
	for _, l := range append(append(got[0].Events, got[0].Runs...), got[0].Checks...) {
		if bytes.Contains(l, []byte("ubuntu-server")) {
			t.Errorf("relayed another computer's data: %s", l)
		}
	}
}

// L14: "via" is only for a computer seen only through another; once it
// delivers itself, a relay does not make it "via" again. W1b: a sender's
// former names reach the collector.
func TestViaOnlyWhenRelayedOnly(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	st.NoteSystem("ubuntu-server", "linux", "test", "WIN-498EC8UMUEL", t0, t0, t0)
	if s := st.State.Systems["UBUNTU-SERVER"]; s.Via != "WIN-498EC8UMUEL" {
		t.Fatalf("relayed only: via %q", s.Via)
	}
	st.NoteSystem("ubuntu-server", "linux", "test", "ubuntu-server", t0.Add(time.Hour), t0.Add(time.Hour), t0.Add(time.Hour))
	st.NoteSystem("ubuntu-server", "linux", "test", "WIN-498EC8UMUEL", t0.Add(2*time.Hour), t0.Add(2*time.Hour), t0.Add(2*time.Hour))
	if s := st.State.Systems["UBUNTU-SERVER"]; s.Via != "" {
		t.Errorf("delivers directly, but shown via %q", s.Via)
	}

	srv := system(t, "WIN-498EC8UMUEL", "windows", 1, t0)
	srv.State.OwnNames = []string{"WIN-R5L5B9EF403", "WIN-498EC8UMUEL"}
	in := inboxOf(t, "WIN11-COL")
	send(t, srv, "WIN-498EC8UMUEL", in, t0)
	col, _ := store.Open(t.TempDir())
	Import(col, in, Dirs{}, t0.Add(time.Minute), nil)
	sys := col.State.Systems["WIN-498EC8UMUEL"]
	if sys == nil || len(sys.Former) != 1 || sys.Former[0] != "WIN-R5L5B9EF403" {
		t.Errorf("former names: %+v", sys)
	}
}

// L11b: a batch sent again that was already imported is counted as such,
// not as a received batch with no records.
func TestResentDuplicateCounted(t *testing.T) {
	ws := system(t, "WS-01", "windows", 2, t0)
	in := inboxOf(t, "COL")
	Export(ws, "WS-01", "test", t0)
	if _, err := Deliver(ws, in, "WS-01", true); err != nil {
		t.Fatal(err)
	}
	col, _ := store.Open(t.TempDir())
	if res, _ := Import(col, in, Dirs{}, t0, nil); res.Batches != 1 || res.Already != 0 {
		t.Fatalf("first import: %+v", res)
	}
	if sent, _, err := Resend(ws, in, "WS-01", 1, 1); err != nil || len(sent) != 1 {
		t.Fatalf("resend: %v %v", sent, err)
	}
	if res, _ := Import(col, in, Dirs{}, t0.Add(time.Hour), nil); res.Batches != 0 || res.Already != 1 || res.Records != 0 {
		t.Errorf("resent duplicate: %+v", res)
	}
}
