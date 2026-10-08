package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/store"
)

// sendFrom collects one event on a computer and delivers it to in.
func sendFrom(t *testing.T, st *store.Store, host, in string, at time.Time) {
	t.Helper()
	st.AppendEvents(at, []*event.Event{{Time: at, Collected: at, Host: host, Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "logon"}})
	if _, err := lan.Export(st, host, "0.24.0", at); err != nil {
		t.Fatal(err)
	}
	if _, err := lan.Deliver(st, in, host, false); err != nil {
		t.Fatal(err)
	}
}

// DESIGN1: the collector's status names a new sender and its key, a
// key change (with what to run, and exit 4), and unsigned senders to
// upgrade; "blackbox senders" lists them; "senders rekey" takes the new
// key and is recorded with who did it and why (event 102).
func TestSendersStatusAndCommands(t *testing.T) {
	at := time.Date(2026, 10, 8, 14, 2, 0, 0, time.UTC)
	base := t.TempDir()
	in := filepath.Join(base, "inbox")
	lan.PrepareInbox(in, "COL")
	col, _ := store.Open(filepath.Join(base, "col"))
	ws, _ := store.Open(filepath.Join(base, "ws"))
	sendFrom(t, ws, "ubu-ws-01", in, at)
	old := &lan.Batch{Header: lan.Header{Sender: "OLD-PC", SenderID: "o1", Seq: 1, Created: at}, Events: [][]byte{[]byte(`{"host":"OLD-PC","summary":"x"}`)}}
	reviewBatch(t, in, old)
	if res, err := lan.Import(col, in, lan.Dirs{}, at, nil); err != nil || res.Batches != 2 {
		t.Fatalf("import: %+v %v", res, err)
	}
	a := &App{Cfg: &config.Config{DataDir: col.Dir, Inbox: in, ReportEvery: "weekly", ReportAt: config.DefaultReportAt, CollectEvery: time.Hour},
		Now: func() time.Time { return at.Add(time.Hour) }, Loc: time.UTC}
	var recorded []event.SelfChange
	a.RecordSelf = func(dir string, c event.SelfChange, now time.Time) error { recorded = append(recorded, c); return nil }
	wk, _ := lan.LoadKey(ws.Dir)
	var b bytes.Buffer
	a.Status(&b)
	out := b.String()
	for _, want := range []string{"New sender:       ubu-ws-01 (key " + wk.Fingerprint() + ", first seen 2026-10-08 14:02)",
		"Unsigned:         OLD-PC delivers unsigned (Blackbox before 0.24): upgrade these to 0.24"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	// Reinstalled: a new data folder and key.
	re, _ := store.Open(filepath.Join(base, "re"))
	sendFrom(t, re, "ubu-ws-01", in, at.Add(time.Hour))
	if res, _ := lan.Import(col, in, lan.Dirs{}, at.Add(time.Hour), nil); len(res.Held) != 1 {
		t.Fatalf("held: %+v", res)
	}
	rk, _ := lan.LoadKey(re.Dir)
	b.Reset()
	err := a.Status(&b)
	want := "ubu-ws-01 is now signing with a different key (" + rk.Fingerprint() + ", was " + wk.Fingerprint() + "). If that computer was reinstalled: blackbox senders rekey ubu-ws-01"
	var na *NeedsAttention
	if !strings.Contains(b.String(), want) || !errors.As(err, &na) || !strings.Contains(err.Error(), "different key") {
		t.Errorf("key change: %v\n%s", err, b.String())
	}
	b.Reset()
	a.Senders(&b)
	if l := b.String(); !strings.Contains(l, "NEW KEY") || !strings.Contains(l, rk.Fingerprint()) || !strings.Contains(l, "OLD-PC") || !strings.Contains(l, "unsigned") {
		t.Errorf("senders:\n%s", l)
	}
	n, err := a.SenderKey("ubu-ws-01", lan.Rekey, "reinstalled 8 Oct, ticket 4411")
	if err != nil || n != 1 {
		t.Fatalf("rekey: %d %v", n, err)
	}
	if len(recorded) != 1 || recorded[0].Kind != "sender_key" || recorded[0].Setting != "ubu-ws-01" || recorded[0].New != "rekeyed" ||
		recorded[0].Old != "reinstalled 8 Oct, ticket 4411" || recorded[0].Program != "blackbox senders rekey" {
		t.Errorf("recorded: %+v", recorded)
	}
	// What goes to the Application log (event 102) or journal reads back.
	c := recorded[0]
	c.Who = "admin"
	if back, ok := event.ParseSelfChange(c.Message()); !ok || back != c {
		t.Errorf("message %q reads back as %+v", c.Message(), back)
	}
	if e := c.Event(); e.Action != "blackbox_sender_rekeyed" || !strings.Contains(e.Summary, "reinstalled 8 Oct") {
		t.Errorf("row: %+v", e)
	}
	b.Reset()
	a.Status(&b)
	if strings.Contains(b.String(), "different key") {
		t.Errorf("still a key change after rekey:\n%s", b.String())
	}
	if _, err := a.SenderKey("nobody", lan.Approve, ""); err == nil {
		t.Error("approve of an unknown computer")
	}
}

// DESIGN1: a sender's status shows its key's fingerprint, and says so
// when the key file can be read by other accounts.
func TestSenderStatusShowsKey(t *testing.T) {
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	base := t.TempDir()
	in := filepath.Join(base, "inbox")
	lan.PrepareInbox(in, "COL")
	ws, _ := store.Open(filepath.Join(base, "ws"))
	sendFrom(t, ws, "WS-01", in, at)
	a := &App{Cfg: &config.Config{DataDir: ws.Dir, SendTo: in, KeepSentDays: 14, CollectEvery: time.Hour}, Now: func() time.Time { return at }, Loc: time.UTC}
	k, _ := lan.LoadKey(ws.Dir)
	var b bytes.Buffer
	a.Status(&b)
	if !strings.Contains(b.String(), "Signing key:      "+k.Fingerprint()) {
		t.Errorf("status:\n%s", b.String())
	}
	if runtime.GOOS == "windows" {
		return
	}
	os.Chmod(lan.KeyPath(ws.Dir), 0o644)
	b.Reset()
	err := a.Status(&b)
	if !strings.Contains(b.String(), "SIGNING KEY EXPOSED:") || err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Errorf("exposed key: %v\n%s", err, b.String())
	}
}
