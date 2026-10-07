package app

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
)

// AR3 and L14: a collector that becomes a sender first makes a final
// report of what it had (its own events and those other computers sent,
// with every original log it held), then sends only its own new data.
func TestCollectorBecomesSender(t *testing.T) {
	base := t.TempDir()
	at := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	me := collect.LocalHost()
	logon := func(host string, when time.Time) *event.Event {
		return &event.Event{Time: when, Collected: when, Host: host, OS: "linux", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", User: "claude", Summary: "claude logged on."}
	}

	// Ubuntu sends to this computer while it is a collector.
	oldInbox := filepath.Join(base, "old-inbox")
	lan.PrepareInbox(oldInbox, me)
	ubu, _ := store.Open(filepath.Join(base, "ubu"))
	ubu.AppendEvents(at, []*event.Event{logon("ubuntu-server", at)})
	ubu.AppendRun(&store.Run{Time: at, Host: "ubuntu-server", OS: "linux", Version: "test"})
	lan.Export(ubu, "ubuntu-server", "test", at)
	lan.Deliver(ubu, oldInbox, "ubuntu-server", false)

	col, _ := store.Open(filepath.Join(base, "col"))
	col.AppendEvents(at, []*event.Event{logon(me, at)})
	col.AppendRun(&store.Run{Time: at, Host: me, OS: "linux", Version: "test"})
	col.NoteSystem(me, "linux", "test", "", at, time.Time{}, at)
	if _, err := lan.Import(col, oldInbox, lan.Dirs{}, at.Add(time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	col.State.LastGenerated = at.Add(-24 * time.Hour) // it made reports
	col.State.LastWindowEnd = at.Add(-24 * time.Hour)
	col.State.ArchivedUntil = at.Add(time.Hour)
	col.Save()
	a := &App{Cfg: &config.Config{DataDir: col.Dir, ReportDir: filepath.Join(base, "reports"), ReportEvery: "daily", Inbox: oldInbox},
		Version: "test", Loc: time.UTC, Now: func() time.Time { return at.Add(time.Hour) }}
	pendingLogs(t, a, "ubuntu-server", at)
	pendingLogs(t, a, me, at)

	// Now a sender.
	newInbox := filepath.Join(base, "new-inbox")
	lan.PrepareInbox(newInbox, "WIN11-COL")
	a.Cfg.Inbox, a.Cfg.SendTo = "", newInbox
	r := a.send(col)
	if r.Err != nil || r.FinalReport == "" || !strings.HasSuffix(r.FinalReport, "_final") {
		t.Fatalf("final report %q, err %v", r.FinalReport, r.Err)
	}
	for _, f := range []string{"logs-ubuntu-server.zip", "logs-" + archive.SafeName(me) + ".zip"} {
		if _, err := os.Stat(filepath.Join(r.FinalReport, f)); err != nil {
			t.Errorf("final report has no %s", f)
		}
	}
	if html := readFile(t, r.FinalReport, "report.html"); !strings.Contains(html, "ubuntu-server") {
		t.Error("the final report does not have what Ubuntu sent")
	}
	if left, _ := archive.List(a.pendingLogsDir()); len(left) != 0 {
		t.Errorf("archives left pending: %+v", left)
	}
	if r.Made != 0 || r.Delivered != 0 {
		t.Errorf("sent what the final report already has: made %d, delivered %d", r.Made, r.Delivered)
	}

	// What it collects from now on goes to the new collector, and only that.
	col.AppendEvents(at.Add(2*time.Hour), []*event.Event{logon(me, at.Add(2*time.Hour))})
	a.Now = func() time.Time { return at.Add(2 * time.Hour) }
	r = a.send(col)
	if r.Err != nil || r.FinalReport != "" || r.Delivered != 1 {
		t.Fatalf("second send: %+v", r)
	}
	newCol, _ := store.Open(filepath.Join(base, "newcol"))
	if _, err := lan.Import(newCol, newInbox, lan.Dirs{}, at.Add(3*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	evs, _ := newCol.ReadEvents(time.Time{})
	if len(evs) != 1 || evs[0].Host != me {
		t.Errorf("the new collector got %d events: %+v", len(evs), evs)
	}
	if newCol.State.Systems["UBUNTU-SERVER"] != nil {
		t.Error("the new collector lists Ubuntu via this computer")
	}
}

// A sender upgraded from a version without the handover keeps sending
// what it has not sent; only archives left from its time as a collector
// go into a final report (AR3).
func TestUpgradedSenderKeepsSending(t *testing.T) {
	base := t.TempDir()
	at := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	st, _ := store.Open(filepath.Join(base, "data"))
	st.State.Send = &store.SendState{ID: "abc", NextSeq: 5}
	st.State.LastGenerated = at.Add(-48 * time.Hour) // long ago, a standalone computer
	st.AppendEvents(at, []*event.Event{{Time: at, Collected: at, Host: collect.LocalHost(), Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "logon"}})
	inbox := filepath.Join(base, "inbox")
	lan.PrepareInbox(inbox, "COL")
	a := &App{Cfg: &config.Config{DataDir: st.Dir, SendTo: inbox}, Version: "test", Loc: time.UTC, Now: func() time.Time { return at }}
	r := a.send(st)
	if r.FinalReport != "" || r.Delivered != 1 || st.State.Send.Since.IsZero() {
		t.Errorf("upgraded sender: %+v, since %v", r, st.State.Send.Since)
	}
}

// L13: the collector suggests "send --resend" only for batches the sender
// says it still keeps.
func TestResendAdviceKeptOnly(t *testing.T) {
	g := store.SeqGap{From: 1, To: 280}
	cases := []struct {
		kept *store.SeqRange
		want string
	}{
		{nil, "run on ubuntu-server: blackbox send --resend 1-280 (it keeps delivered batches"},
		{&store.SeqRange{}, "ubuntu-server no longer keeps them, so they cannot be sent again."},
		{&store.SeqRange{From: 250, To: 300}, "run on ubuntu-server: blackbox send --resend 250-280 (it no longer keeps the others)."},
		{&store.SeqRange{From: 281, To: 300}, "no longer keeps them"},
	}
	for _, c := range cases {
		got := ResendAdvice(&store.SenderState{Host: "ubuntu-server", Kept: c.kept}, g)
		if !strings.Contains(got, c.want) {
			t.Errorf("kept %+v: %q", c.kept, got)
		}
	}
}

// W1b: a computer's events under a name it says it had before are filed
// under it, even with several computers of its OS here, and the old name
// is not a separate system.
func TestFormerNamesFolded(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	at := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	st.NoteSystem("WIN11-COL", "windows", "test", "", at, time.Time{}, at)
	st.NoteSystem("WIN-498EC8UMUEL", "windows", "test", "WIN-498EC8UMUEL", at, at, at)
	st.NoteSystem("WIN-R5L5B9EF403", "windows", "test", "WIN-498EC8UMUEL", at, at, at)
	st.State.Systems["WIN-498EC8UMUEL"].Former = []string{"WIN-R5L5B9EF403"}
	systems := systemsFor(st, time.Time{}, true)
	if len(systems) != 2 {
		t.Fatalf("systems: %+v", systems)
	}
	ev := &event.Event{Time: at, Host: "WIN-R5L5B9EF403", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "logon"}
	r := report.Build([]*event.Event{ev}, nil, report.Options{WindowEnd: at.Add(time.Hour), Location: time.UTC, Systems: systems})
	if strings.Join(r.Hosts, ",") != "WIN-498EC8UMUEL,WIN11-COL" || ev.Host != "WIN-498EC8UMUEL" {
		t.Errorf("hosts: %v; event under %s", r.Hosts, ev.Host)
	}
}

// ROLE1: a former collector, now standalone, leaves out of its report the
// sender it heard nothing from this period; a collector still lists it
// (as not reporting).
func TestStandaloneLeavesOutFormerSenders(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	start := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	st.NoteSystem(collect.LocalHost(), "windows", "0.19.0", "", start.Add(time.Hour), time.Time{}, start.Add(time.Hour))
	st.NoteSystem("ubuntu-server", "linux", "0.18.0", "", start.Add(-48*time.Hour), start.Add(-47*time.Hour), start.Add(-47*time.Hour))
	st.NoteSystem("ws-recent", "windows", "0.19.0", "", start.Add(2*time.Hour), start.Add(3*time.Hour), start.Add(3*time.Hour))
	names := func(collector bool) string {
		var n []string
		for _, s := range systemsFor(st, start, collector) {
			n = append(n, strings.ToLower(s.Name))
		}
		sort.Strings(n)
		return strings.Join(n, ",")
	}
	local := strings.ToLower(collect.LocalHost())
	if got := names(false); strings.Contains(got, "ubuntu-server") || !strings.Contains(got, local) || !strings.Contains(got, "ws-recent") {
		t.Errorf("standalone: %s", got)
	}
	if got := names(true); !strings.Contains(got, "ubuntu-server") {
		t.Errorf("collector: %s", got)
	}
}
