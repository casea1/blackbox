package app

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
)

// SEC1: a cloned sender (one sender ID, two computers) is kept and is a
// High detection in the next report, saying what to run.
func TestClonedSenderIsADetection(t *testing.T) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	in := t.TempDir()
	lan.PrepareInbox(in, "COL")
	st, _ := store.Open(t.TempDir())
	ev := func(h string) [][]byte { return [][]byte{[]byte(`{"host":"` + h + `","summary":"x"}`)} }
	reviewBatch(t, in, &lan.Batch{Header: lan.Header{Sender: "WS-01", SenderID: "same", Seq: 5, Created: at}, Events: ev("WS-01")})
	lan.Import(st, in, lan.Dirs{}, at, nil)
	reviewBatch(t, in, &lan.Batch{Header: lan.Header{Sender: "WS-02", SenderID: "same", Seq: 5, Created: at}, Events: ev("WS-02")})
	lan.Import(st, in, lan.Dirs{}, at.Add(time.Minute), nil)
	evs := lan.ConflictEvents(st, at.Add(-time.Hour), at.Add(time.Hour))
	r := report.Build(evs, nil, report.Options{WindowEnd: at.Add(time.Hour), Location: time.UTC})
	found := false
	for _, f := range r.Findings {
		if f.Severity == event.SevHigh {
			found = true
		}
	}
	if len(evs) != 1 || !strings.Contains(evs[0].Summary, "blackbox send --new-id") || !found {
		t.Errorf("conflicts %d, findings %+v", len(evs), r.Findings)
	}
}

// SEC1d: a computer retired with "blackbox systems remove" is in no
// sender warning: not in its missing batches, "no batch since" or the
// report's warnings,
// and does not make status exit 4. Once it delivers again it is back.
func TestRemovedSystemNotInSenderWarnings(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	st, _ := store.Open(t.TempDir())
	sent := now.Add(-3 * 24 * time.Hour)
	for i, h := range []string{"WS-07", "WS-08"} {
		st.NoteSystem(h, "windows", "0.23.0", "", sent, sent, sent)
		st.State.Senders["id-"+h] = &store.SenderState{Host: h, LastSeq: 10, FirstSeen: sent, LastReceived: sent,
			Missing: []store.SeqGap{{From: uint64(5 + i), To: uint64(6 + i), Noted: sent}}}
	}
	// 0.23's record of sender folders is still read, harmlessly (DESIGN1).
	st.State.InboxFolders = map[string]*store.InboxFolder{"ws-09": {Account: "bb-ws-09", Hosts: []string{"WS-09"}}}
	st.Save()
	a := &App{Cfg: &config.Config{DataDir: st.Dir, Inbox: t.TempDir(), ReportEvery: "weekly", ReportAt: config.DefaultReportAt, CollectEvery: time.Hour},
		Now: func() time.Time { return now }, Loc: time.UTC}
	if err := a.RemoveSystem("WS-07"); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	a.Status(&b)
	out := b.String()
	if strings.Contains(out, "WS-07") || !strings.Contains(out, "WS-08") {
		t.Errorf("status:\n%s", out)
	}
	st, _ = store.Open(st.Dir)
	if w := strings.Join(lanWarnings(st, sent.Add(-time.Hour), now, time.UTC), "\n"); strings.Contains(w, "WS-07") || !strings.Contains(w, "WS-08") {
		t.Errorf("report warnings: %s", w)
	}
	// Only the retired one: status needs no attention for senders.
	delete(st.State.Senders, "id-WS-08")
	delete(st.State.Systems, "WS-08")
	st.Save()
	b.Reset()
	if err := a.Status(&b); err != nil && strings.Contains(err.Error(), "WS-07") {
		t.Errorf("status needs attention for a retired computer: %v", err)
	}
	// It delivers again: back in the warnings.
	back := now.Add(time.Hour)
	st.NoteSystem("WS-07", "windows", "0.23.0", "", back, back, back)
	st.State.Senders["id-WS-07"].LastReceived = back
	if retiredSender(st, st.State.Senders["id-WS-07"]) {
		t.Error("not listed again after it delivered")
	}
}
