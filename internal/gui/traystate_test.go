package gui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/app"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/rollover"
	"github.com/casea1/blackbox/internal/store"
)

var trayNow = time.Date(2026, 10, 2, 14, 30, 0, 0, time.Local)

func healthy() app.Health {
	return app.Health{Role: "collector", ReportEvery: "weekly", Every: time.Hour, LastCollect: trayNow.Add(-25 * time.Minute),
		LastRun: app.LastRun{Time: trayNow.Add(-25 * time.Minute)}, NextReport: time.Date(2026, 10, 7, 0, 0, 0, 0, time.Local),
		ReportsDir: `C:\Reports`, AuditGaps: map[string]int{}, Quiet: map[string]time.Time{}}
}

func TestClassify(t *testing.T) {
	v := classify(healthy(), nil, trayNow)
	if v.State != stateOK || !strings.HasPrefix(v.Status, "Collecting every hour · last 14:05 · next report") || len(v.Items) != 0 {
		t.Errorf("healthy: %+v", v)
	}

	h := healthy()
	h.AuditGaps["WS-13"] = 2
	h.AVOld = []string{"WS-05"}
	h.Quiet["WS-09"] = trayNow.Add(-72 * time.Hour)
	v = classify(h, nil, trayNow)
	if v.State != stateLook || len(v.Items) != 3 || v.Items[0] != "Audit settings: 2 settings to fix on WS-13" ||
		!strings.HasPrefix(v.Items[2], "WS-09 has not sent since") {
		t.Errorf("things to look at: %+v", v)
	}

	h = healthy()
	h.LastCollect = trayNow.Add(-2*time.Hour - 16*time.Minute) // past twice the interval plus 15 minutes
	if v = classify(h, nil, trayNow); v.State != stateStopped || !strings.Contains(v.Status, "Collection has stopped") {
		t.Errorf("stopped: %+v", v)
	}
	h.LastCollect = trayNow.Add(-2 * time.Hour) // not yet
	if v = classify(h, nil, trayNow); v.State != stateOK {
		t.Errorf("not overdue yet: %+v", v)
	}

	h = healthy()
	h.LastRun = app.LastRun{Time: trayNow.Add(-5 * time.Minute), Error: "disk full"}
	if v = classify(h, nil, trayNow); v.State != stateStopped || !strings.Contains(v.Status, "disk full") {
		t.Errorf("failed run: %+v", v)
	}

	if v = classify(app.Health{}, errors.New("access is denied"), trayNow); v.State != stateUnknown {
		t.Errorf("unreadable: %+v", v)
	}
}

func TestNotices(t *testing.T) {
	h := healthy()
	h.Latest = &report.IndexEntry{Dir: `C:\Reports\week-39`, Summary: report.Summary{WindowStart: trayNow.AddDate(0, 0, -7), WindowEnd: trayNow}}
	h.AuditGaps["WS-13"] = 1

	// The first look notifies nothing, only remembers.
	n, m := notices(trayMemory{}, h, classify(h, nil, trayNow), "1.0", trayNow)
	if len(n) != 0 || m.Report != `C:\Reports\week-39` || !m.Gaps["WS-13"] {
		t.Fatalf("first look: %v %+v", n, m)
	}
	// Nothing new: nothing notified.
	if n, _ = notices(m, h, classify(h, nil, trayNow), "1.0", trayNow); len(n) != 0 {
		t.Errorf("repeat: %v", n)
	}

	// A new scheduled report, a new gap, an update and a stop: one each.
	h2 := healthy()
	h2.Latest = &report.IndexEntry{Dir: `C:\Reports\week-40`, Summary: report.Summary{WindowStart: trayNow.AddDate(0, 0, -7), WindowEnd: trayNow,
		Detections: []report.Detection{{Severity: "high"}, {Severity: "medium"}}}}
	h2.AuditGaps["WS-13"] = 1
	h2.AuditGaps["WS-02"] = 3
	h2.LastCollect = trayNow.Add(-5 * time.Hour)
	n, m2 := notices(m, h2, classify(h2, nil, trayNow), "1.1", trayNow)
	var texts []string
	for _, x := range n {
		texts = append(texts, x.Text)
	}
	all := strings.Join(texts, "\n")
	for _, want := range []string{"Blackbox updated to 1.1.", "Weekly report ready: 2 detections, 1 high.",
		"Collection has stopped", "Audit settings on WS-02 no longer match the STIG: 3 settings to fix."} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "WS-13") || len(n) != 4 {
		t.Errorf("WS-13 was already notified; got %d notices:\n%s", len(n), all)
	}
	// Once notified, the outage is not repeated.
	if n, _ = notices(m2, h2, classify(h2, nil, trayNow), "1.1", trayNow); len(n) != 0 {
		t.Errorf("outage repeated: %v", n)
	}
	// An interim report is not announced.
	h3 := h2
	h3.Latest = &report.IndexEntry{Dir: `C:\Reports\interim`, Summary: report.Summary{Interim: true}}
	h3.LastCollect = trayNow
	if n, _ = notices(m2, h3, classify(h3, nil, trayNow), "1.1", trayNow); len(n) != 0 {
		t.Errorf("interim announced: %v", n)
	}
}

// The icon is the logo whatever the state: no coloured dot (owner, 7 Oct
// 2026).
func TestTrayImage(t *testing.T) {
	plain := trayImage(32, stateOK)
	for _, s := range []trayState{stateLook, stateStopped, stateUnknown} {
		if img := trayImage(32, s); string(img.Pix) != string(plain.Pix) {
			t.Errorf("state %d draws a different icon", s)
		}
	}
}

// "Collect now" is watched until the run ends: success is notified with
// its time; a failure is left to the "last run failed" notification.
func TestCollectDone(t *testing.T) {
	started := trayNow
	h := healthy()
	h.LastRun = app.LastRun{Time: started.Add(-15 * time.Minute)}
	if _, done, _ := collectDone(h, started); done {
		t.Error("an earlier run counted as the one started")
	}
	h.LastRun = app.LastRun{Time: started.Add(40 * time.Second)}
	h.LastCollect = started.Add(time.Second)
	n, done, tell := collectDone(h, started)
	if !done || !tell || n.Text != "Collection finished ("+clock(h.LastCollect)+")." {
		t.Errorf("finished: %+v %v %v", n, done, tell)
	}
	h.LastRun.Error = "could not read the Security log"
	if _, done, tell := collectDone(h, started); !done || tell {
		t.Errorf("failed: done %v, notify %v", done, tell)
	}
}

// C1: events lost to rollover are something to look at (amber), named by
// log, and notified once per report period.
func TestLostEvents(t *testing.T) {
	h := healthy()
	h.PeriodStart = trayNow.AddDate(0, 0, -2)
	h.Lost = []app.LostLog{{Loss: rollover.Loss{Host: "DSK1", Channel: "Security", Every: time.Hour}, Count: 17925, Since: trayNow.Add(-3 * time.Hour)}}
	v := classify(h, nil, trayNow)
	if v.State != stateLook || len(v.Items) != 1 || !strings.HasPrefix(v.Items[0], "Security log on DSK1: 17,925 events overwritten since") {
		t.Errorf("lost events: %+v", v)
	}
	_, m := notices(trayMemory{}, healthy(), classify(healthy(), nil, trayNow), "1.0", trayNow)
	n, m := notices(m, h, v, "1.0", trayNow)
	if len(n) != 1 || !strings.Contains(n[0].Text, "overwrote 17,925 events") || !strings.Contains(n[0].Text, "15 minutes") {
		t.Fatalf("notice: %+v", n)
	}
	if n, _ = notices(m, h, v, "1.0", trayNow); len(n) != 0 {
		t.Errorf("notified twice in one period: %+v", n)
	}
}

// S9: notifications found together are shown one after another, not
// replaced by the last; S8: an update is among them.
func TestNoticeQueue(t *testing.T) {
	h := healthy()
	h.AuditGaps["WS-02"] = 1
	h.Lost = []app.LostLog{{Loss: rollover.Loss{Host: "DSK1", Channel: "Security"}, Count: 5}}
	n, _ := notices(trayMemory{Seen: true, Version: "0.9.3"}, h, classify(h, nil, trayNow), "0.10.1", trayNow)
	if len(n) != 3 || n[0].Text != "Blackbox updated to 0.10.1." {
		t.Fatalf("notices: %+v", n)
	}
	var q noticeQueue
	var shown []string
	for _, x := range n {
		if q.add(x) {
			shown = append(shown, x.Text)
		}
	}
	for {
		x, ok := q.next()
		if !ok {
			break
		}
		shown = append(shown, x.Text)
	}
	if len(shown) != 3 || shown[0] != n[0].Text || shown[2] != n[2].Text {
		t.Errorf("shown %v", shown)
	}
	if !q.add(n[0]) {
		t.Error("an empty queue should show straight away")
	}
}

// Wording: the next report is a weekday and time, even a week ahead.
func TestNextReportWording(t *testing.T) {
	h := healthy()
	h.NextReport = trayNow.Add(7 * 24 * time.Hour).Truncate(time.Hour)
	v := classify(h, nil, trayNow)
	want := " · next report " + h.NextReport.Local().Format("Mon 15:04")
	if !strings.HasSuffix(v.Status, want) {
		t.Errorf("status %q, want it to end %q", v.Status, want)
	}
}

// L3: auditing off is red, with its own line and notification.
func TestAuditOffIsRed(t *testing.T) {
	h := healthy()
	h.AuditOff = map[string]string{"ubu7": "the audit service (auditd) is not running"}
	v := classify(h, nil, trayNow)
	if v.State != stateStopped || v.Down || len(v.Items) != 1 || v.Items[0] != "Auditing is off on ubu7" {
		t.Errorf("view: %+v", v)
	}
	ns, m := notices(trayMemory{Seen: true}, h, v, "0.10.2", trayNow)
	if len(ns) != 1 || !strings.Contains(ns[0].Text, "Auditing is off on ubu7") || m.Off["ubu7"] == "" {
		t.Errorf("notices: %+v", ns)
	}
	if ns, _ = notices(m, h, v, "0.10.2", trayNow); len(ns) != 0 {
		t.Errorf("notified twice: %+v", ns)
	}
}

// LOCK1: collection blocked by a run holding the lock is red, says so,
// and is notified once.
func TestBlockedIsRed(t *testing.T) {
	h := healthy()
	h.Blocked = &store.Blocked{Holder: store.Holder{PID: 31025, Since: trayNow.Add(-31 * time.Minute)}, First: trayNow.Add(-20 * time.Minute), Refused: 2}
	v := classify(h, nil, trayNow)
	if v.State != stateStopped || !v.Down || !strings.Contains(v.Status, "Collection is blocked: a run has held the lock since") || !strings.Contains(v.Status, "PID 31025") {
		t.Errorf("view: %+v", v)
	}
	ns, m := notices(trayMemory{Seen: true}, h, v, "0.18.0", trayNow)
	if len(ns) != 1 || !strings.Contains(ns[0].Text, "blocked") {
		t.Errorf("notices: %+v", ns)
	}
	if ns, _ = notices(m, h, v, "0.18.0", trayNow); len(ns) != 0 {
		t.Errorf("notified twice: %+v", ns)
	}
}

// A scheduled report deleted or changed is notified once.
func TestMissingReportNotice(t *testing.T) {
	h := healthy()
	h.MissingReports = []report.MissingReport{{Name: "2026-09-30_CI", From: trayNow.AddDate(0, 0, -14), To: trayNow.AddDate(0, 0, -7), Problem: "missing"}}
	v := classify(h, nil, trayNow)
	ns, m := notices(trayMemory{Seen: true}, h, v, "0.19.0", trayNow)
	if len(ns) != 1 || !strings.Contains(ns[0].Text, "is missing from the reports folder") || !ns[0].Warn {
		t.Fatalf("notices: %+v", ns)
	}
	if ns, _ = notices(m, h, v, "0.19.0", trayNow); len(ns) != 0 {
		t.Errorf("notified twice: %+v", ns)
	}
}
