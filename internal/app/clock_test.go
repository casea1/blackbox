package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
)

// T3: the clock is 3 hours fast at install, a report is made, then the
// clock is set back. What is collected after that (a log clear, here) must
// be in a report: not skipped because its time is before the previous
// report's end or its collection time before the previous report's.
func TestClockMovedBackBetweenRuns(t *testing.T) {
	base := t.TempDir()
	st, _ := store.Open(filepath.Join(base, "data"))
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportDir: filepath.Join(base, "reports"), ReportEvery: "daily", ReportAt: config.DefaultReportAt},
		Version: "test", Loc: time.UTC}
	ev := func(at time.Time, action, summary string, sev event.Severity) *event.Event {
		return &event.Event{Time: at, Collected: at, Host: "WIN11-TEST", OS: "windows", Category: event.CatIntegrity,
			Severity: sev, Action: action, User: "claude", Summary: summary}
	}

	// The fast clock: 23:00 on 4 Oct, really 20:00.
	fast := time.Date(2026, 10, 4, 23, 0, 0, 0, time.UTC)
	st.AppendEvents(fast.Add(-30*time.Minute), []*event.Event{ev(fast.Add(-30*time.Minute), "logon", "claude logged on.", event.SevInfo)})
	st.State.LastCollect = fast
	a.Now = func() time.Time { return fast.Add(time.Minute) }
	if _, err := a.report(st, fast, true); err != nil {
		t.Fatal(err)
	}

	// The clock is corrected: 20:08. The Security log is cleared and
	// collected.
	back := time.Date(2026, 10, 4, 20, 8, 0, 0, time.UTC)
	a.Now = func() time.Time { return back }
	a.noticeClock(st)
	st.AppendEvents(back, []*event.Event{ev(back, "log_cleared", "The Security log was cleared by claude.", event.SevHigh)})
	st.State.LastCollect = back
	st.Save()

	var out bytes.Buffer
	var na *NeedsAttention
	if err := a.Status(&out); !errors.As(err, &na) || !strings.Contains(out.String(), "CLOCK MOVED BACK") {
		t.Errorf("status after the clock change: %v\n%s", err, out.String())
	}

	// A report run by hand now: a period that makes sense, with the log clear.
	a.Now = func() time.Time { return back.Add(time.Minute) }
	interim, err := a.report(st, back.Add(time.Minute), false)
	if err != nil {
		t.Fatal(err)
	}
	sum := summaryOf(t, interim)
	if sum.WindowStart.After(sum.WindowEnd) || sum.LogClears != 1 || !hasDetection(sum, "The clock was moved back") {
		t.Errorf("interim: %s → %s, %d log clears, detections %+v", sum.WindowStart, sum.WindowEnd, sum.LogClears, sum.Detections)
	}

	// The next scheduled report (midnight, by the correct clock) has the
	// log clear and what came after, but not what the first report showed.
	st.AppendEvents(back.Add(3*time.Hour), []*event.Event{ev(back.Add(3*time.Hour), "audit_policy_changed", "Audit policy was changed by claude.", event.SevHigh)})
	midnight := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	a.Now = func() time.Time { return midnight.Add(5 * time.Minute) }
	dir, err := a.report(st, midnight, true)
	if err != nil {
		t.Fatal(err)
	}
	sum = summaryOf(t, dir)
	if sum.WindowStart.After(sum.WindowEnd) || sum.Events != 2 || sum.LogClears != 1 || !hasDetection(sum, "The clock was moved back") {
		t.Errorf("scheduled: %s → %s, %d events, %d log clears, detections %+v", sum.WindowStart, sum.WindowEnd, sum.Events, sum.LogClears, sum.Detections)
	}
	if len(st.State.ClockBack) != 0 {
		t.Errorf("clock change not cleared once reported: %+v", st.State.ClockBack)
	}

	// And the report after that has neither again.
	a.Now = func() time.Time { return midnight.AddDate(0, 0, 1).Add(5 * time.Minute) }
	dir, err = a.report(st, midnight.AddDate(0, 0, 1), true)
	if err != nil {
		t.Fatal(err)
	}
	if sum = summaryOf(t, dir); sum.Events != 0 || hasDetection(sum, "The clock was moved back") {
		t.Errorf("the day after: %d events, %+v", sum.Events, sum.Detections)
	}
}

// T3: an event recorded while the clock was ahead is in the report made
// once the clock is right, not held back until the clock catches up.
func TestSelectByCollectionFutureEvents(t *testing.T) {
	now := time.Date(2026, 10, 4, 20, 10, 0, 0, time.UTC)
	ahead := &event.Event{Time: now.Add(3 * time.Hour), Unreported: true}
	normal := &event.Event{Time: now.Add(-time.Minute), Unreported: true}
	old := &event.Event{Time: now.Add(-48 * time.Hour)}
	got := SelectByCollection([]*event.Event{ahead, normal, old}, now.Add(-24*time.Hour), now.Add(-24*time.Hour), now, now)
	if len(got) != 2 {
		t.Errorf("selected %d, want the event ahead and the normal one", len(got))
	}
}

func summaryOf(t *testing.T, dir string) report.Summary {
	t.Helper()
	var s report.Summary
	if err := json.Unmarshal([]byte(readFile(t, dir, "summary.json")), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func hasDetection(s report.Summary, title string) bool {
	for _, d := range s.Detections {
		if d.Title == title {
			return true
		}
	}
	return false
}

// T1: after the clock is set back, the next run notices that the last
// collection is in the future, registers the collection task again (so it
// runs by the corrected clock), and status no longer says "just now".
func TestClockBackReschedules(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	fast := time.Date(2026, 10, 4, 23, 0, 0, 0, time.UTC)
	st.State.LastCollect = fast
	st.Save()
	calls := 0
	a := &App{Cfg: &config.Config{DataDir: st.Dir, CollectEvery: time.Hour, ReportEvery: "daily"}, Loc: time.UTC,
		Reschedule: func(every time.Duration) error { calls++; return nil }}

	// A run by the fast clock: nothing to notice.
	a.Now = func() time.Time { return fast.Add(time.Hour) }
	a.noticeClock(st)
	if calls != 0 || len(st.State.ClockBack) != 0 {
		t.Fatalf("noticed a change that wasn't there: %d, %+v", calls, st.State.ClockBack)
	}
	// The clock is set back 3 hours before the next run.
	back := fast.Add(-3 * time.Hour)
	a.Now = func() time.Time { return back }
	var out bytes.Buffer
	a.Status(&out)
	if strings.Contains(out.String(), "just now") || !strings.Contains(out.String(), "in the future: the clock was moved back") {
		t.Errorf("status:\n%s", out.String())
	}
	a.noticeClock(st)
	if calls != 1 || len(st.State.ClockBack) != 1 || !st.State.ClockBack[0].Was.Equal(fast) {
		t.Errorf("after the change: %d calls, %+v", calls, st.State.ClockBack)
	}
}
