package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// LC1: a cleared log is named. A System 104 for the PowerShell log reads
// "PowerShell log cleared" everywhere, not "Security log cleared"; a 1102
// still reads "Security log cleared".
func TestClearedLogNamed(t *testing.T) {
	end := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	clear := func(host, target string, at time.Time) *event.Event {
		return &event.Event{Time: at, Host: host, Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_cleared", User: `LAB\claude`, Target: target,
			Summary: "The " + target + " log was cleared by LAB\\claude."}
	}
	events := []*event.Event{
		clear("WIN-498EC8UMUEL", "Microsoft-Windows-PowerShell/Operational", end.Add(-5*time.Hour)),
		clear("WS-07", "Security", end.Add(-2*time.Hour)),
	}
	runs := []*store.Run{{Time: end.Add(-time.Hour), Host: "WIN-498EC8UMUEL"}, {Time: end.Add(-time.Hour), Host: "WS-07"}}
	r := Build(events, runs, Options{Location: time.UTC, WindowStart: end.Add(-24 * time.Hour), WindowEnd: end, Generated: end})
	o := r.overview(nil)
	if !strings.Contains(o.AlertDetail, "WIN-498EC8UMUEL: PowerShell log cleared") || !strings.Contains(o.AlertDetail, "WS-07: Security log cleared") {
		t.Errorf("alert: %s", o.AlertDetail)
	}
	for _, c := range o.Checks {
		if c.Title == "Logs cleared" && c.What != "Security and PowerShell logs cleared" {
			t.Errorf("checklist: %+v", c)
		}
	}
	var html bytes.Buffer
	if err := r.WriteHTML(&html, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), "PowerShell log cleared at 07:00 on 7 Oct by LAB\\claude") {
		t.Error("Systems page does not name the PowerShell log")
	}
	if !strings.Contains(html.String(), "PowerShell log cleared on 7 Oct 07:00 by LAB\\claude") {
		t.Error("Audit health does not name the PowerShell log")
	}
	if strings.Contains(html.String(), "WIN-498EC8UMUEL: Security log cleared") {
		t.Error("the PowerShell clear still reads as a Security clear")
	}
}

// TIME1: a person moving the clock more than 5 minutes is a detection
// (forward Medium, back High); the time service's corrections are not.
func TestClockMovedDetection(t *testing.T) {
	end := time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)
	moved := func(user string, by time.Duration) *event.Event {
		prev := end.Add(-time.Hour)
		return &event.Event{Time: prev, Host: "WS-07", Category: event.CatIntegrity, Severity: event.SevMedium, Action: "time_changed", User: user,
			Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Summary: "System time was changed.",
			Fields: map[string]string{"PreviousTime": prev.Format(time.RFC3339Nano), "NewTime": prev.Add(by).Format(time.RFC3339Nano)}}
	}
	events := []*event.Event{moved(`WS-07\claude`, 30*time.Minute), moved(`WS-07\claude`, 2*time.Minute), moved("LOCAL SERVICE", 20*time.Minute)}
	r := Build(events, nil, Options{Location: time.UTC, WindowStart: end.Add(-24 * time.Hour), WindowEnd: end, Generated: end})
	var got []string
	for _, f := range r.Findings {
		if strings.Contains(f.Title, "clock") {
			got = append(got, string(f.Severity)+" "+f.Title+": "+f.Detail)
		}
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "medium The clock was moved forward by a person: WS-07\\claude moved the clock on WS-07 forward by 30 minutes") ||
		!strings.Contains(got[0], "(using powershell.exe)") {
		t.Errorf("findings: %q", got)
	}
}
