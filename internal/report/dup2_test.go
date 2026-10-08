package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// DUP2: one wevtutil cl is one High detection, the clear, with the
// command line in its details. A command clearing another log, or by
// someone else, stays its own row.
func TestClearCommandFolded(t *testing.T) {
	at := time.Date(2026, 10, 7, 16, 24, 0, 0, time.UTC)
	cmd := func(sec int, user, line string) *event.Event {
		e := &event.Event{Time: at.Add(time.Duration(sec) * time.Second), Host: "W11", OS: "windows", Category: event.CatPrivileged, Severity: event.SevHigh,
			Action: "audit_tamper_command", User: user, Process: `C:\Windows\System32\wevtutil.exe`,
			Summary: user + " ran a command that can clear logs or weaken auditing: " + line}
		e.AddDetail("Program", `C:\Windows\System32\wevtutil.exe`)
		e.AddDetail("Command line", line)
		return e
	}
	clear := func(sec int, log string) *event.Event {
		return &event.Event{Time: at.Add(time.Duration(sec) * time.Second), Host: "W11", OS: "windows", Category: event.CatIntegrity, Severity: event.SevHigh,
			Action: "log_cleared", User: "claude", Target: log, Summary: "claude cleared the " + log + " log."}
	}
	events := []*event.Event{
		cmd(0, `W11\claude`, `"C:\Windows\system32\wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational`),
		clear(1, "Microsoft-Windows-PowerShell/Operational"),
		cmd(30, `W11\claude`, `wevtutil.exe cl Security`),
		clear(31, ""), // 1102: the Security log
		cmd(40, `W11\claude`, `wevtutil.exe cl Application`), // no clear of it recorded
		cmd(50, `W11\mallory`, `wevtutil.exe cl System`),
		clear(51, "System"), // by claude, not mallory
	}
	r := Build(events, nil, Options{Location: time.UTC, WindowStart: at.Add(-time.Hour), WindowEnd: at.Add(time.Hour), Generated: at.Add(time.Hour)})
	var clears, cmds []*event.Event
	for _, e := range r.Events {
		switch e.Action {
		case "log_cleared":
			clears = append(clears, e)
		case "audit_tamper_command":
			cmds = append(cmds, e)
		}
	}
	if len(clears) != 3 || len(cmds) != 2 {
		t.Fatalf("%d clears, %d commands; want 3 and 2", len(clears), len(cmds))
	}
	if !strings.Contains(detail(clears[0], "Cleared with"), "cl Microsoft-Windows-PowerShell/Operational") || !strings.Contains(detail(clears[1], "Cleared with"), "cl Security") {
		t.Errorf("command lines not kept: %+v / %+v", clears[0].Details, clears[1].Details)
	}
	if detail(clears[2], "Cleared with") != "" {
		t.Errorf("someone else's command folded: %+v", clears[2].Details)
	}
	// The live case: one wevtutil cl is one High detection.
	r = Build(events[:2], nil, Options{Location: time.UTC, WindowStart: at.Add(-time.Hour), WindowEnd: at.Add(time.Hour), Generated: at.Add(time.Hour)})
	if len(r.Findings) != 1 || r.Findings[0].Severity != event.SevHigh || !strings.HasPrefix(r.Findings[0].Title, "Log cleared") {
		t.Errorf("detections: %+v", r.Findings)
	}
}
