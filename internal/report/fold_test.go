package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// UX1: the console host Windows starts for each elevated console program
// is folded into that program's row; one started by a program that is not
// a row (other than sshd) stays a row (DUP3); identical records within a minute
// are one row "×N" with every time kept; failed logons stay one row each.
func TestFoldedRows(t *testing.T) {
	at := time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC)
	elevated := func(sec int, proc, parent string) *event.Event {
		e := &event.Event{Time: at.Add(time.Duration(sec) * time.Second), Host: "W11", OS: "windows", Category: event.CatPrivileged, Severity: event.SevLow,
			Action: "elevated_process", User: `W11\claude`, Process: proc, Summary: `W11\claude ran with administrator rights: ` + proc}
		e.AddDetail("Started by", parent)
		if strings.HasSuffix(proc, "conhost.exe") {
			e.Command = `\??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1`
		}
		return e
	}
	refused := func(sec int) *event.Event {
		return &event.Event{Time: at.Add(time.Duration(sec) * time.Millisecond), Host: "ubu", OS: "linux", Category: event.CatOther, Severity: event.SevLow,
			Action: "file_access_denied", User: "claude", Summary: "claude was refused access to /var/log/journal/x/system.journal (using journalctl)."}
	}
	failed := func(sec int) *event.Event {
		return &event.Event{Time: at.Add(time.Duration(sec) * time.Second), Host: "W11", OS: "windows", Category: event.CatFailedLogon, Severity: event.SevLow,
			Action: "logon_failed", User: "admin", Outcome: "failure", Summary: "Failed logon for admin over the network."}
	}
	cmd := `C:\Windows\System32\cmd.exe`
	con := `C:\Windows\System32\conhost.exe`
	events := []*event.Event{
		elevated(0, cmd, `C:\Windows\explorer.exe`), elevated(0, con, cmd),
		elevated(5, cmd, `C:\Windows\explorer.exe`), elevated(5, con, cmd),
		elevated(9, con, `C:\Tools\other.exe`), // its parent has no row and is not sshd: a row (DUP3)
	}
	for i := 0; i < 7; i++ {
		events = append(events, refused(i))
	}
	events = append(events, refused(90_000)) // 90 s later: a row of its own
	for i := 0; i < 3; i++ {
		events = append(events, failed(i))
	}
	r := Build(events, nil, Options{Location: time.UTC, WindowStart: at.Add(-time.Hour), WindowEnd: at.Add(time.Hour), Generated: at.Add(time.Hour)})

	count := func(f func(e *event.Event) bool) (n int) {
		for _, e := range r.Events {
			if f(e) {
				n++
			}
		}
		return
	}
	if n := count(func(e *event.Event) bool { return strings.HasSuffix(e.Process, "conhost.exe") }); n != 1 {
		t.Errorf("%d console host rows, want the one started by other.exe", n)
	}
	// The two cmd.exe runs are identical too: one row ×2, with both
	// console windows in its details.
	var cmdRow *event.Event
	for _, e := range r.Events {
		if e.Process == cmd {
			if cmdRow != nil {
				t.Fatal("two cmd.exe rows")
			}
			cmdRow = e
		}
	}
	if cmdRow == nil || cmdRow.Repeat != 2 || !strings.Contains(detail(cmdRow, "Also started"), "console window") {
		t.Errorf("cmd.exe row: %+v", cmdRow)
	}
	var refusedRows []*event.Event
	for _, e := range r.Events {
		if e.Action == "file_access_denied" {
			refusedRows = append(refusedRows, e)
		}
	}
	if len(refusedRows) != 2 || refusedRows[0].Repeat != 7 || !strings.HasPrefix(detail(refusedRows[0], "Recorded"), "7 times: 13:00:00.000, 13:00:00.001") {
		t.Errorf("refused rows: %d, first %+v", len(refusedRows), refusedRows[0])
	}
	if n := count(func(e *event.Event) bool { return e.Action == "logon_failed" }); n != 3 {
		t.Errorf("failed logons folded: %d rows", n)
	}
	if r.Folded != 2+1+6 {
		t.Errorf("folded %d", r.Folded)
	}
	// The row shows ×7.
	for _, row := range r.rows {
		if row.Event == refusedRows[0] && strings.Join(row.Flags, ",") != "×7" {
			t.Errorf("flags %v", row.Flags)
		}
	}
}

// UX2: each Audit integrity row has its own kind (the page's Kind counts
// and filter, UI-R1), so "Logging stopped" is only real stops, not
// Blackbox, firewall or clock changes.
func TestIntegrityKinds(t *testing.T) {
	at := time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC)
	ev := func(min int, action string, sev event.Severity) *event.Event {
		return &event.Event{Time: at.Add(time.Duration(min) * time.Minute), Host: "W11", OS: "windows", Category: event.CatIntegrity, Severity: sev,
			Action: action, User: `W11\claude`, Summary: action + " happened."}
	}
	events := []*event.Event{ev(1, "blackbox_upgraded", event.SevMedium), ev(2, "firewall_rule_added", event.SevLow), ev(3, "time_changed", event.SevMedium),
		ev(4, "eventlog_shutdown", event.SevLow), ev(5, "audit_stopped", event.SevHigh), ev(6, "system_start", event.SevInfo)}
	r := Build(events, nil, Options{Location: time.UTC, WindowStart: at.Add(-time.Hour), WindowEnd: at.Add(time.Hour), Generated: at.Add(time.Hour)})
	spec := pageSpecs["integrity"]
	want := map[string]string{"blackbox_upgraded": "Blackbox", "firewall_rule_added": "Firewall", "time_changed": "Clock",
		"eventlog_shutdown": "Logging stopped", "audit_stopped": "Logging stopped", "system_start": "Startup and shutdown"}
	for _, e := range r.Events {
		if got := spec.kindOf(e); got != want[e.Action] {
			t.Errorf("%s: kind %q, want %q", e.Action, got, want[e.Action])
		}
	}
}
