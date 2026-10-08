package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// DUP3a: each log clear is a row of its own, however close together: two
// wevtutil cl Application runs 52 seconds apart are two rows, each with
// its own command, and the detection counts every clear and ends at the
// last one.
func TestLogClearsNotFolded(t *testing.T) {
	at := time.Date(2026, 10, 7, 16, 24, 30, 0, time.UTC)
	cmd := func(d time.Duration) *event.Event {
		line := `wevtutil.exe cl Application`
		e := &event.Event{Time: at.Add(d), Host: "WIN11-TEST", OS: "windows", Category: event.CatPrivileged, Severity: event.SevHigh,
			Action: "audit_tamper_command", User: `WIN11-TEST\claude`, Process: `C:\Windows\System32\wevtutil.exe`, Command: line,
			Summary: `WIN11-TEST\claude ran a command that can clear logs or weaken auditing: ` + line}
		e.AddDetail("Command line", line)
		return e
	}
	clear := func(d time.Duration, rec uint64) *event.Event {
		return &event.Event{Time: at.Add(d + time.Second), Host: "WIN11-TEST", OS: "windows", Source: "System", EventID: 104, RecordID: rec,
			Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_cleared", User: `WIN11-TEST\claude`, Target: "Application",
			Summary: `The Application log was cleared by WIN11-TEST\claude.`}
	}
	opt := Options{Location: time.UTC, WindowStart: at.Add(-time.Hour), WindowEnd: at.Add(4 * time.Hour), Generated: at.Add(4 * time.Hour)}
	check := func(events []*event.Event, clears int, want string) {
		t.Helper()
		r := Build(events, nil, opt)
		var rows []*event.Event
		for _, e := range r.Events {
			if e.Action == "log_cleared" {
				rows = append(rows, e)
				if e.Repeat > 1 || detail(e, "Cleared with") == "" {
					t.Errorf("clear row: repeat %d, details %+v", e.Repeat, e.Details)
				}
			} else {
				t.Errorf("other row: %s", e.Summary)
			}
		}
		if len(rows) != clears {
			t.Errorf("%d clear rows, want %d", len(rows), clears)
		}
		var got []string
		for _, f := range r.Findings {
			got = append(got, f.Title+": "+f.Detail)
		}
		if len(got) != 1 || !strings.Contains(got[0], want) {
			t.Errorf("detections %q, want one with %q", got, want)
		}
	}
	check([]*event.Event{cmd(0), clear(0, 1679), cmd(52 * time.Second), clear(52*time.Second, 1680)},
		2, "2 logs cleared on WIN11-TEST between 2026-10-07 16:24 and 2026-10-07 16:25")
	check([]*event.Event{cmd(0), clear(0, 1679), cmd(52 * time.Second), clear(52*time.Second, 1680), cmd(155 * time.Minute), clear(155*time.Minute, 1702)},
		3, "3 logs cleared on WIN11-TEST between 2026-10-07 16:24 and 2026-10-07 18:59")
}

// DUP3b: two SSH logons of one account are joined only when their
// addresses match or one has none.
func TestSSHPairsSameSource(t *testing.T) {
	at := time.Date(2026, 10, 6, 3, 0, 0, 0, time.UTC)
	mk := func(ip, id string) *event.Event {
		e := &event.Event{Time: at, Host: "SRV-01", OS: "windows", Category: event.CatLogon, Action: "logon", User: `CORP\admin`, SourceIP: ip,
			EventID: 4624, Summary: "admin logged on over SSH"}
		e.AddDetail("Logon type", "SSH (OpenSSH)")
		e.AddDetail("Logon ID", id)
		return e
	}
	for _, c := range []struct {
		a, b string
		rows int
	}{{"10.0.0.5", "10.0.0.5", 1}, {"10.0.0.5", "", 1}, {"", "10.0.0.5", 1}, {"10.0.0.5", "10.0.0.6", 2}} {
		r := Build([]*event.Event{mk(c.a, "0x1"), mk(c.b, "0x2")}, nil, Options{Location: time.UTC})
		if len(r.Events) != c.rows {
			t.Errorf("%q and %q: %d rows, want %d", c.a, c.b, len(r.Events), c.rows)
		}
		if c.rows == 1 && r.Events[0].SourceIP != "10.0.0.5" {
			t.Errorf("%q and %q: address %q lost", c.a, c.b, r.Events[0].SourceIP)
		}
	}
}

// DUP3c: only Windows' own console host started by sshd with its usual
// arguments is left out; a console host with no command line stays.
func TestSSHConsoleHostStrict(t *testing.T) {
	at := time.Date(2026, 10, 6, 3, 0, 0, 0, time.UTC)
	mk := func(proc, cmd, parent string) *event.Event {
		e := &event.Event{Time: at, Host: "WS-01", OS: "windows", Category: event.CatPrivileged, Severity: event.SevLow, Action: "elevated_process",
			User: `WS-01\claude`, Process: proc, Command: cmd, Summary: "claude ran " + proc}
		e.AddDetail("Started by", parent)
		return e
	}
	sshd := `C:\Windows\System32\OpenSSH\sshd.exe`
	for _, c := range []struct {
		proc, cmd, parent string
		rows              int
	}{
		{`C:\Windows\System32\conhost.exe`, `\??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1`, sshd, 0},
		{`C:\Windows\System32\conhost.exe`, `"C:\Windows\System32\conhost.exe" 0xffffffff -ForceV1`, sshd, 0},
		{`C:\Windows\System32\conhost.exe`, ``, sshd, 1},
		{`C:\Windows\System32\conhost.exe`, `conhost.exe 0xffffffff -ForceV1`, sshd, 1},
		{`C:\Windows\System32\conhost.exe`, `\??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1`, `C:\Users\Public\dropper.exe`, 1},
		{`C:\Temp\conhost.exe`, `\??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1`, sshd, 1},
	} {
		r := Build([]*event.Event{mk(c.proc, c.cmd, c.parent)}, nil, Options{Location: time.UTC})
		if len(r.Events) != c.rows {
			t.Errorf("%s %q from %s: %d rows, want %d", c.proc, c.cmd, c.parent, len(r.Events), c.rows)
		}
	}
}

// DUP4: one auditpol /set is one High row, Windows' record of the change
// (4719), with the command under "Changed with". Enable then disable is
// two rows; a command by someone else, or with no change recorded, stays.
func TestAuditpolFolded(t *testing.T) {
	at := time.Date(2026, 10, 7, 17, 0, 0, 0, time.UTC)
	cmd := func(sec int, user, line string) *event.Event {
		e := &event.Event{Time: at.Add(time.Duration(sec) * time.Second), Host: "WIN11-TEST", OS: "windows", EventID: 4688, Category: event.CatPrivileged,
			Severity: event.SevHigh, Action: "audit_tamper_command", User: user, Process: `C:\Windows\System32\auditpol.exe`, Command: line,
			Summary: user + " ran a command that can clear logs or weaken auditing: " + line}
		e.AddDetail("Command line", line)
		return e
	}
	change := func(sec int, what string) *event.Event {
		return &event.Event{Time: at.Add(time.Duration(sec) * time.Second), Host: "WIN11-TEST", OS: "windows", EventID: 4719, Category: event.CatIntegrity,
			Severity: event.SevHigh, Action: "audit_policy_changed", User: `WIN11-TEST\claude`, Target: "Logon",
			Summary: `Audit policy for "Logon" was changed by WIN11-TEST\claude: ` + what + "."}
	}
	opt := Options{Location: time.UTC, WindowStart: at.Add(-time.Hour), WindowEnd: at.Add(time.Hour), Generated: at.Add(time.Hour)}

	r := Build([]*event.Event{cmd(0, `WIN11-TEST\claude`, `auditpol /set /subcategory:"Logon" /success:disable`), change(0, "success removed")}, nil, opt)
	if len(r.Events) != 1 || r.Events[0].Action != "audit_policy_changed" || !strings.Contains(detail(r.Events[0], "Changed with"), `auditpol /set /subcategory:"Logon"`) {
		t.Fatalf("one change: %d rows, first %+v", len(r.Events), r.Events[0])
	}
	if len(r.Findings) != 1 {
		t.Errorf("one change: %d detections", len(r.Findings))
	}

	events := []*event.Event{
		cmd(0, `WIN11-TEST\claude`, `"C:\Windows\system32\auditpol.exe" /set /subcategory:"Logon" /success:disable`), change(1, "success removed"),
		cmd(30, `claude`, `auditpol.exe /set /subcategory:"Logon" /success:enable`), change(30, "success added"),
		cmd(60, `WIN11-TEST\mallory`, `auditpol /set /subcategory:"Logon" /failure:disable`), change(61, "failure removed"), // not mallory's change
		cmd(120, `WIN11-TEST\claude`, `auditpol /clear /y`), // no change recorded
	}
	r = Build(events, nil, opt)
	var changes, cmds int
	for _, e := range r.Events {
		switch e.Action {
		case "audit_policy_changed":
			changes++
		case "audit_tamper_command":
			cmds++
		}
	}
	if changes != 3 || cmds != 2 {
		t.Errorf("%d changes, %d commands; want 3 and 2", changes, cmds)
	}
	if detail(r.Events[0], "Changed with") == "" || detail(r.Events[1], "Changed with") == "" {
		t.Errorf("enable/disable rows: %+v / %+v", r.Events[0].Details, r.Events[1].Details)
	}
}
