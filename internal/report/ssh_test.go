package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// UX8: the 4624 for an OpenSSH sign-in gets sshd's source address; sshd's
// own row is dropped once joined.
func TestSSHLogonAddress(t *testing.T) {
	at := time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC)
	logon := &event.Event{Time: at, Host: "WIN11-TEST", OS: "windows", Category: event.CatLogon, Action: "logon", EventID: 4624, User: `WIN11-TEST\claude`,
		Outcome: "success", Interactive: true, Summary: `WIN11-TEST\claude logged on via SSH (OpenSSH) with administrator rights.`}
	logon.AddDetail("Logon type", "SSH (OpenSSH)")
	accepted := &event.Event{Time: at.Add(-time.Second), Host: "WIN11-TEST", OS: "windows", Category: event.CatLogon, Action: "ssh_accepted",
		User: `WIN11-TEST\claude`, SourceIP: "10.1.1.20", Summary: `WIN11-TEST\claude signed in over SSH from 10.1.1.20 (publickey).`}
	accepted.AddDetail("Method", "publickey")
	r := Build([]*event.Event{accepted, logon}, nil, Options{Location: time.UTC, WindowStart: at.Add(-time.Hour), WindowEnd: at.Add(time.Hour), Generated: at.Add(time.Hour)})
	if len(r.Events) != 1 {
		t.Fatalf("%d rows, want the logon only", len(r.Events))
	}
	e := r.Events[0]
	if e.SourceIP != "10.1.1.20" || e.Summary != `WIN11-TEST\claude logged on via SSH (OpenSSH) from 10.1.1.20 with administrator rights.` || !strings.Contains(detail(e, "SSH method"), "publickey") {
		t.Errorf("logon: %q %q", e.SourceIP, e.Summary)
	}
}

// UX1b: Windows records each SSH sign-in as two 4624s at the same second,
// not always linked: with sshd's line, 3 sessions are 3 logon rows, each
// with the address, and the console hosts of the sessions (started by
// sshd, which is not a row) fold into the logons. The Logon activity
// count is the number of logons.
func TestSSHLogonPairsAndConsoleHosts(t *testing.T) {
	at := time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC)
	var in []*event.Event
	for i := 0; i < 3; i++ {
		t0 := at.Add(time.Duration(i) * 5 * time.Minute)
		accepted := &event.Event{Time: t0, Host: "WIN11-TEST", OS: "windows", Category: event.CatLogon, Action: "ssh_accepted",
			User: `WIN11-TEST\claude`, SourceIP: "192.168.1.11", Summary: `claude signed in over SSH from 192.168.1.11 (publickey).`}
		in = append(in, accepted)
		for k, id := range []string{"0x1a" + string(rune('0'+i)), "0x2b" + string(rune('0'+i))} {
			l := &event.Event{Time: t0, Host: "WIN11-TEST", OS: "windows", Category: event.CatLogon, Action: "logon", EventID: 4624, User: `WIN11-TEST\claude`,
				Outcome: "success", Interactive: true, Summary: `WIN11-TEST\claude logged on via SSH (OpenSSH) with administrator rights.`}
			l.AddDetail("Logon type", "SSH (OpenSSH)")
			l.AddDetail("Logon ID", id)
			_ = k
			in = append(in, l)
		}
		ch := &event.Event{Time: t0.Add(2 * time.Second), Host: "WIN11-TEST", OS: "windows", Category: event.CatPrivileged, Action: "admin_process", EventID: 4688,
			User: `WIN11-TEST\claude`, Process: `C:\Windows\System32\conhost.exe`, Command: `\??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1`,
			Summary: `WIN11-TEST\claude ran with administrator rights: \??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1.`}
		ch.AddDetail("Started by", `C:\Windows\System32\OpenSSH\sshd.exe`)
		in = append(in, ch)
	}
	// A console host with a command line someone chose stays.
	odd := &event.Event{Time: at.Add(20 * time.Minute), Host: "WIN11-TEST", OS: "windows", Category: event.CatPrivileged, Action: "admin_process", EventID: 4688,
		User: `WIN11-TEST\claude`, Process: `C:\Windows\System32\conhost.exe`, Command: `conhost.exe --headless cmd.exe /c whoami`, Summary: "odd"}
	in = append(in, odd)
	r := Build(in, nil, Options{Location: time.UTC, WindowStart: at.Add(-time.Hour), WindowEnd: at.Add(time.Hour), Generated: at.Add(time.Hour)})
	logons, others := 0, 0
	for _, e := range r.Events {
		switch {
		case e.Action == "logon":
			logons++
			if e.SourceIP != "192.168.1.11" || !strings.Contains(detail(e, "Also logon ID"), "0x2b") || !strings.Contains(detail(e, "Also started"), "1 console window") {
				t.Errorf("logon row: %q %+v", e.Summary, e.Details)
			}
		case e.Summary == "odd":
		default:
			others++
			t.Errorf("row: %s", e.Summary)
		}
	}
	if logons != 3 || others != 0 {
		t.Errorf("%d logon rows, want 3", logons)
	}
	for _, s := range r.Sections {
		if s.Info.ID == event.CatLogon && s.Total != 3 {
			t.Errorf("Logon activity counts %d, want 3", s.Total)
		}
	}
}
