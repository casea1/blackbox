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
