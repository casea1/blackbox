package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/event"
)

// lnx1Rows builds a report from Linux log files and returns its logon and
// failed-logon rows.
func lnx1Rows(t *testing.T, audit, syslog []string, host string) (logons, failed []*event.Event) {
	t.Helper()
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	evs, _, err := collect.LinuxFiles(audit, syslog, host, "", now)
	if err != nil {
		t.Fatal(err)
	}
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: now})
	for _, e := range r.Events {
		switch e.Action {
		case "logon":
			logons = append(logons, e)
		case "logon_failed":
			failed = append(failed, e)
		}
	}
	return logons, failed
}

// LNX1: Ubuntu 26.04's sshd-session writes no USER_LOGIN for a sign-in,
// only USER_START. Each sign-in is one logon row with the address, and
// with auth.log the method and key; each failed try is one row.
func TestUbuntu2604SSHLogons(t *testing.T) {
	saved := time.Local
	time.Local = time.UTC
	defer func() { time.Local = saved }()
	const dir = "../../testdata/linux/"
	audit, auth := []string{dir + "ubuntu2604-ssh-audit.log"}, []string{dir + "ubuntu2604-ssh-auth.log"}

	// The audit log alone.
	logons, failed := lnx1Rows(t, audit, nil, "ubuntu2604")
	if len(logons) != 2 {
		t.Fatalf("audit.log: %d logon rows, want 2", len(logons))
	}
	for _, e := range logons {
		if e.User != "claude" || e.SourceIP != "192.168.1.11" || detail(e, "Logon type") != "SSH" ||
			e.Summary != "claude logged on via SSH from 192.168.1.11." {
			t.Errorf("audit.log logon: %s %+v", e.Summary, e.Details)
		}
	}
	if len(failed) != 2 {
		t.Errorf("audit.log: %d failed-logon rows, want 2", len(failed))
	}

	// The audit log and auth.log: still one row per sign-in, with the method.
	logons, failed = lnx1Rows(t, audit, auth, "")
	if len(logons) != 2 {
		t.Fatalf("audit.log + auth.log: %d logon rows, want 2", len(logons))
	}
	if e := logons[0]; detail(e, "Authentication") != "publickey" ||
		detail(e, "Key") != "ED25519 SHA256:Xq3vJ1bH0wq8m5yQm1r7S0e2Fq6kTzv9yP4uLr2aB8c" ||
		e.SourceIP != "192.168.1.11" || !strings.HasSuffix(detail(e, "Program"), "sshd-session") {
		t.Errorf("key logon: %s %+v", e.Summary, e.Details)
	}
	if e := logons[1]; detail(e, "Authentication") != "password" || e.SourceIP != "192.168.1.11" {
		t.Errorf("password logon: %s %+v", e.Summary, e.Details)
	}
	var got []string
	for _, e := range failed {
		got = append(got, e.User+" "+e.SourceIP+" — "+detail(e, "Reason"))
	}
	want := "claude 192.168.1.23 — wrong password|claude 192.168.1.23 — no key or password was accepted before the connection closed"
	if strings.Join(got, "|") != want {
		t.Errorf("failed rows:\n got %q\nwant %q", strings.Join(got, "|"), want)
	}
}

// LNX1: a system whose sshd writes USER_LOGIN (Ubuntu 22.04 and 24.04)
// still shows one row per sign-in with the audit log, its USER_START and
// auth.log's "Accepted" line all read.
func TestSSHLogonNotDoubled(t *testing.T) {
	saved := time.Local
	time.Local = time.UTC
	defer func() { time.Local = saved }()
	const dir = "../../testdata/linux/"
	logons, _ := lnx1Rows(t, []string{dir + "ssh-session-audit.log"}, []string{dir + "ssh-session-auth.log"}, "claude-code")
	if len(logons) != 1 {
		t.Fatalf("%d logon rows, want 1", len(logons))
	}
	if e := logons[0]; detail(e, "Authentication") != "password" || e.SourceIP != "192.168.1.20" {
		t.Errorf("logon: %s %+v", e.Summary, e.Details)
	}
}

// LNX1 with U5's live 26.04 records: reading auth.log as well as the
// audit log adds no row; each try is still one.
func TestOpenSSH10FailedLogonsBothLogs(t *testing.T) {
	saved := time.Local
	time.Local = time.UTC
	defer func() { time.Local = saved }()
	const dir = "../../testdata/v0.10.4/"
	_, failed := lnx1Rows(t, []string{dir + "u5-openssh10-audit-records.log"}, []string{dir + "u5-openssh10-auth.log"}, "ubuntu-server")
	var got []string
	for _, e := range failed {
		got = append(got, e.User)
	}
	if strings.Join(got, ",") != "bbuser,bbuser,bbuser,admin,oracle,postgres,claude" {
		t.Errorf("rows for %v", got)
	}
}
