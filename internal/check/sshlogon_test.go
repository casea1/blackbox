package check

import (
	"os"
	"testing"
)

// LNX1: sshd that opens sessions (USER_START) but records no successful
// logon (USER_LOGIN), as on Ubuntu 26.04, is a warning; a failed
// USER_LOGIN does not count.
func TestSSHLogons(t *testing.T) {
	audit, err := os.Open("../../testdata/linux/ubuntu2604-ssh-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	starts, logins, err := SSHAuditCounts(audit)
	if err != nil || starts != 2 || logins != 0 {
		t.Fatalf("26.04: %d starts, %d logins, %v", starts, logins, err)
	}
	if r, ok := EvaluateSSHLogons(true, starts, logins, nil); !ok || r.Status != Warn {
		t.Errorf("26.04: %+v", r)
	}
	older, err := os.Open("../../testdata/linux/ssh-session-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	defer older.Close()
	starts, logins, _ = SSHAuditCounts(older)
	if r, _ := EvaluateSSHLogons(true, starts, logins, nil); r.Status != Pass {
		t.Errorf("older: %+v", r)
	}
	if _, ok := EvaluateSSHLogons(false, 2, 0, nil); ok {
		t.Error("checked without sshd")
	}
	if r, _ := EvaluateSSHLogons(true, 0, 0, nil); r.Status != Info {
		t.Errorf("no sessions: %+v", r)
	}
}
