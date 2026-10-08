package linuxlog

import (
	"strings"
	"testing"
)

// AU3: an auditd event's outcome comes from the system call's success=
// or a user-space record's res=; "" when it records neither.
func TestAuditOutcome(t *testing.T) {
	parse := func(lines ...string) *Event {
		var got *Event
		ParseAuditStream(strings.NewReader(strings.Join(lines, "\n")+"\n"), func(ev *Event) error { got = ev; return nil })
		if got == nil {
			t.Fatalf("no event from %q", lines)
		}
		return got
	}
	for want, ev := range map[string]*Event{
		"failure": parse(`type=SYSCALL msg=audit(1790730000.001:11): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c items=1 ppid=1 pid=4001 auid=1001 uid=1001 comm="cat" exe="/usr/bin/cat" key="perm_access"`,
			`type=EOE msg=audit(1790730000.001:11):`),
		"success": parse(`type=USER_ACCT msg=audit(1790730000.002:12): pid=5000 uid=0 auid=1001 ses=3 msg='op=PAM:accounting grantors=pam_unix acct="jsmith" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'`),
		"":        parse(`type=SERVICE_START msg=audit(1790730000.003:13): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=cron comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=?'`),
	} {
		if got := auditOutcome(ev); got != want {
			t.Errorf("%s: outcome %q, want %q", ev.Main().Type, got, want)
		}
	}
	if got := auditOutcome(parse(`type=CONFIG_CHANGE msg=audit(1790730000.004:14): auid=1001 ses=3 op=remove_rule key="identity" list=4 res=0`)); got != "failure" {
		t.Errorf("CONFIG_CHANGE res=0: %q", got)
	}

	// A translated event that did not set its own outcome gets it.
	tr := NewTranslator("ws12", Users{1001: "admin_jd"})
	lines := []string{
		`type=SYSCALL msg=audit(1790730000.005:15): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffd0000 a2=241 a3=1b6 items=1 ppid=1 pid=4005 auid=1001 uid=0 gid=0 euid=0 tty=pts0 ses=3 comm="tee" exe="/usr/bin/tee" key="actions"`,
		`type=PATH msg=audit(1790730000.005:15): item=0 name="/etc/sudoers.d/tempuser" inode=12 dev=08:01 mode=0100440 ouid=0 ogid=0 rdev=00:00 nametype=CREATE`,
		`type=EOE msg=audit(1790730000.005:15):`,
	}
	var outcome, action string
	ParseAuditStream(strings.NewReader(strings.Join(lines, "\n")+"\n"), func(ev *Event) error {
		if e := tr.Audit(ev); e != nil {
			outcome, action = e.Outcome, e.Action
		}
		return nil
	})
	if action != "sudoers_changed" || outcome != "success" {
		t.Errorf("sudoers change: action %q, outcome %q", action, outcome)
	}
}

// DET1: a failed change to Blackbox's own files is a row whatever the
// error (here ENOENT), so the report can tell a delete that did nothing;
// elsewhere only a refusal (EACCES, EPERM) is.
func TestFailedChangeToBlackboxFiles(t *testing.T) {
	tr := NewTranslator("ub", Users{1000: "claude"})
	run := func(file, exit string) *string {
		lines := []string{
			`type=SYSCALL msg=audit(1790730000.005:15): arch=c000003e syscall=263 success=no exit=` + exit + ` a0=ffffff9c a1=55d1c3a4b4f0 a2=0 a3=0 items=2 ppid=5100 pid=5101 auid=1000 uid=0 gid=0 euid=0 tty=pts0 ses=3 comm="rm" exe="/usr/bin/rm" key="blackbox"`,
			`type=PATH msg=audit(1790730000.005:15): item=0 name="` + file + `" inode=12 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=UNKNOWN`,
			`type=EOE msg=audit(1790730000.005:15):`,
		}
		var got *string
		ParseAuditStream(strings.NewReader(strings.Join(lines, "\n")+"\n"), func(ev *Event) error {
			if e := tr.Audit(ev); e != nil {
				s := e.Action + " " + string(e.Severity) + " " + e.Outcome + ": " + e.Summary
				got = &s
			}
			return nil
		})
		return got
	}
	if got := run("/var/lib/blackbox/spool/a.json", "-2"); got == nil ||
		*got != "file_change_failed low failure: claude tried to change /var/lib/blackbox/spool/a.json, and it failed (-2) (using rm)." {
		t.Errorf("Blackbox file, ENOENT: %v", got)
	}
	if got := run("/home/claude/x", "-2"); got != nil {
		t.Errorf("another file, ENOENT: %s", *got)
	}
	if got := run("/home/claude/x", "-13"); got == nil || !strings.HasPrefix(*got, "file_access_denied medium failure: claude was refused access to /home/claude/x") {
		t.Errorf("another file, EACCES: %v", got)
	}
}
