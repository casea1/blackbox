package linuxlog

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// sysRec is a SYSCALL record by auid 1001 with one PATH item.
func sysRec(serial int, syscall, success, exit, a1, a2, exe, key, file string) []string {
	at := fmt.Sprintf("1790731%03d.000:%d", serial, serial)
	return []string{
		fmt.Sprintf(`type=SYSCALL msg=audit(%s): arch=c000003e syscall=%s success=%s exit=%s a0=ffffff9c a1=%s a2=%s items=1 ppid=1 pid=%d auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=3 comm=%q exe=%q key=%q`,
			at, syscall, success, exit, a1, a2, 7000+serial, base(exe), exe, key),
		fmt.Sprintf(`type=PATH msg=audit(%s): item=0 name=%q inode=12 dev=08:01 mode=0100755 ouid=0 ogid=0 nametype=NORMAL`, at, file),
		fmt.Sprintf(`type=EOE msg=audit(%s):`, at),
	}
}

// A3, U10, A5: refused access, permission changes, setuid, deletions,
// persistence and logon files, Blackbox's own files, and any other rule.
func TestFileActivity(t *testing.T) {
	cases := []struct {
		lines  []string
		action string
		sev    event.Severity
		text   string
	}{
		{sysRec(1, "257", "no", "-13", "0", "0", "/usr/bin/cat", "perm_access", "/etc/shadow"), "file_access_denied", event.SevMedium, "jsmith was refused access to /etc/shadow (using cat)"},
		{sysRec(2, "257", "no", "-2", "0", "0", "/usr/bin/cat", "perm_access", "/nope"), "", "", ""}, // ENOENT: not a refusal
		{sysRec(3, "268", "yes", "0", "7ffd", "9ed", "/usr/bin/chmod", "perm_mod", "/usr/local/bin/tool"), "setuid_set", event.SevHigh, "setuid"},
		{sysRec(4, "268", "yes", "0", "7ffd", "1a4", "/usr/bin/chmod", "perm_mod", "/home/jsmith/notes"), "permissions_changed", event.SevLow, "to 0644"},
		{sysRec(5, "90", "yes", "0", "1ed", "0", "/usr/bin/chmod", "perm_mod", "/etc/hosts"), "permissions_changed", event.SevMedium, "/etc/hosts"},
		{sysRec(6, "260", "yes", "0", "7ffd", "0", "/usr/bin/chown", "perm_mod", "/etc/cron.d/job"), "scheduled_job_changed", event.SevMedium, "scheduled jobs"},
		{sysRec(7, "263", "yes", "0", "7ffd", "0", "/usr/bin/rm", "delete", "/home/jsmith/a.txt"), "file_deleted", event.SevLow, "deleted or renamed"},
		{sysRec(8, "257", "yes", "3", "7ffd", "241", "/usr/bin/vi", "logon_config", "/etc/pam.d/sshd"), "logon_config_changed", event.SevHigh, "logon rules (PAM)"},
		{sysRec(9, "257", "yes", "3", "7ffd", "241", "/usr/bin/vi", "logon_config", "/etc/ssh/sshd_config"), "logon_config_changed", event.SevMedium, "SSH server"},
		{sysRec(10, "257", "yes", "3", "7ffd", "241", "/usr/bin/vi", "systemd_units", "/etc/systemd/system/backdoor.service"), "service_unit_changed", event.SevMedium, "services and timers"},
		{sysRec(11, "257", "yes", "3", "7ffd", "241", "/usr/bin/nano", "blackbox", "/etc/blackbox/blackbox.conf"), "blackbox_config_changed", event.SevHigh, "Blackbox's settings"},
		{sysRec(12, "257", "yes", "3", "7ffd", "241", "/usr/local/bin/blackbox", "blackbox", "/etc/blackbox/blackbox.conf"), "blackbox_config_changed", event.SevMedium, "with Blackbox itself"},
		{sysRec(13, "257", "yes", "3", "7ffd", "241", "/usr/bin/dpkg", "systemd_units", "/usr/lib/systemd/system/foo.service"), "", "", ""}, // package update
		{sysRec(14, "257", "yes", "3", "7ffd", "241", "/usr/bin/vi", "my_site_rule", "/srv/secret/plan.txt"), "audit_rule", event.SevInfo, `the audit rule "my_site_rule"`},
	}
	for _, c := range cases {
		evs := translateLines(t, Users{1001: "jsmith"}, c.lines...)
		if c.action == "" {
			if len(evs) != 0 {
				t.Errorf("%s: want nothing, got %s", c.lines[0][:40], summaries(evs))
			}
			continue
		}
		if len(evs) != 1 || evs[0].Action != c.action || evs[0].Severity != c.sev || !strings.Contains(evs[0].Summary, c.text) {
			t.Errorf("want %s %s %q, got:\n%s", c.action, c.sev, c.text, summaries(evs))
		}
	}
}

// A5, U9: commands that change Blackbox itself.
func TestBlackboxCommands(t *testing.T) {
	cases := map[string]string{
		"blackbox config set exclude_users bob":                     "blackbox_config_changed high",
		"/usr/local/bin/blackbox config set site_name Lab":          "blackbox_config_changed medium",
		"systemctl stop blackbox.timer":                             "blackbox_stopped high",
		"systemctl disable --now blackbox.timer":                    "blackbox_stopped high",
		"blackbox uninstall":                                        "blackbox_uninstalled high",
		`schtasks /Change /TN "Blackbox Audit Collection" /Disable`: "blackbox_stopped high",
		"rm -rf /var/lib/blackbox/spool":                            "blackbox_files_removed high",
		"blackbox status":                                           "",
		"systemctl status blackbox.timer":                           "",
	}
	for cmd, want := range cases {
		action, sev, _, ok := event.BlackboxChange(cmd)
		got := ""
		if ok {
			got = action + " " + string(sev)
		}
		if got != want {
			t.Errorf("%q: %q, want %q", cmd, got, want)
		}
	}
	// Through sudo.
	line := fmt.Sprintf(`type=USER_CMD msg=audit(1790730000.000:20): pid=6000 uid=1001 auid=1001 ses=3 msg='cwd="/home/jsmith" cmd=%s exe="/usr/bin/sudo" terminal=pts/0 res=success'`,
		strings.ToUpper(fmt.Sprintf("%x", "blackbox config set retention_days 30")))
	evs := translateLines(t, Users{1001: "jsmith"}, line)
	if len(evs) != 1 || evs[0].Action != "blackbox_config_changed" || evs[0].Severity != event.SevHigh {
		t.Errorf("sudo config set: %s", summaries(evs))
	}
}

// U12: Ubuntu 26.04's GNU coreutils are named gnurm, gnucp…
func TestGnuCoreutilsNames(t *testing.T) {
	if base("/usr/bin/gnurm") != "rm" || base("/usr/bin/gnupg") != "gnupg" {
		t.Errorf("base: %q %q", base("/usr/bin/gnurm"), base("/usr/bin/gnupg"))
	}
	if g := gnuName("/usr/bin/gnurm -rf /var/log/x"); g != "/usr/bin/rm -rf /var/log/x" {
		t.Errorf("gnuName: %q", g)
	}
	evs := translateLines(t, Users{1001: "jsmith"}, sysRec(20, "263", "yes", "0", "7ffd", "0", "/usr/bin/gnurm", "delete", "/home/jsmith/a.txt")...)
	if len(evs) != 1 || !strings.Contains(evs[0].Summary, "(using rm)") {
		t.Errorf("got %s", summaries(evs))
	}
}

// O1: with sudo-rs, sudo commands come from the journal and merge with the
// root command the audit log records.
func TestSudoRsFromJournal(t *testing.T) {
	tr := NewTranslator("ws12", Users{1001: "jsmith"})
	tr.SudoFromSyslog = true
	l := Line{Prog: "sudo", Host: "ws12", Msg: "jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/systemctl status cron"}
	e := tr.Syslog(l, "journal")
	if e == nil || e.Action != "sudo_command" || e.DedupeKey != "cmd|jsmith|"+cmdKey("systemctl status cron") {
		t.Fatalf("sudo line: %+v", e)
	}
	if e := tr.Syslog(Line{Prog: "sshd", Host: "ws12", Msg: "Accepted password for jsmith from 10.1.1.5 port 5000 ssh2"}, "journal"); e != nil {
		t.Errorf("auditd records logons; the journal's must not repeat them: %s", e.Summary)
	}
}

// O1: sudo-rs on Ubuntu 26.04 writes no TTY= field when there is no
// terminal (testdata/v0.10.4, recorded live): every command is still a row.
func TestSudoRsJournalNoTTY(t *testing.T) {
	b, err := os.ReadFile("../../testdata/v0.10.4/o1-sudo-rs-journal.log")
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTranslator("ubuntu-server", nil)
	tr.SudoFromSyslog = true
	p := LineParser{Loc: time.UTC}
	var rows, cmds []string
	for _, s := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		l, ok := p.Parse(s)
		if !ok {
			t.Fatalf("not parsed: %s", s)
		}
		if strings.Contains(l.Msg, "COMMAND=") {
			cmds = append(cmds, l.Msg)
		}
		if e := tr.Syslog(l, "journal"); e != nil {
			rows = append(rows, e.Summary)
		}
	}
	if len(rows) != len(cmds) || len(rows) == 0 {
		t.Fatalf("%d rows for %d commands: %q", len(rows), len(cmds), rows)
	}
	for _, want := range []string{"claude ran with sudo: /usr/bin/grep -c . /dev/null", "claude ran as bbuser with sudo: /usr/bin/true"} {
		if !slices.Contains(rows, want) {
			t.Errorf("no row %q in %q", want, rows)
		}
	}
}

// A14: groupadd writes /etc/group through /etc/group+ (renamed over it,
// then its owner and mode set), and Blackbox saves its state through a
// temporary file: neither is a row of its own. Another program changing
// Blackbox's data still is (A5).
func TestRoutineFileWrites(t *testing.T) {
	var lines []string
	lines = append(lines, sysRec(1, "82", "yes", "0", "7ffd", "7ffe", "/usr/sbin/groupadd", "delete", "/etc/group+")...)
	lines = append(lines, sysRec(2, "92", "yes", "0", "0", "0", "/usr/sbin/groupadd", "perm_mod", "/etc/group+")...)
	lines = append(lines, sysRec(3, "90", "yes", "0", "1a4", "0", "/usr/sbin/groupadd", "perm_mod", "/etc/gshadow+")...)
	lines = append(lines, sysRec(4, "90", "yes", "0", "180", "0", "/usr/local/bin/blackbox", "perm_mod", "/var/lib/blackbox/.state.json.tmp-123")...)
	lines = append(lines, sysRec(5, "82", "yes", "0", "7ffd", "7ffe", "/usr/local/bin/blackbox", "blackbox", "/var/lib/blackbox/.state.json.tmp-123")...)
	lines = append(lines, sysRec(6, "90", "yes", "0", "1ff", "0", "/usr/bin/chmod", "perm_mod", "/etc/group")...)
	lines = append(lines, sysRec(7, "257", "yes", "3", "7ffd", "241", "/usr/bin/vim.basic", "blackbox", "/var/lib/blackbox/state.json")...)
	evs := translateLines(t, Users{1001: "jsmith"}, lines...)
	got := summaries(evs)
	if len(evs) != 2 || !strings.Contains(got, "jsmith edited /etc/group directly (using chmod)") ||
		!strings.Contains(got, "blackbox_files_changed: jsmith changed Blackbox's collected data: /var/lib/blackbox/state.json (using vim.basic)") {
		t.Errorf("rows:\n%s", got)
	}
}

// I4: configuration management (systemd-run, no login user) changing the
// SSH or PAM settings is shown at Low; a package update is not.
func TestUnattendedChange(t *testing.T) {
	unset := func(lines []string) []string {
		for i := range lines {
			lines[i] = strings.Replace(lines[i], "auid=1001", "auid=4294967295", 1)
		}
		return lines
	}
	var lines []string
	lines = append(lines, unset(sysRec(1, "257", "yes", "3", "7ffd", "241", "/usr/bin/python3.12", "sshd_config", "/etc/ssh/sshd_config"))...)
	lines = append(lines, unset(sysRec(2, "257", "yes", "3", "7ffd", "241", "/usr/bin/dpkg", "pam", "/etc/pam.d/common-auth"))...)
	lines = append(lines, unset(sysRec(3, "257", "yes", "3", "7ffd", "241", "/usr/bin/python3.12", "logins", "/var/log/lastlog"))...)
	evs := translateLines(t, Users{1001: "jsmith"}, lines...)
	if len(evs) != 1 || evs[0].Action != "unattended_change" || evs[0].Severity != event.SevLow || evs[0].User != "" ||
		!strings.Contains(evs[0].Summary, "The SSH server settings were changed with no one logged on") {
		t.Errorf("rows:\n%s", summaries(evs))
	}
}

// I7: on a STIG image that watches /var/log/sudo.log, sudo appending to
// its own log is not a row (the sudo command is).
func TestSudoLogAppend(t *testing.T) {
	evs := translateLines(t, Users{1001: "jsmith"}, sysRec(1, "257", "yes", "3", "7ffd", "441", "/usr/bin/sudo", "maintenance", "/var/log/sudo.log")...)
	if len(evs) != 0 {
		t.Errorf("rows:\n%s", summaries(evs))
	}
}

// A14b: groupadd sets its temporary copy's owner and mode by file handle
// (fchown, fchmod), so the record has no path; not rows of their own.
// Another program doing the same still is.
func TestAccountToolHandleWrites(t *testing.T) {
	noPath := func(serial int, syscall, a1, exe string) []string {
		l := sysRec(serial, syscall, "yes", "0", a1, "0", exe, "perm_mod", "")
		l[0] = strings.Replace(l[0], "items=1", "items=0", 1)
		return []string{l[0], l[2]}
	}
	var lines []string
	lines = append(lines, noPath(1, "93", "0", "/usr/sbin/groupadd")...)   // fchown
	lines = append(lines, noPath(2, "91", "1a4", "/usr/sbin/groupadd")...) // fchmod 0644
	lines = append(lines, noPath(3, "91", "1ff", "/usr/bin/python3.12")...)
	evs := translateLines(t, Users{1001: "jsmith"}, lines...)
	if got := summaries(evs); len(evs) != 1 || !strings.Contains(got, "(using python3.12) to 0777") {
		t.Errorf("rows:\n%s", got)
	}
}
