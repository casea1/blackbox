package check

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// More Linux checks (A6, A11, O1, LNX1): what auditd does when its disk
// fills, who it tells, the audit log's permissions, time synchronisation,
// boot settings waiting for a reboot, sudo-rs, and an sshd that records no
// logon in the audit log.

// EvaluateAuditdActions checks what auditd does as its disk fills or
// fails. SUSPEND and IGNORE stop recording without anyone knowing.
func EvaluateAuditdActions(conf map[string]string) []Result {
	var out []Result
	act := func(key, want string, ok func(string) bool, affects, fix string) {
		v := strings.ToLower(conf[key])
		r := Result{Area: "auditd settings", Item: key, Have: orNotSet(conf[key]), Want: want, Affects: affects}
		if ok(v) {
			r.Status = Pass
		} else {
			r.Status, r.Fix = Fail, fix
		}
		out = append(out, r)
	}
	in := func(list ...string) func(string) bool {
		return func(v string) bool {
			for _, l := range list {
				if v == l {
					return true
				}
			}
			return false
		}
	}
	// What the STIGs accept (ALMA-09-054140/054030, RHEL-09-653025/653020).
	notStop := in("syslog", "single", "halt")
	const conf_ = "/etc/audit/auditd.conf"
	act("space_left_action", "email, exec or syslog (someone is told)", in("email", "exec", "syslog", "single", "halt"),
		"Audit & System Integrity: nobody is warned before the audit disk fills", "set space_left_action = email in "+conf_+", then restart auditd")
	act("admin_space_left_action", "single or halt", in("single", "halt"),
		"Audit & System Integrity: events stop being recorded when the disk is nearly full", "set admin_space_left_action = single in "+conf_+", then restart auditd")
	act("disk_full_action", "halt, single or syslog (not SUSPEND or IGNORE)", notStop,
		"Audit & System Integrity: auditing silently stops when the disk is full", "set disk_full_action = halt (or single) in "+conf_+", then restart auditd")
	act("disk_error_action", "halt, single or syslog (not SUSPEND or IGNORE)", notStop,
		"Audit & System Integrity: auditing silently stops on a disk error", "set disk_error_action = halt (or syslog) in "+conf_+", then restart auditd")
	mail := Result{Area: "auditd settings", Item: "action_mail_acct", Have: orNotSet(conf["action_mail_acct"]), Want: "root, or an administrator's mailbox"}
	if conf["action_mail_acct"] != "" || conf["space_left_action"] == "" {
		// auditd's default is root.
		mail.Status = Pass
		if mail.Have == "not set" {
			mail.Have = "root (default)"
		}
	} else {
		mail.Status, mail.Fix = Fail, "set action_mail_acct = root in "+conf_
	}
	return append(out, mail)
}

func orNotSet(s string) string {
	if strings.TrimSpace(s) == "" {
		return "not set"
	}
	return s
}

// EvaluateAuditLogPerms checks the audit log and its folder: readable only
// by root (and its group), never by everyone.
func EvaluateAuditLogPerms(file, dir os.FileMode, fileErr, dirErr error) Result {
	r := Result{Area: "auditd settings", Item: "Audit log permissions", Want: "log 0600 or 0640, folder 0700 or 0750",
		Affects: "Audit & System Integrity: anyone who can read or change the audit log can see or cover activity"}
	if fileErr != nil || dirErr != nil {
		r.Status, r.Have = Error, "could not read /var/log/audit (run as root)"
		return r
	}
	f, d := file.Perm(), dir.Perm()
	r.Have = fmt.Sprintf("log %04o, folder %04o", f, d)
	if f&0o137 == 0 && d&0o027 == 0 {
		r.Status = Pass
	} else {
		r.Status = Fail
		r.Fix = "chmod 0600 /var/log/audit/audit.log && chmod 0750 /var/log/audit (and set log_group = root in /etc/audit/auditd.conf)"
	}
	return r
}

// EvaluateTimeSync checks that the clock is synchronised: audit records
// from several computers only line up if their clocks agree (AU-8).
// active maps a service name to its `systemctl is-active` answer.
func EvaluateTimeSync(active map[string]string) Result {
	r := Result{Area: "Time", Item: "Time synchronisation", Want: "chrony or systemd-timesyncd active (a basic AU-8 check: the STIG's time rules, such as UBTU-24-600160/600180, are not checked)",
		Affects: "Every section: event times from different computers only line up if their clocks agree"}
	for _, svc := range []string{"chronyd", "chrony", "systemd-timesyncd", "ntpd", "ntp"} {
		if active[svc] == "active" {
			r.Status, r.Have = Pass, svc+" active"
			return r
		}
	}
	r.Status, r.Have = Fail, "no time service running"
	r.Fix = "enable chrony (apt install chrony, or dnf install chrony; systemctl enable --now chronyd) pointed at your site's time source"
	return r
}

var (
	grubLineRE = regexp.MustCompile(`(?m)^\s*GRUB_CMDLINE_LINUX(?:_DEFAULT)?\s*=\s*["']?([^"'\n]*)`)
	backlogRE  = regexp.MustCompile(`(^|\s)audit_backlog_limit=(\d+)`)
)

// EvaluateBoot checks that auditing starts at boot (audit=1) with a large
// enough backlog, in the running kernel and in GRUB's settings. A setting
// in GRUB that the running kernel doesn't have yet takes effect at the
// next boot (A11).
func EvaluateBoot(cmdline, grub string) []Result {
	var grubArgs string
	for _, m := range grubLineRE.FindAllStringSubmatch(grub, -1) {
		grubArgs += " " + m[1]
	}
	audit := Result{Area: "Boot", Item: "audit=1 on the kernel command line", Want: "Present",
		Affects: "Activity during boot, before the audit service starts"}
	switch {
	case cmdlineAuditRE.MatchString(cmdline):
		audit.Status, audit.Have = Pass, "Present"
	case cmdlineAuditRE.MatchString(grubArgs):
		audit.Status, audit.Have = Warn, "Set in GRUB; takes effect at the next boot"
		audit.Fix = "reboot to apply it"
	default:
		audit.Status, audit.Have = Fail, "Missing"
		audit.Fix = `add audit=1 to GRUB_CMDLINE_LINUX in /etc/default/grub, then run update-grub (Ubuntu) or grub2-mkconfig -o /boot/grub2/grub.cfg (Alma)`
	}
	out := []Result{audit}
	bl := Result{Area: "Boot", Item: "audit_backlog_limit on the kernel command line", Want: "at least 8192",
		Affects: "Records from early boot dropped before auditd starts"}
	num := func(s string) int {
		var n int
		fmt.Sscan(s, &n)
		return n
	}
	switch m, g := backlogRE.FindStringSubmatch(cmdline), backlogRE.FindStringSubmatch(grubArgs); {
	case m != nil && num(m[2]) >= 8192:
		bl.Status, bl.Have = Pass, m[2]
	case g != nil && num(g[2]) >= 8192:
		bl.Status, bl.Have, bl.Fix = Warn, g[2]+" set in GRUB; takes effect at the next boot", "reboot to apply it"
	case m != nil:
		bl.Status, bl.Have = Warn, m[2]
		bl.Fix = "set audit_backlog_limit=8192 in GRUB_CMDLINE_LINUX in /etc/default/grub, update GRUB, then reboot"
	default:
		bl.Status, bl.Have = Warn, "not set"
		bl.Fix = "add audit_backlog_limit=8192 to GRUB_CMDLINE_LINUX in /etc/default/grub, update GRUB, then reboot"
	}
	return append(out, bl)
}

// EvaluateSudo flags sudo-rs (Ubuntu 26.04's default sudo), which writes
// no audit record of the commands it runs (O1). version is `sudo -V`.
func EvaluateSudo(version string) Result {
	r := Result{Area: "Audit service", Item: "sudo records its commands in the audit log", Want: "sudo (sudo-rs records no audit events)",
		Affects: "Privileged Activity: sudo commands come only from root commands and the journal"}
	switch {
	case version == "":
		r.Status, r.Have = Info, "sudo not found"
	case strings.Contains(strings.ToLower(version), "sudo-rs"):
		r.Status, r.Have = Warn, "sudo-rs"
		r.Fix = "Blackbox reads sudo-rs's journal lines and the root_commands audit rule instead, but a refused sudo-rs (someone not in sudoers) is logged nowhere; for full audit records, install sudo (apt install sudo-ws) and make it the default with update-alternatives"
	default:
		r.Status, r.Have = Pass, firstLineOf(version)
	}
	return r
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// EvaluateW32Time checks Windows time synchronisation (AU-8): the Windows
// Time service running, synchronising from a domain or an NTP server.
// state is `sc query w32time` output, typ the Parameters\Type value.
func EvaluateW32Time(state, typ string) Result {
	r := Result{Area: "Time", Item: "Windows Time service", Want: "running, synchronising from the domain (NT5DS) or NTP (a basic AU-8 check: how often and how closely the clock is corrected is not checked)",
		Affects: "Every section: event times from different computers only line up if their clocks agree"}
	running := strings.Contains(strings.ToUpper(state), "RUNNING")
	t := strings.ToUpper(strings.TrimSpace(typ))
	switch {
	case !running:
		r.Status, r.Have = Fail, "not running"
		r.Fix = "sc config w32time start= auto && net start w32time, then w32tm /resync"
	case t == "NOSYNC" || t == "":
		r.Status, r.Have = Fail, "running, not synchronising (Type "+orNotSet(typ)+")"
		r.Fix = "Group Policy: Computer Configuration > Administrative Templates > System > Windows Time Service > Time Providers > Configure Windows NTP Client: Enabled, with your site's time source (or Type NT5DS on a domain)"
	default:
		r.Status, r.Have = Pass, "running, "+typ
	}
	return r
}

var sshdExeRE = regexp.MustCompile(`exe="[^"]*/sshd(?:-session|-auth)?"`)

// SSHAuditCounts counts the SSH sessions sshd opened (USER_START) and
// the successful logons it recorded (USER_LOGIN) in an audit log.
func SSHAuditCounts(r io.Reader) (starts, logins int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		l := sc.Text()
		if !sshdExeRE.MatchString(l) || !strings.Contains(l, "res=success") {
			continue
		}
		switch {
		case strings.HasPrefix(l, "type=USER_START "):
			starts++
		case strings.HasPrefix(l, "type=USER_LOGIN "):
			logins++
		}
	}
	return starts, logins, sc.Err()
}

// EvaluateSSHLogons warns when sshd opens sessions but records no logon
// (USER_LOGIN) in the audit log, as Ubuntu 26.04's sshd-session does
// (LNX1). ok is false when sshd is not installed.
func EvaluateSSHLogons(sshd bool, starts, logins int, err error) (r Result, ok bool) {
	if !sshd {
		return r, false
	}
	r = Result{Area: "Audit service", Item: "sshd records SSH logons (USER_LOGIN) in the audit log", Want: "a USER_LOGIN for each SSH session",
		Affects: "Logons: SSH sign-ins come from the session start (USER_START), and how the person signed in only from auth.log or the journal"}
	switch {
	case err != nil:
		r.Status, r.Have = Info, "could not read the audit log (run as root)"
	case logins > 0:
		r.Status, r.Have = Pass, fmt.Sprintf("%d SSH logons recorded", logins)
	case starts == 0:
		r.Status, r.Have = Info, "no SSH sessions in the audit log yet"
	default:
		r.Status, r.Have = Warn, fmt.Sprintf("%d SSH sessions opened (USER_START), no USER_LOGIN", starts)
		r.Fix = "Nothing to change in Blackbox: it reports each SSH sign-in from its USER_START record, and takes the method (password or key) and refused keys from sshd's lines in auth.log or the journal. Keep auth.log (rsyslog) or a persistent journal so those lines are kept"
	}
	return r, true
}
