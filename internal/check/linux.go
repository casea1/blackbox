package check

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// AuditRules is Blackbox's recommended auditd rules file.
//
//go:embed blackbox-audit.rules
var AuditRules string

// RulesFile is where the recommended rules are meant to be saved. It sorts
// after a STIG baseline's own files (augenrules reads rules.d in
// "ls -v" order: actions.rules, privileged.rules …), so where a rule is in
// both, the STIG's key is the one recorded (I1).
const RulesFile = "/etc/audit/rules.d/zz-blackbox.rules"

// OldRulesFiles are where earlier versions saved the rules. They are read
// as Blackbox's own, and the file should be removed when RulesFile is
// saved: auditctl stops loading at a duplicate rule.
var OldRulesFiles = []string{"/etc/audit/rules.d/99-blackbox.rules"}

// rulesFix lists only the rules that are not already loaded (see
// MissingRules), so a STIG baseline's own rules are never duplicated.
// Blackbox prints them; an administrator installs them.
const rulesFix = "sudo blackbox check --audit-rules --missing | sudo install -m 0600 /dev/stdin " + RulesFile + ", then sudo augenrules --load"

// oldRulesFix is how versions before 0.29 worded it: without sudo, which
// both halves of the pipe need (one reads the loaded rules, the other
// writes in /etc), so it failed when copied as it stood.
const oldRulesFix = "blackbox check --audit-rules --missing | install -m 0600 /dev/stdin " + RulesFile + ", then augenrules --load"

// CurrentFix is a fix as this version words it, for a result an earlier
// version recorded.
func CurrentFix(fix string) string {
	if strings.HasPrefix(fix, oldRulesFix) {
		return rulesFix + strings.TrimPrefix(fix, oldRulesFix)
	}
	if fix == "auditctl -e 1 (then load the rules)" {
		return "sudo auditctl -e 1 (then load the rules)"
	}
	return fix
}

type ruleReq struct {
	item, affects string
	required      bool
	match         func(rules []string) bool
}

func anyRule(rules []string, parts ...string) bool {
	for _, r := range rules {
		ok := true
		for _, p := range parts {
			if !strings.Contains(r, p) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// watches reports whether exactly path is watched (not a longer path that
// starts with it), with or without a trailing slash: auditctl lists
// "-w /etc/audit/" as "-w /etc/audit".
func watches(path string) func([]string) bool {
	return func(rules []string) bool {
		for _, f := range ruleTokens(rules) {
			if watchesPath(f, path) {
				return true
			}
		}
		return false
	}
}

var linuxRuleReqs = []ruleReq{
	{"Watch /etc/passwd", "Account & Group Changes (edits made outside the account tools)", true, watches("/etc/passwd")},
	{"Watch /etc/shadow", "Account & Group Changes", true, watches("/etc/shadow")},
	{"Watch /etc/group", "Account & Group Changes", true, watches("/etc/group")},
	{"Watch /etc/gshadow", "Account & Group Changes", true, watches("/etc/gshadow")},
	{"Watch /etc/sudoers and /etc/sudoers.d", "Privileged Activity (changes to sudo rules)", true,
		func(r []string) bool { return watches("/etc/sudoers")(r) && watches("/etc/sudoers.d")(r) }},
	{"Programs run with raised privileges (execve, uid!=euid)", "Privileged Activity (passwd, chage and other setuid programs)", true,
		func(r []string) bool { return anyRule(r, "execve", "uid!=euid") }},
	{"Commands run as root by a person (execve, euid=0, auid set)", "Privileged Activity (commands inside root shells)", false,
		func(r []string) bool { return anyRule(r, "execve", "euid=0", "auid>=") }},
	{"Kernel module loading", "Other Security Events", true,
		func(r []string) bool { return anyRule(r, "init_module") || anyRule(r, "finit_module") }},
	// The DISA STIG for Ubuntu 24.04 audits the mount program (path=
	// /usr/bin/mount) rather than the mount syscall; either records a disk
	// mounted from the command line.
	{"Filesystem mounts", "USB & Removable Media (disks mounted from the command line)", true,
		func(r []string) bool {
			return anyRule(r, "-S mount") || anyRule(r, ",mount") || anyRule(r, "mount,") ||
				watches("/usr/bin/mount")(r) || watches("/bin/mount")(r)
		}},
	{"System time changes", "Audit & System Integrity", false,
		func(r []string) bool { return anyRule(r, "settimeofday") || anyRule(r, "clock_settime") }},
	{"Audit configuration watched (/etc/audit)", "Audit & System Integrity", false, watches("/etc/audit/")},
	{"Unsuccessful file access (EACCES and EPERM)", "Other Security Events (files a person was refused)", true,
		func(r []string) bool { return anyRule(r, "EACCES") && anyRule(r, "EPERM") }},
	{"Permission and ownership changes (chmod, chown, setxattr)", "Other Security Events (setuid and permission changes)", true,
		func(r []string) bool { return anyRule(r, "chmod") && anyRule(r, "chown") && anyRule(r, "setxattr") }},
	{"Logon records watched (utmp, wtmp, btmp)", "Logon Activity", true,
		func(r []string) bool {
			return (watches("/var/run/utmp")(r) || watches("/run/utmp")(r)) && watches("/var/log/wtmp")(r) && watches("/var/log/btmp")(r)
		}},
	{"Module and ACL tools (kmod, setfacl, chacl)", "Other Security Events", true,
		func(r []string) bool {
			return (watches("/usr/bin/kmod")(r) || watches("/bin/kmod")(r)) && (watches("/usr/bin/setfacl")(r) || watches("/bin/setfacl")(r)) &&
				(watches("/usr/bin/chacl")(r) || watches("/bin/chacl")(r))
		}},
	{"Blackbox's own files watched (/etc/blackbox)", "Audit & System Integrity (changes to Blackbox's settings)", false, watches("/etc/blackbox/")},
}

// EvaluateAuditRules compares `auditctl -l` and `auditctl -s` output with
// the rules the report needs.
func EvaluateAuditRules(rulesText, statusText string) []Result {
	var rules []string
	for _, l := range strings.Split(rulesText, "\n") {
		if l = strings.TrimSpace(l); l != "" && l != "No rules" {
			rules = append(rules, l)
		}
	}
	status := map[string]string{}
	for _, l := range strings.Split(statusText, "\n") {
		if f := strings.Fields(l); len(f) >= 2 {
			status[f[0]] = f[1]
		}
	}
	fix := rulesFix
	if status["enabled"] == "2" {
		fix += " (the rules are locked, so they take effect after a reboot)"
	}
	var out []Result
	for _, q := range linuxRuleReqs {
		r := Result{Area: "Audit rules", Item: q.item, Want: "Present", Affects: q.affects}
		switch {
		case q.match(rules):
			r.Status, r.Have = Pass, "Present"
		case q.required:
			r.Status, r.Have, r.Fix = Fail, "Missing", fix
		default:
			r.Status, r.Have, r.Want, r.Fix = Warn, "Missing", "Recommended", fix
		}
		out = append(out, r)
	}
	lock := Result{Area: "Audit rules", Item: "Rules locked until reboot (-e 2)", Want: "Locked (enabled 2)",
		Affects: "Audit & System Integrity (without it, rules can be removed without a reboot)"}
	switch status["enabled"] {
	case "2":
		lock.Status, lock.Have = Pass, "Locked"
	case "1":
		lock.Status, lock.Have, lock.Fix = Fail, "Not locked", rulesFix
	case "0":
		lock.Status, lock.Have, lock.Fix = Fail, "Auditing is OFF", "sudo auditctl -e 1 (then load the rules)"
	default:
		lock.Status, lock.Have = Error, "unknown (run as root)"
	}
	out = append(out, lock)
	if b, err := strconv.Atoi(status["backlog_limit"]); err == nil {
		r := Result{Area: "Audit rules", Item: "Kernel audit backlog", Want: "at least 8192", Have: strconv.Itoa(b),
			Affects: "Records are dropped when a busy system fills the backlog"}
		if b >= 8192 {
			r.Status = Pass
		} else {
			r.Status, r.Fix = Warn, fix
		}
		out = append(out, r)
	}
	return out
}

// ParseAuditdConf reads key = value settings from auditd.conf.
func ParseAuditdConf(text string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			m[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return m
}

// EvaluateAuditdConf checks auditd.conf settings that affect the report.
func EvaluateAuditdConf(conf map[string]string) []Result {
	var out []Result
	f := Result{Area: "auditd settings", Item: "log_format", Have: conf["log_format"], Want: "ENRICHED",
		Affects: "Account names in the report (RAW logs only record user ID numbers)"}
	if strings.EqualFold(conf["log_format"], "ENRICHED") {
		f.Status = Pass
	} else {
		f.Status, f.Fix = Warn, "set log_format = ENRICHED in /etc/audit/auditd.conf, then restart auditd"
	}
	out = append(out, f)
	size, _ := strconv.Atoi(conf["max_log_file"])
	num, _ := strconv.Atoi(conf["num_logs"])
	if size > 0 && num > 0 {
		out = append(out, Result{Area: "auditd settings", Item: "Audit log space", Status: Info,
			Have: fmt.Sprintf("%d files × %d MB = %d MB, then %s", num, size, num*size, strings.ToLower(conf["max_log_file_action"])),
			Want: "Enough to hold at least a day of events between collections"})
	}
	return out
}

var cmdlineAuditRE = regexp.MustCompile(`(^|\s)audit=1(\s|$)`)

// EvaluateCmdline checks that auditing starts at boot, before auditd.
func EvaluateCmdline(cmdline string) Result { return EvaluateBoot(cmdline, "")[0] }
