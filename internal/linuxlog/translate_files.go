package linuxlog

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// File activity recorded by the STIG's audit rules (A3, U10) and by the
// rules that watch Blackbox itself (A5, U9).

// packageManagers install and update software; the files they write are
// the update itself, recorded by the sudo command that ran them.
var packageManagers = map[string]bool{"dpkg": true, "apt": true, "apt-get": true, "rpm": true, "dnf": true, "yum": true,
	"unattended-upgr": true, "unattended-upgrade": true, "snapd": true, "packagekitd": true, "dnf-automatic": true,
	"update-alternatives": true, "systemd-sysusers": true, "systemd-tmpfiles": true, "ldconfig": true, "debconf": true,
	"ucf": true, "ucfr": true, "dpkg-divert": true, "deb-systemd-helper": true, "systemd": true}

// watched is a file or folder whose changes matter whoever changes it.
type watched struct {
	prefix, what string
	action       string
	sev          event.Severity
	cat          event.Category
}

var watchedFiles = []watched{
	{"/etc/blackbox/", "Blackbox's settings", "blackbox_config_changed", event.SevHigh, event.CatIntegrity},
	{"/var/lib/blackbox/archive-pieces/", "the original logs waiting to be archived", "blackbox_files_changed", event.SevHigh, event.CatIntegrity},
	{"/var/lib/blackbox/", "Blackbox's collected data", "blackbox_files_changed", event.SevHigh, event.CatIntegrity},
	{"/usr/local/bin/blackbox", "the Blackbox program", "blackbox_files_changed", event.SevHigh, event.CatIntegrity},
	{"/etc/systemd/system/blackbox.", "Blackbox's schedule", "blackbox_stopped", event.SevHigh, event.CatIntegrity},
	{"/etc/pam.d/", "the logon rules (PAM)", "logon_config_changed", event.SevHigh, event.CatPrivileged},
	{"/etc/security/", "the logon security settings", "logon_config_changed", event.SevHigh, event.CatPrivileged},
	{"/etc/ssh/sshd_config", "the SSH server settings", "logon_config_changed", event.SevMedium, event.CatPrivileged},
	{"/etc/update-motd.d/", "the login message scripts (they run as root at every logon)", "logon_config_changed", event.SevMedium, event.CatPrivileged},
	{"/etc/crontab", "the scheduled jobs (cron)", "scheduled_job_changed", event.SevMedium, event.CatOther},
	{"/etc/cron.", "the scheduled jobs (cron)", "scheduled_job_changed", event.SevMedium, event.CatOther},
	{"/var/spool/cron/", "a user's scheduled jobs (crontab)", "scheduled_job_changed", event.SevMedium, event.CatOther},
	{"/etc/systemd/system/", "the services and timers (systemd)", "service_unit_changed", event.SevMedium, event.CatOther},
	{"/usr/lib/systemd/system/", "the services and timers (systemd)", "service_unit_changed", event.SevMedium, event.CatOther},
	{"/lib/systemd/system/", "the services and timers (systemd)", "service_unit_changed", event.SevMedium, event.CatOther},
}

// watchedFile reports a person changing a file in watchedFiles.
func (t *Translator) watchedFile(r *Record, actor, sc string, paths []string, exe, cmd string) *event.Event {
	prog := base(exe)
	if packageManagers[prog] || packageManagers[r.Get("comm")] || sc == "execve" || sc == "execveat" {
		return nil // running a program is not changing it
	}
	for _, p := range paths {
		for _, w := range watchedFiles {
			if !strings.HasPrefix(p, w.prefix) {
				continue
			}
			if strings.HasPrefix(w.prefix, "/var/lib/blackbox/") && (prog == "blackbox" || strings.HasPrefix(p, "/var/lib/blackbox/reports/")) {
				continue // Blackbox's own run, or someone opening a report
			}
			verb := "changed"
			if destroysFile(sc, r) && sc != "creat" && !strings.HasPrefix(sc, "open") {
				verb = "deleted or renamed a file in"
			}
			e := &event.Event{Category: w.cat, Severity: w.sev, Action: w.action, User: actor, Target: p, Process: exe, Command: cmd,
				DedupeKey: "watch|" + w.action + "|" + actor + "|" + p,
				Summary:   fmt.Sprintf("%s %s %s: %s%s.", actor, verb, w.what, p, usingProg(prog))}
			if prog == "blackbox" && strings.HasPrefix(w.action, "blackbox_") {
				// blackbox install, an upgrade or config set: shown, but as
				// Blackbox's own change.
				e.Severity = event.SevMedium
				e.Summary = fmt.Sprintf("%s changed %s with Blackbox itself (an install, upgrade or config set): %s.", actor, w.what, p)
			}
			e.AddDetail("File", p)
			e.AddDetail("System call", sc)
			e.AddDetail("Command", cmd)
			e.AddDetail("Audit rule", r.Get("key"))
			return e
		}
	}
	return nil
}

func usingProg(prog string) string {
	if prog == "" {
		return ""
	}
	return " (using " + prog + ")"
}

// refusedAccess is a failed system call. Only a file a person was refused
// (EACCES or EPERM, the STIG's perm_access rules) is reported.
func (t *Translator) refusedAccess(r *Record, actor, sc string, paths []string, exe, cmd string) *event.Event {
	if actor == "" || r.Get("key") == "" {
		return nil
	}
	switch strings.ToUpper(firstNonEmpty(r.Fields["EXIT"], r.Get("exit"))) {
	case "-13", "-1", "EACCES", "EPERM", "EACCES(PERMISSION DENIED)", "EPERM(OPERATION NOT PERMITTED)":
	default:
		return nil
	}
	target := firstNonEmpty(strings.Join(paths, ", "), "a file")
	e := &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "file_access_denied", User: actor, Target: target,
		Process: exe, Command: cmd, Outcome: "failure", DedupeKey: "denied|" + actor + "|" + target,
		Summary: fmt.Sprintf("%s was refused access to %s%s.", actor, target, usingProg(base(exe)))}
	e.AddDetail("File", target)
	e.AddDetail("System call", sc)
	e.AddDetail("Audit rule", r.Get("key"))
	return e
}

// systemDirs are where a permission change or deletion affects the whole
// system rather than one person's files.
func systemPath(p string) bool {
	for _, d := range []string{"/etc/", "/usr/", "/var/log/", "/boot/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/root/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// modeArg is the mode a chmod-family call set, from its registers.
func modeArg(sc string, r *Record) (uint64, bool) {
	reg := "a1"
	if sc == "fchmodat" || sc == "fchmodat2" {
		reg = "a2"
	}
	v, err := strconv.ParseUint(r.Get(reg), 16, 64)
	return v, err == nil
}

// accountTools (translate_syscall.go) change the account files through a
// temporary copy: /etc/group+ renamed over /etc/group, then its owner and
// mode set. The tool's own account record is the row (A14).
var accountFile = regexp.MustCompile(`^/etc/(passwd|shadow|group|gshadow|subuid|subgid)([+-]|\.lock|\.\d+|\.edit)?$|^/etc/n(shadow|gshadow|passwd|group)$`)

// ownLogs are the logs a program writes on every use, which the STIG's
// audit rules watch: sudo's own log, and the logon records (I7). The sudo
// command or the logon is the row.
var ownLogs = map[string][]string{
	"sudo": {"/var/log/sudo.log"}, "sudo-rs": {"/var/log/sudo.log"},
	"sshd": {"/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"}, "sshd-session": {"/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"},
	"login": {"/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"}, "gdm-session-wor": {"/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"},
}

// routineFileWrite is a write that is part of a change recorded better
// elsewhere: an account tool's temporary copies of the account files,
// Blackbox's own writes under its data folder (its state saved through a
// temporary file), and a program writing its own log. Writes there by
// anything else are still reported (A5).
func routineFileWrite(prog string, paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	for _, p := range paths {
		switch {
		case slices.Contains(ownLogs[prog], p):
		case accountTools[prog] && accountFile.MatchString(p):
		case prog == "blackbox" && strings.HasPrefix(p, "/var/lib/blackbox/"):
		default:
			return false
		}
	}
	return true
}

// fileChange is a permission, ownership or extended-attribute change, a
// deletion or rename, or any other record of a keyed audit rule.
func (t *Translator) fileChange(r *Record, actor, sc string, paths []string, exe, cmd string) *event.Event {
	key := r.Get("key")
	prog := base(exe)
	if actor == "" || key == "" || packageManagers[prog] || packageManagers[r.Get("comm")] {
		return nil // the system, or a software update (its sudo command is the record)
	}
	if routineFileWrite(prog, paths) || routineFileWrite(r.Get("comm"), paths) {
		return nil // A14
	}
	if t.inLoginMessage(t.hostOf(r), r.Get("pid"), r.Get("ppid"), r.Time) {
		return nil // the login message scripts, in their own row (U4c)
	}
	if len(paths) == 0 && (accountTools[prog] || accountTools[r.Get("comm")]) && (sc == "fchown" || sc == "fchmod") {
		// The tool setting the owner and mode of its temporary copy by
		// file handle, so the record has no path (A14b).
		return nil
	}
	target := firstNonEmpty(strings.Join(paths, ", "), "a file")
	sys := false
	for _, p := range paths {
		sys = sys || systemPath(p)
	}
	e := &event.Event{Category: event.CatOther, Severity: event.SevLow, User: actor, Target: target, Process: exe, Command: cmd}
	switch sc {
	case "chmod", "fchmod", "fchmodat", "fchmodat2":
		mode, ok := modeArg(sc, r)
		e.Action = "permissions_changed"
		e.Summary = fmt.Sprintf("%s changed the permissions of %s%s", actor, target, usingProg(prog))
		if ok {
			e.Summary += fmt.Sprintf(" to %04o", mode&0o7777)
			e.AddDetail("Mode", fmt.Sprintf("%04o", mode&0o7777))
		}
		switch {
		case ok && mode&0o6000 != 0:
			e.Action, e.Severity = "setuid_set", event.SevHigh
			kind := "setuid"
			if mode&0o4000 == 0 {
				kind = "setgid"
			}
			e.Summary = fmt.Sprintf("%s made %s %s (it runs with its owner's rights, often root)%s.", actor, target, kind, usingProg(prog))
		case sys:
			e.Severity = event.SevMedium
			e.Summary += "."
		default:
			e.Summary += "."
		}
	case "chown", "fchown", "lchown", "fchownat":
		e.Action = "owner_changed"
		e.Summary = fmt.Sprintf("%s changed the owner of %s%s.", actor, target, usingProg(prog))
		if sys {
			e.Severity = event.SevMedium
		}
	case "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr":
		e.Action = "attributes_changed"
		e.Summary = fmt.Sprintf("%s changed the extended attributes (ACLs, capabilities or labels) of %s%s.", actor, target, usingProg(prog))
		switch {
		case prog == "setcap":
			e.Action, e.Severity = "capabilities_set", event.SevHigh
			e.Summary = fmt.Sprintf("%s gave %s extra privileges (file capabilities) with setcap.", actor, target)
		case sys:
			e.Severity = event.SevMedium
		}
	case "unlink", "unlinkat", "rename", "renameat", "renameat2", "rmdir":
		e.Action = "file_deleted"
		e.Summary = fmt.Sprintf("%s deleted or renamed %s%s.", actor, target, usingProg(prog))
		if sys {
			e.Severity = event.SevMedium
		}
		if len(paths) > 0 {
			e.DedupeKey = "del|" + actor + "|" + path.Dir(paths[0]) // rm -r is one row per folder
		}
	default:
		// A rule Blackbox has no translation for: still a row, so nothing
		// the audit rules record is silently dropped.
		e.Action, e.Severity = "audit_rule", event.SevInfo
		e.Summary = fmt.Sprintf("%s: the audit rule %q recorded %s on %s%s.", actor, key, firstNonEmpty(sc, "a system call"), target, usingProg(prog))
	}
	if e.DedupeKey == "" {
		e.DedupeKey = "file|" + e.Action + "|" + actor + "|" + target
	}
	e.AddDetail("File", target)
	e.AddDetail("System call", sc)
	e.AddDetail("Command", cmd)
	e.AddDetail("Audit rule", key)
	return e
}
