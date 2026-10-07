// SYSCALL records: commands run as root and privileged programs, mounts,
// modules, time changes, sudoers, account-database and log-file edits.
// File activity under the STIG's rules is in translate_files.go.

package linuxlog

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// notDisks are filesystem types that never come from a disk.
var notDisks = map[string]bool{"tmpfs": true, "proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true,
	"cgroup2": true, "overlay": true, "squashfs": true, "fuse": true, "binfmt_misc": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "mqueue": true, "hugetlbfs": true, "bpf": true, "configfs": true, "efivarfs": true, "autofs": true,
	"pstore": true, "ramfs": true, "nsfs": true, "fusectl": true, "rpc_pipefs": true}

var networkFS = map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "sshfs": true,
	"fuse.sshfs": true, "9p": true, "ceph": true, "glusterfs": true, "davfs": true}

// mountKind says what a mount command mounted: "disk" (a device such as a
// USB drive), "network" (a share on another computer) or "" (a memory or
// system filesystem, or a folder bound or moved somewhere else).
func mountKind(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 || base(f[0]) != "mount" {
		return ""
	}
	var fstype, opts string
	var args []string
	for i := 1; i < len(f); i++ {
		w := f[i]
		switch {
		case w == "-t" || w == "--types":
			if i+1 < len(f) {
				fstype = f[i+1]
				i++
			}
		case strings.HasPrefix(w, "--types="):
			fstype = strings.TrimPrefix(w, "--types=")
		case strings.HasPrefix(w, "-t") && len(w) > 2:
			fstype = w[2:]
		case w == "-o" || w == "--options":
			if i+1 < len(f) {
				opts += "," + f[i+1]
				i++
			}
		case strings.HasPrefix(w, "--options="):
			opts += "," + strings.TrimPrefix(w, "--options=")
		case strings.HasPrefix(w, "-o") && len(w) > 2:
			opts += "," + w[2:]
		case w == "--bind" || w == "--rbind" || w == "--move" || w == "-B" || w == "-R" || w == "-M" ||
			w == "--make-private" || w == "--make-shared" || w == "--make-slave" || w == "--make-rprivate":
			return ""
		case strings.HasPrefix(w, "-"):
		default:
			args = append(args, w)
		}
	}
	for _, o := range strings.Split(opts, ",") {
		if o == "bind" || o == "rbind" || o == "remount" || o == "move" {
			return ""
		}
	}
	for _, t := range strings.Split(fstype, ",") {
		if notDisks[t] {
			return ""
		}
		if networkFS[t] {
			return "network"
		}
	}
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "//") || strings.Contains(a, ":/"):
			return "network"
		case strings.HasPrefix(a, "/dev/") || strings.HasPrefix(a, "LABEL=") || strings.HasPrefix(a, "UUID=") ||
			strings.HasPrefix(a, "PARTUUID="):
			return "disk"
		}
	}
	if len(args) == 1 && fstype == "" {
		// "mount /mnt/usb": the device comes from /etc/fstab; a path
		// where removable disks are mounted is taken as one.
		for _, p := range []string{"/media/", "/run/media/", "/mnt"} {
			if strings.HasPrefix(args[0], p) {
				return "disk"
			}
		}
	}
	return ""
}

// accountTools legitimately write /etc/passwd, /etc/shadow and /etc/group;
// their changes are reported from ADD_USER/USER_MGMT records instead.
var accountTools = map[string]bool{
	"useradd": true, "usermod": true, "userdel": true, "groupadd": true, "groupmod": true, "groupdel": true,
	"gpasswd": true, "passwd": true, "chpasswd": true, "chage": true, "chfn": true, "chsh": true,
	"newusers": true, "adduser": true, "deluser": true, "addgroup": true, "delgroup": true,
	"pwconv": true, "grpconv": true, "systemd-sysusers": true, "systemd-sysuser": true, "update-passwd": true,
}

// setuidHelpers are privileged programs reported another way (sudo and su
// have their own records) or that only run as part of normal logons.
var setuidHelpers = map[string]bool{
	"sudo": true, "su": true, "sudoedit": true, "pkexec": true, "unix_chkpwd": true, "ssh-keysign": true,
	"dbus-daemon-launch-helper": true, "polkit-agent-helper-1": true, "Xorg.wrap": true, "fusermount3": true,
	"fusermount": true, "gnome-keyring-daemon": true, "chrome-sandbox": true,
	// Started at every desktop logon; the STIG audits it as a privileged program.
	"ssh-agent": true,
}

var identityFiles = map[string]bool{
	"/etc/passwd": true, "/etc/shadow": true, "/etc/group": true, "/etc/gshadow": true, "/etc/security/opasswd": true,
}

// syscallName uses the enriched name, or common x86_64 numbers.
// destroysFile reports whether a system call deletes, renames or empties
// the file it names (opening with O_TRUNC is how "> file" empties one).
func destroysFile(sc string, r *Record) bool {
	switch sc {
	case "unlink", "unlinkat", "rename", "renameat", "renameat2", "truncate", "ftruncate", "rmdir", "creat":
		return true
	case "open":
		return truncates(r.Get("a1"))
	case "openat", "openat2":
		return truncates(r.Get("a2"))
	}
	return false
}

// truncates reports whether open flags (hex, as auditd records them)
// include O_TRUNC.
func truncates(hexFlags string) bool {
	f, err := strconv.ParseUint(hexFlags, 16, 64)
	return err == nil && f&0o1000 != 0
}

func syscallName(r *Record) string {
	if n := r.Fields["SYSCALL"]; n != "" {
		return n
	}
	switch r.Get("syscall") {
	case "59":
		return "execve"
	case "322":
		return "execveat"
	case "175":
		return "init_module"
	case "313":
		return "finit_module"
	case "176":
		return "delete_module"
	case "165":
		return "mount"
	case "166":
		return "umount2"
	case "227":
		return "clock_settime"
	case "164":
		return "settimeofday"
	case "159":
		return "adjtimex"
	case "305":
		return "clock_adjtime"
	// File changes (x86_64 numbers; ENRICHED logs give the names).
	case "2":
		return "open"
	case "257":
		return "openat"
	case "85":
		return "creat"
	case "76":
		return "truncate"
	case "77":
		return "ftruncate"
	case "82":
		return "rename"
	case "264":
		return "renameat"
	case "316":
		return "renameat2"
	case "87":
		return "unlink"
	case "263":
		return "unlinkat"
	case "84":
		return "rmdir"
	case "169":
		return "reboot"
	case "90":
		return "chmod"
	case "91":
		return "fchmod"
	case "268":
		return "fchmodat"
	case "452":
		return "fchmodat2"
	case "92":
		return "chown"
	case "93":
		return "fchown"
	case "94":
		return "lchown"
	case "260":
		return "fchownat"
	case "188":
		return "setxattr"
	case "189":
		return "lsetxattr"
	case "190":
		return "fsetxattr"
	case "197":
		return "removexattr"
	case "198":
		return "lremovexattr"
	case "199":
		return "fremovexattr"
	case "304":
		return "open_by_handle_at"
	}
	return r.Get("syscall")
}

func commandLine(ev *Event) string {
	if p := ev.First("PROCTITLE"); p != nil && p.Get("proctitle") != "" {
		return gnuName(p.Get("proctitle"))
	}
	if x := ev.First("EXECVE"); x != nil {
		var args []string
		for i := 0; ; i++ {
			v, ok := x.Fields[fmt.Sprintf("a%d", i)]
			if !ok {
				break
			}
			args = append(args, v)
		}
		return gnuName(strings.Join(args, " "))
	}
	return ""
}

// gnuName shows "gnurm -rf x" as "rm -rf x" (U12).
func gnuName(cmd string) string {
	f, rest, _ := strings.Cut(cmd, " ")
	dir, name := "", f
	if i := strings.LastIndex(f, "/"); i >= 0 {
		dir, name = f[:i+1], f[i+1:]
	}
	if c := coreutil(name); c != name {
		f = dir + c
		if rest != "" {
			return f + " " + rest
		}
		return f
	}
	return cmd
}

func (t *Translator) syscall(ev *Event, r *Record) *event.Event {
	actor := t.actor(r)
	// Changes to sudo rules, the account database and log files matter
	// whoever makes them; everything else is reported only for people.
	who := actor
	if who == "" {
		who = "A system process (no logged-in user)"
	}
	sc := syscallName(r)
	exe := r.Get("exe")
	prog := base(exe)
	cmd := commandLine(ev)
	if prog == "coreutils" && cmd != "" {
		prog = firstWord(cmd) // the Rust coreutils, one program for them all
	}
	if sc == "execve" || sc == "execveat" {
		t.remember(r.Time, t.hostOf(r), cmd, actor)
	}
	shown := firstNonEmpty(cmd, exe)
	using := ""
	if prog != "" {
		using = " (using " + prog + ")"
	}
	var paths []string
	for _, p := range ev.All("PATH") {
		if n := p.Get("name"); n != "" && p.Get("nametype") != "PARENT" {
			if !strings.HasPrefix(n, "/") {
				if cwd := ev.First("CWD"); cwd != nil && cwd.Get("cwd") != "" {
					n = path.Join(cwd.Get("cwd"), n)
				}
			}
			paths = append(paths, n)
		}
	}
	if r.Get("success") == "no" {
		return t.refusedAccess(r, actor, sc, paths, exe, cmd) // an attempt that did nothing
	}

	// Changes to who can use sudo.
	for _, p := range paths {
		if p == "/etc/sudoers" || strings.HasPrefix(p, "/etc/sudoers.d/") {
			e := &event.Event{Category: event.CatPrivileged, Severity: event.SevHigh, Action: "sudoers_changed",
				User: actor, Target: p, Process: exe, DedupeKey: "sudoers|" + p,
				Summary: fmt.Sprintf("%s changed the sudo rules: %s%s.", who, p, using)}
			e.AddDetail("File", p)
			e.AddDetail("Command", cmd)
			return e
		}
	}
	// The account database edited directly, not with the account tools.
	for _, p := range paths {
		if identityFiles[p] && !accountTools[prog] && !accountTools[r.Get("comm")] {
			e := &event.Event{Category: event.CatAccount, Severity: event.SevHigh, Action: "account_db_edited",
				User: actor, Target: p, Process: exe, DedupeKey: "iddb|" + p,
				Summary: fmt.Sprintf("%s edited %s directly%s instead of with the standard account tools.", who, p, using)}
			e.AddDetail("File", p)
			e.AddDetail("Command", cmd)
			return e
		}
	}
	// Log files deleted, renamed or emptied by a person. Ordinary writes are
	// not tampering: sudo appends to /var/log/sudo.log and logins update
	// wtmp and lastlog, and the STIG audit rules watch those files.
	for _, p := range paths {
		if actor != "" && strings.HasPrefix(p, "/var/log/") && destroysFile(sc, r) {
			e := &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_tampered",
				User: actor, Target: p, Process: exe, DedupeKey: "logfile|" + p,
				Summary: fmt.Sprintf("%s deleted, renamed or emptied the log file %s%s.", actor, p, using)}
			e.AddDetail("System call", sc)
			e.AddDetail("Command", cmd)
			return e
		}
	}

	if actor == "" {
		// Configuration management (Ansible or Salt through systemd-run)
		// runs with no login user, so its changes name no one. Changes to
		// the logon, SSH, audit and service settings are still shown, at
		// Low (I4); everything else is routine system activity.
		return t.unattendedChange(r, sc, paths, exe, cmd)
	}
	if e := t.watchedFile(r, actor, sc, paths, exe, cmd); e != nil {
		return e
	}
	switch sc {
	case "init_module", "finit_module":
		return &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "module_loaded", User: actor,
			Process: exe, Command: cmd, Summary: fmt.Sprintf("%s loaded a kernel module: %s", actor, shown)}
	case "delete_module":
		return &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "module_unloaded", User: actor,
			Process: exe, Command: cmd, Summary: fmt.Sprintf("%s unloaded a kernel module: %s", actor, shown)}
	case "clock_settime", "settimeofday", "adjtimex", "clock_adjtime", "stime":
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevMedium, Action: "time_changed", User: actor,
			Process: exe, Command: cmd, DedupeKey: "time|" + actor,
			Summary: fmt.Sprintf("%s changed the system time%s: %s", actor, using, shown)}
	case "mount":
		e := &event.Event{Category: event.CatOther, Severity: event.SevLow, Action: "filesystem_mounted", User: actor,
			Process: exe, Command: cmd, Summary: fmt.Sprintf("%s mounted a filesystem: %s", actor, shown)}
		switch mountKind(cmd) {
		case "disk":
			e.Category, e.Severity, e.Action = event.CatRemovable, event.SevMedium, "removable_mounted"
			e.Summary = fmt.Sprintf("%s mounted a disk: %s", actor, shown)
		case "network":
			e.Summary = fmt.Sprintf("%s mounted a network share: %s", actor, shown)
		}
		return e
	case "execve", "execveat":
		return t.execRecord(r, actor, exe, prog, cmd, shown)
	}
	return t.fileChange(r, actor, sc, paths, exe, cmd)
}

// unattendedSettings are the settings whose change is shown even when no
// one was logged on (I4).
var unattendedSettings = []struct{ prefix, what string }{
	{"/etc/pam.d/", "the logon rules (PAM)"},
	{"/etc/security/", "the logon security settings"},
	{"/etc/ssh/sshd_config", "the SSH server settings"},
	{"/etc/audit/", "the audit settings"},
	{"/etc/systemd/system/", "the services and timers (systemd)"},
	{"/usr/lib/systemd/system/", "the services and timers (systemd)"},
	{"/lib/systemd/system/", "the services and timers (systemd)"},
}

// unattendedChange is a change to logon, SSH, audit or service settings
// with no login user: configuration management, or a service. Software
// updates (package managers) are left out: their own records cover them.
func (t *Translator) unattendedChange(r *Record, sc string, paths []string, exe, cmd string) *event.Event {
	prog := base(exe)
	if packageManagers[prog] || packageManagers[r.Get("comm")] || sc == "execve" || sc == "execveat" || r.Get("key") == "" {
		return nil
	}
	for _, p := range paths {
		// The original logs waiting to be archived: changed by anything
		// but Blackbox, whoever ran it, is High (AR6).
		if strings.HasPrefix(p, "/var/lib/blackbox/archive-pieces/") && prog != "blackbox" {
			e := &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "blackbox_files_changed", Target: p, Process: exe, Command: cmd,
				DedupeKey: "unattended|" + p,
				Summary:   fmt.Sprintf("The original logs waiting to be archived were changed with no one logged on: %s%s.", p, usingProg(prog))}
			e.AddDetail("File", p)
			e.AddDetail("System call", sc)
			e.AddDetail("Command", cmd)
			e.AddDetail("Audit rule", r.Get("key"))
			e.AddDetail("Why no person", "The change ran without a login session (auid unset): a service, a scheduled job or a script started by one. Its own log, or the process that started it, says who.")
			return e
		}
		for _, u := range unattendedSettings {
			if !strings.HasPrefix(p, u.prefix) {
				continue
			}
			e := &event.Event{Category: event.CatOther, Severity: event.SevLow, Action: "unattended_change", Target: p, Process: exe, Command: cmd,
				DedupeKey: "unattended|" + p,
				Summary:   fmt.Sprintf("%s were changed with no one logged on (configuration management or a service): %s%s.", capitalize(u.what), p, usingProg(prog))}
			e.AddDetail("File", p)
			e.AddDetail("System call", sc)
			e.AddDetail("Command", cmd)
			e.AddDetail("Audit rule", r.Get("key"))
			e.AddDetail("Why no person", "The change ran without a login session (auid unset), as Ansible, Salt or another tool run through systemd-run does. The tool's own log says who started it.")
			return e
		}
	}
	return nil
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// execRecord is a program started under a keyed rule: a person's command
// running as root (root_commands), or a privileged program (execpriv),
// unless it belongs to sudo, su or the logon's own startup scripts.
func (t *Translator) execRecord(r *Record, actor, exe, prog, cmd, shown string) *event.Event {
	if setuidHelpers[prog] {
		t.endStartup(t.hostOf(r), r.Get("ses"))
		return nil
	}
	if e, skip := t.startup(r, actor, cmd); skip {
		return e
	}
	uid, euid := r.Get("uid"), r.Get("euid")
	key := r.Get("key")
	if key == "" && uid == euid {
		return nil
	}
	e := &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, User: actor, Process: exe, Command: cmd}
	if uid == "0" && euid == "0" {
		// A person's command running as root: from a root shell (sudo -i,
		// su) or started by sudo (then the sudo record is kept instead).
		e.Action = "root_command"
		e.DedupeKey, e.Priority = "cmd|"+actor+"|"+cmdKey(cmd), 1
		e.Summary = fmt.Sprintf("%s ran as root: %s", actor, shown)
	} else {
		e.Action = "privileged_program"
		e.Summary = fmt.Sprintf("%s ran the privileged program %s", actor, prog)
		if cmd != "" && cmd != prog {
			e.Summary += ": " + cmd
		} else {
			e.Summary += "."
		}
	}
	if tampers(cmd) {
		e.Action, e.Severity = "audit_tamper_command", event.SevHigh
		e.Summary = fmt.Sprintf("%s ran a command that can stop or weaken auditing: %s", actor, shown)
	} else {
		blackboxChange(e, cmd, actor)
	}
	e.AddDetail("Program", exe)
	e.AddDetail("Command", cmd)
	e.AddDetail("Runs as", t.Users.Name(euid))
	e.AddDetail("Audit rule", key)
	return e
}
