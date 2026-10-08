// Commands: sudo (USER_CMD), su (USER_START), audit-tampering and
// Blackbox-changing commands, and the logon's own startup scripts
// (login message, root login shell profile) that are folded away.

package linuxlog

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// startup is a logon's own scripts running as root in a session: the
// login message (pam_motd runs /etc/update-motd.d) or a root login
// shell's profile (sudo -i, su -).
type startup struct {
	t    time.Time
	motd bool
}

// profileCommands are what /etc/profile, /etc/profile.d, /etc/bash.bashrc
// and the default .bashrc and .profile run when a login shell starts.
var profileCommands = map[string]bool{
	"locale-check": true, "id": true, "lesspipe": true, "dircolors": true, "tty": true, "mesg": true, "groups": true,
	"basename": true, "dirname": true, "uname": true, "locale": true, "hostname": true, "debuginfod-find": true,
	"byobu-launch": true, "byobu-launcher": true, "whoami": true,
}

// startup reports whether a root command belongs to a logon's own scripts
// rather than to the person. skip is true when it does; e is then the one
// line kept for them (the scripts starting), or nil for each command they
// run.
func (t *Translator) startup(r *Record, actor, cmd string) (e *event.Event, skip bool) {
	if actor == "" || r.Get("euid") != "0" {
		return nil, false
	}
	if t.starting == nil {
		t.starting = map[string]startup{}
	}
	k := t.hostOf(r) + "|" + r.Get("ses")
	f := strings.Fields(cmd)
	// A program the login message scripts started (by its parent process):
	// part of them however long they take (U4b).
	if t.motdPID(r) {
		return nil, true
	}
	switch {
	case loginMessage(f, cmd):
		t.notePID(r)
		if s, ok := t.starting[k]; ok && s.motd && r.Time.Sub(s.t) <= 30*time.Second {
			return nil, true // the same scripts, one more step of the chain
		}
		t.starting[k] = startup{r.Time, true}
		return &event.Event{Category: event.CatPrivileged, Severity: event.SevInfo, Action: "login_scripts", User: actor,
			Process: r.Get("exe"), Command: cmd, DedupeKey: "motd|" + actor,
			Summary: fmt.Sprintf("The login message scripts (/etc/update-motd.d) ran as root when %s logged on; the commands they ran are not listed.", actor)}, true
	case len(f) > 0 && strings.HasPrefix(f[0], "-") && shells[strings.TrimPrefix(base(f[0]), "-")]:
		t.starting[k] = startup{r.Time, false}
		return &event.Event{Category: event.CatPrivileged, Severity: event.SevInfo, Action: "login_scripts", User: actor,
			Process: r.Get("exe"), Command: cmd, DedupeKey: "rootlogin|" + actor,
			Summary: fmt.Sprintf("%s started a root login shell (%s); the commands its startup scripts ran are not listed.", actor, f[0])}, true
	}
	s, ok := t.starting[k]
	if !ok {
		return nil, false
	}
	switch {
	case s.motd && r.Time.Sub(s.t) <= 30*time.Second:
		// Everything run as root before the session itself starts is the
		// login message.
		t.notePID(r)
		return nil, true
	case !s.motd && r.Time.Sub(s.t) <= 3*time.Second && len(f) > 0:
		p := base(f[0])
		if profileCommands[p] || strings.Contains(cmd, "/etc/profile.d/") ||
			(p == "cat" && strings.Contains(cmd, "/etc/debuginfod/")) {
			return nil, true
		}
		return nil, false
	}
	delete(t.starting, k)
	return nil, false
}

// loginMessage says whether a root command starts the login message:
// pam_motd's "run-parts --lsbsysinit /etc/update-motd.d", directly or, on
// Ubuntu 26.04, through "sh -c -- /usr/bin/env -i PATH=… run-parts …",
// whose recorded command line is cut at 128 bytes (U4b), or one of the
// scripts in /etc/update-motd.d run by itself.
func loginMessage(f []string, cmd string) bool {
	if len(f) == 0 {
		return false
	}
	if strings.Contains(cmd, "run-parts") && strings.Contains(cmd, "/etc/update-mo") {
		switch base(f[0]) {
		case "run-parts", "sh", "dash", "bash", "env":
			return true
		}
	}
	for _, a := range f[:min(len(f), 2)] {
		if strings.HasPrefix(a, "/etc/update-motd.d/") {
			return true
		}
	}
	return false
}

// notePID remembers a login message process, so the programs it starts
// are folded with it (by their parent process ID).
func (t *Translator) notePID(r *Record) {
	if pid := r.Get("pid"); pid != "" {
		if t.motdPIDs == nil {
			t.motdPIDs = map[string]time.Time{}
		}
		t.motdPIDs[t.hostOf(r)+"|"+pid] = r.Time
	}
}

// motdPID says whether the record's parent is a login message process
// seen in the last few minutes; if so it is one too.
func (t *Translator) motdPID(r *Record) bool {
	at, ok := t.motdPIDs[t.hostOf(r)+"|"+r.Get("ppid")]
	if !ok || r.Get("ppid") == "" {
		return false
	}
	if r.Time.Sub(at) > 5*time.Minute {
		delete(t.motdPIDs, t.hostOf(r)+"|"+r.Get("ppid"))
		return false
	}
	t.notePID(r)
	return true
}

// inLoginMessage says whether a process (by its ID, or its parent's) is
// part of the login message scripts seen in the last few minutes, so what
// it does (an AppArmor denial, a file change) is folded into their row
// (U4c).
func (t *Translator) inLoginMessage(host, pid, ppid string, at time.Time) bool {
	for _, p := range []string{pid, ppid} {
		if p == "" {
			continue
		}
		if seen, ok := t.motdPIDs[host+"|"+p]; ok && at.Sub(seen) <= 5*time.Minute {
			return true
		}
	}
	return false
}

// endStartup marks a session's own scripts finished: the session has
// started, or the person ran sudo or su.
func (t *Translator) endStartup(host, ses string) {
	if t.starting != nil {
		delete(t.starting, host+"|"+ses)
	}
}

type recentCmd struct {
	t    time.Time
	host string
	cmd  string
	who  string
}

func (t *Translator) remember(tm time.Time, host, cmd, who string) {
	if cmd == "" {
		return
	}
	t.recent = append(t.recent, recentCmd{tm, host, cmd, who})
	if len(t.recent) > 32 {
		t.recent = t.recent[len(t.recent)-32:]
	}
}

// tampers reports whether a command line can stop, weaken or erase
// auditing or logging. Each command in it (split at ;, &&, || and |) is
// judged by its own program and arguments, so a command that only names
// /var/log/audit (ls, or a Blackbox report reading the log) is not
// tampering (U13). "sh -c ..." and sudo are looked through.
func tampers(cmd string) bool {
	for _, part := range splitCommands(cmd) {
		if tampersOne(strings.Fields(part)) {
			return true
		}
	}
	return false
}

var cmdSeparators = regexp.MustCompile(`;|&&|\|\||\||\n`)

func splitCommands(cmd string) []string {
	return cmdSeparators.Split(cmd, -1)
}

// loggingUnits are the services whose stopping stops auditing or logging.
var loggingUnits = map[string]bool{"auditd": true, "rsyslog": true, "syslog": true, "systemd-journald": true, "apparmor": true}

func tampersOne(f []string) bool {
	for i := range f {
		f[i] = strings.Trim(f[i], `"'`)
	}
	// Look through wrappers: sudo, env and VAR=value assignments.
	for len(f) > 0 {
		p := base(f[0])
		if p == "sudo" || p == "doas" || p == "env" || p == "nohup" || (strings.Contains(f[0], "=") && !strings.HasPrefix(f[0], "-")) {
			f = f[1:]
			for (p == "sudo" || p == "doas") && len(f) > 0 && strings.HasPrefix(f[0], "-") {
				f = f[1:] // sudo's own options
			}
			continue
		}
		break
	}
	if len(f) == 0 {
		return false
	}
	// A redirect that empties or overwrites a log: "> /var/log/x".
	for i, w := range f {
		target := ""
		switch {
		case w == ">" || w == ">>" || w == "1>" || w == "2>":
			if i+1 < len(f) {
				target = f[i+1]
			}
		case strings.HasPrefix(w, ">") || strings.HasPrefix(w, "1>") || strings.HasPrefix(w, "2>"):
			target = strings.TrimLeft(w, "12>")
		}
		if underVarLog(target) {
			return true
		}
	}
	prog, args := strings.ToLower(base(f[0])), f[1:]
	lower := make([]string, len(args))
	for i, a := range args {
		lower[i] = strings.ToLower(a)
	}
	has := func(w ...string) bool {
		for _, a := range lower {
			for _, x := range w {
				if a == x {
					return true
				}
			}
		}
		return false
	}
	switch prog {
	case "sh", "bash", "dash", "zsh", "ksh":
		for i, a := range args {
			if a == "-c" && i+1 < len(args) {
				return tampers(strings.Join(args[i+1:], " "))
			}
		}
	case "systemctl":
		if !has("stop", "disable", "mask", "kill") {
			return false
		}
		for _, a := range lower {
			if loggingUnits[strings.TrimSuffix(a, ".service")] {
				return true
			}
		}
	case "service":
		return len(lower) >= 2 && loggingUnits[lower[0]] && lower[1] == "stop"
	case "auditctl":
		for i, a := range args {
			if a == "-D" || a == "-d" || a == "-e0" || (a == "-e" && i+1 < len(args) && args[i+1] == "0") {
				return true
			}
		}
	case "aa-teardown", "aa-disable", "aa-complain":
		return true
	case "setenforce":
		return has("0", "permissive")
	case "journalctl":
		for _, a := range lower {
			if strings.HasPrefix(a, "--vacuum") || a == "--rotate" {
				return true
			}
		}
	case "history":
		return has("-c")
	case "unset":
		return has("histfile")
	case "rm", "gnurm", "shred", "truncate", "mv", "gnumv", "unlink":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") && underVarLog(a) {
				return true
			}
		}
	}
	return false
}

func underVarLog(p string) bool {
	p = strings.Trim(p, `"'`)
	return p == "/var/log" || strings.HasPrefix(p, "/var/log/")
}

var shells = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "-bash": true}

func firstWord(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	return base(f[0])
}

// cmdKey identifies a command for merging sudo's record with the program
// it ran: the program's name without its folder, and every argument, so
// "systemctl status cron" and "systemctl stop rsyslog" stay apart.
func cmdKey(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	f[0] = base(f[0])
	return strings.Join(f, " ")
}

// blackboxChange marks a command that changes Blackbox itself (A5, U9):
// a setting, its schedule, or removing it.
func blackboxChange(e *event.Event, cmd, who string) bool {
	action, sev, what, ok := event.BlackboxChange(cmd)
	if !ok {
		return false
	}
	e.Action, e.Severity, e.Category = action, sev, event.CatIntegrity
	e.Summary = fmt.Sprintf("%s %s: %s", who, what, cmd)
	return true
}

func (t *Translator) userCmd(r *Record) *event.Event {
	actor := t.actor(r)
	if actor == "" {
		actor = t.Users.Name(r.Get("uid"))
	}
	cmd := r.Get("cmd")
	t.remember(r.Time, t.hostOf(r), cmd, actor)
	e := &event.Event{Category: event.CatPrivileged, User: actor, Command: cmd, Process: r.Get("exe"),
		DedupeKey: "cmd|" + actor + "|" + cmdKey(cmd), Priority: 2}
	switch {
	case r.Get("res") == "failed":
		e.Action, e.Severity, e.Outcome = "sudo_denied", event.SevMedium, "failure"
		e.Summary = fmt.Sprintf("%s tried to run a command with sudo but was not permitted: %s", orUnknown(actor), cmd)
	case tampers(cmd):
		e.Action, e.Severity = "audit_tamper_command", event.SevHigh
		e.Summary = fmt.Sprintf("%s used sudo to run a command that can stop or weaken auditing: %s", orUnknown(actor), cmd)
	case blackboxChange(e, cmd, orUnknown(actor)):
	case shells[firstWord(cmd)] || strings.TrimSpace(cmd) == "-i" || strings.TrimSpace(cmd) == "-s":
		e.Action, e.Severity = "root_shell", event.SevLow
		e.Summary = fmt.Sprintf("%s opened a root shell with sudo (commands run in it are listed as \"ran as root\").", orUnknown(actor))
	default:
		e.Action, e.Severity = "sudo_command", event.SevLow
		e.Summary = fmt.Sprintf("%s ran with sudo: %s", orUnknown(actor), cmd)
	}
	e.AddDetail("Command", cmd)
	e.AddDetail("Working directory", r.Get("cwd"))
	e.AddDetail("Terminal", r.Get("terminal"))
	return e
}

func (t *Translator) userStart(r *Record) *event.Event {
	t.endStartup(t.hostOf(r), r.Get("ses"))
	if r.Get("res") != "success" {
		return nil
	}
	if program(r.Get("exe")) == "sshd" {
		return t.sshSessionStart(r)
	}
	actor, acct := t.actor(r), t.acct(r)
	switch base(r.Get("exe")) {
	case "su":
		if acct == "" || acct == actor {
			return nil
		}
		e := &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, Action: "switch_user", User: actor, Target: acct,
			Summary: fmt.Sprintf("%s switched to %s with su.", orUnknown(actor), acct)}
		if acct == "root" {
			e.Summary = fmt.Sprintf("%s switched to root with su (a root shell: commands run in it are listed as \"ran as root\").", orUnknown(actor))
		}
		e.AddDetail("Terminal", r.Get("terminal"))
		return e
	case "pkexec":
		return &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, Action: "pkexec", User: actor, Target: acct,
			Summary: fmt.Sprintf("%s ran a program as %s with pkexec.", orUnknown(actor), orUnknown(acct))}
	}
	return nil
}
