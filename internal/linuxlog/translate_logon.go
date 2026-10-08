// Logons and failed logons from auditd (USER_LOGIN, USER_AUTH, USER_ACCT,
// and USER_START for SSH sessions), including the name tried in an
// unknown-user SSH attempt.

package linuxlog

import (
	"fmt"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

type triedName struct {
	t               time.Time
	host, pid, addr string
	name            string
}

// triedName is the account name of the latest failed SSH password check
// by the same sshd process, just before it recorded the logon as an
// unknown user. Only a record with no process ID falls back to the check
// from the same address a moment before: OpenSSH 10 records the unknown
// name before the check, and the address alone then picked another
// connection's account (U5). The report joins a check that comes after
// (sshAttempts).
func (t *Translator) triedName(tm time.Time, host, pid, addr string) string {
	for i := len(t.tried) - 1; i >= 0; i-- {
		x := t.tried[i]
		if x.host != host || x.t.After(tm) || tm.Sub(x.t) > 2*time.Minute {
			continue
		}
		if pid != "" && x.pid == pid {
			return x.name
		}
	}
	if pid != "" {
		return ""
	}
	for i := len(t.tried) - 1; i >= 0; i-- {
		x := t.tried[i]
		if x.host == host && x.addr == addr && !x.t.After(tm) && tm.Sub(x.t) <= 3*time.Second {
			return x.name
		}
	}
	return ""
}

// session describes how someone logged on.
func session(exe, terminal string) (phrase, label string) {
	b := program(exe)
	switch {
	case b == "sshd" || terminal == "ssh":
		return "via SSH", "SSH"
	case strings.Contains(b, "xrdp"):
		// Remote, not at the machine: must not be treated as the console
		// user when a USB device is plugged in.
		return "via Remote Desktop (RDP)", "Remote Desktop"
	case strings.Contains(b, "gdm") || strings.Contains(b, "lightdm") || strings.Contains(b, "sddm"):
		return "at the graphical console", "Graphical console"
	case b == "login" || strings.HasPrefix(terminal, "tty") || strings.HasPrefix(terminal, "/dev/tty"):
		return "at the text console", "Text console"
	case b == "cockpit-session":
		return "via the Cockpit web console", "Cockpit"
	case b != "":
		return "via " + b, b
	}
	return "", "Unknown"
}

func cleanAddr(a string) string {
	a = strings.TrimPrefix(strings.TrimSpace(a), "::ffff:")
	switch a {
	case "", "?", "0.0.0.0", "::", "UNKNOWN":
		return ""
	case "::1", "127.0.0.1":
		// A logon from this computer to itself: still one source, so
		// several accounts tried from it is still noticed.
		return "localhost"
	}
	return a
}

func fromAddr(a string) string {
	if a == "" {
		return ""
	}
	return " from " + a
}

func (t *Translator) userLogin(r *Record) *event.Event {
	acct := t.acct(r)
	exe, term := r.Get("exe"), r.Get("terminal")
	addr := cleanAddr(r.Get("addr"))
	if addr == "" && program(exe) == "sshd" {
		addr = cleanAddr(r.Get("hostname")) // for other programs it is this machine's own name
	}
	how, label := session(exe, term)
	if r.Get("res") == "success" {
		return logon(acct, how, label, addr, term, exe)
	}
	reason := "wrong password"
	if program(exe) == "sshd" {
		reason = "wrong password or key"
	}
	if acct == "" || strings.Contains(acct, "invalid") {
		// sshd records "(invalid user)" here; the name that was tried is
		// in the password check (USER_AUTH) just before it.
		acct, reason = "(unknown user name)", "the user name does not exist"
		if n := t.triedName(r.Time, t.hostOf(r), r.Get("pid"), addr); n != "" {
			acct = n
		}
	}
	return t.failedLogon(acct, how, label, addr, term, exe, reason, 2)
}

func logon(acct, how, label, addr, term, exe string) *event.Event {
	if acct == "" {
		return nil
	}
	e := &event.Event{Category: event.CatLogon, Action: "logon", User: acct, Outcome: "success", SourceIP: addr,
		Interactive: true, Summary: fmt.Sprintf("%s logged on %s%s.", acct, how, fromAddr(addr)), DedupeKey: logonKey(acct, addr)}
	e.AddDetail("Logon type", label)
	e.AddDetail("Source address", addr)
	e.AddDetail("Terminal", term)
	e.AddDetail("Program", exe)
	return e
}

// sshSessionStart is the logon of an SSH session sshd opened (USER_START).
// Ubuntu 26.04's sshd-session writes no USER_LOGIN record, so this is
// the only audit record of the sign-in (LNX1). Where sshd does write
// USER_LOGIN, the two have the same DedupeKey and the report shows one
// row, as it does with sshd's "Accepted" line in auth.log, which says how
// the person signed in.
func (t *Translator) sshSessionStart(r *Record) *event.Event {
	exe, term := r.Get("exe"), r.Get("terminal")
	addr := cleanAddr(r.Get("addr"))
	if addr == "" {
		addr = cleanAddr(r.Get("hostname"))
	}
	how, label := session(exe, term)
	return logon(t.acct(r), how, label, addr, term, exe)
}

func (t *Translator) failedLogon(acct, how, label, addr, term, exe, reason string, prio int) *event.Event {
	e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
		User: acct, Target: acct, Outcome: "failure", SourceIP: addr,
		DedupeKey: "authfail|" + program(exe) + "|" + addr + "|" + term + "|" + acct, Priority: prio,
		Summary: fmt.Sprintf("Failed logon for %s %s%s — %s.", acct, how, fromAddr(addr), reason)}
	e.AddDetail("Reason", reason)
	e.AddDetail("Logon type", label)
	e.AddDetail("Source address", addr)
	e.AddDetail("Terminal", term)
	e.AddDetail("Program", exe)
	return e
}

func (t *Translator) userAuth(r *Record) *event.Event {
	if r.Get("res") != "failed" {
		return nil
	}
	actor, acct := t.actor(r), t.acct(r)
	exe, term := r.Get("exe"), r.Get("terminal")
	addr := cleanAddr(r.Get("addr"))
	switch program(exe) {
	case "sudo":
		e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
			User: actor, Target: actor, Outcome: "failure",
			Summary: fmt.Sprintf("%s entered a wrong password for sudo.", orUnknown(actor))}
		e.AddDetail("Terminal", term)
		return e
	case "su":
		target := acct
		if target == "" {
			target = "root"
		}
		e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
			User: actor, Target: target, Outcome: "failure",
			Summary: fmt.Sprintf("%s failed to switch to %s with su — wrong password.", orUnknown(actor), target)}
		e.AddDetail("Terminal", term)
		return e
	case "unix_chkpwd":
		return nil // helper called by other programs, which log their own failure
	}
	how, label := session(exe, term)
	if acct == "" {
		acct = "(unknown user name)"
	} else if program(exe) == "sshd" {
		t.tried = append(t.tried, triedName{r.Time, t.hostOf(r), r.Get("pid"), addr, acct})
		if len(t.tried) > 32 {
			t.tried = t.tried[len(t.tried)-32:]
		}
	}
	// The password check can't tell a wrong password from a name that
	// doesn't exist; the report corrects it when sshd says which.
	return t.failedLogon(acct, how, label, addr, term, exe, "wrong password", 1)
}

func (t *Translator) userAcct(r *Record) *event.Event {
	if r.Get("res") != "failed" {
		return nil
	}
	acct := t.acct(r)
	how, label := session(r.Get("exe"), r.Get("terminal"))
	return t.failedLogon(orUnknown(acct), how, label, cleanAddr(r.Get("addr")), r.Get("terminal"), r.Get("exe"),
		"the account is expired, locked or not allowed to log on this way", 1)
}
