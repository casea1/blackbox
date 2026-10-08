// Logons and sign-in failures: 4624/4625, logoffs, Remote Desktop
// reconnects, explicit credentials, administrator logons, Kerberos
// and NTLM failures.

package winevt

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

type logonInfo struct{ logonType, ip string }

func (t *Translator) logonSuccess(r *Raw) *event.Event {
	lt := r.Get("LogonType")
	user := t.account(r, "TargetUserSid", "TargetDomainName", "TargetUserName")
	if lt == "0" || lt == "5" || t.ignoredAccount(r, "Target") {
		return nil
	}
	e := &event.Event{Category: event.CatLogon, Action: "logon", User: user, Outcome: "success",
		SourceIP: cleanIP(r.Get("IpAddress")), Interactive: interactiveLogon(lt) || lt == "7" || lt == "13"}
	if len(t.logons) > 100000 {
		t.logons = map[string]logonInfo{}
	}
	t.logons[r.Computer+"|"+r.Get("TargetLogonId")] = logonInfo{lt, e.SourceIP}
	admin := r.Get("ElevatedToken") == "%%1842"
	how, name := logonHow(r, lt)
	e.Summary = fmt.Sprintf("%s logged on %s%s", user, how, fromWhere(r, e.SourceIP))
	if admin {
		e.Summary += " with administrator rights"
	}
	e.Summary += "."
	// An administrator's interactive logon is recorded twice (UAC's full
	// and filtered tokens, linked to each other): report it once, keeping
	// the one with administrator rights.
	if linked := r.Get("TargetLinkedLogonId"); linked != "" && linked != "0x0" {
		a, b := strings.ToLower(r.Get("TargetLogonId")), strings.ToLower(linked)
		if b < a {
			a, b = b, a
		}
		e.DedupeKey, e.Priority = "linkedlogon|"+a+"|"+b, 1
		if admin {
			e.Priority = 2
		}
	} else if lt == "10" {
		// Also in the Remote Desktop session log (A7); keep this one.
		e.DedupeKey, e.Priority = "rdplogon|"+strings.ToLower(accountName(user))+"|"+e.SourceIP, 1
	}
	e.AddDetail("Logon type", name)
	e.AddDetail("Source address", e.SourceIP)
	e.AddDetail("Source workstation", r.Get("WorkstationName"))
	e.AddDetail("Authentication", r.Get("AuthenticationPackageName"))
	e.AddDetail("Process", r.Get("ProcessName"))
	e.AddDetail("Logon ID", r.Get("TargetLogonId"))
	return e
}

func (t *Translator) logonFailure(r *Raw) *event.Event {
	lt := r.Get("LogonType")
	user := joinAccount(r.Get("TargetDomainName"), r.Get("TargetUserName"), r.Computer)
	if user == "" {
		user = "(no user name given)"
	}
	reason := failureReason(r.Get("Status"), r.Get("SubStatus"))
	e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
		User: user, Target: user, Outcome: "failure", SourceIP: cleanIP(r.Get("IpAddress")),
		Process: r.Get("ProcessName"),
		// 4776 is logged alongside 4625 for local accounts; keep this one.
		// 4776 names the account without a domain.
		DedupeKey: "authfail|" + strings.ToLower(accountName(user)), Priority: 2}
	how, name := logonHow(r, lt)
	e.Summary = fmt.Sprintf("Failed logon for %s %s%s — %s.", user, how, fromWhere(r, e.SourceIP), reason)
	e.AddDetail("Reason", reason)
	e.AddDetail("Logon type", name)
	e.AddDetail("Source address", e.SourceIP)
	e.AddDetail("Source workstation", r.Get("WorkstationName"))
	e.AddDetail("Process", r.Get("ProcessName"))
	e.AddDetail("Status code", r.Get("Status"))
	e.AddDetail("Sub-status code", r.Get("SubStatus"))
	return e
}

func (t *Translator) logoff(r *Raw) *event.Event {
	user := t.account(r, "TargetUserSid", "TargetDomainName", "TargetUserName")
	if t.ignoredAccount(r, "Target") {
		return nil
	}
	e := &event.Event{Category: event.CatLogon, Action: "logoff", User: user, Outcome: "success",
		Summary:   fmt.Sprintf("%s logged off.", user),
		DedupeKey: "logoff|" + strings.ToLower(r.Get("TargetLogonId")), Priority: 2}
	e.AddDetail("Logon ID", r.Get("TargetLogonId"))
	return e
}

// sessionEnded reports the end of a person's session (4634). A logoff the
// person chose is also recorded as 4647, which is kept instead; 4634 alone
// means the session was ended for them (logged off by an administrator,
// or an idle or disconnect time limit).
func (t *Translator) sessionEnded(r *Raw) *event.Event {
	if !interactiveLogon(r.Get("LogonType")) || t.ignoredAccount(r, "Target") {
		return nil
	}
	user := t.account(r, "TargetUserSid", "TargetDomainName", "TargetUserName")
	e := &event.Event{Category: event.CatLogon, Action: "logoff", User: user, Outcome: "success",
		Summary:   fmt.Sprintf("%s's session ended (logged off by the system or an administrator, or it timed out).", user),
		DedupeKey: "logoff|" + strings.ToLower(r.Get("TargetLogonId")), Priority: 1}
	e.AddDetail("Logon type", logonTypeName(r.Get("LogonType")))
	e.AddDetail("Logon ID", r.Get("TargetLogonId"))
	return e
}

// logonHow describes how someone logged on. Logons through the Windows
// OpenSSH server are shown as SSH rather than by their logon type (often
// "network with a clear-text password", which would read as an alarm).
func logonHow(r *Raw, lt string) (phrase, name string) {
	for _, p := range []string{r.Get("LogonProcessName"), r.Get("ProcessName")} {
		if strings.Contains(strings.ToLower(p), "sshd") {
			return "via SSH (OpenSSH)", "SSH (OpenSSH)"
		}
	}
	return logonTypePhrase(lt), logonTypeName(lt)
}

func (t *Translator) rdpSession(r *Raw) *event.Event {
	user := joinAccount(r.Get("AccountDomain"), r.Get("AccountName"), r.Computer)
	client := r.Get("ClientName")
	addr := cleanIP(r.Get("ClientAddress"))
	from := ""
	if client != "" && client != "Unknown" {
		from = " from " + client
		if addr != "" {
			from += " (" + addr + ")"
		}
	} else if addr != "" {
		from = " from " + addr
	}
	// The Remote Desktop session log records the same; keep this one.
	e := &event.Event{Category: event.CatLogon, User: user, SourceIP: addr, Priority: 1}
	if r.EventID == 4778 {
		e.Action, e.Summary = "session_reconnected", fmt.Sprintf("%s reconnected to a Remote Desktop session%s.", user, from)
		e.DedupeKey = "rdprecon|" + strings.ToLower(accountName(user))
	} else {
		e.Action, e.Summary = "session_disconnected", fmt.Sprintf("%s disconnected from a Remote Desktop session%s.", user, from)
		e.DedupeKey = "rdpdisc|" + strings.ToLower(accountName(user))
	}
	return e
}

func (t *Translator) explicitCreds(r *Raw) *event.Event {
	subj := t.subject(r)
	if t.ignoredAccount(r, "Subject") {
		return nil
	}
	target := joinAccount(r.Get("TargetDomainName"), r.Get("TargetUserName"), r.Computer)
	if strings.EqualFold(r.Get("TargetUserName"), r.Get("SubjectUserName")) {
		return nil // same account (e.g. mapping a drive with saved creds)
	}
	proc := strings.TrimSpace(r.Get("ProcessName"))
	if proc == "-" {
		proc = "" // none recorded
	}
	e := &event.Event{Category: event.CatPrivileged, Severity: event.SevMedium, Action: "explicit_credentials",
		User: subj, Target: target, Process: proc, SourceIP: cleanIP(r.Get("IpAddress"))}
	e.Summary = fmt.Sprintf("%s used the credentials of %s", subj, target)
	// svchost/lsass/consent are the Windows plumbing behind RunAs and UAC
	// prompts, not the program the person meant to run. With no process
	// name there is nothing to name ("to run ." before, UI21).
	if proc != "" {
		switch name := filepath.Base(winPath(proc)); strings.ToLower(name) {
		case "", ".", "/", "svchost.exe", "lsass.exe", "consent.exe":
		default:
			e.Summary += " to run " + name
		}
	}
	if srv := r.Get("TargetServerName"); srv != "" && !strings.EqualFold(srv, "localhost") {
		e.Summary += " against " + srv
	}
	e.Summary += " (RunAs / alternate credentials)."
	e.AddDetail("Account used", target)
	e.AddDetail("Target server", r.Get("TargetServerName"))
	e.AddDetail("Process", proc)
	return e
}

func (t *Translator) specialPrivileges(r *Raw) *event.Event {
	if t.ignoredAccount(r, "Subject") {
		return nil
	}
	user := t.subject(r)
	privs := strings.Fields(r.Get("PrivilegeList"))
	e := &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, Action: "admin_logon", User: user,
		Summary:   fmt.Sprintf("%s logged on with administrator privileges.", user),
		DedupeKey: "4672|" + r.Get("SubjectLogonId")}
	if li, ok := t.logons[r.Computer+"|"+r.Get("SubjectLogonId")]; ok {
		how := logonTypePhrase(li.logonType)
		if li.ip != "" {
			how += " from " + li.ip
		}
		e.SourceIP = li.ip
		e.Summary = fmt.Sprintf("%s logged on %s with administrator privileges.", user, how)
		e.AddDetail("Logon type", logonTypeName(li.logonType))
	}
	var named []string
	for _, p := range privs {
		if d, ok := privilegeNames[p]; ok {
			named = append(named, p+" ("+d+")")
		} else {
			named = append(named, p)
		}
	}
	e.AddDetail("Privileges", strings.Join(named, ", "))
	e.AddDetail("Logon ID", r.Get("SubjectLogonId"))
	return e
}

func (t *Translator) kerberosFailure(r *Raw) *event.Event {
	user := r.Get("TargetUserName")
	code := normHex(r.Get("Status"))
	reason, ok := kerberosFailure[code]
	if !ok {
		reason = "Kerberos error " + code
	}
	ip := cleanIP(r.Get("IpAddress"))
	e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
		User: user, Target: user, Outcome: "failure", SourceIP: ip,
		Summary: fmt.Sprintf("Failed domain (Kerberos) logon for %s%s — %s.", user, fromIP(ip), reason)}
	e.AddDetail("Reason", reason)
	e.AddDetail("Source address", ip)
	e.AddDetail("Status code", r.Get("Status"))
	return e
}

func (t *Translator) ntlmValidation(r *Raw) *event.Event {
	status := normHex(r.Get("Status"))
	if status == "0x0" || status == "" {
		return nil
	}
	user := r.Get("TargetUserName")
	ws := r.Get("Workstation")
	reason := failureReason(status, "")
	e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
		User: user, Target: user, Outcome: "failure",
		DedupeKey: "authfail|" + strings.ToLower(accountName(user)), Priority: 1}
	e.Summary = fmt.Sprintf("Password check failed for %s", user)
	if ws != "" && !strings.EqualFold(ws, shortHost(r.Computer)) {
		e.Summary += " from workstation " + ws
	}
	e.Summary += " — " + reason + "."
	e.AddDetail("Reason", reason)
	e.AddDetail("Workstation", ws)
	e.AddDetail("Status code", r.Get("Status"))
	return e
}
