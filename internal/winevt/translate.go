package winevt

import (
	"fmt"
	"github.com/casea1/blackbox/internal/event"
	"strings"
	"time"
)

// Translator turns raw Windows events into normalized events.
type Translator struct {
	// ResolveSID looks up an account name for a SID. Optional; on a live
	// Windows system it asks the OS.
	ResolveSID func(sid string) string

	// MapDevicePath turns \Device\HarddiskVolumeN\… into a drive-letter
	// path. Optional; set on a live Windows system.
	MapDevicePath func(path string) string

	sidNames map[string]string    // learned from events seen so far
	logons   map[string]logonInfo // recent 4624s by host|logon ID
	psModule map[string]bool      // script block IDs found to be Windows' own module code (W3)
}

// NewTranslator returns a ready Translator.
func NewTranslator() *Translator {
	return &Translator{sidNames: map[string]string{}, logons: map[string]logonInfo{}, psModule: map[string]bool{}}
}

// Channels are the logs Blackbox reads on a live Windows system.
var Channels = []string{
	"Security",
	"System",
	"Microsoft-Windows-Partition/Diagnostic",
	"Microsoft-Windows-Kernel-PnP/Configuration",
	"Microsoft-Windows-DriverFrameworks-UserMode/Operational",
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-PowerShell/Operational",
	chApplication,
	chFirewall,
	chRDPLocal,
	chRDPRemote,
	chPrint,
}

// Translate returns the normalized event for r, or nil if r is not
// security-relevant (or is routine system noise).
func (t *Translator) Translate(r *Raw) *event.Event {
	t.learnSIDs(r)
	e := t.translate(r)
	if e == nil {
		return nil
	}
	e.Time = r.Time
	e.Host = shortHost(r.Computer)
	e.OS = "windows"
	e.Source = r.Channel
	e.EventID = r.EventID
	e.RecordID = r.RecordID
	if e.Severity == "" {
		e.Severity = event.SevInfo
	}
	if e.Fields == nil {
		e.Fields = r.Data
	}
	e.RedactSecrets()
	return e
}

func (t *Translator) translate(r *Raw) *event.Event {
	switch {
	case r.Channel == "Security" || r.Provider == "Microsoft-Windows-Security-Auditing":
		return t.security(r)
	case r.Channel == "System":
		return t.system(r)
	case r.Channel == "Microsoft-Windows-Partition/Diagnostic":
		return t.partition(r)
	case r.Channel == "Microsoft-Windows-Kernel-PnP/Configuration":
		return t.kernelPnP(r)
	case r.Channel == "Microsoft-Windows-DriverFrameworks-UserMode/Operational":
		return t.driverFrameworks(r)
	case r.Channel == "Microsoft-Windows-Windows Defender/Operational":
		return t.defender(r)
	case r.Channel == "Microsoft-Windows-PowerShell/Operational":
		return t.powerShell(r)
	case r.Channel == chApplication:
		return t.application(r)
	case r.Channel == chFirewall:
		return t.firewallLog(r)
	case r.Channel == chPrint:
		return t.printed(r)
	case r.Channel == chRDPLocal || r.Channel == chRDPRemote:
		return t.remoteDesktop(r)
	}
	return nil
}

// ---------------------------------------------------------------- Security

func (t *Translator) security(r *Raw) *event.Event {
	switch r.EventID {
	case 4624:
		return t.logonSuccess(r)
	case 4625:
		return t.logonFailure(r)
	case 4647:
		return t.logoff(r)
	case 4634:
		return t.sessionEnded(r)
	case 4778, 4779:
		return t.rdpSession(r)
	case 4648:
		return t.explicitCreds(r)
	case 4672:
		return t.specialPrivileges(r)
	case 4688:
		return t.processCreated(r)
	case 4697:
		return t.serviceInstalled(r, r.Get("ServiceName"), r.Get("ServiceFileName"), r.Get("ServiceAccount"), t.subject(r))
	case 4698, 4699, 4700, 4701, 4702:
		return t.scheduledTask(r)
	case 4719:
		return t.auditPolicyChanged(r)
	case 1100:
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevLow, Action: "eventlog_shutdown",
			Summary: "The event logging service shut down (normal during a system shutdown)."}
	case 1102:
		u := t.subject(r)
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_cleared",
			User: u, Target: "Security", Summary: fmt.Sprintf("The Security log was cleared by %s.", orUnknown(u))}
	case 1104:
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_full",
			Summary: "The Security log is full — new security events are not being recorded."}
	case 1105:
		e := &event.Event{Category: event.CatIntegrity, Severity: event.SevInfo, Action: "log_archived",
			Summary: "The Security log was automatically archived."}
		e.AddDetail("Archive file", r.Get("BackupPath"))
		return e
	case 1108:
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevMedium, Action: "eventlog_error",
			Summary: "The event logging service reported an error while processing events."}
	case 4608:
		return &event.Event{Category: event.CatIntegrity, Action: "system_start", DedupeKey: "boot", Priority: 1,
			Summary: "Windows started up."}
	case 4616:
		return t.timeChanged(r)
	case 4717, 4718:
		return t.systemAccess(r)
	case 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4767, 4781:
		return t.accountChange(r)
	case 4727, 4730, 4731, 4734, 4754, 4758:
		return t.groupLifecycle(r)
	case 4728, 4729, 4732, 4733, 4756, 4757:
		return t.groupMembership(r)
	case 4740:
		acct := r.Get("TargetUserName")
		e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevMedium, Action: "account_locked",
			User: acct, Target: acct, Outcome: "failure",
			Summary: fmt.Sprintf("Account %s was locked out after too many failed logon attempts.", acct)}
		e.AddDetail("Attempts came from", r.Get("TargetDomainName"))
		return e
	case 4771:
		return t.kerberosFailure(r)
	case 4776:
		return t.ntlmValidation(r)
	case 4656, 4663:
		return t.removableAccess(r)
	case 6416:
		return t.pnpDevice(r)
	}
	if e, ok := t.policySecurity(r); ok {
		return e
	}
	return t.otherSecurity(r)
}

// ---------------------------------------------------------------- helpers

// The translations themselves are in translate_*.go: logon, account,
// process, device, powershell (and Defender), policy (more Security-log
// events), channels (other logs) and other (untranslated events).

// account builds DOMAIN\user from the named fields, resolving the SID if
// the name is missing.
func (t *Translator) account(r *Raw, sidF, domF, userF string) string {
	u := joinAccount(r.Get(domF), r.Get(userF), r.Computer)
	if u == "" {
		u = t.resolve(r.Get(sidF))
	}
	return u
}

func (t *Translator) subject(r *Raw) string {
	// Windows names the computer account (WORKGROUP\HOST$) for actions
	// taken by the system itself; say "SYSTEM" as people know it.
	switch r.Get("SubjectUserSid") {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return wellKnownSIDs[r.Get("SubjectUserSid")]
	}
	return t.account(r, "SubjectUserSid", "SubjectDomainName", "SubjectUserName")
}

func (t *Translator) resolve(sid string) string {
	if sid == "" {
		return ""
	}
	if n, ok := wellKnownSIDs[sid]; ok {
		return n
	}
	if n, ok := t.sidNames[sid]; ok {
		return n
	}
	if t.ResolveSID != nil {
		if n := t.ResolveSID(sid); n != "" {
			t.sidNames[sid] = n
			return n
		}
	}
	return sid
}

// learnSIDs remembers SID→name pairs seen in events so later events that
// only carry a SID (e.g. group membership) can show a name.
func (t *Translator) learnSIDs(r *Raw) {
	for _, p := range [][3]string{
		{"TargetUserSid", "TargetDomainName", "TargetUserName"},
		{"SubjectUserSid", "SubjectDomainName", "SubjectUserName"},
	} {
		sid, name := r.Get(p[0]), r.Get(p[2])
		if sid != "" && name != "" && strings.HasPrefix(sid, "S-1-5-21-") {
			t.sidNames[sid] = joinAccount(r.Get(p[1]), name, r.Computer)
		}
	}
}

func (t *Translator) memberName(dn, sid string) string {
	if dn != "" {
		if strings.HasPrefix(strings.ToUpper(dn), "CN=") {
			cn := dn[3:]
			if i := strings.Index(cn, ","); i >= 0 {
				cn = cn[:i]
			}
			return cn
		}
		return dn
	}
	return t.resolve(sid)
}

// isServiceAccount reports built-in, service, virtual and computer
// accounts, whose routine activity is left out of the report.
func (t *Translator) isServiceAccount(sid, name string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-7", "S-1-0-0":
		return true
	}
	// S-1-5-111-: VIRTUAL USERS, such as the sshd_<pid> account OpenSSH for
	// Windows runs each connection's pre-logon stage as (W2).
	for _, p := range []string{"S-1-5-80-", "S-1-5-82-", "S-1-5-90-", "S-1-5-96-", "S-1-5-111-"} {
		if strings.HasPrefix(sid, p) {
			return true
		}
	}
	n := strings.ToUpper(name)
	switch n {
	case "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON":
		return true
	}
	return strings.HasPrefix(n, "DWM-") || strings.HasPrefix(n, "UMFD-") || sshdVirtual(n)
}

// sshdVirtual is OpenSSH for Windows' per-connection virtual account,
// "VIRTUAL USERS\sshd_<pid>": a new one for every connection, not a
// person (W2). The person's own logon follows it.
func sshdVirtual(name string) bool {
	n := strings.ToUpper(name)
	if i := strings.LastIndex(n, `\`); i >= 0 {
		n = n[i+1:]
	}
	rest, ok := strings.CutPrefix(n, "SSHD_")
	if !ok || rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ignoredAccount reports whether an event's Target or Subject account is
// one whose routine activity is left out: a built-in or service account,
// or a computer account. A name ending in "$" is a computer account only
// when it is this computer's own, or comes from a domain: a local account
// can be named "x$" to hide among computer accounts, so it is always kept.
func (t *Translator) ignoredAccount(r *Raw, who string) bool {
	sid, name, domain := r.Get(who+"UserSid"), r.Get(who+"UserName"), strings.TrimSpace(r.Get(who+"DomainName"))
	if t.isServiceAccount(sid, name) {
		return true
	}
	if !strings.HasSuffix(name, "$") {
		return false
	}
	host := shortHost(r.Computer)
	if strings.EqualFold(strings.TrimSuffix(name, "$"), host) {
		return true
	}
	local := domain == "" || domain == "-" || strings.EqualFold(domain, host) ||
		strings.EqualFold(domain, "Builtin") || strings.EqualFold(domain, "NT AUTHORITY")
	return !local
}

// qualifiedAccount normalizes a "DOMAIN\user" string.
func qualifiedAccount(s, computer string) string {
	if i := strings.Index(s, `\`); i >= 0 {
		return joinAccount(s[:i], s[i+1:], computer)
	}
	return joinAccount("", s, computer)
}

// joinAccount returns DOMAIN\user, or just user for local accounts and
// NT AUTHORITY.
func joinAccount(domain, user, computer string) string {
	user = strings.TrimSpace(user)
	domain = strings.TrimSpace(domain)
	if user == "" || user == "-" {
		return ""
	}
	if domain == "" || domain == "-" || strings.EqualFold(domain, "NT AUTHORITY") ||
		strings.EqualFold(domain, shortHost(computer)) || strings.EqualFold(domain, "Builtin") {
		return user
	}
	return domain + `\` + user
}

// accountName is an account without its domain.
func accountName(a string) string {
	if i := strings.LastIndex(a, `\`); i >= 0 {
		return a[i+1:]
	}
	return a
}

func shortHost(fqdn string) string {
	if i := strings.Index(fqdn, "."); i > 0 {
		return strings.ToUpper(fqdn[:i])
	}
	return strings.ToUpper(fqdn)
}

func cleanIP(ip string) string {
	ip = strings.TrimPrefix(strings.TrimSpace(ip), "::ffff:")
	switch ip {
	case "", "-", "::1", "127.0.0.1", "0.0.0.0", "::":
		return ""
	}
	return ip
}

func fromWhere(r *Raw, ip string) string {
	if ip != "" {
		return " from " + ip
	}
	if ws := r.Get("WorkstationName"); ws != "" && !strings.EqualFold(ws, shortHost(r.Computer)) {
		return " from workstation " + ws
	}
	return ""
}

func fromIP(ip string) string {
	if ip == "" {
		return ""
	}
	return " from " + ip
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown account"
	}
	return s
}

// winPath lets filepath.Base split Windows paths on any OS.
func winPath(p string) string { return strings.ReplaceAll(p, `\`, "/") }

func roundDur(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.1f hours", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	}
	return fmt.Sprintf("%.0f seconds", d.Seconds())
}

func trimFields(in map[string]string, drop ...string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		skip := false
		for _, d := range drop {
			if strings.HasPrefix(k, d) {
				skip = true
				break
			}
		}
		if !skip {
			out[k] = v
		}
	}
	return out
}
