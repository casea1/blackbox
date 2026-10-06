package winevt

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// Security-log events beyond logons, accounts and processes: audit and
// security-system integrity, policy and trust changes, the firewall, code
// integrity, shares, registry and permission changes (A1, A2).

// yes reads a yes/no value: Windows writes "Yes"/"No" or the message
// tokens %%1842/%%1843 (and %%8843/%%8844 in some events).
func yes(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "%%1842", "%%8844", "true", "1":
		return true
	}
	return false
}

// standardLSA are the packages and logon processes every Windows computer
// loads at startup (4611, 4614, 4622). Anything else is how password
// filters and credential stealers get into LSA.
var standardLSA = []string{
	"kerberos", "msv1_0", "ntlm", "negoexts", "negotiate", "pku2u", "cloudap", "wdigest", "schannel",
	"tspkg", "tsssp", "credssp", "livessp", "scecli", "rassfm", "microsoft unified security protocol provider",
	"default tls ssp", "winlogon", "secondary logon service", "seclogon", "consent", "credprov", "user32logonprocesss",
	"iisadmin", "w3svc", "ntlmssp", "wsmprovhost", "wsmsvc", "sspi", "pwdssp", "advapi", "mmc", "rdp",
}

func standardPackage(name string) bool {
	n := strings.ToLower(name)
	if n == "" {
		return true
	}
	for _, s := range standardLSA {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// sensitiveRights are user rights that give control of the computer.
var sensitiveRights = map[string]bool{
	"SeDebugPrivilege": true, "SeTcbPrivilege": true, "SeBackupPrivilege": true, "SeRestorePrivilege": true,
	"SeTakeOwnershipPrivilege": true, "SeLoadDriverPrivilege": true, "SeImpersonatePrivilege": true,
	"SeSecurityPrivilege": true, "SeAssignPrimaryTokenPrivilege": true, "SeCreateTokenPrivilege": true,
	"SeEnableDelegationPrivilege": true, "SeManageVolumePrivilege": true, "SeRelabelPrivilege": true,
	"SeSystemEnvironmentPrivilege": true, "SeRemoteInteractiveLogonRight": true, "SeInteractiveLogonRight": true,
}

// policySecurity translates the events this file covers, or reports that
// it doesn't (ok false).
func (t *Translator) policySecurity(r *Raw) (e *event.Event, ok bool) {
	switch r.EventID {
	case 4612:
		e = &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "audit_events_dropped",
			Summary: "Windows ran out of room to queue audit events and some were lost."}
		if n := r.Get("AuditsDiscarded"); n != "" {
			e.Summary = fmt.Sprintf("Windows ran out of room to queue audit events and lost %s of them.", n)
			e.AddDetail("Events lost", n)
		}
	case 4611, 4614, 4622:
		e = t.lsaPackage(r)
	case 4704, 4705:
		e = t.userRight(r)
	case 4739:
		e = t.domainPolicy(r)
	case 4713:
		e = &event.Event{Category: event.CatAccount, Severity: event.SevMedium, Action: "kerberos_policy_changed", User: t.subject(r),
			Summary: fmt.Sprintf("The Kerberos policy was changed by %s.", orUnknown(t.subject(r)))}
		e.AddDetail("Changes", r.Get("KerberosPolicyChange"))
	case 4706, 4707, 4716:
		e = t.trust(r)
	case 4826:
		e = bootConfig(r, t.subject(r))
	case 4907:
		e = t.saclChanged(r)
	case 4946, 4947, 4948, 4949, 4950:
		e = firewallChange(r)
	case 5024:
		e = &event.Event{Category: event.CatIntegrity, Severity: event.SevInfo, Action: "firewall_started",
			DedupeKey: "fwstart", Summary: "The Windows Firewall service started."}
	case 5025:
		e = &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "firewall_stopped",
			Summary: "The Windows Firewall service was stopped — the computer is not protected by its firewall."}
	case 5030:
		e = &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "firewall_failed",
			Summary: "The Windows Firewall service failed to start — the computer is not protected by its firewall."}
	case 5038, 6281:
		e = codeIntegrity(r)
	case 5140, 5145:
		e = t.shareAccess(r)
	case 4657:
		e = t.registryChange(r)
	case 4670:
		e = t.permissionsChanged(r)
	case 4765, 4766:
		e = t.sidHistory(r)
	case 4800, 4801:
		u := t.account(r, "TargetUserSid", "TargetDomainName", "TargetUserName")
		verb := "locked"
		if r.EventID == 4801 {
			verb = "unlocked"
		}
		e = &event.Event{Category: event.CatLogon, Severity: event.SevInfo, Action: "workstation_" + verb, User: u,
			Summary: fmt.Sprintf("%s %s the computer.", orUnknown(u), verb)}
	default:
		return nil, false
	}
	return e, true
}

func (t *Translator) lsaPackage(r *Raw) *event.Event {
	var name, what string
	switch r.EventID {
	case 4611:
		name, what = r.Get("LogonProcessName"), "trusted logon process registered with"
	case 4614:
		name, what = r.Get("NotificationPackageName"), "password notification package loaded by"
	default:
		name, what = r.Get("SecurityPackageName"), "security package loaded by"
	}
	e := &event.Event{Category: event.CatIntegrity, Action: "lsa_package", Target: name, DedupeKey: "lsa|" + strings.ToLower(name)}
	if standardPackage(name) {
		e.Severity = event.SevInfo
		e.Summary = fmt.Sprintf("A standard %s the Local Security Authority: %s.", what, name)
	} else {
		e.Severity = event.SevHigh
		e.Summary = fmt.Sprintf("An unusual %s the Local Security Authority: %s. Programs here see every password; check it is expected.", what, name)
	}
	e.AddDetail("Package", name)
	return e
}

func (t *Translator) userRight(r *Raw) *event.Event {
	who := t.subject(r)
	target := t.resolve(r.Get("TargetSid"))
	rights := strings.Fields(r.Get("PrivilegeList"))
	verb, to := "gave", "to"
	if r.EventID == 4705 {
		verb, to = "removed", "from"
	}
	sev := event.SevMedium
	for _, p := range rights {
		if sensitiveRights[p] && r.EventID == 4704 {
			sev = event.SevHigh
		}
	}
	e := &event.Event{Category: event.CatAccount, Severity: sev, Action: "user_right_" + map[bool]string{true: "assigned", false: "removed"}[r.EventID == 4704],
		User: who, Target: target,
		Summary: fmt.Sprintf("%s %s the user right %s %s %s.", orUnknown(who), verb, strings.Join(rights, ", "), to, orUnknown(target))}
	e.AddDetail("Rights", strings.Join(rights, ", "))
	e.AddDetail("Account", target)
	return e
}

func (t *Translator) domainPolicy(r *Raw) *event.Event {
	who := t.subject(r)
	var changed []string
	// Plain labels: "MinPasswordLength = 8" would read as a password and
	// be hidden from the report.
	for _, f := range [][2]string{{"MinPasswordAge", "minimum age"}, {"MaxPasswordAge", "maximum age"}, {"ForceLogoff", "force logoff"},
		{"LockoutThreshold", "lockout after"}, {"LockoutObservationWindow", "lockout counter reset"}, {"LockoutDuration", "lockout duration"},
		{"PasswordProperties", "complexity flags"}, {"MinPasswordLength", "minimum length"}, {"PasswordHistoryLength", "history kept"},
		{"MachineAccountQuota", "computer account quota"}, {"MixedDomainMode", "mixed mode"}, {"DomainBehaviorVersion", "functional level"},
		{"OemInformation", "OEM information"}} {
		if v := r.Get(f[0]); v != "" {
			changed = append(changed, f[1]+" "+v)
		}
	}
	e := &event.Event{Category: event.CatAccount, Severity: event.SevMedium, Action: "domain_policy_changed", User: who,
		Target:  r.Get("DomainName"),
		Summary: fmt.Sprintf("%s changed the %s policy (password and lockout rules).", orUnknown(who), firstNonBlank(r.Get("DomainName"), "domain"))}
	if len(changed) > 0 {
		e.Summary = strings.TrimSuffix(e.Summary, ".") + ": " + strings.Join(changed, "; ") + "."
	}
	e.AddDetail("Kind of policy", expandTokens(r.Get("DomainPolicyChanged")))
	return e
}

func (t *Translator) trust(r *Raw) *event.Event {
	who := t.subject(r)
	dom := firstNonBlank(r.Get("DomainName"), r.Get("TargetDomainName"))
	e := &event.Event{Category: event.CatAccount, User: who, Target: dom}
	switch r.EventID {
	case 4706:
		e.Action, e.Severity = "trust_created", event.SevHigh
		e.Summary = fmt.Sprintf("%s created a trust with the domain %s — its accounts may now be able to sign in here.", orUnknown(who), orUnknown(dom))
	case 4707:
		e.Action, e.Severity = "trust_removed", event.SevMedium
		e.Summary = fmt.Sprintf("%s removed the trust with the domain %s.", orUnknown(who), orUnknown(dom))
	default:
		e.Action, e.Severity = "trust_changed", event.SevMedium
		e.Summary = fmt.Sprintf("%s changed the trust with the domain %s.", orUnknown(who), orUnknown(dom))
	}
	e.AddDetail("Direction", expandTokens(r.Get("TdoDirection")))
	e.AddDetail("Type", expandTokens(r.Get("TdoType")))
	return e
}

// bootConfig is 4826, written at every start. It matters only when the
// boot settings weaken protection: debugging, test signing, or integrity
// checks off.
func bootConfig(r *Raw, who string) *event.Event {
	var bad []string
	for _, f := range []struct{ field, text string }{
		{"KernelDebug", "kernel debugging on"}, {"HypervisorDebug", "hypervisor debugging on"},
		{"TestSigning", "test signing on (unsigned drivers load)"}, {"FlightSigning", "flight signing on"},
		{"DisableIntegrityChecks", "integrity checks off"}, {"BootDebug", "boot debugging on"},
	} {
		if yes(r.Get(f.field)) {
			bad = append(bad, f.text)
		}
	}
	if len(bad) == 0 {
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevInfo, Action: "boot_config", DedupeKey: "bcd",
			Summary: "Windows loaded its boot settings (nothing weakened)."}
	}
	e := &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "boot_config_weakened", User: who,
		Summary: "Windows started with boot settings that weaken its protection: " + strings.Join(bad, ", ") + "."}
	e.AddDetail("Settings", strings.Join(bad, ", "))
	return e
}

// windowsMaintenance are the programs Windows uses to service itself;
// their permission and auditing changes are routine.
var windowsMaintenance = map[string]bool{"tiworker.exe": true, "trustedinstaller.exe": true, "msiexec.exe": true,
	"svchost.exe": true, "services.exe": true, "lsass.exe": true, "wininit.exe": true, "smss.exe": true, "musnotification.exe": true,
	"mpcmdrun.exe": true, "msmpeng.exe": true, "wuauclt.exe": true, "dismhost.exe": true}

func (t *Translator) saclChanged(r *Raw) *event.Event {
	who := t.subject(r)
	obj := r.Get("ObjectName")
	proc := strings.ToLower(filepath.Base(winPath(r.Get("ProcessName"))))
	if t.ignoredAccount(r, "Subject") && windowsMaintenance[proc] {
		return nil // Windows Update setting up auditing on its own files
	}
	e := &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "object_audit_changed", User: who, Target: obj,
		Process: r.Get("ProcessName"), DedupeKey: "sacl|" + strings.ToLower(obj),
		Summary: fmt.Sprintf("%s changed which access to %s %s is audited.", orUnknown(who), strings.ToLower(firstNonBlank(r.Get("ObjectType"), "object")), obj)}
	e.AddDetail("Object", obj)
	e.AddDetail("Program", r.Get("ProcessName"))
	e.AddDetail("Before", r.Get("OldSd"))
	e.AddDetail("After", r.Get("NewSd"))
	return e
}

// firewallChange is 4946–4950. They name no person: the firewall records
// only what changed.
func firewallChange(r *Raw) *event.Event {
	rule := r.Get("RuleName")
	e := &event.Event{Category: event.CatIntegrity, Severity: event.SevLow, Target: rule}
	switch r.EventID {
	case 4946:
		e.Action, e.Summary = "firewall_rule_added", fmt.Sprintf("A Windows Firewall rule was added: %s.", rule)
	case 4947:
		e.Action, e.Summary = "firewall_rule_changed", fmt.Sprintf("A Windows Firewall rule was changed: %s.", rule)
	case 4948:
		e.Action, e.Severity = "firewall_rule_deleted", event.SevMedium
		e.Summary = fmt.Sprintf("A Windows Firewall rule was deleted: %s.", rule)
	case 4949:
		e.Action, e.Severity = "firewall_reset", event.SevMedium
		e.Summary = "The Windows Firewall settings were restored to their defaults."
	case 4950:
		setting, value := expandTokens(r.Get("SettingType")), expandTokens(r.Get("SettingValue"))
		e.Action, e.Severity, e.Target = "firewall_setting_changed", event.SevMedium, setting
		e.Summary = fmt.Sprintf("A Windows Firewall setting was changed (%s profile): %s = %s.", expandTokens(r.Get("ProfileChanged")), setting, value)
		if strings.Contains(strings.ToLower(setting), "enable") && (strings.EqualFold(value, "no") || r.Get("SettingValue") == "%%1843") {
			e.Severity = event.SevHigh
			e.Summary = fmt.Sprintf("The Windows Firewall was turned off (%s profile).", expandTokens(r.Get("ProfileChanged")))
		}
	}
	if e.Action != "firewall_setting_changed" {
		e.DedupeKey = e.Action + "|" + strings.ToLower(rule)
	}
	e.AddDetail("Rule", rule)
	e.AddDetail("Profile", expandTokens(r.Get("ProfileChanged")))
	return e
}

func codeIntegrity(r *Raw) *event.Event {
	file := firstNonBlank(r.Get("param1"), r.Get("FileName"), r.Get("Data0"))
	e := &event.Event{Category: event.CatIntegrity, Target: file, DedupeKey: "ci|" + strings.ToLower(file)}
	if r.EventID == 5038 {
		e.Action, e.Severity = "code_integrity_failed", event.SevHigh
		e.Summary = fmt.Sprintf("Windows found a system file whose signature doesn't match: %s — it may have been altered.", file)
		if strings.Contains(strings.ToLower(file), `\windows defender\platform\`) {
			// T2: seen on a fresh Windows 11 while Defender installed a new
			// platform version. Not confirmed as a documented false
			// positive, so it stays High, with how to tell.
			e.Summary += " This is a Microsoft Defender platform file: Windows often logs this while Defender is updating its platform."
			e.AddDetail("How to check", "If Defender updated its platform at this time (Defender log events 2000/2014, or a new folder under ProgramData\\Microsoft\\Windows Defender\\Platform), "+
				"and the file's signature is valid now (Get-AuthenticodeSignature), it was the update. Otherwise treat it as a file that was changed.")
		}
	} else {
		e.Action, e.Severity = "code_integrity_page", event.SevMedium
		e.Summary = fmt.Sprintf("Windows found invalid page hashes in %s (often a security or monitoring driver; check it is expected).", file)
	}
	e.AddDetail("File", file)
	return e
}

func (t *Translator) shareAccess(r *Raw) *event.Event {
	who := t.subject(r)
	share := r.Get("ShareName")
	ip := cleanIP(r.Get("IpAddress"))
	if r.EventID == 5145 && !r.AuditFailure() {
		return nil // every file opened over a share: counted under Other security events
	}
	if t.ignoredAccount(r, "Subject") || strings.HasSuffix(strings.ToUpper(share), `\IPC$`) {
		return nil
	}
	e := &event.Event{Category: event.CatLogon, Severity: event.SevLow, Action: "share_accessed", User: who, Target: share, SourceIP: ip,
		DedupeKey: "share|" + strings.ToLower(who+"|"+share+"|"+ip)}
	e.Summary = fmt.Sprintf("%s opened the network share %s%s.", orUnknown(who), share, fromIP(ip))
	if r.AuditFailure() {
		e.Action, e.Severity, e.Outcome = "share_access_denied", event.SevMedium, "failure"
		obj := r.Get("RelativeTargetName")
		e.Summary = fmt.Sprintf("%s was refused access to %s on the network share %s%s.", orUnknown(who), obj, share, fromIP(ip))
		e.DedupeKey = "sharefail|" + strings.ToLower(who+"|"+share+"|"+obj)
		e.AddDetail("File", obj)
	}
	e.AddDetail("Share", share)
	e.AddDetail("Folder", r.Get("ShareLocalPath"))
	e.AddDetail("Source address", ip)
	return e
}

// securityKeys are registry keys whose values control logons, auditing,
// anti-malware or what starts automatically. A change to one matters
// whoever makes it; High for those that control security directly.
var securityKeys = []struct {
	re   *regexp.Regexp
	what string
	high bool
}{
	{regexp.MustCompile(`(?i)\\SYSTEM\\(CurrentControlSet|ControlSet\d+)\\Control\\Lsa(\\|$)`), "Local Security Authority settings", true},
	{regexp.MustCompile(`(?i)\\SYSTEM\\(CurrentControlSet|ControlSet\d+)\\Control\\SecurityProviders`), "security providers", true},
	{regexp.MustCompile(`(?i)\\SYSTEM\\(CurrentControlSet|ControlSet\d+)\\Services\\EventLog`), "event log settings", true},
	{regexp.MustCompile(`(?i)\\SOFTWARE\\Policies\\Microsoft\\Windows Defender`), "Microsoft Defender policy", true},
	{regexp.MustCompile(`(?i)\\SOFTWARE\\Microsoft\\Windows Defender`), "Microsoft Defender settings", true},
	{regexp.MustCompile(`(?i)\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`), "Windows logon settings", true},
	{regexp.MustCompile(`(?i)\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options`), "program debugger settings (Image File Execution Options)", true},
	{regexp.MustCompile(`(?i)\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(Once)?(\\|$)`), "programs started at logon", false},
	{regexp.MustCompile(`(?i)\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog`), "event log policy", true},
	{regexp.MustCompile(`(?i)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`), "User Account Control settings", true},
	{regexp.MustCompile(`(?i)\\SYSTEM\\(CurrentControlSet|ControlSet\d+)\\Services\\[^\\]+$`), "a service's settings", false},
}

func (t *Translator) registryChange(r *Raw) *event.Event {
	key := r.Get("ObjectName")
	for _, k := range securityKeys {
		if !k.re.MatchString(key) {
			continue
		}
		who := t.subject(r)
		proc := strings.ToLower(filepath.Base(winPath(r.Get("ProcessName"))))
		if !k.high && t.ignoredAccount(r, "Subject") && windowsMaintenance[proc] {
			return nil
		}
		val := r.Get("ObjectValueName")
		e := &event.Event{Category: event.CatIntegrity, Severity: event.SevMedium, Action: "security_registry_changed", User: who,
			Target: key + `\` + val, Process: r.Get("ProcessName"), DedupeKey: "reg|" + strings.ToLower(key+`\`+val),
			Summary: fmt.Sprintf("%s changed %s in the registry: %s\\%s.", orUnknown(who), k.what, key, val)}
		if k.high {
			e.Severity = event.SevHigh
		}
		e.AddDetail("Key", key)
		e.AddDetail("Value", val)
		e.AddDetail("Before", r.Get("OldValue"))
		e.AddDetail("After", r.Get("NewValue"))
		e.AddDetail("Program", r.Get("ProcessName"))
		return e
	}
	return nil
}

func (t *Translator) permissionsChanged(r *Raw) *event.Event {
	typ := r.Get("ObjectType")
	switch typ {
	case "File", "Key", "Service", "SERVICE OBJECT", "Directory":
	default:
		return nil // process tokens and other internal objects
	}
	if t.ignoredAccount(r, "Subject") {
		return nil
	}
	who := t.subject(r)
	obj := r.Get("ObjectName")
	e := &event.Event{Category: event.CatIntegrity, Severity: event.SevMedium, Action: "permissions_changed", User: who, Target: obj,
		Process: r.Get("ProcessName"), DedupeKey: "perm|" + strings.ToLower(obj),
		Summary: fmt.Sprintf("%s changed the permissions of %s.", orUnknown(who), obj)}
	e.AddDetail("Object type", typ)
	e.AddDetail("Program", r.Get("ProcessName"))
	e.AddDetail("Before", r.Get("OldSd"))
	e.AddDetail("After", r.Get("NewSd"))
	return e
}

func (t *Translator) sidHistory(r *Raw) *event.Event {
	who := t.subject(r)
	target := t.account(r, "TargetSid", "TargetDomainName", "TargetUserName")
	e := &event.Event{Category: event.CatAccount, Severity: event.SevHigh, Action: "sid_history_added", User: who, Target: target,
		Summary: fmt.Sprintf("%s added SID history to %s — the account gains the rights of another account (%s).", orUnknown(who), orUnknown(target), r.Get("SourceSid"))}
	if r.EventID == 4766 {
		e.Action, e.Outcome = "sid_history_failed", "failure"
		e.Summary = fmt.Sprintf("An attempt to add SID history to %s failed — someone tried to give it the rights of another account.", orUnknown(target))
	}
	e.AddDetail("Source account", firstNonBlank(r.Get("SourceUserName"), r.Get("SourceSid")))
	return e
}

func firstNonBlank(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// reportFolder is the report a path under Blackbox's reports folder
// belongs to ("2026-10-04_2009_WIN11-TEST_manual"), or "".
func reportFolder(p string) string {
	const marker = "/programdata/blackbox/reports/"
	i := strings.Index(strings.ToLower(p), marker)
	if i < 0 {
		return ""
	}
	name, _, _ := strings.Cut(p[i+len(marker):], "/")
	return name
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// exportPiece says whether proc writing obj is the Event Log service
// writing a piece of the original logs Blackbox exports at each
// collection: <archive-pieces | .exports | archives>\<6 digits>\<log>.evtx,
// named after a log Blackbox reads (as archive.SafeName names it).
func exportPiece(proc, obj string) bool {
	if !strings.EqualFold(filepath.Base(winPath(proc)), "svchost.exe") {
		return false
	}
	parts := strings.Split(strings.ToLower(winPath(obj)), "/")
	n := len(parts)
	if n < 3 {
		return false
	}
	switch parts[n-3] {
	case "archive-pieces", ".exports", "archives":
	default:
		return false
	}
	if len(parts[n-2]) != 6 || strings.Trim(parts[n-2], "0123456789") != "" {
		return false
	}
	for _, ch := range Channels {
		if parts[n-1] == strings.ToLower(strings.Trim(unsafeChars.ReplaceAllString(ch, "-"), "-"))+".evtx" {
			return true
		}
	}
	return false
}

// fileAccess is 4656/4663 from the File System subcategory: files and
// folders an administrator has set auditing on (A2). A refused access is
// always shown; a successful one only when it wrote or deleted.
func (t *Translator) fileAccess(r *Raw) *event.Event {
	if r.Task != taskFileSystem || (r.Get("ObjectType") != "" && r.Get("ObjectType") != "File") {
		return nil
	}
	failed := r.AuditFailure()
	op := fileOperation(r.Get("AccessList"))
	if !failed && op != "write" && op != "delete" {
		return nil
	}
	if !failed && t.ignoredAccount(r, "Subject") {
		return nil // Windows itself, or a service, maintaining the file
	}
	who := t.subject(r)
	obj := r.Get("ObjectName")
	if t.MapDevicePath != nil {
		obj = t.MapDevicePath(obj)
	}
	proc := r.Get("ProcessName")
	e := &event.Event{Category: event.CatOther, Severity: event.SevLow, User: who, Target: obj, Process: proc}
	if !failed && op != "delete" && exportPiece(proc, obj) {
		e.Fields = map[string]string{event.ExportPieceFlag: "1"}
	}
	switch {
	case failed:
		e.Action, e.Severity, e.Outcome = "file_access_denied", event.SevMedium, "failure"
		e.Summary = fmt.Sprintf("%s was refused access to %s", orUnknown(who), obj)
	case op == "delete":
		e.Action = "file_deleted"
		e.Summary = fmt.Sprintf("%s deleted %s", orUnknown(who), obj)
	default:
		e.Action = "file_written"
		e.Summary = fmt.Sprintf("%s changed %s", orUnknown(who), obj)
	}
	if proc != "" {
		e.Summary += " (using " + filepath.Base(winPath(proc)) + ")"
	}
	e.Summary += "."
	// Blackbox's own folder, with the auditing entry windows.md describes
	// (A5): its settings, schedule state and collected events.
	if lo := strings.ToLower(winPath(obj)); (strings.Contains(lo, "/programdata/blackbox/") || strings.HasSuffix(lo, "/programdata/blackbox")) && !failed {
		self := strings.EqualFold(filepath.Base(winPath(proc)), "blackbox.exe") || strings.EqualFold(filepath.Base(winPath(proc)), "blackboxw.exe")
		report := reportFolder(winPath(obj))
		switch {
		case self:
			// Blackbox's own run, or config set (self-recorded, A15). The
			// folder itself counts too, not only what is in it (T4).
			return nil
		case report != "":
			// One row for a deleted report, not two per file (T4).
			e.Action, e.Severity, e.Category = "blackbox_files_changed", event.SevHigh, event.CatIntegrity
			verb := "changed"
			if op == "delete" {
				verb = "deleted"
			}
			e.Summary = fmt.Sprintf("%s %s the report %s (using %s).", orUnknown(who), verb, report, filepath.Base(winPath(proc)))
			e.Target = report
			e.DedupeKey = "bbreport|" + verb + "|" + strings.ToLower(who+"|"+report)
			e.AddDetail("Report", report)
			e.AddDetail("File", obj)
			return e
		case strings.HasSuffix(lo, "/blackbox.conf"):
			e.Action, e.Severity, e.Category = "blackbox_config_changed", event.SevHigh, event.CatIntegrity
			e.Summary = fmt.Sprintf("%s edited Blackbox's settings file directly: %s (using %s).", orUnknown(who), obj, filepath.Base(winPath(proc)))
		default:
			e.Action, e.Severity, e.Category = "blackbox_files_changed", event.SevHigh, event.CatIntegrity
			e.Summary = fmt.Sprintf("%s changed or deleted Blackbox's data: %s (using %s).", orUnknown(who), obj, filepath.Base(winPath(proc)))
		}
	}
	e.DedupeKey = "file|" + e.Action + "|" + strings.ToLower(who+"|"+obj)
	e.AddDetail("File", obj)
	e.AddDetail("Access", expandTokens(r.Get("AccessList")))
	e.AddDetail("Program", proc)
	return e
}
