package winevt

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// Logs beyond Security, System and Defender's detections (A7): software
// installed, the firewall's own log, Defender's settings, printing, and
// Remote Desktop.

const (
	chApplication = "Application"
	chFirewall    = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
	chPrint       = "Microsoft-Windows-PrintService/Operational"
	chRDPLocal    = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
	chRDPRemote   = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
)

var msiProductRE = regexp.MustCompile(`^Product: (.+?) -- `)

// application reads Windows Installer's records of software installed and
// removed (CM-11): 1033/1034 carry the product, version and result;
// 11707/11724 say the same in a sentence, and are merged with them.
func (t *Translator) application(r *Raw) *event.Event {
	if strings.EqualFold(r.Provider, "Blackbox") {
		return blackboxSelf(r)
	}
	if !strings.EqualFold(r.Provider, "MsiInstaller") {
		return nil
	}
	var product, version, status string
	switch r.EventID {
	case 1033, 1034:
		product, version, status = r.Get("Data0"), r.Get("Data1"), r.Get("Data3")
	case 11707, 11724:
		m := msiProductRE.FindStringSubmatch(r.Get("Data0"))
		if m == nil {
			return nil
		}
		product = m[1]
	default:
		return nil
	}
	who := t.resolve(r.UserSID)
	if strings.EqualFold(who, "SYSTEM") {
		who = "" // installed by a management tool or Windows Update
	}
	e := &event.Event{Category: event.CatOther, User: who, Target: product}
	by := ""
	if who != "" {
		by = " by " + who
	}
	failed := status != "" && status != "0"
	switch r.EventID {
	case 1033, 11707:
		e.Action, e.Severity = "software_installed", event.SevMedium
		e.Summary = fmt.Sprintf("Software was installed%s: %s", by, product)
		e.DedupeKey = "msi|install|" + strings.ToLower(product)
	default:
		e.Action, e.Severity = "software_removed", event.SevLow
		e.Summary = fmt.Sprintf("Software was removed%s: %s", by, product)
		e.DedupeKey = "msi|remove|" + strings.ToLower(product)
	}
	if version != "" {
		e.Summary += " " + version
		e.Priority = 1
	}
	if failed {
		e.Action, e.Outcome, e.Severity = e.Action+"_failed", "failure", event.SevLow
		e.Summary += fmt.Sprintf(" — it failed (error %s)", status)
	}
	e.Summary += "."
	e.AddDetail("Product", product)
	e.AddDetail("Version", version)
	e.AddDetail("Manufacturer", r.Get("Data4"))
	return e
}

// blackboxSelf is Blackbox's own record of a change to itself, which it
// writes to the Application log as well as its spool (A15). It merges with
// the spool's copy.
func blackboxSelf(r *Raw) *event.Event {
	c, ok := event.ParseSelfChange(firstNonBlank(r.Get("Data0"), r.Get("Data")))
	if !ok {
		return nil
	}
	return c.Event()
}

// firewallLog reads the firewall's own log, which says who and which
// program changed a rule (the Security log's 4946–4948 don't). It merges
// with those events.
func (t *Translator) firewallLog(r *Raw) *event.Event {
	who := t.resolve(r.Get("ModifyingUser"))
	prog := r.Get("ModifyingApplication")
	rule := r.Get("RuleName")
	if rule == "" {
		rule = r.Get("RuleId") // not "deleted: ." (A13b)
	}
	by := ""
	if who != "" && !strings.EqualFold(who, "SYSTEM") {
		by = " by " + who
	}
	e := &event.Event{Category: event.CatIntegrity, Severity: event.SevLow, User: who, Target: rule, Process: prog, Priority: 1}
	switch r.EventID {
	case 2004, 2071, 2097:
		e.Action, e.Summary = "firewall_rule_added", fmt.Sprintf("A Windows Firewall rule was added%s: %s.", by, rule)
	case 2005, 2073, 2099:
		e.Action, e.Summary = "firewall_rule_changed", fmt.Sprintf("A Windows Firewall rule was changed%s: %s.", by, rule)
	case 2006, 2052:
		e.Action, e.Severity = "firewall_rule_deleted", event.SevMedium
		e.Summary = fmt.Sprintf("A Windows Firewall rule was deleted%s: %s.", by, rule)
	case 2033:
		e.Action, e.Severity, e.Target = "firewall_rules_cleared", event.SevHigh, ""
		e.Summary = fmt.Sprintf("All Windows Firewall rules were deleted%s.", by)
	case 2003:
		e.Action, e.Severity, e.Target = "firewall_setting_changed", event.SevMedium, r.Get("SettingType")
		e.Summary = fmt.Sprintf("A Windows Firewall setting was changed%s (%s): %s = %s.", by, firewallProfiles(r.Get("Profiles")),
			firewallSetting(r.Get("SettingType")), firstNonBlank(r.Get("SettingValueString"), r.Get("SettingValue")))
		if r.Get("SettingType") == "1" && strings.TrimSpace(r.Get("SettingValue")) == "0" ||
			strings.EqualFold(r.Get("SettingValueString"), "No") && r.Get("SettingType") == "1" {
			e.Severity = event.SevHigh
			e.Summary = fmt.Sprintf("The Windows Firewall was turned off%s (%s).", by, firewallProfiles(r.Get("Profiles")))
		}
	default:
		return nil
	}
	if e.Target != "" && e.Action != "firewall_setting_changed" {
		e.DedupeKey = e.Action + "|" + strings.ToLower(rule)
	}
	e.AddDetail("Rule", rule)
	e.AddDetail("Program that changed it", prog)
	e.AddDetail("Program the rule is for", r.Get("ApplicationPath"))
	return e
}

func firewallProfiles(p string) string {
	switch p {
	case "1":
		return "domain profile"
	case "2":
		return "private profile"
	case "4":
		return "public profile"
	case "", "0":
		return "all profiles"
	}
	return "profiles " + p
}

func firewallSetting(t string) string {
	switch t {
	case "1":
		return "Firewall on"
	case "2":
		return "Inbound block (shields up)"
	case "3":
		return "Notifications"
	case "7":
		return "Default inbound action"
	case "8":
		return "Default outbound action"
	}
	return "setting " + t
}

// defenderSettings is Defender 5007 (a setting changed) and 5013 (Tamper
// Protection blocked a change).
func (t *Translator) defenderSettings(r *Raw) *event.Event {
	if r.EventID == 5013 {
		v := firstNonBlank(r.Get("Value"), r.Get("Changed Value"))
		e := &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "av_tamper_blocked", Target: v,
			Summary: fmt.Sprintf("Tamper Protection blocked a change to Microsoft Defender: %s — someone or something tried to weaken it.", orUnknown(v))}
		return e
	}
	oldV, newV := r.Get("Old Value"), r.Get("New Value")
	low := strings.ToLower(newV)
	e := &event.Event{Category: event.CatOther, Severity: event.SevLow, Action: "av_setting_changed", Target: newV,
		DedupeKey: "defcfg|" + strings.ToLower(strings.SplitN(newV, " = ", 2)[0]),
		Summary:   fmt.Sprintf("A Microsoft Defender setting was changed: %s.", orUnknown(newV))}
	switch {
	case !defenderSetting(low):
		// Defender recording its own state (WdConfigHash, IsServiceRunning,
		// ServiceStartStates, Diagnostics, Features\EcsConfigs, SpyNet
		// check times): not configuration. Counted once a day (A16).
		e.Action, e.Severity = "av_state_recorded", event.SevInfo
		e.Summary = fmt.Sprintf("Microsoft Defender recorded its own state: %s.", orUnknown(newV))
	case strings.Contains(low, `\nis\consumers\ips\disablebmnetworksensor = 0x1`) && !strings.Contains(low, `\policies\`):
		// Defender sets this itself during platform updates (seen on a
		// fresh Windows 11 25H2, no user named): not protection turned
		// off by someone (A17). A policy setting it is still High below.
		e.Severity = event.SevLow
		e.Summary = fmt.Sprintf("Microsoft Defender changed its own network-inspection sensor setting (usually during a platform update): %s.", newV)
		e.AddDetail("Note", "Defender changes this itself when its platform updates. Set by policy (under Policies), it would be reported as protection turned off.")
	case strings.Contains(low, `\exclusions\`) && oldV == "":
		e.Action, e.Severity = "av_exclusion_added", event.SevHigh
		e.Summary = fmt.Sprintf("An exclusion was added to Microsoft Defender — it no longer scans: %s.", exclusionOf(newV))
	case regexp.MustCompile(`(?i)\\disable\w+ = 0x1\b`).MatchString(newV):
		e.Action, e.Severity = "av_disabled", event.SevHigh
		e.Summary = fmt.Sprintf("A Microsoft Defender protection was turned off: %s.", newV)
	case strings.Contains(low, `\exclusions\`):
		e.Summary = fmt.Sprintf("A Microsoft Defender exclusion was changed or removed: %s.", exclusionOf(firstNonBlank(newV, oldV)))
	}
	e.AddDetail("Before", oldV)
	e.AddDetail("After", newV)
	return e
}

// defenderSettings are the parts of Defender's registry that are its
// configuration (A16): exclusions, real-time and other protections,
// tamper protection, policy, cloud protection consent, threat actions,
// attack surface reduction and controlled folder access, and any
// Disable* switch. Defender writes the rest itself as it runs.
var defenderSettings = []string{`\exclusions\`, `\real-time protection\`, `\features\tamperprotection`, `\policy manager\`,
	`\policies\`, `\spynet\spynetreporting`, `\spynet\submitsamplesconsent`, `\threats\`, `\mpengine\`,
	`\windows defender exploit guard\`, `\nis\`, `\scan\`, `\signature updates\`, `\ux configuration\`}

var disableSwitch = regexp.MustCompile(`\\disable\w+ = `)

func defenderSetting(low string) bool {
	if disableSwitch.MatchString(low) {
		return true
	}
	for _, k := range defenderSettings {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

// exclusionOf is the excluded path, process or extension in a 5007 value
// such as "HKLM\…\Exclusions\Paths\C:\Temp = 0x0".
func exclusionOf(v string) string {
	v = strings.SplitN(v, " = ", 2)[0]
	for _, k := range []string{`\Paths\`, `\Processes\`, `\Extensions\`, `\IpAddresses\`} {
		if i := strings.Index(v, k); i >= 0 {
			return v[i+len(k):]
		}
	}
	return v
}

// printed is PrintService 307: a document printed (MP-2, AU-2 on some
// sites). The log is off by default; check says how to turn it on.
func (t *Translator) printed(r *Raw) *event.Event {
	if r.EventID != 307 {
		return nil
	}
	doc, user, printer, pages := r.Get("Param2"), r.Get("Param3"), r.Get("Param5"), r.Get("Param8")
	e := &event.Event{Category: event.CatOther, Severity: event.SevLow, Action: "document_printed", User: user, Target: doc,
		Summary: fmt.Sprintf("%s printed %q on %s", orUnknown(user), doc, orUnknown(printer))}
	if pages != "" {
		e.Summary += fmt.Sprintf(" (%s pages)", pages)
	}
	e.Summary += "."
	e.AddDetail("Printer", printer)
	e.AddDetail("Pages", pages)
	e.AddDetail("Size (bytes)", r.Get("Param7"))
	e.AddDetail("From computer", r.Get("Param4"))
	return e
}

// remoteDesktop reads the Remote Desktop session logs, which name the
// client address even when the Security log doesn't. They merge with the
// Security log's own records of the same session.
func (t *Translator) remoteDesktop(r *Raw) *event.Event {
	user := qualifiedAccount(firstNonBlank(r.Get("User"), joinAccount(r.Get("Param2"), r.Get("Param1"), r.Computer)), r.Computer)
	addr := cleanIP(firstNonBlank(r.Get("Address"), r.Get("Param3")))
	e := &event.Event{Category: event.CatLogon, Severity: event.SevInfo, User: user, SourceIP: addr, Outcome: "success"}
	switch {
	case r.Channel == chRDPRemote && r.EventID == 1149:
		e.Action = "rdp_authenticated"
		e.Summary = fmt.Sprintf("%s passed Remote Desktop network sign-in%s.", orUnknown(user), fromIP(addr))
	case r.Channel == chRDPLocal && r.EventID == 21:
		e.Action, e.Interactive = "logon", true
		e.Summary = fmt.Sprintf("%s logged on via Remote Desktop%s.", orUnknown(user), fromIP(addr))
		e.DedupeKey = "rdplogon|" + strings.ToLower(accountName(user)) + "|" + addr
	case r.Channel == chRDPLocal && r.EventID == 24:
		e.Action = "session_disconnected"
		e.Summary = fmt.Sprintf("%s disconnected from a Remote Desktop session%s.", orUnknown(user), fromIP(addr))
		e.DedupeKey = "rdpdisc|" + strings.ToLower(accountName(user))
	case r.Channel == chRDPLocal && r.EventID == 25:
		e.Action = "session_reconnected"
		e.Summary = fmt.Sprintf("%s reconnected to a Remote Desktop session%s.", orUnknown(user), fromIP(addr))
		e.DedupeKey = "rdprecon|" + strings.ToLower(accountName(user))
	default:
		return nil
	}
	if user == "" || t.isServiceAccount("", accountName(user)) {
		return nil
	}
	e.AddDetail("Logon type", "Remote Desktop")
	e.AddDetail("Source address", addr)
	e.AddDetail("Session", r.Get("SessionID"))
	return e
}
