package check

import (
	"fmt"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/rollover"
	"github.com/casea1/blackbox/internal/winevt"
)

// Baseline is the audit configuration one DISA STIG requires.
type Baseline struct {
	Name     string // e.g. "Windows 11 STIG V2R11"
	Audit    []auditReq
	Registry []regReq
	Logs     []logReq
}

type logReq struct {
	name  string
	minKB uint64 // minimum maximum-size, in KB
	week  bool   // must hold a week of events instead of a fixed size
	stig  string
}

// Advanced audit policy subcategory GUIDs.
const (
	gSecurityStateChange   = "{0CCE9210-69AE-11D9-BED3-505054503030}"
	gSecuritySystemExt     = "{0CCE9211-69AE-11D9-BED3-505054503030}"
	gSystemIntegrity       = "{0CCE9212-69AE-11D9-BED3-505054503030}"
	gIPsecDriver           = "{0CCE9213-69AE-11D9-BED3-505054503030}"
	gOtherSystemEvents     = "{0CCE9214-69AE-11D9-BED3-505054503030}"
	gLogon                 = "{0CCE9215-69AE-11D9-BED3-505054503030}"
	gLogoff                = "{0CCE9216-69AE-11D9-BED3-505054503030}"
	gAccountLockout        = "{0CCE9217-69AE-11D9-BED3-505054503030}"
	gSpecialLogon          = "{0CCE921B-69AE-11D9-BED3-505054503030}"
	gOtherLogonLogoff      = "{0CCE921C-69AE-11D9-BED3-505054503030}"
	gFileSystem            = "{0CCE921D-69AE-11D9-BED3-505054503030}"
	gRegistry              = "{0CCE921E-69AE-11D9-BED3-505054503030}"
	gHandleManipulation    = "{0CCE9223-69AE-11D9-BED3-505054503030}"
	gFileShare             = "{0CCE9224-69AE-11D9-BED3-505054503030}"
	gOtherObjectAccess     = "{0CCE9227-69AE-11D9-BED3-505054503030}"
	gSensitivePrivilegeUse = "{0CCE9228-69AE-11D9-BED3-505054503030}"
	gProcessCreation       = "{0CCE922B-69AE-11D9-BED3-505054503030}"
	gAuditPolicyChange     = "{0CCE922F-69AE-11D9-BED3-505054503030}"
	gAuthenticationPolicy  = "{0CCE9230-69AE-11D9-BED3-505054503030}"
	gAuthorizationPolicy   = "{0CCE9231-69AE-11D9-BED3-505054503030}"
	gMPSSVCRuleLevel       = "{0CCE9232-69AE-11D9-BED3-505054503030}"
	gOtherPolicyChange     = "{0CCE9234-69AE-11D9-BED3-505054503030}"
	gUserAccountMgmt       = "{0CCE9235-69AE-11D9-BED3-505054503030}"
	gSecurityGroupMgmt     = "{0CCE9237-69AE-11D9-BED3-505054503030}"
	gOtherAccountMgmt      = "{0CCE923A-69AE-11D9-BED3-505054503030}"
	gCredentialValidation  = "{0CCE923F-69AE-11D9-BED3-505054503030}"
	gDetailedFileShare     = "{0CCE9244-69AE-11D9-BED3-505054503030}"
	gRemovableStorage      = "{0CCE9245-69AE-11D9-BED3-505054503030}"
	gPlugAndPlay           = "{0CCE9248-69AE-11D9-BED3-505054503030}"
	gGroupMembership       = "{0CCE9249-69AE-11D9-BED3-505054503030}"
)

// What each subcategory feeds in the report.
const (
	aFailedLogons = "Failed Logons"
	aAccounts     = "Account & Group Changes"
	aUSB          = "USB & Removable Media"
	aElevated     = "Privileged Activity (elevated programs)"
	aLogons       = "Logon Activity and Failed Logons"
	aIntegrity    = "Audit & System Integrity"
)

func w11(n string) string { return "WN11-AU-000" + n }
func w25(n string) string { return "WN25-AU-000" + n }

// Windows11 is the Windows 11 STIG V2R11 (5 October 2026). COMP1: File
// System success and failure (WN11-AU-000582/581) and Handle Manipulation
// success (WN11-AU-000584) were in the Windows 11 STIG up to V2R7 but are
// not in V2R8 or V2R11 (checked against the stigaview.com copy of the
// DISA releases on 8 October 2026). Blackbox still asks for them as its
// own advice: File System success is what records changes to Blackbox's
// own folder, and the Server 2025 STIG still requires all three.
var Windows11 = Baseline{
	Name: "Windows 11 STIG V2R11",
	Audit: []auditReq{
		{gCredentialValidation, "Credential Validation", w11("010"), w11("005"), aFailedLogons, false},
		{gSecurityGroupMgmt, "Security Group Management", w11("030"), "", aAccounts, false},
		{gUserAccountMgmt, "User Account Management", w11("040"), w11("035"), aAccounts, false},
		{gPlugAndPlay, "Plug and Play Events", w11("045"), "", aUSB, false},
		{gProcessCreation, "Process Creation", w11("050"), w11("585"), aElevated, false},
		{gAccountLockout, "Account Lockout", "", w11("054"), aFailedLogons, false},
		{gGroupMembership, "Group Membership", w11("060"), "", "", false},
		{gLogoff, "Logoff", w11("065"), "", "Logon Activity", false},
		{gLogon, "Logon", w11("075"), w11("070"), aLogons, false},
		{gSpecialLogon, "Special Logon", w11("080"), "", "Privileged Activity (administrator logons)", false},
		{gOtherLogonLogoff, "Other Logon/Logoff Events", w11("560"), w11("565"), "Logon Activity (Remote Desktop sessions)", false},
		{gFileShare, "File Share", w11("082"), w11("081"), "", false},
		{gDetailedFileShare, "Detailed File Share", "", w11("570"), "", false},
		{gOtherObjectAccess, "Other Object Access Events", w11("083"), w11("084"), "Other Security Events (scheduled tasks)", false},
		{gRemovableStorage, "Removable Storage", w11("090"), w11("085"), aUSB + " (files read/written)", false},
		{gFileSystem, "File System", advice, advice, "Audit & System Integrity (changes to Blackbox's own folder)", false},
		{gHandleManipulation, "Handle Manipulation", advice, w11("583"), "", false},
		{gRegistry, "Registry", w11("586"), w11("589"), "", false},
		{gAuditPolicyChange, "Audit Policy Change", w11("100"), "", aIntegrity, false},
		{gAuthenticationPolicy, "Authentication Policy Change", w11("105"), "", "", false},
		{gAuthorizationPolicy, "Authorization Policy Change", w11("107"), "", "", false},
		{gMPSSVCRuleLevel, "MPSSVC Rule-Level Policy Change", w11("575"), w11("580"), "", false},
		{gOtherPolicyChange, "Other Policy Change Events", "", w11("555"), "", false},
		{gSensitivePrivilegeUse, "Sensitive Privilege Use", w11("115"), w11("110"), "", false},
		{gIPsecDriver, "IPsec Driver", "", w11("120"), "", false},
		{gOtherSystemEvents, "Other System Events", w11("130"), w11("135"), "", false},
		{gSecurityStateChange, "Security State Change", w11("140"), "", aIntegrity + " (startup, time changes)", false},
		{gSecuritySystemExt, "Security System Extension", w11("150"), "", "Other Security Events (services installed)", false},
		{gSystemIntegrity, "System Integrity", w11("160"), w11("155"), aIntegrity, false},
	},
	Registry: []regReq{
		forceSubcategories("WN11-SO-000030"),
		commandLine("WN11-CC-000066"),
		scriptBlockLogging("WN11-CC-000326"),
		{`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`, "EnableTranscripting",
			"PowerShell transcription", "",
			gpAdmin + " > Windows Components > Windows PowerShell > Turn on PowerShell Transcription: Enabled", "WN11-CC-000327"},
	},
	Logs: []logReq{
		// WN11-AU-000505 (V2R8 to V2R11): the Security log must hold a week of
		// records, and the check fails a MaxSize below 5,120,000 KB (older
		// releases: 1,024,000 KB). C6: a STIG-audited Windows 11 fills the
		// 20 MB default within an hour during Windows Update.
		{"Security", 5120000, false, "WN11-AU-000505"},
		{"System", 32768, false, "WN11-AU-000510"},
		{"Application", 32768, false, "WN11-AU-000500"},
	},
}

// WindowsServer2025 is the Windows Server 2025 STIG V1R1.
var WindowsServer2025 = Baseline{
	Name: "Windows Server 2025 STIG V1R1",
	Audit: []auditReq{
		{gCredentialValidation, "Credential Validation", w25("070"), w25("080"), aFailedLogons, false},
		{gOtherAccountMgmt, "Other Account Management Events", w25("090"), "", "", false},
		{gSecurityGroupMgmt, "Security Group Management", w25("100"), "", aAccounts, false},
		{gUserAccountMgmt, "User Account Management", w25("110"), w25("120"), aAccounts, false},
		{gPlugAndPlay, "Plug and Play Events", w25("130"), "", aUSB, false},
		{gProcessCreation, "Process Creation", w25("140"), "", aElevated, false},
		{gAccountLockout, "Account Lockout", w25("150"), w25("160"), aFailedLogons, false},
		{gGroupMembership, "Group Membership", w25("170"), "", "", false},
		{gLogoff, "Logoff", w25("180"), "", "Logon Activity", false},
		{gLogon, "Logon", w25("190"), w25("200"), aLogons, false},
		{gSpecialLogon, "Special Logon", w25("210"), "", "Privileged Activity (administrator logons)", false},
		{gOtherLogonLogoff, "Other Logon/Logoff Events", "", "", "Logon Activity (Remote Desktop sessions)", true},
		{gOtherObjectAccess, "Other Object Access Events", w25("220"), w25("230"), "Other Security Events (scheduled tasks)", false},
		{gRemovableStorage, "Removable Storage", w25("240"), w25("250"), aUSB + " (files read/written)", false},
		{gFileSystem, "File System", w25("582"), w25("581"), "", false},
		{gHandleManipulation, "Handle Manipulation", w25("584"), w25("583"), "", false},
		{gRegistry, "Registry", w25("586"), w25("585"), "", false},
		{gAuditPolicyChange, "Audit Policy Change", w25("260"), w25("270"), aIntegrity, false},
		{gAuthenticationPolicy, "Authentication Policy Change", w25("280"), "", "", false},
		{gAuthorizationPolicy, "Authorization Policy Change", w25("281"), "", "", false},
		{gSensitivePrivilegeUse, "Sensitive Privilege Use", w25("300"), w25("310"), "", false},
		{gIPsecDriver, "IPsec Driver", w25("320"), w25("330"), "", false},
		{gOtherSystemEvents, "Other System Events", w25("340"), w25("350"), "", false},
		{gSecurityStateChange, "Security State Change", w25("360"), "", aIntegrity + " (startup, time changes)", false},
		{gSecuritySystemExt, "Security System Extension", w25("370"), "", "Other Security Events (services installed)", false},
		{gSystemIntegrity, "System Integrity", w25("380"), w25("390"), aIntegrity, false},
	},
	Registry: []regReq{
		forceSubcategories("WN25-SO-000050"),
		commandLine("WN25-CC-000090"),
		scriptBlockLogging("WN25-CC-000460"),
	},
	Logs: []logReq{
		{"Security", 196608, false, "WN25-CC-000280"},
		{"System", 32768, false, "WN25-CC-000290"},
		{"Application", 32768, false, "WN25-CC-000270"},
	},
}

func forceSubcategories(id string) regReq {
	return regReq{`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, "SCENoApplyLegacyAuditPolicy",
		"Force audit policy subcategory settings", "All sections (advanced audit policy may be ignored without it)",
		gpSecurity + " > Local Policies > Security Options > Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings: Enabled", id}
}

func commandLine(id string) regReq {
	return regReq{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`, "ProcessCreationIncludeCmdLine_Enabled",
		"Include command line in process creation events", "Privileged Activity (full commands, not just program names)",
		gpAdmin + " > System > Audit Process Creation > Include command line in process creation events: Enabled", id}
}

func scriptBlockLogging(id string) regReq {
	return regReq{`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging",
		"PowerShell script block logging", "",
		gpAdmin + " > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging: Enabled", id}
}

// BaselineFor picks the STIG for a Windows installation type ("Client",
// "Server" or "Server Core", from the registry).
func BaselineFor(installationType string) Baseline {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(installationType)), "server") {
		return WindowsServer2025
	}
	return Windows11
}

// weekNeeded is how much history the Security log must hold.
const weekNeeded = 7 * 24 * time.Hour

// holdsWeek checks the Security log holds a week of events: measured from
// the oldest event when the log is full, or estimated from how fast it is
// filling when it is not.
func holdsWeek(r Result, s winevt.LogSettings, history func(string) (winevt.LogHistory, error)) Result {
	r.Want = "enough for at least 7 days of events (DISA's example: 5,120,000 KB)"
	h, err := history("Security")
	held, measured := HeldFor(h, s.MaxSize)
	switch {
	case err != nil:
		r.Status, r.Have = Error, r.Have+"; could not read its history: "+err.Error()
	case !measured:
		r.Status = Info
		r.Have += "; not enough history yet to tell how long it will hold"
	case held >= weekNeeded:
		r.Status = Pass
		r.Have += fmt.Sprintf("; holds about %s", days(held))
	default:
		r.Status = Fail
		r.Have += fmt.Sprintf("; holds about %s", days(held))
		need := uint64(float64(s.MaxSize)*float64(weekNeeded)/float64(held))/1024 + 1
		need = (need + 1023) / 1024 * 1024 // round up to a whole MB
		r.Affects = "Events may be overwritten before collection, and the log does not hold a week of evidence"
		r.Fix = logSizeGPO("Security", need)
	}
	return r
}

// HeldFor says how long a log of maxSize bytes holds events, from its
// current contents: the span of its events when it is (nearly) full, or
// that span scaled up by how much room is left when it is not. It needs at
// least a day of events to estimate.
func HeldFor(h winevt.LogHistory, maxSize uint64) (time.Duration, bool) {
	span := h.Newest.Sub(h.Oldest)
	if h.Oldest.IsZero() || span <= 0 || h.FileSize == 0 || maxSize == 0 {
		return 0, false
	}
	if float64(h.FileSize) >= 0.9*float64(maxSize) {
		return span, true
	}
	if span < 24*time.Hour {
		return 0, false
	}
	return time.Duration(float64(span) * float64(maxSize) / float64(h.FileSize)), true
}

func days(d time.Duration) string {
	n := int(d.Hours()/24 + 0.5)
	if n == 1 {
		return "1 day"
	}
	if n == 0 {
		return rollover.Duration(d) // "1 minute", "40 minutes", "5 hours"
	}
	return fmt.Sprintf("%d days", n)
}
