package winevt

import (
	"fmt"
	"strconv"
	"strings"
)

// logonTypePhrase describes how someone logged on, for use in a sentence.
func logonTypePhrase(t string) string {
	switch strings.TrimSpace(t) {
	case "0":
		return "as the system"
	case "2":
		return "at the keyboard"
	case "3":
		return "over the network"
	case "4":
		return "as a scheduled task"
	case "5":
		return "as a service"
	case "7":
		return "by unlocking the screen"
	case "8":
		return "over the network with a clear-text password"
	case "9":
		return "with alternate credentials (RunAs /netonly)"
	case "10":
		return "via Remote Desktop"
	case "11":
		return "at the keyboard (cached credentials)"
	case "12":
		return "via Remote Desktop (cached credentials)"
	case "13":
		return "by unlocking the screen (cached credentials)"
	}
	if t == "" {
		return ""
	}
	return "with logon type " + t
}

// logonTypeName is a short label for tables.
func logonTypeName(t string) string {
	switch strings.TrimSpace(t) {
	case "2":
		return "Keyboard"
	case "3":
		return "Network"
	case "4":
		return "Scheduled task"
	case "5":
		return "Service"
	case "7":
		return "Unlock"
	case "8":
		return "Network (clear text)"
	case "9":
		return "RunAs /netonly"
	case "10":
		return "Remote Desktop"
	case "11":
		return "Keyboard (cached)"
	case "12":
		return "Remote Desktop (cached)"
	case "13":
		return "Unlock (cached)"
	}
	return "Type " + t
}

// interactiveLogon reports whether a logon type means a person at a
// session (keyboard or Remote Desktop).
func interactiveLogon(t string) bool {
	switch strings.TrimSpace(t) {
	case "2", "10", "11", "12":
		return true
	}
	return false
}

// ntStatus maps NTSTATUS failure codes seen in logon events to reasons.
var ntStatus = map[string]string{
	"0xc0000064": "the user name does not exist",
	"0xc000006a": "wrong password",
	"0xc000006d": "bad user name or password",
	"0xc000006e": "account restriction",
	"0xc000006f": "logon outside the allowed hours",
	"0xc0000070": "not allowed to log on from this workstation",
	"0xc0000071": "password has expired",
	"0xc0000072": "account is disabled",
	"0xc00000dc": "the account database is in an invalid state",
	"0xc0000133": "clock is out of sync with the domain controller",
	"0xc000015b": "user has not been granted this type of logon",
	"0xc000018c": "trust relationship failed",
	"0xc0000192": "the Netlogon service is not running",
	"0xc0000193": "account has expired",
	"0xc0000224": "user must change password before logging on",
	"0xc0000234": "account is locked out",
	"0xc00002ee": "an error occurred during logon",
	"0xc0000371": "the local account store does not hold the needed secret",
	"0xc0000413": "blocked by the authentication firewall",
}

// failureReason picks the most specific reason from Status/SubStatus.
func failureReason(status, subStatus string) string {
	s := strings.ToLower(strings.TrimSpace(subStatus))
	if s == "" || s == "0x0" || s == "0x00000000" {
		s = strings.ToLower(strings.TrimSpace(status))
	}
	s = normHex(s)
	if r, ok := ntStatus[s]; ok {
		return r
	}
	if s == "" {
		return "reason not recorded"
	}
	return "error code " + s
}

// kerberosFailure maps Kerberos result codes (event 4771).
var kerberosFailure = map[string]string{
	"0x6":  "the user name does not exist",
	"0x12": "account is disabled, expired or locked out",
	"0x17": "password has expired",
	"0x18": "wrong password",
	"0x25": "clock is out of sync with the domain controller",
}

// normHex lowercases and strips zero padding: 0xC000006A → 0xc000006a,
// 0x00000018 → 0x18.
func normHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "0x") {
		return s
	}
	n, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil {
		return s
	}
	return fmt.Sprintf("0x%x", n)
}

// messageTokens translates %%NNNN insertion strings used in Security
// events.
var messageTokens = map[string]string{
	// Yes/No
	"%%1842": "Yes", "%%1843": "No",
	// Token elevation type
	"%%1936": "Full token (UAC disabled or built-in account)",
	"%%1937": "Elevated (Run as administrator)",
	"%%1938": "Limited (not elevated)",
	// Audit policy changes
	"%%8448": "Success auditing removed", "%%8449": "Success auditing added",
	"%%8450": "Failure auditing removed", "%%8451": "Failure auditing added",
	// Audit categories
	"%%8272": "System", "%%8273": "Logon/Logoff", "%%8274": "Object Access",
	"%%8275": "Privilege Use", "%%8276": "Detailed Tracking", "%%8277": "Policy Change",
	"%%8278": "Account Management", "%%8279": "DS Access", "%%8280": "Account Logon",
	// File access rights
	"%%4416": "Read data", "%%4417": "Write data", "%%4418": "Append data",
	"%%4419": "Read extended attributes", "%%4420": "Write extended attributes",
	"%%4421": "Execute", "%%4422": "Delete child", "%%4423": "Read attributes",
	"%%4424": "Write attributes",
	"%%1537": "Delete", "%%1538": "Read permissions", "%%1539": "Change permissions",
	"%%1540": "Change owner", "%%1541": "Synchronize",
	// Account enabled/disabled flags in UAC changes
	"%%2080": "Account disabled", "%%2048": "Account enabled",
}

// expandTokens replaces every %%NNNN token in s with its meaning.
func expandTokens(s string) string {
	fields := strings.Fields(strings.NewReplacer(",", " ", ";", " ").Replace(s))
	var out []string
	for _, f := range fields {
		if m, ok := messageTokens[f]; ok {
			out = append(out, m)
		} else {
			out = append(out, f)
		}
	}
	return strings.Join(out, ", ")
}

// wellKnownSIDs resolves SIDs that are the same on every Windows system.
var wellKnownSIDs = map[string]string{
	"S-1-0-0":  "Nobody",
	"S-1-1-0":  "Everyone",
	"S-1-5-7":  "ANONYMOUS LOGON",
	"S-1-5-18": "SYSTEM",
	"S-1-5-19": "LOCAL SERVICE",
	"S-1-5-20": "NETWORK SERVICE",
	// Service SIDs (S-1-5-80-SHA1 of the service name), so exported logs
	// read on another computer still name them (A13c).
	"S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052":  `NT SERVICE\MpsSvc`,
	"S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736": `NT SERVICE\WinDefend`,
	"S-1-5-32-544": "Administrators",
	"S-1-5-32-545": "Users",
	"S-1-5-32-546": "Guests",
	"S-1-5-32-547": "Power Users",
	"S-1-5-32-548": "Account Operators",
	"S-1-5-32-549": "Server Operators",
	"S-1-5-32-550": "Print Operators",
	"S-1-5-32-551": "Backup Operators",
	"S-1-5-32-555": "Remote Desktop Users",
	"S-1-5-32-562": "Distributed COM Users",
	"S-1-5-32-573": "Event Log Readers",
	"S-1-5-32-578": "Hyper-V Administrators",
	"S-1-5-32-580": "Remote Management Users",
}

// privilegedGroups are groups whose membership grants administrative or
// remote access. Adding someone to one of these is high severity.
var privilegedGroups = map[string]bool{
	"administrators": true, "domain admins": true, "enterprise admins": true,
	"schema admins": true, "backup operators": true, "account operators": true,
	"server operators": true, "print operators": true, "remote desktop users": true,
	"remote management users": true, "hyper-v administrators": true,
	"group policy creator owners": true, "dnsadmins": true, "key admins": true,
	"enterprise key admins": true, "event log readers": true,
	"distributed com users": true,
}

// isPrivilegedGroup matches by name or well-known SID (…-512 Domain
// Admins, …-518 Schema Admins, …-519 Enterprise Admins).
func isPrivilegedGroup(name, sid string) bool {
	if privilegedGroups[strings.ToLower(name)] {
		return true
	}
	if n, ok := wellKnownSIDs[sid]; ok && privilegedGroups[strings.ToLower(n)] {
		return true
	}
	for _, suffix := range []string{"-512", "-518", "-519"} {
		if strings.HasPrefix(sid, "S-1-5-21-") && strings.HasSuffix(sid, suffix) {
			return true
		}
	}
	return false
}

// privilegeNames gives short explanations for sensitive privileges in
// event 4672.
var privilegeNames = map[string]string{
	"SeDebugPrivilege":                          "debug programs",
	"SeTcbPrivilege":                            "act as part of the operating system",
	"SeBackupPrivilege":                         "back up files",
	"SeRestorePrivilege":                        "restore files",
	"SeTakeOwnershipPrivilege":                  "take ownership",
	"SeLoadDriverPrivilege":                     "load drivers",
	"SeSecurityPrivilege":                       "manage audit and security log",
	"SeSystemEnvironmentPrivilege":              "modify firmware values",
	"SeImpersonatePrivilege":                    "impersonate",
	"SeAssignPrimaryTokenPrivilege":             "replace process token",
	"SeCreateTokenPrivilege":                    "create tokens",
	"SeEnableDelegationPrivilege":               "enable delegation",
	"SeDelegateSessionUserImpersonatePrivilege": "impersonate session user",
}

// AuditSubcategories maps advanced audit policy subcategory GUIDs to
// names. Used for event 4719 and for the audit configuration check.
var AuditSubcategories = map[string]string{
	"{0CCE9210-69AE-11D9-BED3-505054503030}": "Security State Change",
	"{0CCE9211-69AE-11D9-BED3-505054503030}": "Security System Extension",
	"{0CCE9212-69AE-11D9-BED3-505054503030}": "System Integrity",
	"{0CCE9213-69AE-11D9-BED3-505054503030}": "IPsec Driver",
	"{0CCE9214-69AE-11D9-BED3-505054503030}": "Other System Events",
	"{0CCE9215-69AE-11D9-BED3-505054503030}": "Logon",
	"{0CCE9216-69AE-11D9-BED3-505054503030}": "Logoff",
	"{0CCE9217-69AE-11D9-BED3-505054503030}": "Account Lockout",
	"{0CCE9218-69AE-11D9-BED3-505054503030}": "IPsec Main Mode",
	"{0CCE9219-69AE-11D9-BED3-505054503030}": "IPsec Quick Mode",
	"{0CCE921A-69AE-11D9-BED3-505054503030}": "IPsec Extended Mode",
	"{0CCE921B-69AE-11D9-BED3-505054503030}": "Special Logon",
	"{0CCE921C-69AE-11D9-BED3-505054503030}": "Other Logon/Logoff Events",
	"{0CCE921D-69AE-11D9-BED3-505054503030}": "File System",
	"{0CCE921E-69AE-11D9-BED3-505054503030}": "Registry",
	"{0CCE921F-69AE-11D9-BED3-505054503030}": "Kernel Object",
	"{0CCE9220-69AE-11D9-BED3-505054503030}": "SAM",
	"{0CCE9221-69AE-11D9-BED3-505054503030}": "Certification Services",
	"{0CCE9222-69AE-11D9-BED3-505054503030}": "Application Generated",
	"{0CCE9223-69AE-11D9-BED3-505054503030}": "Handle Manipulation",
	"{0CCE9224-69AE-11D9-BED3-505054503030}": "File Share",
	"{0CCE9225-69AE-11D9-BED3-505054503030}": "Filtering Platform Packet Drop",
	"{0CCE9226-69AE-11D9-BED3-505054503030}": "Filtering Platform Connection",
	"{0CCE9227-69AE-11D9-BED3-505054503030}": "Other Object Access Events",
	"{0CCE9228-69AE-11D9-BED3-505054503030}": "Sensitive Privilege Use",
	"{0CCE9229-69AE-11D9-BED3-505054503030}": "Non Sensitive Privilege Use",
	"{0CCE922A-69AE-11D9-BED3-505054503030}": "Other Privilege Use Events",
	"{0CCE922B-69AE-11D9-BED3-505054503030}": "Process Creation",
	"{0CCE922C-69AE-11D9-BED3-505054503030}": "Process Termination",
	"{0CCE922D-69AE-11D9-BED3-505054503030}": "DPAPI Activity",
	"{0CCE922E-69AE-11D9-BED3-505054503030}": "RPC Events",
	"{0CCE922F-69AE-11D9-BED3-505054503030}": "Audit Policy Change",
	"{0CCE9230-69AE-11D9-BED3-505054503030}": "Authentication Policy Change",
	"{0CCE9231-69AE-11D9-BED3-505054503030}": "Authorization Policy Change",
	"{0CCE9232-69AE-11D9-BED3-505054503030}": "MPSSVC Rule-Level Policy Change",
	"{0CCE9233-69AE-11D9-BED3-505054503030}": "Filtering Platform Policy Change",
	"{0CCE9234-69AE-11D9-BED3-505054503030}": "Other Policy Change Events",
	"{0CCE9235-69AE-11D9-BED3-505054503030}": "User Account Management",
	"{0CCE9236-69AE-11D9-BED3-505054503030}": "Computer Account Management",
	"{0CCE9237-69AE-11D9-BED3-505054503030}": "Security Group Management",
	"{0CCE9238-69AE-11D9-BED3-505054503030}": "Distribution Group Management",
	"{0CCE9239-69AE-11D9-BED3-505054503030}": "Application Group Management",
	"{0CCE923A-69AE-11D9-BED3-505054503030}": "Other Account Management Events",
	"{0CCE923B-69AE-11D9-BED3-505054503030}": "Directory Service Access",
	"{0CCE923C-69AE-11D9-BED3-505054503030}": "Directory Service Changes",
	"{0CCE923D-69AE-11D9-BED3-505054503030}": "Directory Service Replication",
	"{0CCE923E-69AE-11D9-BED3-505054503030}": "Detailed Directory Service Replication",
	"{0CCE923F-69AE-11D9-BED3-505054503030}": "Credential Validation",
	"{0CCE9240-69AE-11D9-BED3-505054503030}": "Kerberos Service Ticket Operations",
	"{0CCE9241-69AE-11D9-BED3-505054503030}": "Other Account Logon Events",
	"{0CCE9242-69AE-11D9-BED3-505054503030}": "Kerberos Authentication Service",
	"{0CCE9243-69AE-11D9-BED3-505054503030}": "Network Policy Server",
	"{0CCE9244-69AE-11D9-BED3-505054503030}": "Detailed File Share",
	"{0CCE9245-69AE-11D9-BED3-505054503030}": "Removable Storage",
	"{0CCE9246-69AE-11D9-BED3-505054503030}": "Central Policy Staging",
	"{0CCE9247-69AE-11D9-BED3-505054503030}": "User / Device Claims",
	"{0CCE9248-69AE-11D9-BED3-505054503030}": "Plug and Play Events",
	"{0CCE9249-69AE-11D9-BED3-505054503030}": "Group Membership",
	"{0CCE924A-69AE-11D9-BED3-505054503030}": "Token Right Adjusted Events",
}

// taskRemovableStorage is the Security event task category for the
// "Removable Storage" audit subcategory (events 4656/4663).
const taskRemovableStorage = 12812

// taskFileSystem is the task category of the "File System" subcategory:
// object access on files and folders with an auditing (SACL) entry.
const taskFileSystem = 12800

// busTypes maps STORAGE_BUS_TYPE values (Partition/Diagnostic 1006).
var busTypes = map[string]string{
	"1": "SCSI", "2": "ATAPI", "3": "ATA", "4": "FireWire (1394)", "5": "SSA",
	"6": "Fibre Channel", "7": "USB", "8": "RAID", "9": "iSCSI", "10": "SAS",
	"11": "SATA", "12": "SD card", "13": "MMC card", "14": "Virtual disk",
	"15": "Virtual disk (file-backed, e.g. ISO/VHD)", "16": "Storage Spaces",
	"17": "NVMe", "18": "SCM", "19": "UFS",
}

// removableBus reports bus types that indicate removable media.
func removableBus(bt string) bool {
	switch bt {
	case "4", "7", "12", "13":
		return true
	}
	return false
}

// virtualBus reports virtual disks (mounted ISO or VHD files).
func virtualBus(bt string) bool { return bt == "14" || bt == "15" }

// EventNames gives short names for event IDs, used in the log volume
// panel so a flood of events can be identified at a glance.
var EventNames = map[int]string{
	1100: "Event logging service shut down", 1102: "Security log cleared",
	1104: "Security log full", 1105: "Log automatic backup",
	4608: "Windows starting up", 4616: "System time changed",
	4624: "Successful logon", 4625: "Failed logon", 4627: "Group membership information",
	4634: "Logoff", 4647: "User-initiated logoff", 4648: "Logon with explicit credentials",
	4656: "Handle to an object requested", 4657: "Registry value modified",
	4658: "Handle to an object closed", 4660: "Object deleted", 4661: "Handle to SAM/DS object requested",
	4662: "Operation performed on an object", 4663: "Attempt to access an object",
	4664: "Hard link created", 4670: "Object permissions changed", 4672: "Special privileges assigned to logon",
	4673: "Privileged service called", 4674: "Operation attempted on a privileged object",
	4688: "Process created", 4689: "Process exited", 4690: "Handle duplicated",
	4697: "Service installed", 4698: "Scheduled task created", 4699: "Scheduled task deleted",
	4700: "Scheduled task enabled", 4701: "Scheduled task disabled", 4702: "Scheduled task updated",
	4703: "Token right adjusted", 4719: "System audit policy changed",
	4720: "User account created", 4722: "User account enabled", 4723: "Password change attempt",
	4724: "Password reset attempt", 4725: "User account disabled", 4726: "User account deleted",
	4728: "Member added to global group", 4732: "Member added to local group", 4738: "User account changed",
	4740: "User account locked out", 4767: "User account unlocked", 4768: "Kerberos TGT requested",
	4769: "Kerberos service ticket requested", 4771: "Kerberos pre-authentication failed",
	4776: "Credential validation (NTLM)", 4778: "Session reconnected", 4779: "Session disconnected",
	4798: "Local group membership enumerated", 4799: "Security group membership enumerated",
	4800: "Workstation locked", 4801: "Workstation unlocked", 4907: "Auditing settings changed on object",
	4946: "Firewall rule added", 4957: "Firewall rule not applied",
	5058: "Key file operation", 5061: "Cryptographic operation",
	5140: "Network share accessed", 5145: "Network share object checked",
	5152: "Packet dropped by Filtering Platform", 5154: "Filtering Platform permitted listen",
	5156: "Filtering Platform permitted connection", 5157: "Filtering Platform blocked connection",
	5158: "Filtering Platform permitted bind", 5379: "Credential Manager credentials read",
	5382: "Vault credentials read",
	6416: "New external device recognized",
	4611: "Trusted logon process registered", 4612: "Audit events dropped (queue full)",
	4614: "Notification package loaded", 4622: "Security package loaded", 4704: "User right assigned",
	4705: "User right removed", 4706: "Domain trust created", 4707: "Domain trust removed",
	4713: "Kerberos policy changed", 4716: "Domain trust changed", 4739: "Domain policy changed",
	4765: "SID history added", 4766: "SID history add failed", 4826: "Boot configuration loaded",
	4947: "Firewall rule changed", 4948: "Firewall rule deleted", 4949: "Firewall settings reset",
	4950: "Firewall setting changed", 5024: "Firewall service started", 5025: "Firewall service stopped",
	5030: "Firewall service failed to start", 5038: "Code integrity: file hash invalid",
	6281: "Code integrity: page hashes invalid", 4691: "Indirect access to an object",
	4944: "Firewall policy at startup", 4945: "Firewall rule listed at startup", 4985: "Transaction state changed",
	5059: "Key migration operation", 5153: "Filtering Platform blocked packet", 5155: "Filtering Platform blocked listen",
	5159: "Filtering Platform blocked bind", 5381: "Vault credentials read", 5444: "Filtering Platform provider",
	5447: "Filtering Platform filter changed", 5632: "Wireless authentication request", 5633: "Wired authentication request",
	4802: "Screen saver started", 4803: "Screen saver stopped", 4649: "Replay attack detected",
	4964: "Special groups assigned to logon", 4902: "Per-user audit policy table created", 4904: "Security event source registered",
	4905: "Security event source unregistered", 4906: "CrashOnAuditFail changed", 4908: "Special groups logon table changed",
	4912: "Per-user audit policy changed", 4715: "Audit policy (SACL) on object changed", 4817: "Auditing settings changed on object",
	5378: "Credential delegation not allowed", 4793: "Password policy checking API called", 4782: "Password hash accessed",
	// System log
	104: "Event log cleared", 1074: "Shutdown/restart initiated", 6005: "Event log service started",
	6006: "Event log service stopped", 6008: "Unexpected shutdown", 7036: "Service state changed",
	7040: "Service start type changed", 7045: "Service installed",
}
