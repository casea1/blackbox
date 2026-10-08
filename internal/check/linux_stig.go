package check

import "strings"

// The DISA STIG rules the Linux checks cover (COMP2), from the STIG for
// the system's distribution. IDs were checked against the stigaview.com
// copy of each DISA release on 8 October 2026: Ubuntu 24.04 LTS STIG V1R5
// (UBTU-24), Ubuntu 22.04 LTS STIG V2R10 (UBTU-22), AlmaLinux OS 9 STIG
// V1R8 (ALMA-09), RHEL 9 STIG V2R10 (RHEL-09) and RHEL 8 STIG V2R9
// (RHEL-08, which sites apply to AlmaLinux 8: DISA has no AlmaLinux 8
// STIG). A check with no ID for a system is Blackbox's advice there, not
// a STIG rule: the report says "Blackbox recommends" and leaves it out of
// "matching the STIG". A cited ID means the check covers the main part of
// that rule; the SCAP scan is the full test.
//
// Left without an ID on purpose, where the STIG asks for something
// different from what Blackbox checks: audit log permissions (the STIGs
// want 0600 for the log, Blackbox accepts 0640), time synchronisation
// (UBTU-24-100010 forbids systemd-timesyncd, which Blackbox accepts, and
// UBTU-24-600160/600180 are not checked), and the auditd service on
// Ubuntu (UBTU-24-100400 and UBTU-22-653010 only ask for the package).
var linuxSTIGIDs = map[string][5]string{
	// Ubuntu 24.04, Ubuntu 22.04, AlmaLinux 9, RHEL 9, RHEL 8 / AlmaLinux 8.
	"auditd running":     {"", "", "ALMA-09-054910", "RHEL-09-653015", "RHEL-08-030181"},
	"Watch /etc/passwd":  {"UBTU-24-200280", "UBTU-22-654145", "ALMA-09-005410", "RHEL-09-654240", "RHEL-08-030150"},
	"Watch /etc/shadow":  {"UBTU-24-200300", "UBTU-22-654150", "ALMA-09-005960", "RHEL-09-654245", "RHEL-08-030130"},
	"Watch /etc/group":   {"UBTU-24-200290", "UBTU-22-654130", "ALMA-09-005080", "RHEL-09-654225", "RHEL-08-030170"},
	"Watch /etc/gshadow": {"UBTU-24-200310", "UBTU-22-654135", "ALMA-09-005190", "RHEL-09-654230", "RHEL-08-030160"},
	"Watch /etc/sudoers and /etc/sudoers.d": {"UBTU-24-900510, UBTU-24-900520", "UBTU-22-654220, UBTU-22-654225",
		"ALMA-09-004970, ALMA-09-006070", "RHEL-09-654215, RHEL-09-654220", "RHEL-08-030171, RHEL-08-030172"},
	"Programs run with raised privileges (execve, uid!=euid)": {"UBTU-24-200580", "UBTU-22-654230", "ALMA-09-007280", "RHEL-09-654010", "RHEL-08-030000"},
	"Kernel module loading":                                   {"UBTU-24-900340", "UBTU-22-654175", "ALMA-09-046660", "RHEL-09-654080", "RHEL-08-030360"},
	"Filesystem mounts":                                       {"UBTU-24-900090", "UBTU-22-654065", "ALMA-09-047650", "RHEL-09-654180", "RHEL-08-030300"},
	"Unsuccessful file access (EACCES and EPERM)":             {"UBTU-24-900160", "UBTU-22-654165", "ALMA-09-048090", "RHEL-09-654070", "RHEL-08-030420"},
	"Permission and ownership changes (chmod, chown, setxattr)": {"UBTU-24-900150, UBTU-24-900140, UBTU-24-900130",
		"UBTU-22-654155, UBTU-22-654160, UBTU-22-654180", "ALMA-09-048530, ALMA-09-048640, ALMA-09-051390",
		"RHEL-09-654015, RHEL-09-654020, RHEL-09-654025", "RHEL-08-030490, RHEL-08-030480, RHEL-08-030200"},
	"Logon records watched (utmp, wtmp, btmp)": {"UBTU-24-900600, UBTU-24-900590, UBTU-24-900610",
		"UBTU-22-654205, UBTU-22-654200, UBTU-22-654195", "", "", ""},
	"Module and ACL tools (kmod, setfacl, chacl)": {"UBTU-24-900740, UBTU-24-900230, UBTU-24-900240",
		"UBTU-22-654055, UBTU-22-654085, UBTU-22-654015", "ALMA-09-049300, ALMA-09-050180, ALMA-09-048200",
		"RHEL-09-654105, RHEL-09-654040, RHEL-09-654035", "RHEL-08-030580, RHEL-08-030330, RHEL-08-030570"},
	"Rules locked until reboot (-e 2)":               {"UBTU-24-909000", "UBTU-22-654240", "ALMA-09-057110", "RHEL-09-654275", "RHEL-08-030121"},
	"log_format":                                     {"", "", "ALMA-09-046880", "RHEL-09-653100", "RHEL-08-030063"},
	"space_left_action":                              {"UBTU-24-900960", "UBTU-22-653040", "ALMA-09-053590", "RHEL-09-653040", "RHEL-08-030731"},
	"admin_space_left_action":                        {"", "", "ALMA-09-053370", "RHEL-09-653050", ""},
	"disk_full_action":                               {"", "UBTU-22-653030", "ALMA-09-054140", "RHEL-09-653025", "RHEL-08-030060"},
	"disk_error_action":                              {"", "", "ALMA-09-054030", "RHEL-09-653020", "RHEL-08-030040"},
	"action_mail_acct":                               {"UBTU-24-900980", "UBTU-22-653025", "ALMA-09-053810", "RHEL-09-653070", "RHEL-08-030020"},
	"audit=1 on the kernel command line":             {"UBTU-24-102010", "UBTU-22-212015", "ALMA-09-047980", "RHEL-09-212055", "RHEL-08-030601"},
	"audit_backlog_limit on the kernel command line": {"", "", "ALMA-09-051830", "RHEL-09-653120", "RHEL-08-030602"},
}

// Linux STIG releases Blackbox cites, by column of linuxSTIGIDs.
var linuxBaselines = [5]string{"Ubuntu 24.04 STIG V1R5", "Ubuntu 22.04 STIG V2R10", "AlmaLinux OS 9 STIG V1R8",
	"RHEL 9 STIG V2R10", "RHEL 8 STIG V2R9"}

// LinuxBaseline picks the STIG for a Linux system from /etc/os-release:
// its name and column, or "" and -1 when DISA has no STIG Blackbox cites
// for it (every check is then Blackbox's advice).
func LinuxBaseline(osRelease string) (string, int) {
	kv := map[string]string{}
	for _, l := range strings.Split(osRelease, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	id, ver := kv["ID"], kv["VERSION_ID"]
	major, _, _ := strings.Cut(ver, ".")
	col := -1
	switch {
	case id == "ubuntu" && ver == "24.04":
		col = 0
	case id == "ubuntu" && ver == "22.04":
		col = 1
	case id == "almalinux" && major == "9":
		col = 2
	case id == "rhel" && major == "9":
		col = 3
	case (id == "rhel" || id == "almalinux") && major == "8":
		col = 4
	}
	if col < 0 {
		return "", -1
	}
	name := linuxBaselines[col]
	if id == "almalinux" && col == 4 {
		name += " (applied to AlmaLinux 8, which has no STIG of its own)"
	}
	return name, col
}

// CiteLinuxSTIG fills in the STIG IDs of the Linux checks for this
// distribution and puts the baseline first, as on Windows. Without a
// STIG, it says so: every check is then Blackbox's advice.
func CiteLinuxSTIG(osRelease string, rs []Result) []Result {
	name, col := LinuxBaseline(osRelease)
	base := Result{Area: "Baseline", Item: "Compared with", Status: Info, Have: name, Want: name}
	if col < 0 {
		base.Have = "Blackbox's advice (no DISA STIG cited for this distribution)"
		base.Want = base.Have
	}
	out := []Result{base}
	for _, r := range rs {
		if ids, ok := linuxSTIGIDs[r.Item]; ok && col >= 0 && r.Area != "Antivirus" {
			r.STIG = ids[col]
		}
		out = append(out, r)
	}
	return out
}
