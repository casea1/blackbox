package check

import (
	"strings"
	"testing"
)

// COMP2: the Linux checks cite the STIG of the system's distribution where
// it has a rule, and are Blackbox's advice where it has none.
func TestCiteLinuxSTIG(t *testing.T) {
	rs := EvaluateAuditRules("", "enabled 1\nbacklog_limit 64\n")
	rs = append(rs, EvaluateAuditdActions(map[string]string{})...)
	rs = append(rs, EvaluateBoot("", "")...)
	rs = append(rs, EvaluateTimeSync(map[string]string{}))
	rs = append(rs, EvaluateAuditLogPerms(0o644, 0o755, nil, nil))

	byName := func(rs []Result) map[string]Result {
		m := map[string]Result{}
		for _, r := range rs {
			m[r.Item] = r
		}
		return m
	}
	ubuntu := byName(CiteLinuxSTIG("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n", rs))
	if b := ubuntu["Compared with"]; b.Area != "Baseline" || b.Have != "Ubuntu 24.04 STIG V1R5" {
		t.Errorf("baseline: %+v", b)
	}
	for item, want := range map[string]string{
		"Rules locked until reboot (-e 2)":                            "UBTU-24-909000",
		"Watch /etc/passwd":                                           "UBTU-24-200280",
		"Watch /etc/sudoers and /etc/sudoers.d":                       "UBTU-24-900510, UBTU-24-900520",
		"Module and ACL tools (kmod, setfacl, chacl)":                 "UBTU-24-900740, UBTU-24-900230, UBTU-24-900240",
		"audit=1 on the kernel command line":                          "UBTU-24-102010",
		"Time synchronisation":                                        "",
		"Audit log permissions":                                       "",
		"disk_full_action":                                            "",
		"Commands run as root by a person (execve, euid=0, auid set)": "",
	} {
		r := ubuntu[item]
		if r.STIG != want {
			t.Errorf("Ubuntu %s: STIG %q, want %q", item, r.STIG, want)
		}
		if (want == "") != r.IsAdvice() {
			t.Errorf("Ubuntu %s: advice %v", item, r.IsAdvice())
		}
	}

	alma := byName(CiteLinuxSTIG("ID=\"almalinux\"\nVERSION_ID=\"9.6\"\n", rs))
	if alma["Compared with"].Have != "AlmaLinux OS 9 STIG V1R8" || alma["disk_full_action"].STIG != "ALMA-09-054140" ||
		alma["Rules locked until reboot (-e 2)"].STIG != "ALMA-09-057110" || alma["Logon records watched (utmp, wtmp, btmp)"].STIG != "" {
		t.Errorf("Alma: %+v", alma)
	}
	rhel := byName(CiteLinuxSTIG("ID=\"rhel\"\nVERSION_ID=\"9.4\"\n", rs))
	if rhel["Compared with"].Have != "RHEL 9 STIG V2R10" || rhel["audit_backlog_limit on the kernel command line"].STIG != "RHEL-09-653120" {
		t.Errorf("RHEL: %+v", rhel)
	}

	alma8 := byName(CiteLinuxSTIG("ID=\"almalinux\"\nVERSION_ID=\"8.10\"\n", rs))
	if !strings.HasPrefix(alma8["Compared with"].Have, "RHEL 8 STIG V2R9") || alma8["Rules locked until reboot (-e 2)"].STIG != "RHEL-08-030121" || alma8["admin_space_left_action"].STIG != "" {
		t.Errorf("AlmaLinux 8: %+v", alma8)
	}
	u22 := byName(CiteLinuxSTIG("ID=ubuntu\nVERSION_ID=\"22.04\"\n", rs))
	if u22["Compared with"].Have != "Ubuntu 22.04 STIG V2R10" || u22["disk_full_action"].STIG != "UBTU-22-653030" || u22["log_format"].STIG != "" {
		t.Errorf("Ubuntu 22.04: %+v", u22)
	}

	// No STIG for this distribution: every check is advice.
	other := CiteLinuxSTIG("ID=ubuntu\nVERSION_ID=\"26.04\"\n", rs)
	if !strings.Contains(other[0].Have, "Blackbox's advice") {
		t.Errorf("baseline for an OS with no STIG: %+v", other[0])
	}
	for _, r := range other[1:] {
		if r.STIG != "" || !r.IsAdvice() {
			t.Errorf("%s cites %q with no STIG for this OS", r.Item, r.STIG)
		}
	}
}

// Every cited check exists, so a renamed check cannot silently lose its ID.
func TestLinuxSTIGItemsExist(t *testing.T) {
	items := map[string]bool{"auditd running": true}
	rs := EvaluateAuditRules("", "enabled 1\nbacklog_limit 64\n")
	rs = append(rs, EvaluateAuditdConf(map[string]string{})...)
	rs = append(rs, EvaluateAuditdActions(map[string]string{})...)
	rs = append(rs, EvaluateBoot("", "")...)
	for _, r := range rs {
		items[r.Item] = true
	}
	for item := range linuxSTIGIDs {
		if !items[item] {
			t.Errorf("linuxSTIGIDs names %q, which no check produces", item)
		}
	}
}
