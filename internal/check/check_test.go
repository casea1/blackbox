package check

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/rollover"
	"github.com/casea1/blackbox/internal/winevt"
)

const auditpolCSV = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n" +
	"WS-07,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,\r\n" +
	"WS-07,System,Removable Storage,{0CCE9245-69AE-11D9-BED3-505054503030},No Auditing,\r\n" +
	"WS-07,System,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Success,\r\n"

func TestAuditpol(t *testing.T) {
	have, err := ParseAuditpol(auditpolCSV)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Result{}
	for _, r := range EvaluateAuditpol(Windows11, have) {
		byName[r.Item] = r
	}
	if byName["Logon"].Status != Pass || byName["Logon"].STIG != "WN11-AU-000075, WN11-AU-000070" {
		t.Errorf("Logon: %+v", byName["Logon"])
	}
	rs := byName["Removable Storage"]
	if rs.Status != Fail || !strings.Contains(rs.Fix, "Audit Removable Storage: Configure the following audit events: Success and Failure") || !strings.Contains(rs.Affects, "USB") {
		t.Errorf("Removable Storage: %+v", rs)
	}
	if al := byName["Account Lockout"]; al.Status != Fail || !strings.HasSuffix(al.Fix, "Audit Account Lockout: Configure the following audit events: Failure") {
		t.Errorf("Account Lockout needs failure only on Windows 11: %+v", al)
	}
	if r := byName["Registry"]; r.Want != "Success and Failure" || r.Status != Fail || r.IsAdvice() {
		t.Errorf("Registry is required (WN11-AU-000586/589): %+v", r)
	}
	// COMP1: File System (WN11-AU-000581/582) and Handle Manipulation
	// success (WN11-AU-000584) are not in V2R8 or V2R11: Blackbox's advice.
	if r := byName["File System"]; r.Status != Fail || r.STIG != "" || !r.IsAdvice() || !strings.Contains(r.Want, "Blackbox's advice") {
		t.Errorf("File System is Blackbox's advice on Windows 11: %+v", r)
	}
	if r := byName["Handle Manipulation"]; r.Status != Fail || r.STIG != "WN11-AU-000583" || r.IsAdvice() {
		t.Errorf("Handle Manipulation failure (WN11-AU-000583) is still a STIG gap: %+v", r)
	}
	if r := byName["Process Creation"]; r.Want != "Success and Failure" {
		t.Errorf("Process Creation failures are required (WN11-AU-000585): %+v", r)
	}
}

// COMP1: with Handle Manipulation failure audited, only Blackbox's advice
// (success) is missing; Server 2025 still requires all three.
func TestWindows11AdviceNotSTIG(t *testing.T) {
	have := map[string][2]bool{gHandleManipulation: {false, true}}
	for _, r := range EvaluateAuditpol(Windows11, have) {
		if r.Item == "Handle Manipulation" && (r.Status != Fail || !r.IsAdvice() || r.STIG != "WN11-AU-000583") {
			t.Errorf("only the advised success part is missing: %+v", r)
		}
		if strings.Contains(r.STIG, "WN11-AU-000581") || strings.Contains(r.STIG, "WN11-AU-000582") || strings.Contains(r.STIG, "WN11-AU-000584") {
			t.Errorf("%s cites a rule not in the Windows 11 STIG V2R11: %s", r.Item, r.STIG)
		}
	}
	for _, r := range EvaluateAuditpol(WindowsServer2025, map[string][2]bool{}) {
		if (r.Item == "File System" || r.Item == "Handle Manipulation") && r.IsAdvice() {
			t.Errorf("Server 2025 STIG requires %s: %+v", r.Item, r)
		}
	}
	if Windows11.Name != "Windows 11 STIG V2R11" {
		t.Errorf("baseline name %q", Windows11.Name)
	}
}

func TestOtherPolicyChangeNeedsFailureOnly(t *testing.T) {
	have := map[string][2]bool{gOtherPolicyChange: {false, true}}
	for _, r := range EvaluateAuditpol(Windows11, have) {
		if r.Item == "Other Policy Change Events" && r.Status != Pass {
			t.Errorf("failure-only auditing meets WN11-AU-000555: %+v", r)
		}
	}
}

func TestServerBaselineDiffers(t *testing.T) {
	if BaselineFor("Server").Name != WindowsServer2025.Name || BaselineFor("Server Core").Name != WindowsServer2025.Name || BaselineFor("Client").Name != Windows11.Name {
		t.Fatal("baseline chosen by installation type")
	}
	byName := map[string]Result{}
	for _, r := range EvaluateAuditpol(WindowsServer2025, map[string][2]bool{}) {
		byName[r.Item] = r
	}
	if r := byName["Other Account Management Events"]; r.Status != Fail || r.STIG != "WN25-AU-000090" {
		t.Errorf("Server 2025 requires Other Account Management Events: %+v", r)
	}
	if r := byName["Account Lockout"]; r.Want != "Success and Failure" {
		t.Errorf("Server 2025 Account Lockout: %+v", r)
	}
	if _, ok := byName["MPSSVC Rule-Level Policy Change"]; ok {
		t.Error("MPSSVC is a Windows 11 requirement, not Server 2025")
	}
	if r := byName["Other Logon/Logoff Events"]; r.Status != Info {
		t.Errorf("not a Server 2025 requirement, so only recommended: %+v", r)
	}
}

func TestRegistryAndLogs(t *testing.T) {
	rs := EvaluateRegistry(Windows11, func(key, value string) (string, error) {
		return "\r\nHKEY_LOCAL_MACHINE\\...\r\n    " + value + "    REG_DWORD    0x1\r\n", nil
	})
	if len(rs) != 4 {
		t.Errorf("Windows 11 registry checks: %d, want 4 (incl. PowerShell logging)", len(rs))
	}
	for _, r := range rs {
		if r.Status != Pass || r.STIG == "" {
			t.Errorf("%s: %s %q", r.Item, r.Status, r.STIG)
		}
	}
	settings := func(name string) (winevt.LogSettings, error) {
		return winevt.ParseLogSettings("name: " + name + "\nenabled: false\nlogging:\n  retention: false\n  maxSize: 20971520\n"), nil
	}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	full := func(span time.Duration) func(string) (winevt.LogHistory, error) {
		return func(string) (winevt.LogHistory, error) {
			return winevt.LogHistory{Oldest: now.Add(-span), Newest: now, FileSize: 20971520}, nil
		}
	}
	find := func(rs []Result, item string) Result {
		for _, r := range rs {
			if r.Item == item {
				return r
			}
		}
		return Result{}
	}
	// C6: Windows 11's Security log fails below WN11-AU-000505's 5,120,000
	// KB, whatever history it happens to hold so far.
	sec := find(EvaluateLogs(Windows11, settings, full(9*24*time.Hour)), "Security log")
	if sec.Status != Fail || !strings.Contains(sec.Want, "5120000 KB") || !strings.Contains(sec.Fix, "Specify the maximum log file size (KB): Enabled, 5120000") || sec.STIG != "WN11-AU-000505" {
		t.Errorf("a 20 MB Security log fails WN11-AU-000505: %+v", sec)
	}
	big := func(name string) (winevt.LogSettings, error) {
		return winevt.ParseLogSettings("name: " + name + "\nenabled: true\nlogging:\n  retention: false\n  maxSize: 5242880000\n"), nil
	}
	if sec := find(EvaluateLogs(Windows11, big, full(time.Hour)), "Security log"); sec.Status != Pass {
		t.Errorf("a 5,120,000 KB log passes: %+v", sec)
	}
	if part := find(EvaluateLogs(Windows11, settings, full(time.Hour)), "Microsoft-Windows-Partition/Diagnostic"); part.Status != Fail {
		t.Errorf("disabled Partition/Diagnostic log should fail: %+v", part)
	}
	if psl := find(EvaluateLogs(Windows11, settings, full(time.Hour)), "Microsoft-Windows-PowerShell/Operational"); psl.Status != Info {
		t.Errorf("a disabled PowerShell log is information, not a failure: %+v", psl)
	}
	srv := find(EvaluateLogs(WindowsServer2025, settings, full(time.Hour)), "Security log")
	if srv.Status != Fail || !strings.Contains(srv.Want, "196608 KB") || srv.STIG != "WN25-CC-000280" {
		t.Errorf("Server 2025 Security log needs 196608 KB: %+v", srv)
	}
}

func TestHeldFor(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// Half full after 4 days: holds about 8.
	if d, ok := HeldFor(winevt.LogHistory{Oldest: now.Add(-96 * time.Hour), Newest: now, FileSize: 50}, 100); !ok || d != 192*time.Hour {
		t.Errorf("half full: %v %v", d, ok)
	}
	// Under a day of events in a mostly empty log: too early to tell.
	if _, ok := HeldFor(winevt.LogHistory{Oldest: now.Add(-time.Hour), Newest: now, FileSize: 1}, 100); ok {
		t.Error("too little history to estimate")
	}
}

func TestLinuxAuditRules(t *testing.T) {
	// The recommended rules, as auditctl -l would list them, pass every check.
	var loaded []string
	for _, l := range strings.Split(AuditRules, "\n") {
		if strings.HasPrefix(l, "-a") || strings.HasPrefix(l, "-w") {
			loaded = append(loaded, l)
		}
	}
	for _, r := range EvaluateAuditRules(strings.Join(loaded, "\n"), "enabled 2\nbacklog_limit 8192\nlost 0\n") {
		if r.Status != Pass {
			t.Errorf("%s: %s (%s)", r.Item, r.Status, r.Have)
		}
	}
	// No rules at all: required items fail and point at the fix.
	var fails int
	for _, r := range EvaluateAuditRules("No rules", "enabled 1\nbacklog_limit 64\n") {
		if r.Status == Fail {
			fails++
			if r.Fix == "" {
				t.Errorf("%s: no fix given", r.Item)
			}
		}
	}
	if fails < 8 {
		t.Errorf("only %d failures with no rules loaded", fails)
	}
	if r := EvaluateCmdline("BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro audit=1 quiet"); r.Status != Pass {
		t.Error("audit=1 not detected")
	}
	if r := EvaluateCmdline("BOOT_IMAGE=/vmlinuz audit=0"); r.Status != Fail {
		t.Error("audit=0 should fail")
	}
	conf := ParseAuditdConf("log_format = RAW\nmax_log_file = 8\nnum_logs = 5\nmax_log_file_action = ROTATE\n")
	rs := EvaluateAuditdConf(conf)
	if rs[0].Status != Warn || !strings.Contains(rs[1].Have, "40 MB") {
		t.Errorf("auditd.conf evaluation wrong: %+v", rs)
	}
}

// usgLoaded is `auditctl -l` output in the form the DISA STIG for Ubuntu
// 24.04 (applied by Canonical USG) loads: its own key names, the mount
// program rather than the mount syscall, trailing slashes dropped.
var usgLoaded = strings.Join([]string{
	"-w /etc/passwd -p wa -k usergroup_modification",
	"-w /etc/group -p wa -k usergroup_modification",
	"-w /etc/shadow -p wa -k usergroup_modification",
	"-w /etc/gshadow -p wa -k usergroup_modification",
	"-w /etc/security/opasswd -p wa -k usergroup_modification",
	"-w /etc/sudoers -p wa -k privilege_modification",
	"-w /etc/sudoers.d -p wa -k privilege_modification",
	"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv",
	"-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv",
	"-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv",
	"-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv",
	"-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
	"-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
	"-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
	"-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
	"-a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount",
	"-w /var/log/lastlog -p wa -k logins",
	"-w /var/run/utmp -p wa -k logins",
	"-w /var/log/wtmp -p wa -k logins",
	"-w /var/log/btmp -p wa -k logins",
	"-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access",
	"-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access",
	"-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng",
	"-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng",
	"-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_chng",
	"-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=modules",
	"-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng",
	"-a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng",
}, "\n")

func TestSTIGHardenedRulesPass(t *testing.T) {
	for _, r := range EvaluateAuditRules(usgLoaded, "enabled 2\nbacklog_limit 8192\n") {
		if r.Status == Fail {
			t.Errorf("a STIG-hardened system fails %q", r.Item)
		}
	}
}

func TestWatchMatchingIsExact(t *testing.T) {
	// /etc/sudoers.d alone must not count as watching /etc/sudoers.
	if watches("/etc/sudoers")([]string{"-w /etc/sudoers.d -p wa -k x"}) {
		t.Error("/etc/sudoers.d matched /etc/sudoers")
	}
	// auditctl lists "-w /etc/audit/" without the slash.
	if !watches("/etc/audit/")([]string{"-w /etc/audit -p wa -k auditconfig"}) {
		t.Error("/etc/audit without the trailing slash not recognised")
	}
}

func TestLockedRulesSayReboot(t *testing.T) {
	for _, r := range EvaluateAuditRules("No rules", "enabled 2\nbacklog_limit 8192\n") {
		if r.Status == Fail && !strings.Contains(r.Fix, "reboot") {
			t.Errorf("%s: fix %q should say a reboot is needed while rules are locked", r.Item, r.Fix)
		}
	}
}

func TestMissingRulesAddsOnlyGaps(t *testing.T) {
	exists := func(p string) bool { return p != "/var/run/faillock" }
	// auditctl -l lists a path rule with -S all and key= (A12).
	if m := MissingRules("-a always,exit -F path=/etc/shadow -F perm=wa -k identity", "-a always,exit -S all -F path=/etc/shadow -F perm=wa -F key=x", nil); len(m) != 0 {
		t.Errorf("listed path rule not recognised: %v", m)
	}
	if m := MissingRules("-a always,exit -F dir=/etc/cron.d/ -F perm=wa -k jobs", "-w /etc/cron.d -p wa -k cron", nil); len(m) != 0 {
		t.Errorf("-w on a folder doesn't cover dir=: %v", m)
	}
	missing := MissingRules(AuditRules, usgLoaded, exists)
	joined := strings.Join(missing, "\n")
	// Already loaded under the STIG's own keys: not added again.
	// A12: the baseline's "-w" watches cover the recommended "path=" and
	// "dir=" rules.
	for _, dup := range []string{"path=/etc/passwd ", "path=/etc/sudoers ", "dir=/etc/sudoers.d/", "uid!=euid", "init_module", "path=/var/log/lastlog"} {
		if strings.Contains(joined, dup) {
			t.Errorf("rule already loaded would be added again: %s", dup)
		}
	}
	// Not loaded: added.
	for _, want := range []string{"-S mount,umount2", "clock_settime", "dir=/etc/audit/", "-k root_commands", "-k blackbox", "-k scheduled_jobs", "-k log_tamper"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing rule not added: %s\n%s", want, joined)
		}
	}
	// A watch on a path that does not exist would stop the rules loading.
	if strings.Contains(joined, "/var/run/faillock") {
		t.Error("watch on a missing path added")
	}
	// Nothing is missing once everything is loaded.
	if again := MissingRules(AuditRules, AuditRules, nil); len(again) != 0 {
		t.Errorf("rules missing from themselves: %v", again)
	}
}

func TestNotInRulesDFindsRulesAugenrulesWouldDrop(t *testing.T) {
	auditRules := "-D\n-b 8192\n-w /etc/sudoers -p wa -k actions\n-a always,exit -F arch=b64 -S execve -F euid=0 -k rootcmd\n-e 2\n"
	if got := NotInRulesD(auditRules, nil); len(got) != 2 || got[0] != "-w /etc/sudoers -p wa -k actions" {
		t.Errorf("empty rules.d: %q, want 2", got)
	}
	d := []string{"-w /etc/sudoers/ -p aw -k other_key\n", "-a always,exit -F arch=b64 -S execve -F euid=0\n"}
	if got := NotInRulesD(auditRules, d); len(got) != 0 {
		t.Errorf("all in rules.d: %q, want none", got)
	}
	// I2: only the rule rules.d lacks, not all of audit.rules.
	if got := NotInRulesD(auditRules, d[:1]); len(got) != 1 || !strings.Contains(got[0], "execve") {
		t.Errorf("one missing: %q", got)
	}
}

// I5: on a merged-/usr system, a rule on /sbin/modprobe is the rule on
// /usr/sbin/modprobe; --missing does not propose it again.
func TestMergedUsrPaths(t *testing.T) {
	defer func(v bool) { MergedUsr = v }(MergedUsr)
	rec := "-a always,exit -F path=/usr/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=unset -k modules\n-w /usr/sbin/fdisk -p x -k fdisk\n"
	loaded := "-a always,exit -S all -F path=/sbin/modprobe -F perm=x -F auid>=1000 -F auid!=-1 -F key=stig\n-w /sbin/fdisk -p x -k stig\n"
	MergedUsr = true
	if got := MissingRules(rec, loaded, nil); len(got) != 0 {
		t.Errorf("merged /usr: proposed %q", got)
	}
	MergedUsr = false
	if got := MissingRules(rec, loaded, nil); len(got) != 2 {
		t.Errorf("separate /usr: proposed %q", got)
	}
}

// I1: the rules file sorts after a STIG baseline's own files.
func TestRulesFileSortsLast(t *testing.T) {
	for _, stig := range []string{"actions.rules", "privileged.rules", "time-change.rules", "99-finalize.rules", "audit_rules_usergroup_modification.rules"} {
		if !(stig < filepath.Base(RulesFile)) {
			t.Errorf("%s sorts after %s", stig, RulesFile)
		}
	}
}

// Sites set audit policy in Group Policy, so "How to fix" names the
// Group Policy setting.
func TestFixesAreGroupPolicy(t *testing.T) {
	rs := EvaluateAuditpol(Windows11, map[string][2]bool{})
	for _, r := range rs {
		if r.Status == Fail && !strings.Contains(r.Fix, "Advanced Audit Policy Configuration > Audit Policies > ") {
			t.Errorf("%s: %s", r.Item, r.Fix)
		}
	}
	for _, r := range rs {
		if r.Item == "Removable Storage" && !strings.HasSuffix(r.Fix, "Object Access > Audit Removable Storage: Configure the following audit events: Success and Failure") {
			t.Errorf("removable storage fix: %s", r.Fix)
		}
	}
	for _, r := range EvaluateRegistry(Windows11, func(k, v string) (string, error) { return "", nil }) {
		if !strings.HasPrefix(r.Fix, "Computer Configuration > Policies > ") {
			t.Errorf("%s: %s", r.Item, r.Fix)
		}
	}
	for _, q := range append(Windows11.Audit, WindowsServer2025.Audit...) {
		if _, ok := auditCategories[q.name]; !ok {
			t.Errorf("no Group Policy location for %s", q.name)
		}
	}
}

func TestDefender(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	fresh := `{"AMServiceEnabled":true,"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureVersion":"1.419.231.0",` +
		`"AntivirusSignatureLastUpdated":"\/Date(1790848800000)\/","AMProductVersion":"4.18.25080.5"}`
	rs := EvaluateDefender(fresh, nil, now)
	if len(rs) != 2 || rs[0].Status != Pass || !strings.Contains(rs[0].Have, "1.419.231.0 · version created on 1 Oct 2026") || rs[1].Status != Pass {
		t.Errorf("fresh definitions: %+v", rs)
	}
	// Up to 30 days old is current; older is a gap.
	if rs := EvaluateDefender(strings.Replace(fresh, "1790848800000", "1789639200000", 1), nil, now); rs[0].Status != Pass || !strings.Contains(rs[0].Have, "15 days old") {
		t.Errorf("15-day-old definitions: %+v", rs[0])
	}
	old := strings.Replace(strings.Replace(fresh, "1790848800000", "1788256800000", 1), `"RealTimeProtectionEnabled":true`, `"RealTimeProtectionEnabled":false`, 1)
	rs = EvaluateDefender(old, nil, now)
	if rs[0].Status != Fail || !strings.Contains(rs[0].Have, "31 days old") || !strings.Contains(rs[0].Fix, "Security Intelligence Updates") {
		t.Errorf("old definitions: %+v", rs[0])
	}
	if rs[1].Status != Fail || !strings.Contains(rs[1].Fix, "Real-time Protection > Turn off real-time protection: Disabled") {
		t.Errorf("real-time protection off: %+v", rs[1])
	}
	iso := `{"AMServiceEnabled":true,"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureVersion":"1.1","AntivirusSignatureLastUpdated":"2026-09-30T08:00:00Z"}`
	if rs := EvaluateDefender(iso, nil, now); rs[0].Status != Pass {
		t.Errorf("PowerShell 7 date: %+v", rs[0])
	}
	if rs := EvaluateDefender("", errors.New("not installed"), now); len(rs) != 1 || rs[0].Status != Warn {
		t.Errorf("no Defender: %+v", rs)
	}
}

// A6: what auditd does as its disk fills, who it tells, log permissions.
func TestAuditdActions(t *testing.T) {
	status := func(rs []Result) map[string]Status {
		m := map[string]Status{}
		for _, r := range rs {
			m[r.Item] = r.Status
		}
		return m
	}
	good := status(EvaluateAuditdActions(ParseAuditdConf("space_left_action = email\nadmin_space_left_action = single\ndisk_full_action = HALT\ndisk_error_action = SYSLOG\naction_mail_acct = root\n")))
	for k, v := range good {
		if v != Pass {
			t.Errorf("good %s = %s", k, v)
		}
	}
	bad := status(EvaluateAuditdActions(ParseAuditdConf("space_left_action = ignore\nadmin_space_left_action = SUSPEND\ndisk_full_action = SUSPEND\ndisk_error_action = ignore\naction_mail_acct =\n")))
	for _, k := range []string{"space_left_action", "admin_space_left_action", "disk_full_action", "disk_error_action", "action_mail_acct"} {
		if bad[k] != Fail {
			t.Errorf("bad %s = %s", k, bad[k])
		}
	}
	if r := EvaluateAuditLogPerms(0o600, 0o750, nil, nil); r.Status != Pass {
		t.Errorf("0600/0750: %s", r.Status)
	}
	if r := EvaluateAuditLogPerms(0o644, 0o755, nil, nil); r.Status != Fail {
		t.Errorf("0644/0755: %s", r.Status)
	}
}

// A6: time synchronisation, Linux and Windows.
func TestTimeSync(t *testing.T) {
	if r := EvaluateTimeSync(map[string]string{"chronyd": "active"}); r.Status != Pass {
		t.Errorf("chrony: %+v", r)
	}
	if r := EvaluateTimeSync(map[string]string{"chronyd": "inactive", "systemd-timesyncd": "inactive"}); r.Status != Fail {
		t.Errorf("none: %+v", r)
	}
	if r := EvaluateW32Time("STATE              : 4  RUNNING", "NT5DS"); r.Status != Pass {
		t.Errorf("w32time: %+v", r)
	}
	if r := EvaluateW32Time("STATE              : 1  STOPPED", "NTP"); r.Status != Fail {
		t.Errorf("stopped: %+v", r)
	}
	if r := EvaluateW32Time("STATE              : 4  RUNNING", "NoSync"); r.Status != Fail {
		t.Errorf("nosync: %+v", r)
	}
}

// A11: set in GRUB but not in the running kernel takes effect at the
// next boot.
func TestBootSettingsPendingReboot(t *testing.T) {
	grub := "GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX=\"audit=1 audit_backlog_limit=8192\"\n"
	rs := EvaluateBoot("BOOT_IMAGE=/vmlinuz ro quiet", grub)
	if rs[0].Status != Warn || !strings.Contains(rs[0].Have, "next boot") || rs[1].Status != Warn || !strings.Contains(rs[1].Have, "next boot") {
		t.Errorf("pending: %+v", rs)
	}
	rs = EvaluateBoot("ro audit=1 audit_backlog_limit=8192", grub)
	if rs[0].Status != Pass || rs[1].Status != Pass {
		t.Errorf("running: %+v", rs)
	}
	if rs = EvaluateBoot("ro quiet", ""); rs[0].Status != Fail {
		t.Errorf("missing: %+v", rs)
	}
}

// O1: sudo-rs writes no audit records of its commands.
func TestSudoRs(t *testing.T) {
	if r := EvaluateSudo("sudo-rs 0.2.8\n"); r.Status != Warn {
		t.Errorf("sudo-rs: %+v", r)
	}
	if r := EvaluateSudo("Sudo version 1.9.15p5\nSudoers policy plugin version 1.9.15p5\n"); r.Status != Pass || r.Have != "Sudo version 1.9.15p5" {
		t.Errorf("sudo: %+v", r)
	}
}

// Rules on files a system doesn't have are left out of --audit-rules:
// auditctl refuses them and the rest would not load.
func TestRulesForThisSystem(t *testing.T) {
	out := RulesForThisSystem(AuditRules, func(p string) bool { return p != "/usr/sbin/semanage" && p != "/etc/cron.hourly" })
	if strings.Contains(out, "-F path=/usr/sbin/semanage") || strings.Contains(out, "-F dir=/etc/cron.hourly/") {
		t.Error("rule on a missing file kept")
	}
	if !strings.Contains(out, "## Left out: /usr/sbin/semanage is not on this system.") || !strings.Contains(out, "-F path=/etc/passwd") {
		t.Errorf("output:\n%s", out)
	}
	if RulesForThisSystem(AuditRules, nil) != AuditRules {
		t.Error("nil exists changed the rules")
	}
}

// A5 on Windows: Blackbox's own folder has the auditing entry windows.md
// describes.
func TestOwnFolderAudit(t *testing.T) {
	if r := EvaluateOwnFolderAudit("Everyone|Write, Delete, ChangePermissions, TakeOwnership, Synchronize|Success, Failure\r\n", nil); r.Status != Pass {
		t.Errorf("with entry: %+v", r)
	}
	if r := EvaluateOwnFolderAudit("", nil); r.Status != Warn || r.Fix == "" {
		t.Errorf("no entry: %+v", r)
	}
	if r := EvaluateOwnFolderAudit("Everyone|ReadData|Success\n", nil); r.Status != Warn {
		t.Errorf("reads only: %+v", r)
	}
	if r := EvaluateOwnFolderAudit("", errors.New("exit status 1")); r.Status != Error {
		t.Errorf("error: %+v", r)
	}
}

// LOG1: the PowerShell log is sized too (Windows' default 15 MB holds a
// few hundred script block events), with how to set it, since Group
// Policy has no setting for it; another log Blackbox reads is warned about
// only when it holds less than a week.
func TestReadLogSizes(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	settings := map[string]winevt.LogSettings{
		"Microsoft-Windows-PowerShell/Operational":                           {Enabled: true, MaxSize: 15 << 20},
		"Microsoft-Windows-Windows Defender/Operational":                     {Enabled: true, MaxSize: 16 << 20},
		"Microsoft-Windows-PrintService/Operational":                         {Enabled: false, MaxSize: 1 << 20},
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": {Enabled: true, MaxSize: 1 << 20},
	}
	hist := map[string]winevt.LogHistory{
		// Full, and spanning 9 minutes: as on the Windows 11 VM.
		"Microsoft-Windows-PowerShell/Operational": {Oldest: now.Add(-9 * time.Minute), Newest: now, FileSize: 15 << 20},
		// Half full after 30 days.
		"Microsoft-Windows-Windows Defender/Operational": {Oldest: now.AddDate(0, 0, -30), Newest: now, FileSize: 8 << 20},
		// Full after 2 days.
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": {Oldest: now.AddDate(0, 0, -2), Newest: now, FileSize: 1 << 20},
	}
	get := func(n string) (winevt.LogSettings, error) {
		s, ok := settings[n]
		if !ok {
			return winevt.LogSettings{}, errors.New("not found")
		}
		return s, nil
	}
	history := func(n string) (winevt.LogHistory, error) { return hist[n], nil }
	got := map[string]Result{}
	for _, r := range readLogSizes(get, history) {
		got[r.Item] = r
	}
	ps, ok := got["PowerShell log"]
	if !ok || ps.Status != Warn || ps.Area != "Event log size" || ps.STIG != "" {
		t.Fatalf("PowerShell log: %+v", ps)
	}
	for _, want := range []string{`wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:`, `WINEVT\Channels\Microsoft-Windows-PowerShell/Operational`, "make it 2 GB"} {
		if !strings.Contains(ps.Fix, want) {
			t.Errorf("PowerShell fix lacks %q: %s", want, ps.Fix)
		}
	}
	if !strings.Contains(ps.Have, "15 MB") || !strings.Contains(ps.Want, "1 GB") {
		t.Errorf("PowerShell have/want: %q / %q", ps.Have, ps.Want)
	}
	if _, ok := got["Windows Defender log"]; ok {
		t.Error("a log holding 30 days is warned about")
	}
	if _, ok := got["Print log"]; ok {
		t.Error("a log that is off is sized")
	}
	rdp, ok := got["Remote Desktop sessions log"]
	if !ok || rdp.Status != Warn || !strings.Contains(rdp.Fix, "make it 4 MB") {
		t.Errorf("Remote Desktop log holding 2 days: %+v", rdp)
	}
	// Already 1 GB and holding a week: passes.
	settings["Microsoft-Windows-PowerShell/Operational"] = winevt.LogSettings{Enabled: true, MaxSize: 1 << 30}
	hist["Microsoft-Windows-PowerShell/Operational"] = winevt.LogHistory{Oldest: now.AddDate(0, 0, -10), Newest: now, FileSize: 1 << 30}
	for _, r := range readLogSizes(get, history) {
		if r.Item == "PowerShell log" && r.Status != Pass {
			t.Errorf("1 GB holding 10 days: %+v", r)
		}
	}
}

// LOG1d: when collection has seen a log turn over, check gives the size
// status gives, from the same rate, even when the log's history can't be
// measured (the Server: "make it 1 GB" in check, "at least 2 GB" in
// status).
func TestReadLogSizesFromTurnover(t *testing.T) {
	ps := "Microsoft-Windows-PowerShell/Operational"
	get := func(n string) (winevt.LogSettings, error) {
		if n == ps {
			return winevt.LogSettings{Enabled: true, MaxSize: 15 << 20}, nil
		}
		return winevt.LogSettings{}, errors.New("not found")
	}
	history := func(string) (winevt.LogHistory, error) { return winevt.LogHistory{}, nil } // not measurable
	loss := rollover.Loss{Host: "SRV", Channel: ps, Held: 20 * time.Second, MaxSize: 15 << 20, Every: 15 * time.Minute}
	Turnover = func(n string) (rollover.Loss, bool) { return loss, n == ps }
	defer func() { Turnover = nil }()
	rs := readLogSizes(get, history)
	if len(rs) != 1 || rs[0].Status != Warn {
		t.Fatalf("results: %+v", rs)
	}
	want := "make it " + rollover.Size(loss.Needed())
	if !strings.Contains(rs[0].Fix, want) || !strings.Contains(loss.Advice(true), "at least "+rollover.Size(loss.Needed())) {
		t.Errorf("check %q and status %q disagree", rs[0].Fix, loss.Advice(true))
	}
	if rollover.Size(loss.Needed()) != "2 GB" || !strings.Contains(rs[0].Have, "turned over after about 1 minute") {
		t.Errorf("size %s, have %q", rollover.Size(loss.Needed()), rs[0].Have)
	}
}
