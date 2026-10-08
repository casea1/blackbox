package winevt

import (
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/event"
)

var person = map[string]string{"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "mallory", "SubjectDomainName": "WS-07"}

func with(base map[string]string, kv ...string) map[string]string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// A1: the Security-log events the STIG audits that were dropped before.
func TestSecurityCoverage(t *testing.T) {
	tr := NewTranslator()
	cases := []struct {
		r      *Raw
		action string
		sev    event.Severity
		text   string
	}{
		{sec(4612, map[string]string{"AuditsDiscarded": "312"}), "audit_events_dropped", event.SevHigh, "lost 312"},
		{sec(4622, map[string]string{"SecurityPackageName": `C:\Windows\system32\kerberos.DLL : Kerberos`}), "lsa_package", event.SevInfo, "standard"},
		{sec(4614, map[string]string{"NotificationPackageName": "evilpwfilter"}), "lsa_package", event.SevHigh, "evilpwfilter"},
		{sec(4704, with(person, "TargetSid", "S-1-5-21-1-2-3-1002", "PrivilegeList", "SeDebugPrivilege")), "user_right_assigned", event.SevHigh, "SeDebugPrivilege"},
		{sec(4705, with(person, "TargetSid", "S-1-5-32-545", "PrivilegeList", "SeShutdownPrivilege")), "user_right_removed", event.SevMedium, "removed"},
		{sec(4739, with(person, "DomainName", "CORP", "MinPasswordLength", "8")), "domain_policy_changed", event.SevMedium, "minimum length 8"},
		{sec(4706, with(person, "DomainName", "EVIL.LOCAL")), "trust_created", event.SevHigh, "EVIL.LOCAL"},
		{sec(4826, map[string]string{"KernelDebug": "%%8843", "TestSigning": "%%8843"}), "boot_config", event.SevInfo, "nothing weakened"},
		{sec(4826, map[string]string{"KernelDebug": "%%8843", "TestSigning": "Yes"}), "boot_config_weakened", event.SevHigh, "test signing"},
		{sec(4907, with(person, "ObjectType", "File", "ObjectName", `C:\Secret\plan.docx`, "ProcessName", `C:\Windows\explorer.exe`)), "object_audit_changed", event.SevHigh, "plan.docx"},
		{sec(4948, map[string]string{"RuleName": "Allow SMB"}), "firewall_rule_deleted", event.SevMedium, "Allow SMB"},
		{sec(5025, nil), "firewall_stopped", event.SevHigh, "stopped"},
		{sec(5038, map[string]string{"param1": `\Device\HarddiskVolume3\Windows\System32\lsass.exe`}), "code_integrity_failed", event.SevHigh, "lsass.exe"},
		{sec(5140, with(person, "ShareName", `\\*\Finance`, "IpAddress", "10.1.1.20")), "share_accessed", event.SevLow, "Finance"},
		{sec(4657, with(person, "ObjectName", `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`, "ObjectValueName", "RunAsPPL", "OldValue", "1", "NewValue", "0")), "security_registry_changed", event.SevHigh, "RunAsPPL"},
		{sec(4670, with(person, "ObjectType", "File", "ObjectName", `C:\Windows\System32\drivers\etc\hosts`)), "permissions_changed", event.SevMedium, "hosts"},
		{sec(4765, with(person, "TargetUserName", "bob", "TargetDomainName", "CORP", "SourceSid", "S-1-5-21-9-9-9-500")), "sid_history_added", event.SevHigh, "SID history"},
		{sec(4800, map[string]string{"TargetUserName": "bob", "TargetDomainName": "WS-07"}), "workstation_locked", event.SevInfo, "locked"},
		{sec(5379, person), "", "", ""}, // counted only
		{sec(4664, person), "", "", ""},
		{sec(4910, person), "other_security", event.SevInfo, "Security event 4910"},
	}
	for _, c := range cases {
		e := tr.Translate(c.r)
		if c.action == "" {
			if e != nil {
				t.Errorf("%d: want nothing (counted), got %s", c.r.EventID, e.Summary)
			}
			continue
		}
		if e == nil {
			t.Errorf("%d: no event", c.r.EventID)
			continue
		}
		if e.Action != c.action || e.Severity != c.sev || !strings.Contains(e.Summary, c.text) {
			t.Errorf("%d: %s %s %q", c.r.EventID, e.Action, e.Severity, e.Summary)
		}
	}
	// Windows Update setting auditing on its own files is routine.
	sys := map[string]string{"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS-07$", "SubjectDomainName": "CORP",
		"ObjectType": "File", "ObjectName": `C:\Windows\WinSxS\x`, "ProcessName": `C:\Windows\WinSxS\amd64\TiWorker.exe`}
	if e := tr.Translate(sec(4907, sys)); e != nil {
		t.Errorf("TiWorker 4907: %s", e.Summary)
	}
}

// A1: every translated ID is in Reviewed, and the subcategory view says
// which audit subcategories are not reviewed.
func TestSubcategoryReviewed(t *testing.T) {
	for name, want := range map[string]string{"Logon": "reviewed", "Sensitive Privilege Use": "counted", "Handle Manipulation": "counted",
		"IPsec Driver": "other", "Authentication Policy Change": "reviewed", "Nope": ""} {
		if got := SubcategoryReviewed(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

// A2: files with an auditing entry: refused access always, writes and
// deletes when they succeed, reads not.
func TestFileSystemAccess(t *testing.T) {
	tr := NewTranslator()
	file := func(access string, failed bool) *Raw {
		r := sec(4663, with(person, "ObjectType", "File", "ObjectName", `C:\Finance\pay.xlsx`, "AccessList", access, "ProcessName", `C:\Windows\explorer.exe`))
		r.Task = taskFileSystem
		r.Keywords = "0x8020000000000000"
		if failed {
			r.Keywords = "0x8010000000000000"
		}
		return r
	}
	for _, c := range []struct {
		access string
		failed bool
		want   string
	}{{"%%4417", false, "file_written"}, {"%%1537", false, "file_deleted"}, {"%%4416", false, ""}, {"%%4416", true, "file_access_denied"}} {
		e := tr.Translate(file(c.access, c.failed))
		got := ""
		if e != nil {
			got = e.Action
		}
		if got != c.want {
			t.Errorf("%s failed=%v: %q, want %q", c.access, c.failed, got, c.want)
		}
	}
}

// A7: software installed, the firewall log, Defender settings, printing
// and Remote Desktop.
func TestOtherLogs(t *testing.T) {
	tr := NewTranslator()
	ev := func(ch, prov string, id int, data map[string]string) *Raw {
		r := sec(id, data)
		r.Channel, r.Provider = ch, prov
		return r
	}
	cases := []struct {
		r      *Raw
		action string
		sev    event.Severity
		text   string
	}{
		{ev(chApplication, "MsiInstaller", 1033, map[string]string{"Data0": "7-Zip 24.08 (x64)", "Data1": "24.08.00.0", "Data3": "0", "Data4": "Igor Pavlov"}), "software_installed", event.SevMedium, "7-Zip 24.08 (x64) 24.08.00.0"},
		{ev(chApplication, "MsiInstaller", 11724, map[string]string{"Data0": "Product: 7-Zip 24.08 (x64) -- Removal completed successfully."}), "software_removed", event.SevLow, "7-Zip"},
		{ev(chApplication, "Application Error", 1000, nil), "", "", ""},
		// A15: Blackbox's own record of a setting it changed.
		{ev(chApplication, "Blackbox", 100, map[string]string{"Data0": `Blackbox setting retention_days changed from "365" to "30" by SERVER\claude (blackbox config set).`}),
			"blackbox_config_changed", event.SevHigh, `SERVER\claude changed Blackbox's retention_days setting from 365 to 30`},
		{ev(chApplication, "Blackbox", 100, map[string]string{"Data0": "something else"}), "", "", ""},
		{ev(chFirewall, "", 2004, map[string]string{"RuleName": "Backdoor 4444", "ModifyingUser": "S-1-5-21-1-2-3-1001", "ModifyingApplication": `C:\Windows\System32\netsh.exe`}), "firewall_rule_added", event.SevLow, "Backdoor 4444"},
		{ev(chFirewall, "", 2003, map[string]string{"Profiles": "4", "SettingType": "1", "SettingValue": "0"}), "firewall_setting_changed", event.SevHigh, "turned off"},
		// A13b: a rule deleted with no name is named by its ID, not "deleted: .".
		{ev(chFirewall, "", 2052, map[string]string{"RuleName": "", "RuleId": "Microsoft.WindowsTerminal_8wekyb3d8bbwe_S-1-5-21-1-2-3-1001_In_emptyRemoteName_Cellular", "ModifyingUser": "S-1-5-18"}),
			"firewall_rule_deleted", event.SevMedium, "deleted: Microsoft.WindowsTerminal_8wekyb3d8bbwe_"},
		{ev("Microsoft-Windows-Windows Defender/Operational", "", 5007, map[string]string{"Old Value": "", "New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Temp = 0x0`}), "av_exclusion_added", event.SevHigh, `C:\Temp`},
		// A16: Defender's own bookkeeping is Info (counted once a day by the
		// report); its settings keep their rows.
		{ev("Microsoft-Windows-Windows Defender/Operational", "", 5007, map[string]string{"Old Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\WdConfigHash = 0x1a`, "New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\WdConfigHash = 0x2b`}), "av_state_recorded", event.SevInfo, "recorded its own state"},
		{ev("Microsoft-Windows-Windows Defender/Operational", "", 5007, map[string]string{"New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet\LastMAPSFailureTimeString = 2026-10-04T23:01`}), "av_state_recorded", event.SevInfo, "recorded its own state"},
		{ev("Microsoft-Windows-Windows Defender/Operational", "", 5007, map[string]string{"New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\EcsConfigs\X = 0x1`}), "av_state_recorded", event.SevInfo, "recorded its own state"},
		{ev("Microsoft-Windows-Windows Defender/Operational", "", 5007, map[string]string{"New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 0x4`}), "av_setting_changed", event.SevLow, "TamperProtection"},
		{ev("Microsoft-Windows-Windows Defender/Operational", "", 5007, map[string]string{"New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\NIS\Consumers\IPS\DisableBmNetworkSensor = 0x1`}), "av_setting_changed", event.SevLow, "its own network-inspection sensor"},
		{ev("Microsoft-Windows-Windows Defender/Operational", "", 5007, map[string]string{"New Value": `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS\DisableBmNetworkSensor = 0x1`}), "av_disabled", event.SevHigh, "turned off"},
		{ev("Microsoft-Windows-Windows Defender/Operational", "", 5007, map[string]string{"Old Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x0`, "New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1`}), "av_disabled", event.SevHigh, "turned off"},
		{ev("Microsoft-Windows-Windows Defender/Operational", "", 5013, map[string]string{"Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring`}), "av_tamper_blocked", event.SevHigh, "Tamper Protection"},
		{ev(chPrint, "", 307, map[string]string{"Param2": "salaries.xlsx", "Param3": "bob", "Param4": `\\WS-07`, "Param5": "HP LaserJet", "Param8": "3"}), "document_printed", event.SevLow, `"salaries.xlsx" on HP LaserJet (3 pages)`},
		{ev(chRDPLocal, "", 21, map[string]string{"User": `CORP\bob`, "Address": "10.1.1.50", "SessionID": "3"}), "logon", event.SevInfo, "via Remote Desktop from 10.1.1.50"},
		{ev(chRDPRemote, "", 1149, map[string]string{"Param1": "bob", "Param2": "CORP", "Param3": "10.1.1.50"}), "rdp_authenticated", event.SevInfo, "10.1.1.50"},
	}
	for _, c := range cases {
		e := tr.Translate(c.r)
		if c.action == "" {
			if e != nil {
				t.Errorf("%d: want nothing, got %s", c.r.EventID, e.Summary)
			}
			continue
		}
		if e == nil {
			t.Errorf("%s %d: no event", c.r.Channel, c.r.EventID)
			continue
		}
		if e.Action != c.action || e.Severity != c.sev || !strings.Contains(e.Summary, c.text) {
			t.Errorf("%s %d: %s %s %q", c.r.Channel, c.r.EventID, e.Action, e.Severity, e.Summary)
		}
	}
	// The firewall log's rule and the Security log's 4946 are one row.
	a := tr.Translate(ev(chFirewall, "", 2004, map[string]string{"RuleName": "X"}))
	b := tr.Translate(sec(4946, map[string]string{"RuleName": "X"}))
	if a.DedupeKey != b.DedupeKey || a.DedupeKey == "" {
		t.Errorf("keys %q %q", a.DedupeKey, b.DedupeKey)
	}
}

// Reviewed lists exactly the IDs that are translated: nothing translated
// is missing from it, and nothing in it falls through to the plain row.
func TestReviewedMatchesTranslations(t *testing.T) {
	tr := NewTranslator()
	data := with(person, "TargetUserSid", "S-1-5-21-1-2-3-1002", "TargetUserName", "bob", "TargetDomainName", "WS-07", "LogonType", "2",
		"ObjectType", "File", "ObjectName", `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`, "AccessList", "%%4417", "ShareName", `\\*\x`)
	for id := 1000; id < 7000; id++ {
		e := tr.Translate(sec(id, data))
		switch {
		case e != nil && e.Action != "other_security" && !Reviewed[id]:
			t.Errorf("%d is translated (%s) but not in Reviewed", id, e.Action)
		case e != nil && e.Action == "other_security" && Reviewed[id]:
			t.Errorf("%d is in Reviewed but not translated", id)
		}
	}
}

// A5, U9: Blackbox watching itself on Windows.
func TestBlackboxSelfAudit(t *testing.T) {
	tr := NewTranslator()
	e := tr.Translate(elevatedRun(`"C:\Program Files\Blackbox\blackbox.exe" config set exclude_users bob`))
	if e == nil || e.Action != "blackbox_config_changed" || e.Severity != event.SevHigh {
		t.Errorf("config set: %+v", e)
	}
	e = tr.Translate(sec(4701, with(person, "TaskName", `\Blackbox Audit Collection`)))
	if e == nil || e.Action != "blackbox_stopped" || e.Severity != event.SevHigh || !strings.Contains(e.Summary, "no longer collected") {
		t.Errorf("task disabled: %+v", e)
	}
	sys := map[string]string{"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS-07$", "SubjectDomainName": "CORP", "TaskName": `\Blackbox Audit Collection`}
	if e = tr.Translate(sec(4702, sys)); e == nil || e.Severity != event.SevMedium {
		t.Errorf("task updated by SYSTEM: %+v", e)
	}
	r := sec(4663, with(person, "ObjectType", "File", "ObjectName", `C:\ProgramData\Blackbox\blackbox.conf`, "AccessList", "%%4417", "ProcessName", `C:\Windows\System32\notepad.exe`))
	r.Task, r.Keywords = taskFileSystem, "0x8020000000000000"
	if e = tr.Translate(r); e == nil || e.Action != "blackbox_config_changed" || e.Severity != event.SevHigh {
		t.Errorf("conf edited: %+v", e)
	}
	r.Data["ProcessName"] = `C:\Program Files\Blackbox\blackbox.exe`
	if e = tr.Translate(r); e != nil {
		t.Errorf("Blackbox's own write: %s", e.Summary)
	}
}

// T4: Blackbox's own folder writes and child processes are left out; a
// deleted report is one row; 4717/4718 are a sentence, or left out when
// Windows grants them itself.
func TestBlackboxOwnActivity(t *testing.T) {
	tr := NewTranslator()
	folder := sec(4663, with(person, "ObjectType", "File", "ObjectName", `C:\ProgramData\Blackbox`, "AccessList", "%%4417", "ProcessName", `C:\Program Files\Blackbox\blackbox.exe`))
	folder.Task, folder.Keywords = taskFileSystem, "0x8020000000000000"
	if e := tr.Translate(folder); e != nil {
		t.Errorf("Blackbox writing its own folder: %s", e.Summary)
	}

	child := elevatedRun("wevtutil gl Security")
	child.Data["ParentProcessName"] = `C:\Program Files\Blackbox\blackbox.exe`
	if e := tr.Translate(child); e != nil {
		t.Errorf("child of Blackbox: %s", e.Summary)
	}
	if e := tr.Translate(elevatedRun("wevtutil gl Security")); e == nil {
		t.Error("the same command run by a person was dropped")
	}

	keys := map[string]bool{}
	// One file moved out names the file (LEDGER3); the folder itself is
	// the report.
	for f, want := range map[string]string{
		`index.html`:     "mallory deleted index.html from the report 2026-10-04_2009_WIN11-TEST_interim (using explorer.exe)",
		`data\events.js`: "mallory deleted data/events.js from the report 2026-10-04_2009_WIN11-TEST_interim (using explorer.exe)",
		``:               "mallory deleted the report 2026-10-04_2009_WIN11-TEST_interim (using explorer.exe)",
	} {
		r := sec(4663, with(person, "ObjectType", "File", "ObjectName", `C:\ProgramData\Blackbox\reports\2026-10-04_2009_WIN11-TEST_interim\`+f, "AccessList", "%%1537", "ProcessName", `C:\Windows\explorer.exe`))
		r.Task, r.Keywords = taskFileSystem, "0x8020000000000000"
		e := tr.Translate(r)
		if e == nil || e.Severity != event.SevHigh || e.Summary != want+"." {
			t.Fatalf("report delete: %+v", e)
		}
		keys[e.DedupeKey] = true
	}
	if len(keys) != 1 {
		t.Errorf("a deleted report should merge to one row, got keys %v", keys)
	}

	sys := map[string]string{"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS-07$", "SubjectDomainName": "CORP", "TargetSid": "S-1-5-83-1-2", "AccessGranted": "SeServiceLogonRight"}
	if e := tr.Translate(sec(4717, sys)); e != nil {
		t.Errorf("4717 by SYSTEM: %s", e.Summary)
	}
	e := tr.Translate(sec(4717, with(person, "TargetSid", "S-1-5-32-545", "AccessGranted", "SeRemoteInteractiveLogonRight")))
	if e == nil || e.Action != "logon_right_granted" || e.Severity != event.SevMedium || !strings.Contains(e.Summary, "the right to log on through Remote Desktop") {
		t.Errorf("4717 by a person: %+v", e)
	}
	e = tr.Translate(sec(4718, with(person, "TargetSid", "S-1-5-32-545", "AccessRemoved", "SeDenyNetworkLogonRight")))
	if e == nil || e.Action != "logon_right_removed" || !strings.Contains(e.Summary, "right to be refused access from the network") {
		t.Errorf("4718 by a person: %+v", e)
	}
}

// T2: 5038 on a Defender platform file stays High, with how to tell an
// update from a changed file.
func TestDefenderPlatform5038(t *testing.T) {
	e := NewTranslator().Translate(sec(5038, map[string]string{"param1": `\Device\HarddiskVolume3\ProgramData\Microsoft\Windows Defender\Platform\4.18.25080.5-0\DefenderSessionHelper.dll`}))
	if e == nil || e.Severity != event.SevHigh || !strings.Contains(e.Summary, "Defender is updating its platform") || !hasDetail(e, "How to check") {
		t.Errorf("Defender 5038: %+v", e)
	}
	e = NewTranslator().Translate(sec(5038, map[string]string{"param1": `\Device\HarddiskVolume3\Windows\System32\lsass.exe`}))
	if strings.Contains(e.Summary, "Defender") {
		t.Errorf("non-Defender 5038 got the note: %s", e.Summary)
	}
}
