package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// A13: a fresh Server 2025 registers firewall rules for its app packages
// (by NT SERVICE\mpssvc); they are one Info row a day, and a person
// enabling SMB-In keeps a row of its own.
func TestAppPackageFirewallRules(t *testing.T) {
	at := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	var evs []*event.Event
	add := func(i int, action, user, rule string, sev event.Severity) {
		evs = append(evs, &event.Event{Time: at.Add(time.Duration(i) * time.Second), Host: "WIN-SRV", OS: "windows", Category: event.CatIntegrity,
			Severity: sev, Action: action, User: user, Target: rule, Summary: action + " " + rule})
	}
	for i := 0; i < 74; i++ {
		add(i, "firewall_rule_added", `NT SERVICE\mpssvc`, fmt.Sprintf("@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}%d", i), event.SevLow)
	}
	for i := 0; i < 32; i++ {
		add(100+i, "firewall_rule_deleted", `NT SERVICE\mpssvc`, fmt.Sprintf("@{Microsoft.Windows.Search_1.0?ms-resource://x}%d", i), event.SevMedium)
	}
	for i := 0; i < 17; i++ {
		add(200+i, "firewall_rule_changed", `NT SERVICE\mpssvc`, fmt.Sprintf("@{Microsoft.Windows.Photos_1.0?ms-resource://x}%d", i), event.SevLow)
	}
	add(300, "firewall_rule_changed", `WIN-SRV\claude`, "File and Printer Sharing (SMB-In)", event.SevLow)
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: at.Add(24 * time.Hour)})
	var rows []string
	for _, e := range r.Events {
		rows = append(rows, string(e.Severity)+" "+e.Summary)
	}
	want := []string{
		"info Windows updated the firewall rules of its built-in apps and services: 74 added, 17 changed, 32 deleted (by the Windows Firewall service or SYSTEM).",
		"low firewall_rule_changed File and Printer Sharing (SMB-In)",
	}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Errorf("rows:\n%s", strings.Join(rows, "\n"))
	}
}

// A13b/c/d: Windows 11 names its app-container rules (display names, not
// "@{…}"), exported logs show the firewall service only as its SID, and
// SYSTEM deletes package rules with no name. All are counted; SYSTEM
// changing an ordinary rule is still a row.
func TestWindowsOwnFirewallRules(t *testing.T) {
	at := time.Date(2026, 10, 4, 21, 0, 0, 0, time.UTC)
	fw := func(i int, action, user, sid, name, id string) *event.Event {
		return &event.Event{Time: at.Add(time.Duration(i) * time.Second), Host: "WIN11-TEST", OS: "windows", Category: event.CatIntegrity,
			Severity: event.SevLow, Action: action, User: user, Target: name, Summary: action + " " + name,
			Fields: map[string]string{"ModifyingUser": sid, "RuleId": id, "RuleName": name}}
	}
	evs := []*event.Event{
		fw(1, "firewall_rule_added", `NT SERVICE\mpssvc`, "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052", "Widgets Platform Runtime",
			"Microsoft.WidgetsPlatformRuntime_8wekyb3d8bbweS-1-5-21-1-2-3-1001-Out-Allow-AllCapabilities"),
		fw(2, "firewall_rule_deleted", `NT SERVICE\mpssvc`, "", "Usermode Font Driver Host", "microsoft.windows.fontdrvhostS-1-5-18-In-Block"),
		fw(3, "firewall_rule_changed", "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052", "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052",
			"Windows Web Experience Pack", "MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy-In"),
		fw(4, "firewall_rule_deleted", "SYSTEM", "S-1-5-18", "Microsoft.WindowsTerminal_8wekyb3d8bbwe_S-1-5-21-1-2-3-1001_In_emptyRemoteName_Cellular",
			"Microsoft.WindowsTerminal_8wekyb3d8bbwe_S-1-5-21-1-2-3-1001_In_emptyRemoteName_Cellular"),
		fw(5, "firewall_rule_changed", "SYSTEM", "S-1-5-18", "Windows Defender Antivirus Service", "{0ac1-WinDefend-Out}"),
		fw(6, "firewall_rule_changed", "SYSTEM", "S-1-5-18", "Remote Desktop - User Mode (TCP-In)", "RemoteDesktop-UserMode-In-TCP"),
		fw(7, "firewall_rule_added", `WIN11-TEST\claude`, "S-1-5-21-1-2-3-1001", "Open 8080", "{5d3c}"),
	}
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: at.Add(time.Hour)})
	var rows []string
	for _, e := range r.Events {
		rows = append(rows, e.Summary)
	}
	want := []string{
		"Windows updated the firewall rules of its built-in apps and services: 1 added, 2 changed, 2 deleted (by the Windows Firewall service or SYSTEM).",
		"firewall_rule_changed Remote Desktop - User Mode (TCP-In)",
		"firewall_rule_added Open 8080",
	}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Errorf("rows:\n%s", strings.Join(rows, "\n"))
	}
}

// W1: events stored under a new server's name from before setup renamed
// it are shown on that server, not as a third system.
func TestFormerNameIsNotASystem(t *testing.T) {
	at := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	evs := []*event.Event{
		{Time: at, Host: "WIN-R5L5B9EF403", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "a"},
		{Time: at.Add(time.Minute), Host: "SRV25", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "b"},
		{Time: at.Add(2 * time.Minute), Host: "ubuntu-server", OS: "linux", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "c"},
	}
	systems := []SystemInfo{{Name: "SRV25", OS: "windows"}, {Name: "ubuntu-server", OS: "linux", Via: "SRV25"}}
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: at.Add(time.Hour), Systems: systems, Collector: true})
	if strings.Join(r.Hosts, ",") != "SRV25,ubuntu-server" || detail(r.Events[0], "Recorded under") != "its former name WIN-R5L5B9EF403" {
		t.Errorf("hosts %v; first row %+v", r.Hosts, r.Events[0])
	}
}

// A16: Defender recording its own state is one Info row a day; an
// exclusion added keeps its row.
func TestDefenderStateCounted(t *testing.T) {
	at := time.Date(2026, 10, 4, 21, 0, 0, 0, time.UTC)
	var evs []*event.Event
	for i, k := range []string{"WdConfigHash = 0x1", "IsServiceRunning = 0x1", "SpyNet\\LastMAPSFailureTimeString = x", "WdConfigHash = 0x2"} {
		evs = append(evs, &event.Event{Time: at.Add(time.Duration(i) * time.Minute), Host: "WIN11-TEST", OS: "windows", Category: event.CatOther,
			Severity: event.SevInfo, Action: "av_state_recorded", Target: `HKLM\SOFTWARE\Microsoft\Windows Defender\` + k, Summary: "state"})
	}
	evs = append(evs, &event.Event{Time: at.Add(time.Hour), Host: "WIN11-TEST", OS: "windows", Category: event.CatOther, Severity: event.SevHigh,
		Action: "av_exclusion_added", Summary: "An exclusion was added to Microsoft Defender — it no longer scans: C:\\Temp."})
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: at.Add(2 * time.Hour)})
	if len(r.Events) != 2 || r.Events[0].Severity != event.SevInfo || !strings.HasPrefix(r.Events[0].Summary, "Microsoft Defender recorded its own state 4 times") ||
		r.Events[1].Action != "av_exclusion_added" {
		for _, e := range r.Events {
			t.Log(e.Severity, e.Summary)
		}
		t.Error("Defender state not counted")
	}
}

// A17: a new Windows 11's first report: setup's defaultuser0 and the
// MINWINPC image events are one Info row, and no "covering of tracks"
// pairs them with Defender's own change an hour later. A person creating
// an account named defaultuser0 is still shown.
func TestWindowsSetupIsNotAnAttack(t *testing.T) {
	at := time.Date(2026, 10, 4, 22, 0, 0, 0, time.UTC)
	row := func(min int, user, action, target, summary string, sev event.Severity, cat event.Category) *event.Event {
		return &event.Event{Time: at.Add(time.Duration(min) * time.Minute), Host: "WIN11-TEST", OS: "windows", Category: cat, Severity: sev,
			Action: action, User: user, Target: target, Summary: summary}
	}
	evs := []*event.Event{
		row(0, `MINWINPC\SYSTEM`, "account_created", `MINWINPC\WDAGUtilityAccount`, "SYSTEM created the user account WDAGUtilityAccount.", event.SevMedium, event.CatAccount),
		row(1, "SYSTEM", "policy_changed", "MINWINPC policy", "The domain policy of MINWINPC was changed.", event.SevMedium, event.CatIntegrity),
		row(2, "SYSTEM", "account_created", "defaultuser0", "SYSTEM created the user account defaultuser0.", event.SevMedium, event.CatAccount),
		row(3, "SYSTEM", "group_member_added", `WIN11-TEST\defaultuser0`, "SYSTEM added defaultuser0 to the privileged group Administrators.", event.SevHigh, event.CatAccount),
		row(30, "SYSTEM", "account_deleted", "defaultuser0", "SYSTEM deleted the user account defaultuser0.", event.SevMedium, event.CatAccount),
		row(65, "", "av_disabled", "", "A Microsoft Defender protection was turned off: X.", event.SevHigh, event.CatOther),
		row(90, `WIN11-TEST\claude`, "account_created", "defaultuser0", "claude created the user account defaultuser0.", event.SevMedium, event.CatAccount),
	}
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: at.Add(3 * time.Hour)})
	var setup, claude int
	for _, e := range r.Events {
		switch {
		case e.Action == "windows_setup":
			setup++
			if e.Severity != event.SevInfo || !strings.Contains(e.Summary, "(5 events)") {
				t.Errorf("setup row: %s %s", e.Severity, e.Summary)
			}
		case e.User == `WIN11-TEST\claude`:
			claude++
		case e.Action != "av_disabled":
			t.Errorf("setup event kept: %s", e.Summary)
		}
	}
	if setup != 1 || claude != 1 {
		t.Errorf("%d setup rows, %d of claude's", setup, claude)
	}
	if hasFinding(r, "Possible covering of tracks") {
		t.Errorf("findings: %v", findingTitles(r))
	}
}
