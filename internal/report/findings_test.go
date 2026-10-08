package report

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/winevt"
)

// Tests for the findings of the v0.10.0 Windows test run
// (docs/testing/2026-10-02-v0.10.0), built from Windows event XML.

var fx0 = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

// winEvent is one Security-log event as Windows writes it.
func winEvent(id, rec int, at time.Time, data ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>%d</EventID><TimeCreated SystemTime="%s"/><EventRecordID>%d</EventRecordID><Channel>Security</Channel><Computer>DSK1</Computer></System><EventData>`,
		id, at.Format("2006-01-02T15:04:05.0000000Z"), rec)
	for i := 0; i+1 < len(data); i += 2 {
		fmt.Fprintf(&b, `<Data Name="%s">%s</Data>`, data[i], data[i+1])
	}
	b.WriteString(`</EventData></Event>`)
	return b.String()
}

func translateAll(t *testing.T, xml ...string) []*event.Event {
	t.Helper()
	tr := winevt.NewTranslator()
	var out []*event.Event
	err := winevt.ParseStream(strings.NewReader(strings.Join(xml, "\n")), func(r *winevt.Raw) error {
		if e := tr.Translate(r); e != nil {
			out = append(out, e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func buildFrom(events []*event.Event, opt Options) *Report {
	opt.Location = time.UTC
	opt.WindowEnd = fx0.Add(24 * time.Hour)
	return Build(events, nil, opt)
}

func findingTitles(r *Report) []string {
	var l []string
	for _, f := range r.Findings {
		l = append(l, f.Title)
	}
	sort.Strings(l)
	return l
}

func hasFinding(r *Report, title string) bool {
	for _, f := range r.Findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

// failedLogon is a network logon failure (4625) and its password check (4776).
func failedLogon(rec int, at time.Time, domain, user, ip string) []string {
	return []string{
		winEvent(4776, rec, at, "TargetUserName", user, "Workstation", "KALI", "Status", "0xc000006a"),
		winEvent(4625, rec+1, at, "TargetUserName", user, "TargetDomainName", domain, "Status", "0xc000006d",
			"SubStatus", "0xc000006a", "LogonType", "3", "IpAddress", ip, "WorkstationName", "KALI"),
	}
}

// D1: five wrong passwords within one second are five attempts, and are
// password guessing; the two records of each attempt still count once.
func TestFastGuessingIsDetected(t *testing.T) {
	var xml []string
	for i := 0; i < 5; i++ {
		xml = append(xml, failedLogon(100+2*i, fx0.Add(time.Duration(i)*150*time.Millisecond), "WORKGROUP", "Administrator", "10.1.1.99")...)
	}
	r := buildFrom(translateAll(t, xml...), Options{})
	fails := 0
	for _, e := range r.Events {
		if e.Action == "logon_failed" {
			fails++
		}
	}
	if fails != 5 {
		t.Errorf("want 5 failed logons (one per attempt), got %d", fails)
	}
	if !hasFinding(r, "Possible password guessing") {
		t.Errorf("no password guessing finding: %v", findingTitles(r))
	}
}

// D1: many accounts from one address within a second.
func TestFastSprayIsDetected(t *testing.T) {
	var xml []string
	for i, u := range []string{"admin", "guest", "backup", "svc", "test"} {
		xml = append(xml, failedLogon(200+2*i, fx0.Add(time.Duration(i)*100*time.Millisecond), "WORKGROUP", u, "10.1.1.99")...)
	}
	r := buildFrom(translateAll(t, xml...), Options{})
	if !hasFinding(r, "One source tried several accounts") {
		t.Errorf("no spray finding: %v", findingTitles(r))
	}
}

// Review item: a failure over the network names WORKGROUP\user, the logon
// that follows names user. They are the same account.
func TestSuccessAfterFailuresAcrossDomainNames(t *testing.T) {
	var xml []string
	for i := 0; i < 3; i++ {
		xml = append(xml, failedLogon(300+2*i, fx0.Add(time.Duration(i)*20*time.Second), "WORKGROUP", "jsmith", "10.1.1.50")...)
	}
	xml = append(xml, winEvent(4624, 400, fx0.Add(2*time.Minute), "TargetUserName", "jsmith", "TargetDomainName", "DSK1",
		"TargetUserSid", "S-1-5-21-1-2-3-1001", "LogonType", "3", "IpAddress", "10.1.1.50"))
	r := buildFrom(translateAll(t, xml...), Options{})
	if !hasFinding(r, "Successful logon after failures") {
		t.Errorf("no success-after-failures finding: %v", findingTitles(r))
	}
}

// D3: excluding an account hides its routine activity only. Guessing its
// password, or a domain account of the same name, is still reported, and
// the report says what was left out.
func TestExclusionsDoNotHideAttacks(t *testing.T) {
	var xml []string
	for i := 0; i < 6; i++ {
		xml = append(xml, failedLogon(500+2*i, fx0.Add(time.Duration(i)*time.Second), "", "bbtest", "10.1.1.99")...)
		xml = append(xml, failedLogon(600+2*i, fx0.Add(time.Hour+time.Duration(i)*time.Second), "OTHERDOMAIN", "bbtest", "10.1.1.98")...)
	}
	// A routine logon by the excluded account is left out.
	xml = append(xml, winEvent(4624, 700, fx0.Add(2*time.Hour), "TargetUserName", "bbtest", "TargetDomainName", "DSK1",
		"TargetUserSid", "S-1-5-21-1-2-3-1005", "LogonType", "2"))
	r := buildFrom(translateAll(t, xml...), Options{ExcludeUsers: []string{"bbtest"}})
	n := 0
	for _, f := range r.Findings {
		if f.Title == "Possible password guessing" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want password guessing for both bursts, got %d: %v", n, findingTitles(r))
	}
	for _, e := range r.Events {
		if e.Action == "logon" {
			t.Errorf("the excluded account's routine logon is still listed: %s", e.Summary)
		}
	}
	if r.Excluded != 1 || r.ExcludedBy["bbtest"] != 1 {
		t.Errorf("excluded %d %v, want the one logon", r.Excluded, r.ExcludedBy)
	}
}

// D3: an entry with a domain matches only that account.
func TestExcludeWithDomain(t *testing.T) {
	r := &Report{Options: Options{ExcludeUsers: []string{`CORP\svc_backup`, "svc_scan"}}}
	for user, want := range map[string]string{`CORP\svc_backup`: `CORP\svc_backup`, `OTHER\svc_backup`: "", "svc_backup": "",
		"svc_scan": "svc_scan", `DSK1\svc_scan`: "svc_scan", `CORP\svc_scan`: ""} {
		if got := r.excludedBy(&event.Event{User: user, Host: "DSK1"}); got != want {
			t.Errorf("%s: excluded by %q, want %q", user, got, want)
		}
	}
}

// D3: the report says what the settings left out.
func TestExclusionsAreStated(t *testing.T) {
	xml := []string{winEvent(4624, 800, fx0, "TargetUserName", "svc_backup", "TargetDomainName", "DSK1",
		"TargetUserSid", "S-1-5-21-1-2-3-1006", "LogonType", "2"),
		winEvent(4624, 801, fx0, "TargetUserName", "jsmith", "TargetDomainName", "DSK1",
			"TargetUserSid", "S-1-5-21-1-2-3-1001", "LogonType", "2")}
	r := buildFrom(translateAll(t, xml...), Options{ExcludeUsers: []string{"svc_backup"}})
	want := "1 routine event by svc_backup (" // U2: no "×1" for one account
	if !strings.Contains(r.excludedText(), want) {
		t.Errorf("excludedText = %q, want it to contain %q", r.excludedText(), want)
	}
	found := false
	hp := r.healthPage()
	if hp == nil {
		t.Fatal("no Audit health page")
	}
	// UI-R1: a note under Settings to fix, not a row of its own.
	found = strings.Contains(hp.Excluded, want)
	if !found {
		t.Error("Audit health does not say what was left out")
	}
}

// D6: one service install, recorded by 7045 (display name) and 4697
// (service name), is one row naming both.
func TestServiceInstallIsOneRow(t *testing.T) {
	sys := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager"/><EventID>7045</EventID><TimeCreated SystemTime="` +
		fx0.Format("2006-01-02T15:04:05.0000000Z") + `"/><EventRecordID>9</EventRecordID><Channel>System</Channel><Computer>DSK1</Computer><Security UserID="S-1-5-21-1-2-3-1001"/></System><EventData><Data Name="ServiceName">Blackbox Test Service</Data><Data Name="ImagePath">C:\Temp\bbsvc.exe</Data><Data Name="ServiceType">user mode service</Data><Data Name="StartType">demand start</Data><Data Name="AccountName">LocalSystem</Data></EventData></Event>`
	sec := winEvent(4697, 900, fx0.Add(time.Second), "SubjectUserSid", "S-1-5-21-1-2-3-1001", "SubjectUserName", "jsmith",
		"SubjectDomainName", "DSK1", "ServiceName", "BBTestSvc", "ServiceFileName", `C:\Temp\bbsvc.exe`, "ServiceAccount", "LocalSystem")
	r := buildFrom(translateAll(t, sys, sec), Options{})
	var rows []*event.Event
	for _, e := range r.Events {
		if e.Action == "service_installed" {
			rows = append(rows, e)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 service row, got %d", len(rows))
	}
	if !strings.Contains(rows[0].Summary, "BBTestSvc") || !strings.Contains(rows[0].Summary, "Blackbox Test Service") {
		t.Errorf("the row should name both: %s", rows[0].Summary)
	}
}

// D7: deleting a user also removes it from its primary group "None";
// that is not a separate change.
func TestPrimaryGroupRemovalIsDropped(t *testing.T) {
	xml := []string{
		winEvent(4729, 950, fx0, "SubjectUserSid", "S-1-5-21-1-2-3-500", "SubjectUserName", "Administrator", "SubjectDomainName", "DSK1",
			"TargetUserName", "None", "TargetSid", "S-1-5-21-1-2-3-513", "MemberName", "-", "MemberSid", "S-1-5-21-1-2-3-1007"),
		winEvent(4733, 951, fx0, "SubjectUserSid", "S-1-5-21-1-2-3-500", "SubjectUserName", "Administrator", "SubjectDomainName", "DSK1",
			"TargetUserName", "Administrators", "TargetSid", "S-1-5-32-544", "MemberName", "-", "MemberSid", "S-1-5-21-1-2-3-1007"),
	}
	r := buildFrom(translateAll(t, xml...), Options{})
	if len(r.Events) != 1 || !strings.Contains(r.Events[0].Summary, "Administrators") {
		for _, e := range r.Events {
			t.Log(e.Summary)
		}
		t.Errorf("want only the Administrators removal, got %d rows", len(r.Events))
	}
}
