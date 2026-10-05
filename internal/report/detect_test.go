package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
)

var t0 = time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC) // a Wednesday

func ev(min int, host, action string, cat event.Category, sev event.Severity, user, target string) *event.Event {
	return &event.Event{Time: t0.Add(time.Duration(min) * time.Minute), Host: host, Action: action, Category: cat,
		Severity: sev, User: user, Target: target, Summary: action + " by " + user + "."}
}

func findings(r *Report) map[string][]Finding {
	m := map[string][]Finding{}
	for _, f := range r.Findings {
		m[f.Title] = append(m[f.Title], f)
	}
	return m
}

func detectOnly(events, context []*event.Event, opt Options) *Report {
	opt.Location = time.UTC
	opt.WindowStart = t0.Add(-time.Hour)
	opt.WindowEnd = t0.Add(48 * time.Hour)
	opt.Context = context
	return Build(events, nil, opt)
}

func TestSprayAcrossComputers(t *testing.T) {
	var evs []*event.Event
	for i, h := range []string{"WS-01", "WS-02", "WS-03", "WS-03"} {
		evs = append(evs, ev(i*2, h, "logon_failed", event.CatFailedLogon, event.SevLow, "", "jdoe"))
	}
	f := findings(detectOnly(evs, nil, Options{}))["Same account failing on several computers"]
	if len(f) != 1 || !strings.Contains(f[0].Detail, "3 computers") {
		t.Fatalf("spray: %+v", f)
	}
	// Two computers is not enough.
	if f := findings(detectOnly(evs[:2], nil, Options{}))["Same account failing on several computers"]; len(f) != 0 {
		t.Errorf("two computers flagged: %+v", f)
	}
}

func TestCoverTracksUsesThePreviousDay(t *testing.T) {
	setup := ev(-120, "WS-01", "group_member_added", event.CatAccount, event.SevHigh, "mallory", "mallory")
	clear := ev(30, "WS-01", "log_cleared", event.CatIntegrity, event.SevHigh, "mallory", "Security")
	f := findings(detectOnly([]*event.Event{clear}, []*event.Event{setup}, Options{}))["Possible covering of tracks"]
	if len(f) != 1 || f[0].RowID == "" || !strings.Contains(f[0].Detail, "log_cleared") {
		t.Fatalf("cover tracks across reports: %+v", f)
	}
	// Other computer, or an ordinary group: nothing.
	other := ev(-120, "WS-02", "group_member_added", event.CatAccount, event.SevHigh, "mallory", "mallory")
	plain := ev(-60, "WS-01", "group_member_added", event.CatAccount, event.SevMedium, "mallory", "mallory")
	if f := findings(detectOnly([]*event.Event{clear}, []*event.Event{other, plain}, Options{}))["Possible covering of tracks"]; len(f) != 0 {
		t.Errorf("unrelated setup flagged: %+v", f)
	}
	// A Group Policy refresh changing the audit policy is not tampering.
	gpo := ev(30, "WS-01", "audit_policy_changed", event.CatIntegrity, event.SevMedium, `NT AUTHORITY\SYSTEM`, "")
	if f := findings(detectOnly([]*event.Event{gpo}, []*event.Event{setup}, Options{}))["Possible covering of tracks"]; len(f) != 0 {
		t.Errorf("system change flagged: %+v", f)
	}
	// Only a pattern completed in this period is reported.
	if f := findings(detectOnly(nil, []*event.Event{setup, ev(-100, "WS-01", "log_cleared", event.CatIntegrity, event.SevHigh, "m", "Security")}, Options{}))["Possible covering of tracks"]; len(f) != 0 {
		t.Errorf("pattern from the previous report repeated: %+v", f)
	}
}

func TestShortLivedAccount(t *testing.T) {
	evs := []*event.Event{
		ev(0, "WS-01", "account_created", event.CatAccount, event.SevMedium, "admin1", "temp1"),
		ev(90, "WS-01", "account_deleted", event.CatAccount, event.SevMedium, "admin1", "TEMP1"),
		ev(0, "WS-01", "account_created", event.CatAccount, event.SevMedium, "admin1", "keeper"),
	}
	f := findings(detectOnly(evs, nil, Options{}))["Account created and deleted within a day"]
	if len(f) != 1 || !strings.Contains(f[0].Detail, "temp1") {
		t.Fatalf("short-lived: %+v", f)
	}
}

func TestOffHoursAdminActivity(t *testing.T) {
	wh, _ := config.ParseWorkingHours("Mon-Fri 06:00-18:00")
	evs := []*event.Event{
		ev(0, "WS-01", "elevated_process", event.CatPrivileged, event.SevLow, "jdoe", ""),   // 10:00: fine
		ev(780, "WS-01", "elevated_process", event.CatPrivileged, event.SevLow, "jdoe", ""), // 23:00
		ev(790, "WS-01", "elevated_process", event.CatPrivileged, event.SevLow, "jdoe", ""),
		ev(795, "WS-01", "elevated_process", event.CatPrivileged, event.SevLow, "SYSTEM", ""),
	}
	f := findings(detectOnly(evs, nil, Options{WorkingHours: wh}))["Administrator activity outside working hours"]
	if len(f) != 1 || !strings.Contains(f[0].Detail, "2 actions") || !strings.Contains(f[0].Detail, "between 23:00:00 and 23:10:00") {
		t.Fatalf("off hours: %+v", f)
	}
	if f := findings(detectOnly(evs, nil, Options{}))["Administrator activity outside working hours"]; len(f) != 0 {
		t.Error("checked without working hours set")
	}
}

func TestAdminAfterNewDevice(t *testing.T) {
	usb := ev(0, "WS-01", "usb_connected", event.CatRemovable, event.SevMedium, "", "Kingston DataTraveler")
	usb.DedupeKey = "usb|0951:1666|ABC"
	evs := []*event.Event{usb, ev(5, "WS-01", "elevated_process", event.CatPrivileged, event.SevLow, "jdoe", "")}
	f := findings(detectOnly(evs, nil, Options{KnownDevices: map[string]time.Time{}}))["New USB device, then administrator activity"]
	if len(f) != 1 {
		t.Fatalf("usb then admin: %+v", f)
	}
	known := map[string]time.Time{"WS-01|0951:1666|ABC": t0}
	if f := findings(detectOnly(evs, nil, Options{KnownDevices: known}))["New USB device, then administrator activity"]; len(f) != 0 {
		t.Error("known device flagged")
	}
}

func logon(min int, host, user, ip string) *event.Event {
	e := ev(min, host, "logon", event.CatLogon, event.SevInfo, user, "")
	e.Interactive, e.SourceIP = true, ip
	return e
}

func TestFirstTimeSeen(t *testing.T) {
	baseline := map[string]time.Time{}
	hosts := map[string]time.Time{}
	evs := []*event.Event{logon(0, "WS-01", "jdoe", "10.0.0.5"), logon(5, "WS-01", "jdoe", "10.0.0.5"),
		ev(6, "WS-01", "elevated_process", event.CatPrivileged, event.SevLow, "jdoe", "")}

	// First report of a computer: learn only.
	r := detectOnly(evs, nil, Options{Baseline: baseline, BaselineHosts: hosts})
	if len(r.Findings) != 0 || len(r.Learning) != 1 {
		t.Fatalf("learning report flagged: %+v %v", r.Findings, r.Learning)
	}
	UpdateBaseline(baseline, hosts, r, t0)

	// Same activity again: nothing new.
	r = detectOnly(evs, nil, Options{Baseline: baseline, BaselineHosts: hosts})
	if len(r.Findings) != 0 || len(r.Learning) != 0 {
		t.Fatalf("known activity flagged: %+v", r.Findings)
	}

	// A new person, from a new address, using admin rights: each once.
	evs = append(evs, logon(10, "WS-01", "mallory", "10.0.0.66"), logon(11, "WS-01", "mallory", "10.0.0.66"),
		ev(12, "WS-01", "elevated_process", event.CatPrivileged, event.SevLow, "mallory", ""),
		logon(13, "WS-01", "jdoe", "127.0.0.1"))
	f := findings(detectOnly(evs, nil, Options{Baseline: baseline, BaselineHosts: hosts}))
	for _, want := range []string{"First logon to this computer", "First logon from this address", "First use of administrator rights"} {
		if len(f[want]) != 1 {
			t.Errorf("%s: %+v", want, f[want])
		}
	}

	// Forgotten after a year unseen.
	UpdateBaseline(baseline, hosts, r, t0.AddDate(1, 0, 2))
	if len(baseline) != 0 {
		t.Errorf("baseline not expired: %v", baseline)
	}
}

func TestPerson(t *testing.T) {
	for u, want := range map[string]bool{"jdoe": true, `CORP\jdoe.adm`: true, "SYSTEM": false, `NT AUTHORITY\SYSTEM`: false, "WS-07$": false, "": false, "unset": false, "root": true} {
		if person(u) != want {
			t.Errorf("person(%q) = %v", u, !want)
		}
	}
}

// D9: commands and scripts that clear logs or weaken auditing, and
// Defender being switched off (its events name no user), complete
// "Possible covering of tracks" like a log clear does.
func TestCoverTracksByCommandsAndDefender(t *testing.T) {
	setup := ev(-30, "WS-01", "account_created", event.CatAccount, event.SevMedium, "mallory", "helper")
	for _, tamper := range []*event.Event{
		ev(10, "WS-01", "audit_tamper_command", event.CatPrivileged, event.SevHigh, "mallory", ""),
		ev(10, "WS-01", "powershell_tamper", event.CatIntegrity, event.SevHigh, "mallory", ""),
		ev(10, "WS-01", "powershell_av_tamper", event.CatIntegrity, event.SevHigh, "mallory", ""),
		ev(10, "WS-01", "av_disabled", event.CatOther, event.SevHigh, "", ""),
	} {
		if f := findings(detectOnly([]*event.Event{setup, tamper}, nil, Options{}))["Possible covering of tracks"]; len(f) != 1 {
			t.Errorf("%s did not complete covering of tracks", tamper.Action)
		}
	}
}

// A17b: setting up a collector (creating the delivery account, then
// running Blackbox setup, which records its own inbox setting) is not
// covering tracks; changing what Blackbox leaves out still is.
func TestCoverTracksNotBlackboxSetup(t *testing.T) {
	acct := ev(0, "WIN11-COL", "account_created", event.CatAccount, event.SevMedium, `WIN11-COL\claude`, "bbsend2")
	self := func(setting string) *event.Event {
		e := event.SelfChange{Kind: "changed", Who: `WIN11-COL\claude`, Setting: setting, Old: "", New: `C:\BlackboxInbox`, Program: "blackbox setup"}.Event()
		e.Time, e.Host = t0.Add(30*time.Second), "WIN11-COL"
		return e
	}
	if f := findings(detectOnly([]*event.Event{acct, self("inbox")}, nil, Options{}))["Possible covering of tracks"]; len(f) != 0 {
		t.Errorf("collector setup flagged: %+v", f)
	}
	if f := findings(detectOnly([]*event.Event{acct, self("exclude_users")}, nil, Options{}))["Possible covering of tracks"]; len(f) != 1 {
		t.Errorf("an exclusion after creating an account: %+v", f)
	}
}
