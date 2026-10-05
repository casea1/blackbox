package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/casea1/blackbox/internal/archive"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// TestDemoReport writes a realistic LAN report (24 systems, like the
// approved mockups in docs/redesign) to BLACKBOX_DEMO_OUT, for screenshots.
// BLACKBOX_DEMO_STANDALONE=1 writes a one-computer report with a VM.
func TestDemoReport(t *testing.T) {
	out := os.Getenv("BLACKBOX_DEMO_OUT")
	if out == "" {
		t.Skip("set BLACKBOX_DEMO_OUT")
	}
	standalone := os.Getenv("BLACKBOX_DEMO_STANDALONE") != ""
	rnd := rand.New(rand.NewSource(7))
	end := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	days := 7
	if n, err := strconv.Atoi(os.Getenv("BLACKBOX_DEMO_DAYS")); err == nil && n > 0 {
		days = n // a report for a longer, chosen period
	}
	start := end.AddDate(0, 0, -days)

	type sys struct {
		name, os, baseline, via string
		silent                  bool
	}
	var systems []sys
	if standalone {
		systems = []sys{{name: "ENG-WS-21", os: "windows", baseline: "Windows 11 STIG V2R8"}, {name: "ENG-WS-21-VM1", os: "linux", baseline: "Ubuntu 24.04 STIG V1R3", via: "ENG-WS-21"}}
	} else {
		systems = []sys{{name: "SRV-DC01", os: "windows", baseline: "Windows Server 2025 STIG V1R1"}, {name: "SRV-FS01", os: "windows", baseline: "Windows Server 2025 STIG V1R1"},
			{name: "alma-build01", os: "linux", baseline: "Alma 8 (RHEL 8 STIG)"}, {name: "alma-db01", os: "linux", baseline: "Alma 8 (RHEL 8 STIG)"}}
		for i := 1; i <= 14; i++ {
			systems = append(systems, sys{name: fmt.Sprintf("WS-%02d", i), os: "windows", baseline: "Windows 11 STIG V2R8", silent: i == 9})
		}
		for _, n := range []string{"ubu-ws10", "ubu-ws11", "ubu-ws12", "ubu-ws13"} {
			systems = append(systems, sys{name: n, os: "linux", baseline: "Ubuntu 24.04 STIG V1R3"})
		}
		systems = append(systems, sys{name: "WS-03-VM1", os: "windows", baseline: "Windows 11 STIG V2R8", via: "WS-03"}, sys{name: "ubu-ws12-vm", os: "linux", baseline: "Ubuntu 24.04 STIG V1R3", via: "ubu-ws12"})
	}
	users := []string{"admin_jd", "jsmith", "mjones", "kpatel", "lnguyen", "rgarcia", "bwilliams", "dchen"}
	var events []*event.Event
	var runs []*store.Run
	var infos []SystemInfo
	var checks []CheckSet
	add := func(at time.Time, host string, cat event.Category, sev event.Severity, action, user, summary string) *event.Event {
		e := &event.Event{Time: at, Host: host, OS: "windows", Source: "Security", Category: cat, Severity: sev, Action: action,
			User: user, Summary: summary, Outcome: "success", SourceIP: fmt.Sprintf("10.1.1.%d", 10+rnd.Intn(50))}
		events = append(events, e)
		return e
	}
	for _, s := range systems {
		last := end.Add(-5 * time.Minute)
		if s.silent {
			last = start.Add(-10 * time.Hour)
		}
		infos = append(infos, SystemInfo{Name: s.name, OS: s.os, Via: s.via, FirstSeen: start.AddDate(0, -3, 0), LastRun: last})
		for h := start.Add(time.Hour); !h.After(last); h = h.Add(time.Hour) {
			runs = append(runs, &store.Run{Time: h, Host: s.name, OS: s.os, Version: "0.9.0"})
		}
		res := demoChecks(s.os, s.baseline, s.name)
		cs := NewCheckSet(s.name, end.Add(-time.Hour), res)
		cs.Baseline = s.baseline
		checks = append(checks, cs)
		n := 1500 + rnd.Intn(2500)
		if s.silent {
			continue
		}
		owner := users[rnd.Intn(len(users))]
		for i := 0; i < n; i++ {
			// Mostly working hours on weekdays.
			at := start.Add(time.Duration(rnd.Intn(days))*24*time.Hour + time.Duration(7+rnd.Intn(10))*time.Hour + time.Duration(rnd.Intn(3600))*time.Second)
			if rnd.Intn(1500) == 0 {
				at = at.Add(8 * time.Hour)
			}
			weekend := at.Weekday() == time.Saturday || at.Weekday() == time.Sunday
			if weekend && rnd.Intn(10) > 0 {
				continue // a little weekend work: logons only
			}
			if at.After(last) {
				continue
			}
			u := owner
			if rnd.Intn(5) == 0 {
				u = users[rnd.Intn(len(users))]
			}
			switch r := rnd.Intn(100); {
			case weekend:
				add(at, s.name, event.CatLogon, event.SevInfo, "logon", u, u+" logged on at the console.")
			case r < 70:
				add(at, s.name, event.CatLogon, event.SevInfo, "logon", u, u+" logged on (Remote Desktop) from 10.1.1.42.")
			case r < 95:
				add(at, s.name, event.CatPrivileged, event.SevLow, "elevated_process", u, u+` ran with administrator rights: C:\Windows\System32\mmc.exe`)
			case r < 96 && rnd.Intn(4) == 0:
				add(at, s.name, event.CatFailedLogon, event.SevLow, "logon_failed", "", "Logon failed for "+u+": bad password.").Target = u
			default:
				dev := []string{"SanDisk Cruzer Blade", "Kingston DataTraveler 3.0", "Samsung T7", "Logitech USB receiver"}[rnd.Intn(4)]
				add(at, s.name, event.CatRemovable, event.SevMedium, "usb_connected", u, "USB storage connected: "+dev+".").Target = dev
			}
		}
	}
	if !standalone {
		// The mockups' story: WS-07 cleared its log, someone guessed passwords.
		day := end.AddDate(0, 0, -2)
		add(day.Add(9*time.Hour+20*time.Minute), "WS-07", event.CatAccount, event.SevHigh, "group_member_added", "admin_jd", "admin_jd added tempuser to the privileged group Administrators.").Target = "tempuser"
		add(day.Add(9*time.Hour+38*time.Minute), "WS-07", event.CatIntegrity, event.SevHigh, "audit_policy_changed", "admin_jd", "admin_jd changed the audit policy: Removable Storage → No auditing.")
		add(day.Add(12*time.Hour+38*time.Minute), "WS-07", event.CatIntegrity, event.SevHigh, "log_cleared", "admin_jd", "The Security log was cleared by admin_jd.")
		add(day.Add(12*time.Hour+40*time.Minute), "WS-07", event.CatIntegrity, event.SevHigh, "log_cleared", "admin_jd", "The Security log was cleared by admin_jd.")
		for i := 0; i < 8; i++ {
			e := add(day.Add(6*time.Hour+time.Duration(i*5)*time.Second), "WS-07", event.CatFailedLogon, event.SevLow, "logon_failed", "", "Logon failed for administrator: bad password.")
			e.Target, e.SourceIP = "administrator", "10.1.1.99"
		}
		add(day.Add(-48*time.Hour+11*time.Hour), "SRV-DC01", event.CatAccount, event.SevHigh, "group_member_added", "admin_jd", "admin_jd added mjones to the privileged group Domain Admins.").Target = "mjones"
		add(day.Add(-60*time.Hour), "WS-11", event.CatFailedLogon, event.SevMedium, "account_locked", "rgarcia", "Account rgarcia was locked out after too many failed logon attempts.")
	}
	var history []Summary
	for w := 11; w >= 1; w-- {
		history = append(history, Summary{WindowEnd: end.AddDate(0, 0, -7*w), Detections: make([]Detection, 2+rnd.Intn(6)), Events: 70000 + rnd.Intn(15000),
			Metrics: map[string]int{MHighEvents: rnd.Intn(5), MFailedLogons: 110 + rnd.Intn(40), MPrivileged: 11000 + rnd.Intn(2000),
				MSystems: 23 + rnd.Intn(2), MLockouts: rnd.Intn(2), MUSB: 2000 + rnd.Intn(600), MAccountChanges: 3 + rnd.Intn(4)}})
	}
	// Original logs: a week of daily archives per system, bundled, as the
	// collector files them. The silent system has none.
	var archives []ArchiveRef
	tmp := t.TempDir()
	for _, sy := range systems {
		if sy.silent {
			continue
		}
		var days []archive.Stored
		for d := 0; d < 7; d++ {
			from, to := start.AddDate(0, 0, d), start.AddDate(0, 0, d+1)
			var srcs []archive.Source
			names := map[string]string{"Security.evtx": "Security", "System.evtx": "System", "Application.evtx": "Application",
				"PowerShell-Operational.evtx": "Microsoft-Windows-PowerShell/Operational"}
			if sy.os == "linux" {
				names = map[string]string{"audit.log": "audit", "auth.log": "auth", "syslog": "syslog"}
			}
			for n, src := range names {
				f := filepath.Join(tmp, fmt.Sprintf("%s-%d-%s", sy.name, d, n))
				os.WriteFile(f, bytes.Repeat([]byte(sy.name+n), 2000+rnd.Intn(4000)), 0o600)
				srcs = append(srcs, archive.Source{Name: n, Source: src, Path: f})
			}
			path := filepath.Join(tmp, fmt.Sprintf("%s-%d.zip", sy.name, d))
			if _, err := archive.Write(path, archive.Info{Host: sy.name, OS: sy.os, From: from, To: to, Created: to}, srcs); err != nil {
				t.Fatal(err)
			}
			days = append(days, archive.Stored{Host: sy.name, From: from, To: to, Path: path})
		}
		dst := filepath.Join(tmp, "logs-"+sy.name+".zip")
		from, to, sum, _, err := archive.Bundle(dst, days)
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(dst)
		archives = append(archives, ArchiveRef{Host: sy.name, From: from, To: to, Name: "logs-" + sy.name + ".zip", Path: dst, Bytes: uint64(fi.Size()), SHA256: sum})
	}
	site := "Lab 3 LAN"
	if standalone {
		site = ""
	}
	r := Build(events, runs, Options{Site: site, WindowStart: start, WindowEnd: end, Generated: end.Add(5 * time.Minute), Location: time.UTC,
		Source: "Live collection", Collector: !standalone, Systems: infos, CheckSets: checks, History: history, Period: "weekly",
		KnownDevices: map[string]time.Time{}, WorkingHours: mustHours("Mon-Fri 06:00-18:00"),
		Archives: archives, ArchivesKept: true, Interim: days != 7, Scap: scapScans(t), ScapEnabled: true, ScapMaxAgeDays: 30})
	os.RemoveAll(out)
	if err := r.Write(out); err != nil {
		t.Fatal(err)
	}
	// BLACKBOX_DEMO_INDEX: a reports folder with the earlier weeks too.
	if idx := os.Getenv("BLACKBOX_DEMO_INDEX"); idx != "" {
		os.RemoveAll(idx)
		for i, h := range history {
			h.WindowStart, h.Hosts = h.WindowEnd.AddDate(0, 0, -7), r.Hosts
			for k := range h.Detections {
				h.Detections[k] = Detection{Severity: []string{"high", "medium", "medium"}[rnd.Intn(3)], Host: r.Hosts[rnd.Intn(len(r.Hosts))]}
				if h.Detections[k].Severity == "high" {
					h.High++
				} else {
					h.Medium++
				}
			}
			if i == 7 {
				h.Metrics["late_events"] = 1
			}
			b, _ := json.Marshal(h)
			d := filepath.Join(idx, h.WindowEnd.Format("2006-01-02_1504"))
			os.MkdirAll(d, 0o750)
			os.WriteFile(filepath.Join(d, "summary.json"), b, 0o640)
		}
		for i, a := range r.Archives { // the first Write moved them
			b, _ := os.ReadFile(filepath.Join(out, a.Name))
			r.Archives[i].Path = filepath.Join(tmp, "again-"+a.Name)
			os.WriteFile(r.Archives[i].Path, b, 0o640)
		}
		if err := r.Write(filepath.Join(idx, end.Format("2006-01-02_1504")+"_Lab3")); err != nil {
			t.Fatal(err)
		}
		if err := WriteIndex(idx, site, "weekly, ready Wednesday 00:00 (each covers the week to Tuesday night)", time.UTC); err != nil {
			t.Fatal(err)
		}
	}
}

func mustHours(v string) config.WorkingHours {
	w, err := config.ParseWorkingHours(v)
	if err != nil {
		panic(err)
	}
	return w
}

// demoChecks is a realistic audit settings check: everything matching,
// except a few gaps on named systems.
func demoChecks(os, baseline, name string) []check.Result {
	sf := "Success and Failure"
	res := []check.Result{{Area: "Baseline", Item: "Compared with", Status: check.Info, Have: baseline, Want: baseline}}
	if os == "windows" {
		for _, x := range [][3]string{{"Logon", sf, "WN11-AU-000070, -075"}, {"Logoff", "Success", "WN11-AU-000065"},
			{"Credential Validation", sf, "WN11-AU-000005, -010"}, {"User Account Management", sf, "WN11-AU-000035, -040"},
			{"Security Group Management", "Success", "WN11-AU-000030"}, {"Audit Policy Change", "Success", "WN11-AU-000100"},
			{"Sensitive Privilege Use", sf, "WN11-AU-000110, -115"}, {"Process Creation", "Success", "WN11-AU-000050"},
			{"Removable Storage", sf, "WN11-AU-000085, -090"}} {
			r := check.Result{Area: "Audit policy", Item: x[0], Want: x[1], Have: x[1], STIG: x[2], Status: check.Pass}
			if x[0] == "Removable Storage" && name == "WS-13" {
				r.Have, r.Status = "No auditing", check.Fail
				r.Affects = "USB & Removable Media (files read/written)"
				r.Fix = "Group Policy: Advanced Audit Policy > Object Access > Audit Removable Storage: Success and Failure"
			}
			res = append(res, r)
		}
		ps := check.Result{Area: "Audit settings", Item: "PowerShell script block logging", Want: "Enabled (1)", Have: "Enabled (1)", STIG: "WN11-CC-000326", Status: check.Pass}
		if name == "WS-12" {
			ps.Have, ps.Status = "Not set", check.Warn
			ps.Fix = "Group Policy: Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging"
		}
		av := check.Result{Area: "Antivirus", Item: "Defender security intelligence", Want: "Version created within the last 30 days",
			Have: "1.419.231.0 · version created on 29 Sep 2026 03:12 (1 day old) · engine 4.18.25080.5", Status: check.Pass}
		if name == "WS-05" {
			av.Have, av.Status = "1.417.88.0 · version created on 12 Sep 2026 02:40 (18 days old) · engine 4.18.25080.5", check.Fail
			av.Fix = "Import the latest security intelligence update (mpam-fe.exe) from your update source onto this system."
		}
		res = append(res, av, check.Result{Area: "Antivirus", Item: "Defender real-time protection", Want: "On", Have: "On", Status: check.Pass})
		res = append(res, ps, check.Result{Area: "Event log size", Item: "Security log", Want: "Holds a week", Have: "Holds 9 days (1 GB)", STIG: "WN11-AU-000505", Status: check.Pass})
		return res
	}
	for _, x := range []string{"Watch /etc/passwd", "Watch /etc/shadow", "Watch /etc/sudoers and /etc/sudoers.d", "Programs run with raised privileges (execve, uid!=euid)",
		"Commands run as root by a person (execve, euid=0, auid set)", "Filesystem mounts", "Audit configuration watched (/etc/audit)"} {
		r := check.Result{Area: "Audit rules", Item: x, Want: "Present", Have: "Present", Status: check.Pass}
		if x == "Filesystem mounts" && name == "alma-db01" {
			r.Have, r.Status = "Missing", check.Fail
			r.Affects = "USB & Removable Media (disks mounted from the command line)"
			r.Fix = "blackbox check --audit-rules --missing | install -m 0600 /dev/stdin /etc/audit/rules.d/blackbox.rules, then augenrules --load"
		}
		res = append(res, r)
	}
	return append(res, check.Result{Area: "Audit service", Item: "auditd running", Want: "active", Have: "active", Status: check.Pass},
		check.Result{Area: "auditd settings", Item: "Audit log space", Want: "a week", Have: "12 days", Status: check.Pass})
}
