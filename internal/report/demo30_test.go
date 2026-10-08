package report

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/inventory"
	"github.com/casea1/blackbox/internal/scap"
	"github.com/casea1/blackbox/internal/store"
)

// The 30-system test network of the report redesign (UI-R1): the network
// the mockups in docs/testing/2026-10-02-v0.10.1/redesign-2026-10-08 show.
//
//	r, net := demo30(t)
//
// builds it (deterministic, a fixed seed, about a second) and returns the
// built report and what it was built from. Every page's tests can use it:
//
//   - 30 systems: 11 servers and 19 workstations, 15 Windows and 15 Ubuntu;
//     two of them silent (WS-ENG-06, ubu-ws-07: nothing since 6 Oct);
//   - local accounts only, no domain: 50 to 100 accounts on each system
//     (its inventory), about 20 of them used in the period, exactly one
//     root on each Ubuntu system and one Administrator on each Windows one;
//   - a daily report, 7 Oct 2026 00:00 to 8 Oct 00:00 EDT (UTC-4), site
//     ENG-NET, with the previous day's report in History (no gap);
//   - logons, SSH password guessing (412 failures on ubu-web01 from
//     203.0.113.50), privileged commands and sudo, USB devices, an audit
//     policy weakened, the Security log cleared on SRV-DC02, a new local
//     administrator, a PowerShell download, a clock moved back, and events
//     overwritten in the PowerShell log of three systems;
//   - audit settings with gaps on 22 systems, antivirus out of date on 5,
//     SCAP results (CAT I on 4), original-log zips for the 28 that
//     reported, drive serial numbers in each inventory.
//
// BLACKBOX_DEMO30_OUT=<dir> go test ./internal/report -run TestDemo30 -count=1
// writes the whole report folder, to open in a browser.

// demo30System is one computer of the test network.
type demo30System struct {
	Name, OS, Baseline string // OS: windows | linux
	Server, Silent     bool
	Accounts           int      // accounts in its inventory
	Active             []string // the accounts used in the period
}

// demo30Net is what the report was built from.
type demo30Net struct {
	Systems    []demo30System
	Events     []*event.Event
	Runs       []*store.Run
	Options    Options
	Start, End time.Time
}

// demo30Zone is the network's time zone: a fixed offset, so the report is
// the same on every computer.
var demo30Zone = time.FixedZone("EDT", -4*3600)

// demo30 builds the 30-system report (not written; call r.Write).
func demo30(t testing.TB) (*Report, *demo30Net) {
	t.Helper()
	net := demo30Network(t)
	return Build(net.Events, net.Runs, net.Options), net
}

func demo30Network(t testing.TB) *demo30Net {
	t.Helper()
	rnd := rand.New(rand.NewSource(30))
	end := time.Date(2026, 10, 8, 0, 0, 0, 0, demo30Zone)
	start := end.AddDate(0, 0, -1)
	net := &demo30Net{Start: start, End: end}

	win := func(name string, server bool) demo30System {
		b := "Windows 11 STIG V2R8"
		if server {
			b = "Windows Server 2025 STIG V1R1"
		}
		return demo30System{Name: name, OS: "windows", Baseline: b, Server: server}
	}
	ubu := func(name string, server bool) demo30System {
		return demo30System{Name: name, OS: "linux", Baseline: "Ubuntu 24.04 STIG V1R3", Server: server}
	}
	for _, n := range []string{"SRV-DC01", "SRV-DC02", "SRV-FS01", "SRV-APP01", "SRV-APP02", "SRV-SQL01"} {
		net.Systems = append(net.Systems, win(n, true))
	}
	for _, n := range []string{"ubu-web01", "ubu-db01", "ubu-git01", "ubu-mon01", "ubu-build01"} {
		net.Systems = append(net.Systems, ubu(n, true))
	}
	for _, n := range []string{"WS-ENG-01", "WS-ENG-02", "WS-ENG-03", "WS-ENG-04", "WS-ENG-05", "WS-ENG-06", "WS-ADM-01", "WS-ADM-02", "WS-LAB-01"} {
		net.Systems = append(net.Systems, win(n, false))
	}
	for i := 1; i <= 10; i++ {
		net.Systems = append(net.Systems, ubu(fmt.Sprintf("ubu-ws-%02d", i), false))
	}

	// People: a pool of local account names; each system has its own
	// accounts, about 20 of which are used in the period.
	first := "abcdefghjklmnprstw"
	last := []string{"lee", "doe", "patel", "lopez", "smith", "nguyen", "garcia", "chen", "jones", "brown", "kim", "wright", "olsen", "baker", "reyes", "ford", "hale", "moss", "price", "quinn"}
	var pool []string
	for _, l := range last {
		for _, f := range first {
			pool = append(pool, string(f)+l)
		}
	}
	rnd.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	staff := []string{"jlee", "jdoe", "kpatel", "tlopez"} // the people in the mockups' story

	evs := []*event.Event{}
	rec := map[string]uint64{}
	add := func(at time.Time, s demo30System, cat event.Category, sev event.Severity, action, user, summary string) *event.Event {
		rec[s.Name]++
		e := &event.Event{Time: at, Host: s.Name, OS: s.OS, Category: cat, Severity: sev, Action: action, User: user, Summary: summary,
			Outcome: "success", RecordID: 100000 + rec[s.Name]*7}
		if s.OS == "windows" {
			e.Source = "Security"
		} else {
			e.Source = "audit"
		}
		evs = append(evs, e)
		return e
	}
	byName := map[string]demo30System{}
	var infos []SystemInfo
	var checks []CheckSet
	var archives []ArchiveRef
	var scans []*scap.Scan
	tmp := t.TempDir()
	for i := range net.Systems {
		s := &net.Systems[i]
		s.Silent = s.Name == "WS-ENG-06" || s.Name == "ubu-ws-07"
		s.Accounts = 50 + rnd.Intn(51)
		// Accounts: built-in first, then people.
		var names []string
		admins := map[string]bool{}
		if s.OS == "windows" {
			names = []string{"Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "svc-backup", "svc-patch", "adm-jlee"}
			admins["Administrator"], admins["adm-jlee"] = true, true
		} else {
			names = []string{"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup",
				"list", "irc", "_apt", "nobody", "systemd-network", "systemd-resolve", "messagebus", "systemd-timesync", "syslog", "uuidd", "tss",
				"sshd", "tcpdump", "landscape", "fwupd-refresh", "polkitd", "svc-backup", "ansible"}
			admins["root"], admins["ansible"] = true, true
		}
		names = append(names, staff...)
		admins["jlee"] = true
		for k := 0; len(names) < s.Accounts; k++ {
			names = append(names, pool[(i*37+k)%len(pool)])
		}
		names = dedupeNames(names, pool)[:s.Accounts]
		// About 20 used: the staff, the admin account, and people.
		active := []string{"jlee", "jdoe", "kpatel", "tlopez"}
		if s.OS == "windows" {
			active = append(active, "adm-jlee", "svc-backup")
		} else {
			active = append(active, "root", "ansible")
		}
		for _, n := range names {
			if len(active) >= 18+rnd.Intn(5) {
				break
			}
			if !contains(active, n) && !builtinAccount(n) {
				active = append(active, n)
			}
		}
		s.Active = active
		byName[s.Name] = *s

		// Inventory: make, model, serials, drives, accounts.
		inv := &inventory.Inventory{Memory: uint64(16<<(i%2)) << 30, Server: s.Server && s.OS == "linux"}
		if s.Server {
			inv.Manufacturer, inv.Model, inv.Serial = "Dell Inc.", "PowerEdge R650", fmt.Sprintf("8%02dQ2RT", i)
		} else {
			inv.Manufacturer, inv.Model, inv.Serial = "Dell Inc.", "OptiPlex 7090", fmt.Sprintf("7X%02dPQ3", i)
		}
		if s.OS == "windows" {
			inv.OS, inv.CPU = "Microsoft Windows 11 Enterprise 10.0.26100", "Intel(R) Core(TM) i7-11700 @ 2.50GHz"
			if s.Server {
				inv.OS = "Microsoft Windows Server 2025 Standard 10.0.26100"
			}
		} else {
			inv.OS, inv.CPU = "Ubuntu 24.04.1 LTS", "Intel(R) Xeon(R) Silver 4314 @ 2.40GHz"
		}
		inv.Drives = []inventory.Drive{{Model: "Samsung SSD 980 PRO 1TB", Serial: fmt.Sprintf("S5GXNX0T%06dA", 100000+i*731), Size: 1000202273280, Interface: "NVMe", Media: "SSD"}}
		if s.Server {
			inv.Drives = append(inv.Drives, inventory.Drive{Model: "SEAGATE ST4000NM0035", Serial: fmt.Sprintf("ZC1%05dK", 20000+i*97), Size: 4000787030016, Interface: "SATA", Media: "HDD"})
		}
		for k, n := range names {
			a := inventory.Account{Name: n, Enabled: n != "Guest" && n != "DefaultAccount" && n != "WDAGUtilityAccount", Admin: admins[n], Kind: "Local"}
			if s.OS == "windows" {
				a.ID = fmt.Sprintf("…%d", 1000+k)
				switch n {
				case "Administrator":
					a.ID = "…500"
				case "Guest":
					a.ID = "…501"
				}
			} else {
				a.ID = fmt.Sprintf("uid %d", 1000+k)
				if n == "root" {
					a.ID, a.Note = "uid 0", "password locked"
				} else if builtinAccount(n) {
					a.ID, a.Kind = fmt.Sprintf("uid %d", k), "System"
				}
			}
			if contains(active, n) && !s.Silent {
				a.LastLogon = start.Add(time.Duration(7+rnd.Intn(10)) * time.Hour)
			}
			inv.Accounts = append(inv.Accounts, a)
		}

		// Collection: hourly, and none from the silent two since 6 Oct.
		lastRun := end.Add(-10 * time.Minute)
		if s.Silent {
			lastRun = start.Add(-20 * time.Hour)
		}
		infos = append(infos, SystemInfo{Name: s.Name, OS: s.OS, Version: "0.23.0", FirstSeen: start.AddDate(0, -2, 0), LastRun: lastRun})
		if !s.Silent {
			for h := start.Add(50 * time.Minute); h.Before(end); h = h.Add(time.Hour) {
				run := &store.Run{Time: h, Host: s.Name, OS: s.OS, Version: "0.23.0"}
				ch := store.ChannelRun{Channel: "Security", Read: 40 + rnd.Intn(80), Kept: 20 + rnd.Intn(30)}
				if s.OS == "linux" {
					ch.Channel = "audit"
				}
				run.Channels = []store.ChannelRun{ch}
				// Events overwritten: the PowerShell log is too small.
				if h.Hour() == 13 && (s.Name == "WS-ENG-02" || s.Name == "WS-ADM-01" || s.Name == "SRV-APP02") {
					run.Channels = append(run.Channels, store.ChannelRun{Channel: powerShellLog, Read: 900,
						Gap: &store.Gap{Lost: uint64(120 + rnd.Intn(300)), From: h.Add(-70 * time.Minute), To: h.Add(-50 * time.Minute)}, MaxSizeBytes: 15 << 20})
				}
				net.Runs = append(net.Runs, run)
			}
		}

		// Audit settings: gaps on 22 systems; antivirus out of date on 5.
		res := []check.Result{{Area: "Baseline", Item: "Compared with", Status: check.Info, Have: s.Baseline, Want: s.Baseline}}
		fails := 0
		if i%4 != 0 { // 22 of the 30
			fails = 1 + (i*7)%12
		}
		items := demo30Settings(s.OS)
		for k, it := range items {
			r := check.Result{Area: it[0], Item: it[1], Want: it[2], Have: it[2], STIG: it[3], Status: check.Pass, Affects: demo30Affects[it[1]]}
			if s.Server {
				// Server 2025 has its own STIG IDs for the same settings.
				r.STIG = strings.Replace(r.STIG, "WN11-", "WN25-", 1)
			}
			if k < fails {
				r.Have, r.Status = "Not set", check.Fail
				r.Fix = demo30Fix(it)
			}
			res = append(res, r)
		}
		avAge := 1 + i%3
		if s.Name == "WS-ENG-03" || s.Name == "WS-LAB-01" || s.Name == "ubu-ws-02" || s.Name == "ubu-ws-05" || s.Name == "SRV-APP02" {
			avAge = 9 + i%6
		}
		dated := end.Add(-time.Duration(avAge*24+3) * time.Hour)
		av := check.Result{Area: "Antivirus", Status: check.Pass, Dated: dated, Want: "Definitions under 7 days old"}
		if s.OS == "windows" {
			av.Item = "Defender security intelligence"
			av.Have = fmt.Sprintf("1.419.%d.0 · version created on %s (%d days old) · engine 4.18.25080.5", 200+i, dated.Format("2 Jan 2006 15:04"), avAge)
		} else {
			av.Item = "ClamAV definitions"
			av.Have = fmt.Sprintf("daily 27%03d · built on %s (%d days old) · engine 1.0.7", 100+i, dated.Format("2 Jan 2006 15:04"), avAge)
		}
		if avAge > 7 {
			av.Status = check.Fail
			av.Fix = "Update the antivirus definitions from your update source."
		}
		res = append(res, av)
		if s.OS == "windows" {
			res = append(res, check.Result{Area: "Antivirus", Item: "Defender real-time protection", Want: "On", Have: "On", Status: check.Pass})
		} else {
			res = append(res, check.Result{Area: "Antivirus", Item: "ClamAV scanner service", Want: "Running", Have: "Running", Status: check.Pass})
		}
		cs := NewCheckSet(s.Name, end.Add(-30*time.Minute), res)
		if s.Silent {
			cs = NewCheckSet(s.Name, start.Add(-20*time.Hour), res)
		}
		cs.Baseline = s.Baseline
		cs.Inventory = inv
		checks = append(checks, cs)

		// SCAP: every system scanned last week; CAT I open on 4.
		scanFile := filepath.Join(tmp, "scap-"+s.Name+".xml")
		if err := os.WriteFile(scanFile, []byte("<Benchmark/>\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		res2 := &scap.Result{File: scanFile, Host: s.Name, Benchmark: strings.TrimSuffix(s.Baseline, " V1R1"), Version: "V1R1",
			Start: end.AddDate(0, 0, -3), End: end.AddDate(0, 0, -3).Add(20 * time.Minute), HasScore: true,
			Counts: map[string]int{"pass": 180 + i, "fail": 6 + i%9}}
		res2.Score = float64(res2.Counts["pass"]) * 100 / float64(res2.Counts["pass"]+res2.Counts["fail"])
		for k := 0; k < res2.Counts["fail"]; k++ {
			sev := []string{"medium", "medium", "low"}[k%3]
			if k == 0 && (s.Name == "SRV-APP01" || s.Name == "ubu-web01" || s.Name == "ubu-db01" || s.Name == "ubu-git01") {
				sev = "high"
			}
			res2.Open = append(res2.Open, scap.Rule{ID: fmt.Sprintf("xccdf_mil.disa.stig_rule_SV-%d_rule", 250000+i*100+k), VulnID: fmt.Sprintf("V-%d", 250000+i*100+k),
				STIGID: fmt.Sprintf("%s-%06d", map[string]string{"windows": "WN11-CC", "linux": "UBTU-24"}[s.OS], 10000+k*10), Title: fmt.Sprintf("Rule %d of the benchmark must be met.", k+1), Severity: sev})
		}
		scans = append(scans, &scap.Scan{Latest: res2})

		// Original logs: one zip for the day, for every system that reported.
		if !s.Silent {
			var srcs []archive.Source
			files := []string{"Security.evtx", "System.evtx", "PowerShell-Operational.evtx"}
			if s.OS == "linux" {
				files = []string{"audit.log", "auth.log", "syslog"}
			}
			for _, f := range files {
				p := filepath.Join(tmp, s.Name+"-"+f)
				if err := os.WriteFile(p, []byte(strings.Repeat(s.Name+" "+f+"\n", 40)), 0o600); err != nil {
					t.Fatal(err)
				}
				src := strings.TrimSuffix(f, filepath.Ext(f))
				if f == "PowerShell-Operational.evtx" {
					src = powerShellLog // the channel, as the collector names it
				}
				srcs = append(srcs, archive.Source{Name: f, Source: src, Path: p})
			}
			zp := filepath.Join(tmp, "day-"+s.Name+".zip")
			if _, err := archive.Write(zp, archive.Info{Host: s.Name, OS: s.OS, From: start, To: end, Created: end}, srcs); err != nil {
				t.Fatal(err)
			}
			sum, err := archive.FileSHA256(zp)
			if err != nil {
				t.Fatal(err)
			}
			fi, _ := os.Stat(zp)
			archives = append(archives, ArchiveRef{Host: s.Name, From: start, To: end, Name: "logs-" + s.Name + ".zip", Path: zp, Bytes: uint64(fi.Size()), SHA256: sum})
		}
	}

	// Routine activity: logons, privileged commands and sudo, mostly in
	// working hours.
	hourWeight := []int{1, 1, 1, 1, 1, 1, 2, 6, 10, 12, 12, 11, 9, 11, 12, 11, 9, 6, 3, 2, 1, 1, 1, 1}
	pickHour := func() int {
		n := rnd.Intn(115)
		for h, w := range hourWeight {
			if n < w {
				return h
			}
			n -= w
		}
		return 12
	}
	for _, s := range net.Systems {
		if s.Silent {
			continue
		}
		people := s.Active
		n := 280 + rnd.Intn(260)
		if s.Server {
			n += 200
		}
		for k := 0; k < n; k++ {
			h := pickHour()
			at := start.Add(time.Duration(h)*time.Hour + time.Duration(rnd.Intn(3600))*time.Second + time.Duration(rnd.Intn(1000))*time.Millisecond)
			u := people[rnd.Intn(len(people))]
			ip := fmt.Sprintf("10.20.%d.%d", 1+rnd.Intn(4), 10+rnd.Intn(200))
			if h < 7 || h >= 19 {
				// Out of hours: only service accounts.
				if s.OS == "windows" {
					u = "svc-backup"
				} else {
					u = "ansible"
				}
			}
			r := rnd.Intn(100)
			if h < 7 || h >= 19 {
				r %= 55 // logons only: no administrator work out of hours
			}
			switch {
			case r < 55:
				if s.OS == "windows" {
					e := add(at, s, event.CatLogon, event.SevInfo, "logon", u, fmt.Sprintf("%s logged on (Remote Desktop) from %s.", u, ip))
					e.EventID, e.SourceIP, e.Interactive = 4624, ip, true
					e.AddDetail("Logon type", "10 (Remote Desktop)")
				} else {
					e := add(at, s, event.CatLogon, event.SevInfo, "logon", u, fmt.Sprintf("%s logged on over SSH from %s port %d.", u, ip, 40000+rnd.Intn(20000)))
					e.Source, e.SourceIP, e.Interactive, e.RecordType = "auth", ip, true, "sshd"
				}
			case r < 85:
				if s.OS == "windows" {
					proc := []string{`C:\Windows\System32\mmc.exe`, `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\sc.exe`}[rnd.Intn(4)]
					e := add(at, s, event.CatPrivileged, event.SevLow, "elevated_process", u, u+" ran with administrator rights: "+proc)
					e.EventID, e.Process = 4688, proc
				} else {
					cmd := []string{"apt-get update", "systemctl restart nginx", "journalctl -u ssh", "tail -n 50 /var/log/syslog", "docker ps"}[rnd.Intn(5)]
					e := add(at, s, event.CatPrivileged, event.SevLow, "sudo", u, fmt.Sprintf("%s ran as root with sudo: %s (#%d)", u, cmd, rnd.Intn(99999)))
					e.Command, e.Process, e.RecordType = cmd, "/usr/bin/sudo", "USER_CMD"
				}
			case r < 93:
				if s.OS == "windows" {
					e := add(at, s, event.CatLogon, event.SevInfo, "logoff", u, fmt.Sprintf("%s logged off (session %d).", u, rnd.Intn(9999)))
					e.EventID = 4634
				} else {
					e := add(at, s, event.CatLogon, event.SevInfo, "logoff", u, fmt.Sprintf("%s's SSH session %d ended.", u, rnd.Intn(9999)))
					e.Source = "auth"
				}
			case r < 97:
				// A mistyped password now and then, each system its own
				// people (no account failing across the network).
				u = people[len(people)-1-rnd.Intn(3)]
				e := add(at, s, event.CatFailedLogon, event.SevLow, "logon_failed", "", fmt.Sprintf("Logon failed for %s from %s: bad password.", u, ip))
				e.Target, e.SourceIP, e.Outcome, e.EventID = u, ip, "failure", 4625
			default:
				svc := []string{"Windows Update", "Print Spooler", "Remote Registry", "BITS"}[rnd.Intn(4)]
				if s.OS == "linux" {
					svc = []string{"nginx", "cron", "postgresql", "snapd"}[rnd.Intn(4)]
				}
				e := add(at, s, event.CatOther, event.SevInfo, "service_started", "", fmt.Sprintf("The %s service was started (%d).", svc, rnd.Intn(99999)))
				e.EventID = 7036
			}
		}
	}

	// The mockups' story.
	at := func(h, m int) time.Time { return start.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }
	sys := byName
	// SSH password guessing on ubu-web01 from 203.0.113.50.
	for k := 0; k < 412; k++ {
		u := "root"
		e := add(at(3, 2).Add(time.Duration(k*1500)*time.Millisecond), sys["ubu-web01"], event.CatFailedLogon, event.SevLow, "logon_failed", "",
			fmt.Sprintf("Failed SSH password for %s from 203.0.113.50 port %d.", u, 50000+k))
		e.Target, e.SourceIP, e.Outcome, e.Source, e.RecordType = u, "203.0.113.50", "failure", "auth", "sshd"
	}
	e := add(at(11, 5), sys["SRV-DC01"], event.CatAccount, event.SevHigh, "group_member_added", "adm-jlee", "adm-jlee added svc-backup to the privileged group Administrators.")
	e.Target, e.EventID = "svc-backup", 4732
	// adm-jlee's Remote Desktop session on SRV-DC02 that cleared the log:
	// the event panel ties the commands to it by its logon ID.
	e = add(at(14, 18).Add(40*time.Second), sys["SRV-DC02"], event.CatLogon, event.SevInfo, "logon", "adm-jlee", "adm-jlee logged on (Remote Desktop) from WS-ADM-01.")
	e.EventID, e.SourceIP, e.Interactive = 4624, "10.20.2.31", true
	e.AddDetail("Logon type", "10 (Remote Desktop)")
	e.AddDetail("Source workstation", "WS-ADM-01")
	e.AddDetail("Logon ID", "0x8a21f3")
	e = add(at(14, 21).Add(50*time.Second), sys["SRV-DC02"], event.CatPrivileged, event.SevLow, "elevated_process", "adm-jlee", `adm-jlee ran with administrator rights: C:\Windows\System32\cmd.exe`)
	e.EventID, e.Process, e.Command = 4688, `C:\Windows\System32\cmd.exe`, "cmd.exe"
	e.Fields = map[string]string{"NewProcessName": `C:\Windows\System32\cmd.exe`, "ParentProcessName": `C:\Windows\explorer.exe`, "SubjectUserName": "adm-jlee", "SubjectLogonId": "0x8a21f3", "TokenElevationType": "%%1937"}
	e = add(at(14, 22).Add(5118*time.Millisecond), sys["SRV-DC02"], event.CatPrivileged, event.SevLow, "elevated_process", "adm-jlee", `adm-jlee ran with administrator rights: C:\Windows\System32\wevtutil.exe`)
	e.EventID, e.Process, e.Command = 4688, `C:\Windows\System32\wevtutil.exe`, "wevtutil cl Security"
	e.Fields = map[string]string{"NewProcessName": `C:\Windows\System32\wevtutil.exe`, "CommandLine": "wevtutil cl Security", "ParentProcessName": `C:\Windows\System32\cmd.exe`, "SubjectUserName": "adm-jlee", "SubjectLogonId": "0x8a21f3", "TokenElevationType": "%%1937"}
	e = add(at(14, 22).Add(5400*time.Millisecond), sys["SRV-DC02"], event.CatIntegrity, event.SevHigh, "log_cleared", "adm-jlee", "The Security log was cleared by adm-jlee.")
	e.EventID = 1102
	e = add(at(14, 31), sys["WS-ENG-04"], event.CatIntegrity, event.SevHigh, "audit_policy_changed", "jdoe", "jdoe changed the audit policy: Logon → No auditing.")
	e.EventID = 4719
	e = add(at(8, 54), sys["WS-LAB-01"], event.CatAccount, event.SevMedium, "account_created", "tlopez", "tlopez created the local account labadmin.")
	e.Target, e.EventID = "labadmin", 4720
	e = add(at(8, 55), sys["WS-LAB-01"], event.CatAccount, event.SevHigh, "group_member_added", "tlopez", "tlopez added labadmin to the privileged group Administrators.")
	e.Target, e.EventID = "labadmin", 4732
	e = add(at(10, 18), sys["SRV-APP01"], event.CatRemovable, event.SevMedium, "usb_connected", "kpatel", "USB storage connected: SanDisk Cruzer Blade (serial 4C530001230615117).")
	e.Target, e.EventID = "SanDisk Cruzer Blade", 6416
	e = add(at(9, 47), sys["WS-ADM-02"], event.CatOther, event.SevHigh, "powershell_suspicious", "jlee",
		"jlee ran a PowerShell script that downloads: Invoke-WebRequest https://github.com/tools/x.ps1 -OutFile x.ps1")
	e.Source, e.EventID, e.Command = powerShellLog, 4104, "Invoke-WebRequest https://github.com/tools/x.ps1 -OutFile x.ps1"
	e = add(at(7, 15), sys["ubu-ws-03"], event.CatIntegrity, event.SevMedium, "time_changed", "root", "root moved the clock back by 8 minutes.")
	e.Process = "/usr/bin/date"
	e.Fields = map[string]string{"PreviousTime": at(7, 15).UTC().Format(time.RFC3339Nano), "NewTime": at(7, 7).UTC().Format(time.RFC3339Nano)}
	e = add(at(13, 2), sys["ubu-db01"], event.CatPrivileged, event.SevMedium, "sudo", "kpatel", "kpatel opened a root shell with sudo: sudo -i")
	e.Command, e.Process = "sudo -i", "/usr/bin/sudo"
	e = add(at(23, 40), sys["SRV-FS01"], event.CatLogon, event.SevInfo, "logon", "jdoe", "jdoe logged on (Remote Desktop) from 10.20.3.44.")
	e.EventID, e.SourceIP, e.Interactive = 4624, "10.20.3.44", true
	e.AddDetail("Privileges", "SeDebugPrivilege, SeBackupPrivilege")
	e = add(at(10, 20), sys["SRV-APP01"], event.CatOther, event.SevMedium, "service_installed", "kpatel", `kpatel installed the service UpdaterSvc (C:\ProgramData\upd\svc.exe).`)
	e.EventID = 4697

	// The previous daily report, so this one continues with no gap.
	var history []Summary
	for d := 6; d >= 1; d-- {
		we := start.AddDate(0, 0, -d+1)
		history = append(history, Summary{WindowStart: we.AddDate(0, 0, -1), WindowEnd: we, Generated: we.Add(2 * time.Minute), Events: 15000 + rnd.Intn(4000),
			Metrics: map[string]int{MPrivileged: 8000 + rnd.Intn(2000), MFailedLogons: 300 + rnd.Intn(200), MSystems: 30}})
	}
	net.Events = evs
	net.Options = Options{Site: "ENG-NET", WindowStart: start, WindowEnd: end, Generated: end.Add(2 * time.Minute), Location: demo30Zone,
		Version: "0.23.0", Source: "Live collection", Collector: true, Period: "daily", Systems: infos, CheckSets: checks, History: history,
		KnownDevices: map[string]time.Time{}, WorkingHours: mustHours("Mon-Fri 07:00-19:00"), Archives: archives, ArchivesKept: true,
		Scap: scans, ScapEnabled: true, ScapMaxAgeDays: 30, InReportsDir: true}
	return net
}

// demo30Affects is what the report misses without each setting.
var demo30Affects = map[string]string{"Logon": "Logon Activity and Failed Logons", "Logoff": "Logon Activity", "Credential Validation": "Failed Logons",
	"User Account Management": "Account & Group Changes", "Security Group Management": "Account & Group Changes", "Audit Policy Change": "Audit & System Integrity",
	"Sensitive Privilege Use": "Privileged Activity", "Process Creation": "Privileged Activity (elevated programs)", "Removable Storage": "USB & Removable Media",
	"PowerShell script block logging": "PowerShell", "Command line in process creation events": "command lines", "Security log": "Events may be overwritten before collection on busy systems",
	"Watch /etc/passwd": "Account & Group Changes", "Watch /etc/shadow": "Account & Group Changes", "Watch /etc/sudoers and /etc/sudoers.d": "sudoers changes",
	"Programs run with raised privileges (execve, uid!=euid)": "Privileged Activity", "Commands run as root by a person (execve, euid=0, auid set)": "Privileged Activity",
	"Filesystem mounts": "USB & Removable Media", "Audit configuration watched (/etc/audit)": "Audit & System Integrity", "auditd running": "every section",
	"Audit log space": "events lost when busy", "Action when the disk is full": "auditing stops silently"}

// demo30Fix is how to fix a setting, worded as the checks word it.
func demo30Fix(it [4]string) string {
	switch it[0] {
	case "Audit policy":
		return "Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Audit " + it[1] + ": Configure the following audit events: " + it[2]
	case "Audit settings", "Event log size":
		return "Computer Configuration > Policies > Administrative Templates > " + it[1] + ": " + it[2]
	case "Audit rules":
		return "blackbox check --audit-rules --missing | install -m 0600 /dev/stdin /etc/audit/rules.d/blackbox.rules, then augenrules --load"
	}
	return "set " + it[1] + " to " + it[2] + " in /etc/audit/auditd.conf, then restart auditd"
}

// demo30Settings are the audit settings checked on each system: area,
// item, required value, STIG ID.
func demo30Settings(osName string) [][4]string {
	if osName == "windows" {
		return [][4]string{{"Audit policy", "Logon", "Success and Failure", "WN11-AU-000070"}, {"Audit policy", "Logoff", "Success", "WN11-AU-000065"},
			{"Audit policy", "Credential Validation", "Success and Failure", "WN11-AU-000005"}, {"Audit policy", "User Account Management", "Success and Failure", "WN11-AU-000035"},
			{"Audit policy", "Security Group Management", "Success", "WN11-AU-000030"}, {"Audit policy", "Audit Policy Change", "Success", "WN11-AU-000100"},
			{"Audit policy", "Sensitive Privilege Use", "Success and Failure", "WN11-AU-000110"}, {"Audit policy", "Process Creation", "Success", "WN11-AU-000050"},
			{"Audit policy", "Removable Storage", "Success and Failure", "WN11-AU-000085"}, {"Audit settings", "PowerShell script block logging", "Enabled (1)", "WN11-CC-000326"},
			{"Audit settings", "Command line in process creation events", "Enabled (1)", "WN11-CC-000066"}, {"Event log size", "Security log", "at least 1024000 KB", "WN11-AU-000505"}}
	}
	return [][4]string{{"Audit rules", "Watch /etc/passwd", "Present", "UBTU-24-900040"}, {"Audit rules", "Watch /etc/shadow", "Present", "UBTU-24-900050"},
		{"Audit rules", "Watch /etc/sudoers and /etc/sudoers.d", "Present", "UBTU-24-900090"}, {"Audit rules", "Programs run with raised privileges (execve, uid!=euid)", "Present", "UBTU-24-900110"},
		{"Audit rules", "Commands run as root by a person (execve, euid=0, auid set)", "Present", "UBTU-24-900120"}, {"Audit rules", "Filesystem mounts", "Present", "UBTU-24-900130"},
		{"Audit rules", "Audit configuration watched (/etc/audit)", "Present", "UBTU-24-900140"}, {"Audit rules", "Kernel modules loaded or removed", "Present", "UBTU-24-900150"},
		{"Audit rules", "Use of chmod and chown", "Present", "UBTU-24-900160"}, {"Audit service", "auditd running", "active", "UBTU-24-900010"},
		{"auditd settings", "Audit log space", "a week", "UBTU-24-900020"}, {"auditd settings", "Action when the disk is full", "SYSLOG or SINGLE", "UBTU-24-900030"}}
}

// builtinAccount is an account the operating system made, not a person's.
func builtinAccount(n string) bool {
	switch n {
	case "Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
		"uucp", "proxy", "www-data", "backup", "list", "irc", "_apt", "nobody", "systemd-network", "systemd-resolve", "messagebus",
		"systemd-timesync", "syslog", "uuidd", "tss", "sshd", "tcpdump", "landscape", "fwupd-refresh", "polkitd":
		return true
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// dedupeNames drops repeated names, topping the list up from pool.
func dedupeNames(names, pool []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range pool {
		if len(out) >= len(names) {
			break
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// TestDemo30 checks the 30-system network's shape, and with
// BLACKBOX_DEMO30_OUT set writes the report there.
func TestDemo30(t *testing.T) {
	began := time.Now()
	r, net := demo30(t)
	if len(net.Systems) != 30 || len(r.SystemRows) != 30 {
		t.Fatalf("%d systems, %d rows", len(net.Systems), len(r.SystemRows))
	}
	servers, win, silent := 0, 0, 0
	for _, s := range r.SystemRows {
		if systemKind(s) == "server" {
			servers++
		}
		if s.OS == "windows" {
			win++
		}
		if s.Status == "silent" {
			silent++
		}
		inv := s.Checks.Inventory
		if inv == nil || len(inv.Accounts) < 50 || len(inv.Accounts) > 100 {
			t.Errorf("%s: accounts %v", s.Name, inv)
			continue
		}
		roots, admins, used := 0, 0, 0
		for _, a := range inv.Accounts {
			if a.Name == "root" {
				roots++
			}
			if a.Name == "Administrator" {
				admins++
			}
			if strings.Contains(a.Kind, "Domain") || strings.Contains(a.Name, `\`) {
				t.Errorf("%s: a domain account %s", s.Name, a.Name)
			}
			if !a.LastLogon.IsZero() {
				used++
			}
		}
		if s.OS == "linux" && (roots != 1 || admins != 0) || s.OS == "windows" && (admins != 1 || roots != 0) {
			t.Errorf("%s: %d root, %d Administrator", s.Name, roots, admins)
		}
		if s.Status != "silent" && (used < 17 || used > 23) {
			t.Errorf("%s: %d accounts used", s.Name, used)
		}
		if len(inv.Drives) == 0 || inv.Drives[0].Serial == "" {
			t.Errorf("%s: no drive serial", s.Name)
		}
	}
	if servers != 11 || win != 15 || silent != 2 {
		t.Errorf("servers %d (want 11), Windows %d (want 15), silent %d (want 2)", servers, win, silent)
	}
	if len(r.Findings) < 6 || len(r.Archives) != 28 || len(r.Events) < 10000 {
		t.Errorf("%d detections, %d archives, %d events", len(r.Findings), len(r.Archives), len(r.Events))
	}
	out := os.Getenv("BLACKBOX_DEMO30_OUT")
	if out == "" {
		out = filepath.Join(t.TempDir(), "rep")
	} else {
		os.RemoveAll(out)
	}
	if err := r.Write(out); err != nil {
		t.Fatal(err)
	}
	if p, err := Verify(out); err != nil || len(p) != 0 {
		t.Errorf("verify: %v %v", p, err)
	}
	t.Logf("30 systems, %d events, %d detections: %v", len(r.Events), len(r.Findings), time.Since(began).Round(time.Millisecond))
}
