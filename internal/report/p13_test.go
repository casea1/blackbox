package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/inventory"
	"github.com/casea1/blackbox/internal/store"
)

// OS1: a Linux system with no STIG of its own (its baseline is
// "Blackbox's advice") shows the OS its inventory reports on Systems,
// Overview and its own page, never the baseline; without an inventory,
// the STIG's OS or "Linux"/"Windows".
func TestOSLabelFromInventory(t *testing.T) {
	end := time.Date(2026, 10, 8, 6, 0, 0, 0, time.UTC)
	advice := check.CiteLinuxSTIG("ID=ubuntu\nVERSION_ID=\"26.04\"\n", []check.Result{{Area: "File System", Item: "x", Status: check.Pass}})
	cs := NewCheckSet("ubuntu-server", end.Add(-time.Hour), advice)
	if !strings.Contains(cs.Baseline, "Blackbox's advice") {
		t.Fatalf("baseline: %q", cs.Baseline)
	}
	cs.Inventory = &inventory.Inventory{OS: "Ubuntu 26.04.1 LTS", Server: true, Manufacturer: "QEMU", Model: "Standard PC"}
	noInv := NewCheckSet("ubu-02", end.Add(-time.Hour), advice)
	win := NewCheckSet("WS-01", end.Add(-time.Hour), []check.Result{{Area: "Baseline", Item: "Compared with", Status: check.Info, Have: "Windows 11 STIG V2R11"}})
	evs := []*event.Event{
		{Time: end.Add(-2 * time.Hour), Host: "ubuntu-server", OS: "linux", Category: event.CatLogon, Severity: event.SevHigh, Action: "logon", Summary: "x"},
		{Time: end.Add(-2 * time.Hour), Host: "ubu-02", OS: "linux", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
		{Time: end.Add(-2 * time.Hour), Host: "WS-01", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
	}
	var runs []*store.Run
	var infos []SystemInfo
	for _, h := range []string{"ubuntu-server", "ubu-02", "WS-01"} {
		o := "linux"
		if h == "WS-01" {
			o = "windows"
		}
		runs = append(runs, &store.Run{Time: end.Add(-time.Hour), Host: h, OS: o})
		infos = append(infos, SystemInfo{Name: h, OS: o, LastRun: end.Add(-time.Hour)})
	}
	r := Build(evs, runs, Options{WindowStart: end.Add(-24 * time.Hour), WindowEnd: end, Generated: end, Location: time.UTC,
		Systems: infos, CheckSets: []CheckSet{cs, noInv, win}})
	want := map[string][2]string{ // osLabel, listOS
		"ubuntu-server": {"Ubuntu 26.04.1 LTS", "Ubuntu 26.04"},
		"ubu-02":        {"Linux", "Linux"},
		"WS-01":         {"Windows 11", "Windows 11"},
	}
	for _, s := range r.SystemRows {
		if got := [2]string{osLabel(s), listOS(s)}; got != want[s.Name] {
			t.Errorf("%s: %q, want %q", s.Name, got, want[s.Name])
		}
	}
	sp := r.systemsPage()
	for _, g := range sp.Groups {
		for _, v := range g.Systems {
			if v.Name == "ubuntu-server" && (v.OS != "Ubuntu 26.04" || !strings.HasPrefix(v.Line, "Ubuntu 26.04.1 LTS · ")) {
				t.Errorf("Systems: %q %q", v.OS, v.Line)
			}
		}
	}
	var html strings.Builder
	if err := r.WriteHTML(&html, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html.String(), "Blackbox&#39;s advice · ") || strings.Contains(html.String(), "Blackbox's advice · ") {
		t.Error("the report still names the baseline as an OS")
	}
	if !strings.Contains(html.String(), "Ubuntu 26.04.1 LTS · ") {
		t.Error("the report lacks the inventory's OS")
	}
	for in, out := range map[string]string{
		"Microsoft Windows 11 Enterprise 10.0.26100":        "Windows 11 Enterprise",
		"Microsoft Windows Server 2025 Standard 10.0.26100": "Windows Server 2025 Standard",
		"AlmaLinux 8.10 (Cerulean Leopard)":                 "AlmaLinux 8.10",
		"Ubuntu 26.04.1 LTS":                                "Ubuntu 26.04.1 LTS",
		"Debian GNU/Linux 12.5.0":                           "Debian GNU/Linux 12.5.0",
	} {
		if got := cleanInvOS(in); got != out {
			t.Errorf("cleanInvOS(%q) = %q, want %q", in, got, out)
		}
	}
}

// PPL1: an account written HOST\name, where HOST is one of the report's
// computers (by short name or FQDN, any case), is a local account; only a
// real domain makes a domain account.
func TestLocalAccountNotDomain(t *testing.T) {
	end := time.Date(2026, 10, 8, 6, 0, 0, 0, time.UTC)
	logon := func(host, user string, ago time.Duration) *event.Event {
		return &event.Event{Time: end.Add(-ago), Host: host, OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon",
			User: user, Summary: user + " signed in"}
	}
	evs := []*event.Event{
		logon("WIN11-TEST", `win11-test\claude`, 3*time.Hour),
		logon("WIN-498EC8UMUEL", `WIN-498EC8UMUEL\claude`, 2*time.Hour),
		logon("ubuntu-server", `ubuntu-server.lab.local\claude`, time.Hour),
		logon("WIN11-TEST", `CORP\jdoe`, time.Hour),
	}
	var infos []SystemInfo
	var runs []*store.Run
	for _, h := range []string{"WIN11-TEST", "WIN-498EC8UMUEL", "ubuntu-server"} {
		infos = append(infos, SystemInfo{Name: h, OS: "windows", LastRun: end.Add(-time.Hour)})
		runs = append(runs, &store.Run{Time: end.Add(-time.Hour), Host: h, OS: "windows"})
	}
	r := Build(evs, runs, Options{WindowStart: end.Add(-24 * time.Hour), WindowEnd: end, Generated: end, Location: time.UTC, Systems: infos})
	pp := r.peoplePage()
	claude, jdoe := pp.people[r.pkey("claude")], pp.people[r.pkey("jdoe")]
	if claude == nil || jdoe == nil {
		t.Fatalf("people: %v", pp.people)
	}
	if strings.Contains(claude.Line, "Domain account") || !strings.HasPrefix(claude.Line, "Local account on 3 systems") {
		t.Errorf("claude: %q", claude.Line)
	}
	if !strings.HasPrefix(jdoe.Line, `Domain account CORP\jdoe`) {
		t.Errorf("jdoe: %q", jdoe.Line)
	}
}

// UI22: a sender whose first batch arrived this period, with no
// collection run on record yet, has a green Reporting square saying so,
// not a grey "no data" one; and Overview's summary shortens key
// fingerprints.
func TestFirstDeliveryReportsAndShortFP(t *testing.T) {
	end := time.Date(2026, 10, 8, 6, 0, 0, 0, time.UTC)
	got := end.Add(-12 * time.Minute)
	infos := []SystemInfo{
		{Name: "WIN-498EC8UMUEL", OS: "windows", FirstSeen: got, LastRun: got, LastReceived: got, Delivery: &Delivery{Signed: true, KeyFP: "SHA256:LuoiZpT863cm6vjzUZ89qoi4KDxOEIxa8Eykg/yfzNw", Since: got, New: true}},
		{Name: "WS-02", OS: "windows"},
	}
	// Its first batch carried a collection run from before this period.
	runs := []*store.Run{{Time: end.Add(-7 * time.Hour), Host: "WIN-498EC8UMUEL", OS: "windows"}}
	r := Build(nil, runs, Options{WindowStart: end.Add(-6 * time.Hour), WindowEnd: end, Generated: end, Location: time.UTC, Collector: true, Systems: infos})
	cells := map[string]CheckCell{}
	for _, g := range r.systemsPage().Groups {
		for _, v := range g.Systems {
			cells[v.Name] = v.Cells[0].CheckCell
		}
	}
	if c := cells["WIN-498EC8UMUEL"]; c.Label != "Reporting" || c.Level != "ok" || c.Title != "first delivery received 05:48" {
		t.Errorf("first sender: %+v", c)
	}
	if c := cells["WS-02"]; c.Level == "ok" {
		t.Errorf("a system with nothing delivered: %+v", c)
	}
	in := "ubuntu-server is now signing with a different key (SHA256:LuoiZpT863cm6vjzUZ89qoi4KDxOEIxa8Eykg/yfzNw, was SHA256:pyYPjcGf4XJKTB53Yhj/G7ExNjbqPCqASFLwhT28umo)."
	if out := shortFPs(in); out != "ubuntu-server is now signing with a different key (SHA256:LuoiZpT8…, was SHA256:pyYPjcGf…)." {
		t.Errorf("shortFPs: %s", out)
	}
}

// The field test's network in small (0.24.0 pre-production): WIN11-TEST,
// a Server 2025 sender that has just delivered for the first time, and an
// Ubuntu 26.04 server with no STIG of its own; claude is a local account
// on all three, and ubuntu-server has changed its key. OS1, PPL1 and UI22
// together, end to end. BLACKBOX_P13_OUT=<dir> writes the report there.
func TestP13Sample(t *testing.T) {
	end := time.Date(2026, 10, 8, 5, 48, 0, 0, time.UTC)
	start := end.Add(-6 * time.Hour)
	got := end.Add(-2 * time.Minute)
	oldFP, newFP := "SHA256:pyYPjcGf4XJKTB53Yhj/G7ExNjbqPCqASFLwhT28umo", "SHA256:LuoiZpT863cm6vjzUZ89qoi4KDxOEIxa8Eykg/yfzNw"
	advice := check.CiteLinuxSTIG("ID=ubuntu\nVERSION_ID=\"26.04\"\n", []check.Result{{Area: "File System", Item: "/var/log/audit on its own partition", Status: check.Fail, Want: "Its own partition", Have: "On /"}})
	ubu := NewCheckSet("ubuntu-server", end.Add(-time.Hour), advice)
	ubu.Inventory = &inventory.Inventory{OS: "Ubuntu 26.04.1 LTS", Server: true, Manufacturer: "QEMU", Model: "Standard PC (Q35 + ICH9, 2009)",
		Accounts: []inventory.Account{{Name: "claude", ID: "uid 1000", Enabled: true, Admin: true, Kind: "Local"}}}
	w11 := NewCheckSet("WIN11-TEST", end.Add(-time.Hour), []check.Result{{Area: "Baseline", Item: "Compared with", Status: check.Info, Have: "Windows 11 STIG V2R11"}})
	w11.Inventory = &inventory.Inventory{OS: "Microsoft Windows 11 Pro 10.0.26200", Manufacturer: "QEMU",
		Accounts: []inventory.Account{{Name: "claude", ID: "…1001", Enabled: true, Admin: true, Kind: "Local"}}}
	srv := NewCheckSet("WIN-498EC8UMUEL", got, []check.Result{{Area: "Baseline", Item: "Compared with", Status: check.Info, Have: "Windows Server 2025 STIG V1R1"}})
	srv.Inventory = &inventory.Inventory{OS: "Microsoft Windows Server 2025 Standard Evaluation 10.0.26100", Manufacturer: "QEMU",
		Accounts: []inventory.Account{{Name: "claude", ID: "…500", Enabled: true, Admin: true, Kind: "Local"}}}
	logon := func(host, o, user string, at time.Time) *event.Event {
		return &event.Event{Time: at, Host: host, OS: o, Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", User: user, Summary: user + " signed in"}
	}
	evs := []*event.Event{
		logon("WIN11-TEST", "windows", `WIN11-TEST\claude`, start.Add(time.Hour)),
		logon("WIN-498EC8UMUEL", "windows", `WIN-498EC8UMUEL\claude`, got.Add(-time.Hour)),
		logon("ubuntu-server", "linux", `ubuntu-server\claude`, start.Add(2*time.Hour)),
		{Time: end.Add(-9 * time.Minute), Host: "ubuntu-server", Source: "Blackbox", RecordType: "Blackbox", Category: event.CatIntegrity, Severity: event.SevHigh,
			Action: "blackbox_inbox_conflict", Summary: "ubuntu-server is now signing with a different key (" + newFP + ", was " + oldFP + "). Its deliveries are not imported; they wait in the inbox's rejected\\held folder. If that computer was reinstalled: blackbox senders rekey ubuntu-server",
			Fields: map[string]string{"blackbox_inbox": "conflict"}},
	}
	var runs []*store.Run
	for h := start.Add(time.Hour); !h.After(end); h = h.Add(time.Hour) {
		runs = append(runs, &store.Run{Time: h.Add(-time.Minute), Host: "WIN11-TEST", OS: "windows"}, &store.Run{Time: h.Add(-2 * time.Minute), Host: "ubuntu-server", OS: "linux"})
	}
	runs = append(runs, &store.Run{Time: start.Add(-time.Hour), Host: "WIN-498EC8UMUEL", OS: "windows"}) // its first batch, from before this period
	infos := []SystemInfo{
		{Name: "WIN11-TEST", OS: "windows", FirstSeen: start.AddDate(0, 0, -20), LastRun: end.Add(-time.Minute), LastReceived: end.Add(-time.Minute),
			Delivery: &Delivery{Signed: true, KeyFP: "SHA256:9fQ2xK7vLm3pR8sT1uW4yZ6bC0dE5gH2jN7kP9qS3tU", Since: start.AddDate(0, 0, -1)}},
		{Name: "WIN-498EC8UMUEL", OS: "windows", FirstSeen: got, LastRun: got, LastReceived: got, Delivery: &Delivery{Signed: true, KeyFP: "SHA256:Hk3mQ9rT2vX5zA8cE1gJ4nP7sU0wY3bD6fH9kM2pR5t", Since: got, New: true}},
		{Name: "ubuntu-server", OS: "linux", FirstSeen: start.AddDate(0, 0, -20), LastRun: end.Add(-2 * time.Minute), LastReceived: end.Add(-2 * time.Minute),
			Delivery: &Delivery{Signed: true, KeyFP: oldFP, Since: start.AddDate(0, 0, -1), NewKeyFP: newFP}},
	}
	r := Build(evs, runs, Options{WindowStart: start, WindowEnd: end, Generated: end, Location: time.UTC, Collector: true, Period: "daily",
		Source: "Live collection", Systems: infos, CheckSets: []CheckSet{w11, srv, ubu}})

	ov := r.overview(nil)
	if !strings.Contains(ov.ReviewDetail, "SHA256:LuoiZpT8…") || strings.Contains(ov.ReviewDetail, newFP) || strings.Contains(ov.ReviewDetail, oldFP) {
		t.Errorf("Overview summary: %s", ov.ReviewDetail)
	}
	for _, g := range r.systemsPage().Groups {
		for _, v := range g.Systems {
			switch v.Name {
			case "ubuntu-server":
				if v.OS != "Ubuntu 26.04" || !strings.HasPrefix(v.Line, "Ubuntu 26.04.1 LTS · server") {
					t.Errorf("ubuntu-server: %q %q", v.OS, v.Line)
				}
			case "WIN-498EC8UMUEL":
				if c := v.Cells[0]; c.Level != "ok" || !strings.HasPrefix(c.Title, "first delivery received") {
					t.Errorf("first sender's Reporting: %+v", c.CheckCell)
				}
			}
		}
	}
	if c := r.peoplePage().people[r.pkey("claude")]; c == nil || !strings.HasPrefix(c.Line, "Local account on 3 systems") {
		t.Errorf("claude: %+v", c)
	}
	out := os.Getenv("BLACKBOX_P13_OUT")
	if out == "" {
		out = filepath.Join(t.TempDir(), "rep")
	} else {
		os.RemoveAll(out)
	}
	if err := r.Write(out); err != nil {
		t.Fatal(err)
	}
}
