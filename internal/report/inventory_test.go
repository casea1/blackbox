package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/inventory"
	"github.com/casea1/blackbox/internal/store"
)

// The Inventory page: each system's make, model and serial number, its
// drives and accounts (administrators first, SID's last four digits), the
// systems with no inventory yet, and the CSV.
func TestInventoryPage(t *testing.T) {
	end := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	evs := []*event.Event{
		{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
		{Time: end.Add(-time.Hour), Host: "ubu-01", OS: "linux", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
	}
	inv := &inventory.Inventory{Manufacturer: "Dell Inc.", Model: "OptiPlex 7090", Serial: "7XK2PQ3", OS: "Microsoft Windows 11 Enterprise 10.0.26100",
		CPU: "Intel i7-11700", Memory: 16 << 30, Domain: "corp.example.mil",
		Drives: []inventory.Drive{{Model: "Samsung SSD 980 PRO 1TB", Serial: "S5GXNX0T123456A", Size: 1000202273280, Interface: "SCSI", Media: "SSD"}},
		Accounts: []inventory.Account{
			{Name: `CORP\jsmith`, ID: "…3105", Enabled: true, Kind: "Domain (profile)", LastLogon: end.Add(-2 * time.Hour)},
			{Name: "Administrator", ID: "…500", Enabled: false, Admin: true, Kind: "Local"},
			{Name: "localadmin", ID: "…1001", Enabled: true, Admin: true, Kind: "Local"},
		}}
	cs := NewCheckSet("WS-07", end.Add(-3*time.Hour), nil)
	cs.Inventory = inv
	r := Build(evs, nil, Options{WindowEnd: end, Location: time.UTC, CheckSets: []CheckSet{cs}})
	ip := r.inventoryPage()
	if len(ip.Rows) != 1 || len(ip.Missing) != 1 || ip.Missing[0].Host != "ubu-01" || ip.Stats[0].Value != "1 / 2" {
		t.Fatalf("page: %+v", ip)
	}
	row := ip.Rows[0]
	if row.Make != "Dell Inc. OptiPlex 7090" || row.Memory != "16.0 GB" || row.Admins != 2 || row.Drives[0].Size != "1.0 TB" ||
		row.Accounts[0].Name != "localadmin" || row.Accounts[1].Name != "Administrator" || row.Accounts[1].Status != "Disabled" || row.Accounts[2].Key != "jsmith" {
		t.Errorf("row: %+v", row)
	}
	csv := r.inventoryCSV(ip)
	for _, want := range []string{
		"WS-07,system,Dell Inc. OptiPlex 7090,7XK2PQ3,16.0 GB,Microsoft Windows 11 Enterprise 10.0.26100; Intel i7-11700; corp.example.mil,5 Oct 2026 09:00",
		"WS-07,drive,Samsung SSD 980 PRO 1TB,S5GXNX0T123456A,1.0 TB,SCSI SSD,",
		"WS-07,account,localadmin,…1001,,Local; Enabled; administrator,",
		`WS-07,account,CORP\jsmith,…3105,,Domain (profile); Enabled; last logon 5 Oct 2026 10:00,`,
	} {
		if !strings.Contains(csv, want) {
			t.Errorf("csv lacks %q:\n%s", want, csv)
		}
	}
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, want := range []string{`data-view="inventory"`, `href="#inventory"`, "Samsung SSD 980 PRO 1TB", "S5GXNX0T123456A", "Accounts on WS-07", "<b>ubu-01</b>: it has sent no settings check yet", `data-act="invcsv"`, `href="#search?user=jsmith"`} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

// "No inventory yet" gives the real reason for each system (UI2): it sent
// nothing since a time, it runs a version from before inventory, or it has
// sent no settings check.
func TestInventoryMissingWhy(t *testing.T) {
	end := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	runs := []*store.Run{{Time: end.Add(-time.Hour), Host: "old", OS: "linux"}, {Time: end.Add(-time.Hour), Host: "nocheck", OS: "linux"},
		{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows"}}
	r := Build(nil, runs, Options{WindowStart: end.AddDate(0, 0, -1), WindowEnd: end, Location: time.UTC, Source: "Live collection", Collector: true,
		Systems: []SystemInfo{{Name: "ubuntu-server", OS: "linux", LastRun: time.Date(2026, 10, 3, 6, 31, 0, 0, time.UTC)},
			{Name: "old", OS: "linux", Version: "0.12.1"}, {Name: "nocheck", OS: "linux", Version: "0.15.0"},
			{Name: "WS-07", OS: "windows", Version: "0.15.0"}},
		CheckSets: []CheckSet{NewCheckSet("WS-07", end.Add(-2*time.Hour), nil)}})
	why := map[string]string{}
	for _, m := range r.inventoryPage().Missing {
		why[m.Host] = m.Why
	}
	for host, want := range map[string]string{
		"ubuntu-server": "it has sent nothing since 3 Oct 06:31",
		"old":           "it runs Blackbox 0.12.1; inventory is sent from version 0.13 on",
		"nocheck":       "it has sent no settings check yet; inventory is read with the daily settings check",
		"WS-07":         "its last settings check (5 Oct 10:00) had no inventory",
	} {
		if why[host] != want {
			t.Errorf("%s: %q, want %q", host, why[host], want)
		}
	}
	if !versionBefore("v0.12", 0, 13) || versionBefore("0.13.0", 0, 13) || versionBefore("1.0", 0, 13) || versionBefore("dev", 0, 13) {
		t.Error("versionBefore")
	}
}

// UI15: the Inventory page has Systems, Drives and Accounts tabs; each
// system's drives and accounts open under its own row (no panel whose
// accounts change); the tiles open their tab.
func TestInventoryTabs(t *testing.T) {
	end := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	mk := func(host, serial string, admin bool) CheckSet {
		cs := NewCheckSet(host, end.Add(-time.Hour), nil)
		cs.Inventory = &inventory.Inventory{Manufacturer: "Dell Inc.", Model: "OptiPlex 7090", Serial: serial,
			Drives:   []inventory.Drive{{Model: "Samsung SSD", Serial: "SN-" + host, Size: 512110190592}},
			Accounts: []inventory.Account{{Name: "localadmin", ID: "…1001", Enabled: true, Admin: admin, Kind: "Local"}, {Name: "guest", ID: "…501", Kind: "Local"}}}
		return cs
	}
	r := Build(nil, nil, Options{WindowEnd: end, Location: time.UTC, CheckSets: []CheckSet{mk("WS-01", "AAA", true), mk("WS-02", "BBB", false)}})
	ip := r.inventoryPage()
	if ip.DriveN != 2 || ip.AccountN != 4 {
		t.Errorf("counts: %d drives, %d accounts", ip.DriveN, ip.AccountN)
	}
	var b bytes.Buffer
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	for _, want := range []string{`data-invtab="systems"`, `data-invtab="drives"`, `data-invtab="accounts"`, `data-invsys="WS-01"`, `data-invtoggle`,
		`class="invdetail" hidden`, "Drives on WS-01", "Accounts on WS-02", `data-invacct="admin"`, `data-invitem data-admin data-enabled`,
		`data-scroll="inv-tab-drives"`, `data-scroll="inv-tab-admin"`, `href="#inventory/WS-02"`, "SN-WS-02"} {
		if !strings.Contains(h, want) {
			t.Errorf("Inventory lacks %q", want)
		}
	}
	if strings.Contains(h, `data-pane="WS-01"`) {
		t.Error("the old one-system-at-a-time panel is still there")
	}
}
