package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/inventory"
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
	if len(ip.Rows) != 1 || len(ip.Missing) != 1 || ip.Missing[0] != "ubu-01" || ip.Stats[0].Value != "1 / 2" {
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
	for _, want := range []string{`data-view="inventory"`, `href="#inventory"`, "Drives on WS-07", "S5GXNX0T123456A", "No inventory yet from: ubu-01", `data-act="invcsv"`, `href="#search?user=jsmith"`} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report lacks %q", want)
		}
	}
}
