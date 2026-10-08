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
	if len(ip.Rows) != 2 || ip.Have != 1 || len(ip.Missing) != 1 || ip.Missing[0].Host != "ubu-01" {
		t.Fatalf("page: %+v", ip)
	}
	var row *InvRow
	for _, x := range ip.Rows {
		if x.Host == "WS-07" {
			row = x
		}
	}
	if row.Make != "Dell Inc. OptiPlex 7090" || row.Memory != "16.0 GB" || row.Admins != 2 || row.Drives[0].Size != "1.0 TB" ||
		row.Drives[0].Note != "internal" || row.Drives[0].Type != "SCSI · SSD" ||
		row.Accounts[0].Name != "localadmin" || row.Accounts[1].Name != "Administrator" || row.Accounts[1].Status != "Disabled" || row.Accounts[2].Key != "jsmith" {
		t.Errorf("row: %+v", row)
	}
	csv := r.inventoryCSV(ip)
	for _, want := range []string{
		"system,item,name,type,size,serial_or_id,note,inventoried",
		"WS-07,drive,Samsung SSD 980 PRO 1TB,SCSI · SSD,1.0 TB,S5GXNX0T123456A,internal,2026-10-05 09:00:00 +00:00",
		"WS-07,account,localadmin,Local administrator,,…1001,Enabled,",
		`WS-07,account,CORP\jsmith,Domain (profile) user,,…3105,Enabled; last used 2026-10-05 10:00:00 +00:00,2026-10-05 09:00:00 +00:00`,
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
	for _, want := range []string{`data-view="inventory"`, `href="#inventory"`, "Samsung SSD 980 PRO 1TB", "S5GXNX0T123456A", `data-keys="S5GXNX0T123456A"`,
		"<b>ubu-01</b>: it has sent no settings check yet", `"inventory":{"label":"Drives and accounts"`, `href="#search?user=jsmith"`,
		"No inventory yet: it has sent no settings check yet."} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report lacks %q", want)
		}
	}
	// The accounts are in a data file, recorded in the manifest.
	data, err := os.ReadFile(filepath.Join(dir, "data", "inventory-accounts.js"))
	if err != nil || !strings.HasPrefix(string(data), `BB.put("inventory/accounts",`) {
		t.Errorf("accounts data file: %v", err)
	}
	if man, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256")); !strings.Contains(string(man), "data/inventory-accounts.js") {
		t.Error("the accounts data file is not in the manifest")
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

// UI-R1 (design 11): the systems on the left, found by name or drive
// serial, grouped Servers / Workstations; the one selected on the right
// with its drives (serial numbers; a removable drive seen in the USB
// events, "not connected now" when the settings check after it did not
// find it) and five accounts, the rest in the data file.
func TestInventoryUIR1(t *testing.T) {
	r, _ := demo30(t)
	ip := r.inventoryPage()
	if len(ip.Groups) != 2 || ip.Groups[0].Label != "Servers · 11" || ip.Groups[1].Label != "Workstations · 19" || ip.Have != 30 {
		t.Fatalf("groups: %+v", ip.Groups)
	}
	by := map[string]*InvRow{}
	for _, row := range ip.Rows {
		by[row.Host] = row
	}
	app := by["SRV-APP01"]
	var usb *InvDrive
	for i, d := range app.Drives {
		if d.Serial == "4C530001230615117" {
			usb = &app.Drives[i]
		}
	}
	if usb == nil || usb.Type != "USB · removable" || usb.Note != "seen 7 Oct 10:18 · not connected now" || app.DrivesNote != "2 internal · 1 removable seen" ||
		!strings.Contains(app.Keys, "4C530001230615117") {
		t.Errorf("SRV-APP01 drives: %+v", app.Drives)
	}
	adm := by["WS-ADM-01"]
	if d := adm.Drives[len(adm.Drives)-1]; d.Type != "USB · removable" || d.Note != "connected at the settings check" {
		t.Errorf("WS-ADM-01 USB stick: %+v", d)
	}
	if len(app.Shown) != 5 || app.More != len(app.Accounts)-5 || app.Used < 10 || !app.Shown[0].Admin {
		t.Errorf("accounts: %d shown, %d more, %d used", len(app.Shown), app.More, app.Used)
	}
	var b bytes.Buffer
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	for _, want := range []string{`placeholder="Find a system or serial"`, `data-pick="SRV-DC02"`, `data-pane="SRV-DC02"`, "4C530001230615117",
		"seen 7 Oct 10:18 · not connected now", `data-invall="SRV-APP01"`, "Show all"} {
		if !strings.Contains(h, want) {
			t.Errorf("Inventory lacks %q", want)
		}
	}
	// Five accounts per system in the page, not 2,000 of them.
	inv := h[strings.Index(h, `data-view="inventory"`):]
	inv = inv[:strings.Index(inv, "</section>")]
	if n := strings.Count(inv, `href="#search?user=`); n != 5*30 {
		t.Errorf("%d accounts in the page", n)
	}
	// The CSV: one row per drive and one per account.
	csv := r.inventoryCSV(ip)
	if n := strings.Count(csv, ",drive,"); n != ip.DriveN {
		t.Errorf("%d drive rows, %d drives", n, ip.DriveN)
	}
	if n := strings.Count(csv, ",account,"); n != ip.AccountN {
		t.Errorf("%d account rows, %d accounts", n, ip.AccountN)
	}
	if !strings.Contains(csv, "SRV-APP01,drive,SanDisk Cruzer Blade,USB · removable,—,4C530001230615117,seen 7 Oct 10:18 · not connected now,") {
		t.Error("the CSV lacks the removable drive")
	}
}
