package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The Inventory page (ISSO request): each system's make, model and serial
// number, its drives and their serial numbers, and its user accounts with
// the last four digits of their SIDs. Read with each system's daily
// settings check; Blackbox changes nothing.

// InventoryPage is the Inventory page.
type InventoryPage struct {
	Stats   []EventCard
	Rows    []*InvRow
	Missing []InvMissing // systems in the report with no inventory yet
	// DriveN and AccountN count the Drives and Accounts tabs.
	DriveN, AccountN int
}

// InvMissing is a system with no inventory, and why (UI2).
type InvMissing struct {
	Host, Why string
}

// InvRow is one system's inventory.
type InvRow struct {
	Host, OS, Make, Serial, CPU, Memory, BIOS, Domain, Checked string
	Drives                                                     []InvDrive
	Accounts                                                   []InvAccount
	Admins                                                     int
	Notes                                                      []string
	checked                                                    time.Time
}

// InvDrive is one drive on the Inventory page.
type InvDrive struct {
	Model, Serial, Size, Interface, Media string
}

// InvAccount is one account on the Inventory page.
type InvAccount struct {
	Name, ID, Kind, Status, LastLogon string
	Key                               string // personKey, for Search
	Admin, Disabled                   bool
	lastLogon                         time.Time
}

func (r *Report) inventoryPage() *InventoryPage {
	ip := &InventoryPage{}
	have := map[string]bool{}
	drives, accounts, admins := 0, 0, 0
	for _, cs := range r.CheckSets {
		inv := cs.Inventory
		if inv == nil {
			continue
		}
		have[strings.ToLower(cs.Host)] = true
		row := &InvRow{Host: cs.Host, OS: inv.OS, Make: strings.TrimSpace(inv.Manufacturer + " " + inv.Model), Serial: inv.Serial,
			CPU: inv.CPU, BIOS: inv.BIOS, Domain: inv.Domain, Checked: cs.Time.In(r.Location).Format("2 Jan 2006 15:04"), Notes: inv.Notes, checked: cs.Time}
		if inv.Memory > 0 {
			row.Memory = humanBytes(inv.Memory)
		}
		for _, d := range inv.Drives {
			row.Drives = append(row.Drives, InvDrive{Model: d.Model, Serial: d.Serial, Size: driveSize(d.Size), Interface: d.Interface, Media: d.Media})
		}
		for _, a := range inv.Accounts {
			ia := InvAccount{Name: a.Name, Key: personKey(a.Name), ID: a.ID, Kind: a.Kind, Admin: a.Admin, Disabled: !a.Enabled, Status: "Enabled", lastLogon: a.LastLogon}
			if !a.Enabled {
				ia.Status = "Disabled"
			}
			if a.Note != "" {
				ia.Status += " · " + a.Note
			}
			if !a.LastLogon.IsZero() {
				ia.LastLogon = a.LastLogon.In(r.Location).Format("2 Jan 2006 15:04")
			}
			if a.Admin {
				row.Admins++
			}
			row.Accounts = append(row.Accounts, ia)
		}
		sort.SliceStable(row.Accounts, func(i, j int) bool {
			a, b := row.Accounts[i], row.Accounts[j]
			if a.Admin != b.Admin {
				return a.Admin
			}
			if a.Disabled != b.Disabled {
				return !a.Disabled
			}
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		})
		drives += len(row.Drives)
		accounts += len(row.Accounts)
		admins += row.Admins
		ip.Rows = append(ip.Rows, row)
	}
	sort.SliceStable(ip.Rows, func(i, j int) bool { return naturalLess(ip.Rows[i].Host, ip.Rows[j].Host) })
	var missing []string
	for _, h := range r.Hosts {
		if !have[strings.ToLower(h)] {
			missing = append(missing, h)
			ip.Missing = append(ip.Missing, InvMissing{Host: h, Why: r.noInventoryWhy(h)})
		}
	}
	lvl := ""
	if len(ip.Missing) > 0 {
		lvl = "warn"
	}
	ip.DriveN, ip.AccountN = drives, accounts
	ip.Stats = []EventCard{
		{Icon: "server", Label: "Systems inventoried", Value: fmt.Sprintf("%d / %d", len(ip.Rows), len(ip.Rows)+len(ip.Missing)), Note: missingNote(missing), Level: lvl, Scroll: "inv-tab-systems"},
		{Icon: "hard-drive", Label: "Drives", Value: commas(drives), Note: "with serials", Scroll: "inv-tab-drives"},
		{Icon: "users", Label: "Accounts", Value: commas(accounts), Note: "local and domain", Scroll: "inv-tab-accounts"},
		{Icon: "key-round", Label: "Administrators", Value: commas(admins), Note: "admin rights", Scroll: "inv-tab-admin"},
	}
	return ip
}

// inventoryCSV is the Export menu's inventory: one line per system, drive
// and account.
func (r *Report) inventoryCSV(ip *InventoryPage) string { return csvText(r.inventoryRows(ip)) }

// inventoryRows are the Inventory page's CSV: each system, its drives and
// its accounts; times with their zone (ASSESS1).
func (r *Report) inventoryRows(ip *InventoryPage) [][]string {
	rows := [][]string{{"system", "item", "name", "serial_or_id", "size", "details", "inventoried"}}
	for _, row := range ip.Rows {
		at := r.csvTime(row.checked)
		rows = append(rows, []string{row.Host, "system", row.Make, row.Serial, row.Memory, strings.Join(nonEmpty(row.OS, row.CPU, row.BIOS, row.Domain), "; "), at})
		for _, d := range row.Drives {
			rows = append(rows, []string{row.Host, "drive", d.Model, d.Serial, d.Size, strings.Join(nonEmpty(d.Interface, d.Media), " "), at})
		}
		for _, a := range row.Accounts {
			det := []string{a.Kind, a.Status}
			if a.Admin {
				det = append(det, "administrator")
			}
			if !a.lastLogon.IsZero() {
				det = append(det, "last logon "+r.csvTime(a.lastLogon))
			}
			rows = append(rows, []string{row.Host, "account", a.Name, a.ID, "", strings.Join(nonEmpty(det...), "; "), at})
		}
	}
	return rows
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			out = append(out, x)
		}
	}
	return out
}

// driveSize is a drive's size as its maker labels it (decimal: a 1 TB
// drive is "1.0 TB", not "931.5 GB").
func driveSize(b uint64) string {
	switch {
	case b == 0:
		return "—"
	case b >= 1e12:
		return fmt.Sprintf("%.1f TB", float64(b)/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.0f GB", float64(b)/1e9)
	}
	return fmt.Sprintf("%.0f MB", float64(b)/1e6)
}

// noInventoryWhy says why a system has no inventory: it sent nothing, it
// runs a Blackbox from before inventory, or it has sent no settings check.
func (r *Report) noInventoryWhy(host string) string {
	var row *SystemRow
	for i := range r.SystemRows {
		if strings.EqualFold(r.SystemRows[i].Name, host) {
			row = &r.SystemRows[i]
		}
	}
	switch {
	case row == nil:
		return "it has sent no settings check yet"
	case row.Runs == 0 && row.LastRun.IsZero():
		return "it has sent nothing yet"
	case row.Runs == 0:
		return "it has sent nothing since " + r.since(row.LastRun)
	case row.Version != "" && versionBefore(row.Version, 0, 13):
		return "it runs Blackbox " + row.Version + "; inventory is sent from version 0.13 on"
	case row.Checks == nil:
		return "it has sent no settings check yet; inventory is read with the daily settings check"
	}
	return "its last settings check (" + r.since(row.Checks.Time) + ") had no inventory"
}

// versionBefore reports whether v ("0.12.1", "v0.12") is older than
// major.minor. A version it can't read is not older.
func versionBefore(v string, major, minor int) bool {
	var a, b int
	if n, _ := fmt.Sscanf(strings.TrimPrefix(v, "v"), "%d.%d", &a, &b); n < 2 {
		return false
	}
	return a < major || a == major && b < minor
}

func missingNote(missing []string) string {
	if len(missing) == 0 {
		return ""
	}
	return "none yet: " + short(set(missing), 2)
}
