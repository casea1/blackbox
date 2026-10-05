package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"sort"
	"strings"
)

// The Inventory page (ISSO request): each system's make, model and serial
// number, its drives and their serial numbers, and its user accounts with
// the last four digits of their SIDs. Read with each system's daily
// settings check; Blackbox changes nothing.

// InventoryPage is the Inventory page.
type InventoryPage struct {
	Stats   []EventCard
	Rows    []*InvRow
	Missing []string // systems in the report with no inventory yet
}

// InvRow is one system's inventory.
type InvRow struct {
	Host, OS, Make, Serial, CPU, Memory, BIOS, Domain, Checked string
	Drives                                                     []InvDrive
	Accounts                                                   []InvAccount
	Admins                                                     int
	Notes                                                      []string
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
			CPU: inv.CPU, BIOS: inv.BIOS, Domain: inv.Domain, Checked: cs.Time.In(r.Location).Format("2 Jan 2006 15:04"), Notes: inv.Notes}
		if inv.Memory > 0 {
			row.Memory = humanBytes(inv.Memory)
		}
		for _, d := range inv.Drives {
			row.Drives = append(row.Drives, InvDrive{Model: d.Model, Serial: d.Serial, Size: driveSize(d.Size), Interface: d.Interface, Media: d.Media})
		}
		for _, a := range inv.Accounts {
			ia := InvAccount{Name: a.Name, Key: personKey(a.Name), ID: a.ID, Kind: a.Kind, Admin: a.Admin, Disabled: !a.Enabled, Status: "Enabled"}
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
	for _, h := range r.Hosts {
		if !have[strings.ToLower(h)] {
			ip.Missing = append(ip.Missing, h)
		}
	}
	lvl := ""
	if len(ip.Missing) > 0 {
		lvl = "warn"
	}
	ip.Stats = []EventCard{
		{Icon: "server", Label: "Systems inventoried", Value: fmt.Sprintf("%d / %d", len(ip.Rows), len(ip.Rows)+len(ip.Missing)), Note: strings.Join(ip.Missing, ", "), Level: lvl, Scroll: "inv-systems"},
		{Icon: "hard-drive", Label: "Drives", Value: commas(drives), Note: "with serial numbers", Scroll: "inv-systems"},
		{Icon: "users", Label: "Accounts", Value: commas(accounts), Note: "local, and domain accounts with a profile", Scroll: "inv-systems"},
		{Icon: "key-round", Label: "Administrators", Value: commas(admins), Note: "accounts with administrator rights", Scroll: "inv-systems"},
	}
	return ip
}

// inventoryCSV is the Export menu's inventory: one line per system, drive
// and account.
func (r *Report) inventoryCSV(ip *InventoryPage) string {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.Write([]string{"system", "item", "name", "serial_or_id", "size", "details", "inventoried"})
	for _, row := range ip.Rows {
		w.Write(csvSafe([]string{row.Host, "system", row.Make, row.Serial, row.Memory, strings.Join(nonEmpty(row.OS, row.CPU, row.BIOS, row.Domain), "; "), row.Checked}))
		for _, d := range row.Drives {
			w.Write(csvSafe([]string{row.Host, "drive", d.Model, d.Serial, d.Size, strings.Join(nonEmpty(d.Interface, d.Media), " "), row.Checked}))
		}
		for _, a := range row.Accounts {
			det := []string{a.Kind, a.Status}
			if a.Admin {
				det = append(det, "administrator")
			}
			if a.LastLogon != "" {
				det = append(det, "last logon "+a.LastLogon)
			}
			w.Write(csvSafe([]string{row.Host, "account", a.Name, a.ID, "", strings.Join(nonEmpty(det...), "; "), row.Checked}))
		}
	}
	w.Flush()
	return b.String()
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
