package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The Inventory page (UI-R1, design 11): the systems on the left, grouped
// Servers / Workstations, found by name or by a drive's serial number; the
// one selected on the right: what it is, its serial, memory and accounts,
// its drives with their serial numbers (removable drives seen in the USB
// events too), and its accounts, five shown and the rest on request (from
// a data file, so a network of thousands of accounts keeps a light page).
// Read with each system's daily settings check; Blackbox changes nothing.

// invShown is how many accounts a system shows before "Show all".
const invShown = 5

// InventoryPage is the Inventory page.
type InventoryPage struct {
	Groups  []InvGroup
	Rows    []*InvRow    // every system, inventoried or not
	Missing []InvMissing // systems in the report with no inventory yet
	// Have counts the systems inventoried; DriveN, AccountN and AdminN
	// their drives, accounts and administrators.
	Have, DriveN, AccountN, AdminN int
	Crumb                          string
}

// InvGroup is one group of the Inventory list: "Servers · 11".
type InvGroup struct {
	Title, Label string
	Rows         []*InvRow
}

// InvMissing is a system with no inventory, and why (UI2).
type InvMissing struct {
	Host, Why string
}

// InvRow is one system's inventory.
type InvRow struct {
	Host, OS, Make, Serial, CPU, Memory, BIOS, Domain, Checked string
	Kind, ListOS, Line                                         string
	Why                                                        string // no inventory, and why
	Drives                                                     []InvDrive
	DrivesNote                                                 string // "2 internal · 1 removable seen"
	Accounts                                                   []InvAccount
	Shown                                                      []InvAccount // the first few
	More                                                       int          // the rest, read on request
	Admins, Used                                               int
	Keys                                                       string // drive serials, for the find box
	Notes                                                      []string
	checked                                                    time.Time
}

// InvDrive is one drive on the Inventory page.
type InvDrive struct {
	Model, Serial, Size, Interface, Media string
	Type, Note                            string // "NVMe · SSD"; "internal", "seen 7 Oct 10:18 · not connected now"
	Removable                             bool
}

// InvAccount is one account on the Inventory page.
type InvAccount struct {
	Name, ID, Kind, Status, LastLogon string
	Key                               string // personKey, for Search
	Role                              string // admin | user
	LastUsed                          string // "7 Oct", or "—"
	Admin, Disabled, Used             bool
	lastLogon                         time.Time
}

// usbSerialRE reads a device's serial number from a USB event's text.
var usbSerialRE = regexp.MustCompile(`\(serial ([^)\s]+)\)`)

// seenDrive is a removable drive seen in a system's USB events.
type seenDrive struct {
	model, serial string
	last          time.Time
}

func (r *Report) inventoryPage() *InventoryPage {
	ip := &InventoryPage{}
	// Removable drives seen in the USB events, and accounts used, by system.
	seen := map[string][]*seenDrive{}
	used := map[string]map[string]time.Time{}
	for _, row := range r.rows {
		h := strings.ToLower(row.Host)
		if row.User != "" {
			if used[h] == nil {
				used[h] = map[string]time.Time{}
			}
			if k := personKey(row.User); row.Time.After(used[h][k]) {
				used[h][k] = row.Time
			}
		}
		if row.Action != "usb_connected" {
			continue
		}
		serial := ""
		for _, d := range row.Details {
			if d.Label == "Serial number" {
				serial = d.Value
			}
		}
		if m := usbSerialRE.FindStringSubmatch(row.Summary); serial == "" && m != nil {
			serial = m[1]
		}
		var sd *seenDrive
		for _, x := range seen[h] {
			if serial != "" && strings.EqualFold(x.serial, serial) || serial == "" && x.serial == "" && x.model == row.Target {
				sd = x
			}
		}
		if sd == nil {
			sd = &seenDrive{model: row.Target, serial: serial}
			seen[h] = append(seen[h], sd)
		}
		if row.Time.After(sd.last) {
			sd.last = row.Time
		}
	}
	at := func(t time.Time) string { return t.In(r.Location).Format("2 Jan 15:04") }
	byHost := map[string]*InvRow{}
	for _, cs := range r.CheckSets {
		inv := cs.Inventory
		if inv == nil {
			continue
		}
		h := strings.ToLower(cs.Host)
		row := &InvRow{Host: cs.Host, OS: inv.OS, Make: strings.TrimSpace(inv.Manufacturer + " " + inv.Model), Serial: inv.Serial,
			CPU: inv.CPU, BIOS: inv.BIOS, Domain: inv.Domain, Checked: cs.Time.In(r.Location).Format("2 Jan 2006 15:04"), Notes: inv.Notes, checked: cs.Time}
		if inv.Memory > 0 {
			row.Memory = humanBytes(inv.Memory)
		}
		internal, removable := 0, 0
		var keys []string
		for _, d := range inv.Drives {
			dr := InvDrive{Model: d.Model, Serial: d.Serial, Size: driveSize(d.Size), Interface: d.Interface, Media: d.Media,
				Type: driveType(d.Interface, d.Media), Note: "internal"}
			if strings.EqualFold(d.Interface, "USB") || strings.Contains(strings.ToLower(d.Media), "removable") {
				dr.Removable, dr.Note = true, "connected at the settings check"
				for _, sd := range seen[h] {
					if sd.serial != "" && strings.EqualFold(sd.serial, d.Serial) {
						dr.Note = "seen " + at(sd.last) + " · connected at the settings check"
						sd.serial = "\x00" // shown
					}
				}
				removable++
			} else {
				internal++
			}
			keys = append(keys, d.Serial)
			row.Drives = append(row.Drives, dr)
		}
		for _, sd := range seen[h] {
			if sd.serial == "\x00" {
				continue
			}
			dr := InvDrive{Model: sd.model, Serial: sd.serial, Size: "—", Interface: "USB", Type: "USB · removable", Removable: true, Note: "seen " + at(sd.last)}
			if cs.Time.After(sd.last) {
				dr.Note += " · not connected now"
			}
			keys = append(keys, sd.serial)
			row.Drives = append(row.Drives, dr)
			removable++
		}
		row.Keys = strings.Join(nonEmpty(keys...), " ")
		row.DrivesNote = fmt.Sprintf("%d internal", internal)
		if removable > 0 {
			row.DrivesNote += fmt.Sprintf(" · %d removable seen", removable)
		}
		for _, a := range inv.Accounts {
			ia := InvAccount{Name: a.Name, Key: personKey(a.Name), ID: a.ID, Kind: a.Kind, Admin: a.Admin, Disabled: !a.Enabled, Status: "Enabled", lastLogon: a.LastLogon, Role: "user"}
			if !a.Enabled {
				ia.Status = "Disabled"
			}
			if a.Note != "" {
				ia.Status += " · " + a.Note
			}
			if !a.LastLogon.IsZero() {
				ia.LastLogon = a.LastLogon.In(r.Location).Format("2 Jan 2006 15:04")
			}
			last := a.LastLogon
			if t, ok := used[h][ia.Key]; ok {
				ia.Used = true
				row.Used++
				if t.After(last) {
					last = t
				}
			}
			ia.lastLogon = last
			ia.LastUsed = "—"
			if !last.IsZero() {
				ia.LastUsed = last.In(r.Location).Format("2 Jan")
				if last.In(r.Location).Year() != r.WindowEnd.In(r.Location).Year() {
					ia.LastUsed = last.In(r.Location).Format("2 Jan 2006")
				}
			}
			if a.Admin {
				row.Admins++
				ia.Role = "admin"
			}
			row.Accounts = append(row.Accounts, ia)
		}
		// Administrators first, enabled before disabled, then the most
		// recently used.
		sort.SliceStable(row.Accounts, func(i, j int) bool {
			a, b := row.Accounts[i], row.Accounts[j]
			if a.Admin != b.Admin {
				return a.Admin
			}
			if a.Disabled != b.Disabled {
				return !a.Disabled
			}
			if !a.lastLogon.Equal(b.lastLogon) {
				return a.lastLogon.After(b.lastLogon)
			}
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		})
		row.Shown = row.Accounts[:min(invShown, len(row.Accounts))]
		row.More = len(row.Accounts) - len(row.Shown)
		ip.DriveN += len(row.Drives)
		ip.AccountN += len(row.Accounts)
		ip.AdminN += row.Admins
		ip.Have++
		byHost[h] = row
	}
	for _, h := range r.Hosts {
		if byHost[strings.ToLower(h)] == nil {
			m := InvMissing{Host: h, Why: r.noInventoryWhy(h)}
			ip.Missing = append(ip.Missing, m)
			byHost[strings.ToLower(h)] = &InvRow{Host: h, Why: m.Why}
		}
	}
	sysOf := map[string]SystemRow{}
	for _, s := range append(append([]SystemRow(nil), r.SystemRows...), r.Retired...) {
		sysOf[strings.ToLower(s.Name)] = s
	}
	for h, row := range byHost {
		row.Kind = r.hostKind(row.Host)
		s, ok := sysOf[h]
		if ok {
			row.ListOS = listOS(s)
		}
		if (!ok || s.Checks == nil || s.Checks.Baseline == "") && row.OS != "" {
			row.ListOS = shortInvOS(row.OS)
		}
		var line []string
		if ok {
			line = append(line, osLabel(s))
		} else if row.OS != "" {
			line = append(line, row.OS)
		}
		line = append(line, strings.ToLower(kindWord(row.Kind)))
		if row.Make != "" {
			line = append(line, strings.TrimSpace(strings.Replace(row.Make, " Inc.", "", 1)))
		}
		row.Line = strings.Join(line, " · ")
		ip.Rows = append(ip.Rows, row)
	}
	sort.SliceStable(ip.Rows, func(i, j int) bool { return naturalLess(ip.Rows[i].Host, ip.Rows[j].Host) })
	sort.SliceStable(ip.Missing, func(i, j int) bool { return naturalLess(ip.Missing[i].Host, ip.Missing[j].Host) })
	for _, g := range groupByKind(ip.Rows, func(x *InvRow) string { return x.Kind }) {
		ip.Groups = append(ip.Groups, InvGroup{Title: g.Title, Label: g.Label(), Rows: g.Items})
	}
	ip.Crumb = fmt.Sprintf("%d of %d systems · %s · %s · read at each system's last settings check",
		ip.Have, len(ip.Rows), plural(ip.DriveN, "drive"), plural(ip.AccountN, "account"))
	if ip.Have == 0 {
		ip.Crumb = "no inventory yet"
	} else if ip.Have == len(ip.Rows) {
		ip.Crumb = strings.Replace(ip.Crumb, fmt.Sprintf("%d of %d systems", ip.Have, len(ip.Rows)), plural(ip.Have, "system"), 1)
	}
	return ip
}

// driveType is a drive's type: "NVMe · SSD", "SATA · HDD", "USB ·
// removable".
func driveType(iface, media string) string {
	m := media
	if strings.EqualFold(m, "removable") || strings.EqualFold(iface, "USB") && m == "" {
		m = "removable"
	}
	return strings.Join(nonEmpty(iface, m), " · ")
}

// shortInvOS is an inventory's OS in a few words: "Server 2025",
// "Windows 11", "Ubuntu 24.04".
func shortInvOS(os string) string {
	o := strings.TrimPrefix(os, "Microsoft ")
	f := strings.Fields(o)
	switch {
	case len(f) >= 3 && f[0] == "Windows" && f[1] == "Server":
		return "Server " + f[2]
	case len(f) >= 2 && f[0] == "Windows":
		return "Windows " + f[1]
	case len(f) >= 2:
		v := f[1]
		if p := strings.Split(v, "."); len(p) > 2 {
			v = p[0] + "." + p[1]
		}
		return f[0] + " " + v
	}
	return o
}

// inventoryCSV is the Inventory page's CSV: one row per drive and one per
// account.
func (r *Report) inventoryCSV(ip *InventoryPage) string {
	return csvText(append(r.inventoryDriveRows(ip), r.inventoryAccountRows(ip)...))
}

// inventoryDriveRows are the CSV's header and its drives (in the page);
// times with their zone (ASSESS1).
func (r *Report) inventoryDriveRows(ip *InventoryPage) [][]string {
	rows := [][]string{{"system", "item", "name", "type", "size", "serial_or_id", "note", "inventoried"}}
	for _, row := range ip.Rows {
		if row.Why != "" {
			continue
		}
		for _, d := range row.Drives {
			rows = append(rows, []string{row.Host, "drive", d.Model, d.Type, d.Size, d.Serial, d.Note, r.csvTime(row.checked)})
		}
	}
	return rows
}

// inventoryAccountRows are the CSV's accounts (in the data file).
func (r *Report) inventoryAccountRows(ip *InventoryPage) [][]string {
	var rows [][]string
	for _, row := range ip.Rows {
		for _, a := range row.Accounts {
			det := []string{a.Status}
			if a.Used {
				det = append(det, "used this period")
			}
			if !a.lastLogon.IsZero() {
				det = append(det, "last used "+r.csvTime(a.lastLogon))
			}
			kind := "user"
			if a.Admin {
				kind = "administrator"
			}
			rows = append(rows, []string{row.Host, "account", a.Name, strings.Join(nonEmpty(a.Kind, kind), " "), "", a.ID, strings.Join(nonEmpty(det...), "; "), r.csvTime(row.checked)})
		}
	}
	return rows
}

// inventoryData is the data file of every system's accounts, read when
// "Show all" is clicked and for the Export: {"h": {host: [[name, role,
// disabled, last used, search key, id, status]]}, "csv": rows}.
func (r *Report) inventoryData() (dataFile, bool, error) {
	ip := r.inventoryPage()
	if ip.AccountN == 0 {
		return dataFile{}, false, nil
	}
	h := map[string][][]any{}
	for _, row := range ip.Rows {
		for _, a := range row.Accounts {
			h[row.Host] = append(h[row.Host], []any{a.Name, a.Role, a.Disabled, a.LastUsed, a.Key, a.ID, a.Status})
		}
	}
	acc := r.inventoryAccountRows(ip)
	for i := range acc {
		acc[i] = csvSafe(acc[i])
	}
	b, err := dataScript("inventory/accounts", map[string]any{"h": h, "csv": acc})
	return dataFile{Name: "inventory-accounts.js", Body: b}, true, err
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
