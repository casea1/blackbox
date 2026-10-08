package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/rollover"
	"github.com/casea1/blackbox/internal/winevt"
)

// The Audit health page (designs A1 and A3): every system against every
// check in a grid, the gaps as cards with how to fix them, and for one
// system the full table of its settings. Blackbox only reports audit
// settings; it never changes them.

// healthCols are the grid's columns, in order.
var healthCols = []string{"Logon", "Account mgmt", "Policy change", "Privilege use", "Process creation",
	"Removable storage", "PowerShell logging", "Antivirus", "Log size", "Reporting", "Logs intact"}

// HealthCol is one of the grid's column headings: short enough that every
// column fits at 1280 pixels, with the full name on hover (UI3).
type HealthCol struct{ Short, Full string }

var healthShort = map[string]string{"Account mgmt": "Accounts", "Policy change": "Policy", "Privilege use": "Privilege",
	"Process creation": "Process", "Removable storage": "USB", "PowerShell logging": "PS log", "Antivirus": "AV", "Logs intact": "Intact"}

// healthFull is a heading's full name, where it says more than the
// column: on hover, and in the key under the table (UI19).
var healthFull = map[string]string{"Account mgmt": "Account management", "Log size": "Log size and space settings",
	"Logs intact": "Logs intact (none cleared)", "Reporting": "Reporting (data received)"}

func healthHeadings() []HealthCol {
	var out []HealthCol
	for _, c := range healthCols {
		short := healthShort[c]
		if short == "" {
			short = c
		}
		full := healthFull[c]
		if full == "" {
			full = c
		}
		out = append(out, HealthCol{Short: short, Full: full})
	}
	return out
}

// healthColumn says which grid column a check result belongs to ("" for
// checks only listed in the system's own table).
func healthColumn(res check.Result) string {
	item := strings.ToLower(res.Item)
	area := strings.ToLower(res.Area)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(item, w) {
				return true
			}
		}
		return false
	}
	switch {
	case area == "baseline":
		return ""
	case area == "antivirus":
		return "Antivirus"
	case area == "event log size", has("audit log space", "audit backlog", "space_left", "disk_full", "disk_error", "action_mail"):
		return "Log size"
	case has("powershell"):
		return "PowerShell logging"
	case has("removable storage", "plug and play", "filesystem mounts", "udisks"):
		return "Removable storage"
	case has("process creation", "command line", "commands run as root"):
		return "Process creation"
	case has("sensitive privilege", "raised privileges", "sudo records"):
		return "Privilege use"
	case has("policy change", "force audit policy", "sudoers", "audit configuration", "rules locked"):
		return "Policy change"
	case has("account management", "group management", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"):
		return "Account mgmt"
	case has("logon", "logoff", "credential validation", "account lockout", "group membership"),
		area == "audit service", area == "boot":
		return "Logon"
	}
	return ""
}

// Cell is one cell of the Audit health grid.
type Cell struct {
	Mark, Class, Title string // ✓ ✕ ! n/a; ok bad warn na
}

// HealthRow is one system in the grid, and its own settings table (A3).
type HealthRow struct {
	Name, Line, Level, Note string
	Cells                   []Cell
	Facts                   []Fact
	Table                   []SettingLine
	Scap                    []ScapOpen // open STIG rules from SCAP scans (SC3)
	Checked                 bool
	CheckedAt               string // when the settings were checked
}

// SettingLine is one line of a system's settings table.
type SettingLine struct {
	Check, STIG, Want, Have, Result, Class, Fix string
	Advice                                      bool   // Blackbox's advice, not a STIG rule (COMP2)
	Note                                        string // how the report covers it, when it doesn't review it
	Href                                        string // where the check's details are, if elsewhere
}

// GapCard is one gap on the Audit health page.
type GapCard struct {
	Title, STIG, Explain, Fix string
	Systems                   []string
	Level                     string
	// STIGs, when the systems are under different STIGs, is each one's
	// IDs with its OS, one per line (STIG1); STIG then joins them.
	STIGs []string
	// Advice: Blackbox's advice, not a STIG rule (COMP2).
	Advice bool
	// OS is the operating systems it is on ("Windows", "Windows · Ubuntu"),
	// Affects what the report misses without it, and OneFix how one change
	// clears it everywhere ("One GPO on the OU fixes all 9.") (UI-R1).
	OS, Affects, OneFix string
	os                  []string
	// FixDot: Fix needs a full stop before OneFix.
	FixDot bool
	// IDs are the STIG IDs alone, for the row (STIG has each one's OS).
	IDs []string
}

// HealthPage is the Audit health page.
type HealthPage struct {
	Cols []HealthCol
	// ColKey are the columns whose heading is short for more, in a key
	// under the table: the full names without hovering (UI19).
	ColKey  []HealthCol
	Groups  []HealthGroup
	Gaps    []GapCard
	Single  string // a report of one system opens its table directly
	Checked int
	Other   []OtherRow // Security-log events Blackbox doesn't translate
	Scap    *ScapView  // STIG compliance from SCAP scans
	AV      []AVRow    // antivirus definitions and protection, by system

	// The grid lists systems with a gap or warning; those that match on
	// every check are folded away (Passing).
	Attention, Passing []HealthGroup
	PassingN           int

	// UI-R1 (design 08): four cards, the tabs, and the settings to fix
	// (Gaps) split into the first eight and the rest, folded (More, with
	// MoreText saying what they are).
	Cards    []HealthCard
	Tabs     []HealthTab
	Top      []GapCard
	More     []GapCard
	MoreText string
	// Excluded is what your settings leave out of the report, if anything.
	Excluded string
	// Losses are the logs that overwrote events before they were read, on
	// the Log sizes tab.
	Losses []LossRow
	// LostCritical: events lost from the Security log or the audit log.
	LostCritical bool
	// LossNote says why the original logs do not have the lost events.
	LossNote string
}

// HealthCard is one of Audit health's four cards. Meter, when set, is the
// share matching in percent, drawn as a green/amber bar.
type HealthCard struct {
	Label, Value, Note, Level, Tab string
	Meter                          int
	HasMeter                       bool
}

// HealthTab is one tab of Audit health: Settings to fix, By system, SCAP,
// Antivirus, Log sizes.
type HealthTab struct {
	ID, Label, Count, Level string
}

// LossRow is one log on one system that overwrote events before Blackbox
// read them, with what to do.
type LossRow struct {
	Host, Log, Lost, When, Advice, Level string
}

// OtherRow is one Security-log event ID Blackbox has no translation for,
// with how many were read in this period.
type OtherRow struct {
	ID     int
	Name   string
	Count  int
	Listed bool   // shown as "Security event <ID>" rows; otherwise only counted
	Href   string // the rows, in Search
}

// otherEvents lists the Security-log events read in this period that the
// report doesn't translate, busiest first (A1).
func (r *Report) otherEvents() []OtherRow {
	var out []OtherRow
	for _, v := range r.Health.Volume {
		if v.Channel != "Security" || v.EventID == 0 || winevt.Reviewed[v.EventID] {
			continue
		}
		o := OtherRow{ID: v.EventID, Name: orDash(winevt.EventNames[v.EventID]), Count: v.Count, Listed: !winevt.Counted[v.EventID]}
		if o.Listed {
			o.Href = searchLink("page", "other", "text", fmt.Sprintf("Security event %d", v.EventID))
		}
		out = append(out, o)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// HealthGroup is a group of rows in the grid.
type HealthGroup struct {
	Title string
	Rows  []*HealthRow
}

func (r *Report) healthPage() *HealthPage {
	systems := r.SystemRows
	if len(systems) == 0 { // a report from saved files: its hosts and checks
		for _, h := range r.Hosts {
			sr := SystemRow{SystemInfo: SystemInfo{Name: h}, Status: "ok"}
			for i := range r.CheckSets {
				if strings.EqualFold(r.CheckSets[i].Host, h) {
					sr.Checks = &r.CheckSets[i]
				}
			}
			systems = append(systems, sr)
		}
		if len(systems) == 0 {
			return nil
		}
	}
	hp := &HealthPage{Cols: healthHeadings(), Other: r.otherEvents(), Scap: r.scapView(), AV: r.avRows()}
	for _, c := range hp.Cols {
		if c.Short != c.Full {
			hp.ColKey = append(hp.ColKey, c)
		}
	}
	cleared := map[string][]*Row{}
	for _, row := range r.rows {
		if row.Action == "log_cleared" {
			cleared[strings.ToLower(row.Host)] = append(cleared[strings.ToLower(row.Host)], row)
		}
	}
	lost := map[string]uint64{}
	blocked := map[string][]BlockedItem{}
	for _, b := range r.Health.Blocked {
		blocked[strings.ToLower(b.Host)] = append(blocked[strings.ToLower(b.Host)], b)
	}
	holds := map[string]time.Duration{}
	// Losses from the audit record (Security log, Linux audit log) are
	// High; other logs' (the PowerShell log) are shown on their own, lower
	// (LOG1).
	otherLost := map[string]uint64{}
	gapsOn := map[string][]GapItem{}
	for _, g := range r.Health.Gaps {
		if g.Lost == 0 {
			continue
		}
		h := strings.ToLower(g.Host)
		if rollover.Critical(g.Channel) {
			lost[h] += g.Lost
		} else {
			otherLost[h] += g.Lost
		}
		gapsOn[h] = append(gapsOn[h], g)
	}
	for _, c := range r.Health.Channels {
		h := strings.ToLower(c.Host)
		if strings.EqualFold(c.Channel, "Security") || strings.Contains(strings.ToLower(c.Channel), "audit") {
			if c.History > 0 && (holds[h] == 0 || c.History < holds[h]) {
				holds[h] = c.History
			}
		}
	}

	matching := 0
	var totalLost, totalOther uint64
	gapCards := map[string]*GapCard{}
	var gapOrder []string
	// Each system's own STIG IDs for a gap (STIG1): Windows 11 and Server
	// 2025 share "Credential Validation" under different IDs.
	type stigIDs struct{ label, ids string }
	gapSTIGs := map[string][]stigIDs{}
	addSTIG := func(key, label, ids string) {
		if ids == "" {
			return
		}
		for _, s := range gapSTIGs[key] {
			if s.ids == ids {
				return
			}
		}
		gapSTIGs[key] = append(gapSTIGs[key], stigIDs{label, ids})
	}
	addGap := func(key string, g GapCard, host string) {
		c := gapCards[key]
		if c == nil {
			c = &g
			gapCards[key] = c
			gapOrder = append(gapOrder, key)
		}
		c.Systems = append(c.Systems, host)
	}

	groups := []*HealthGroup{{Title: "Servers"}, {Title: "Workstations"}, {Title: "Virtual machines"}}
	for _, s := range systems {
		h := strings.ToLower(s.Name)
		row := &HealthRow{Name: s.Name}
		g := groups[1]
		switch {
		case s.VM:
			g = groups[2]
		case isServer(s):
			g = groups[0]
		}
		// Worst result in each column.
		worst := map[string]check.Status{}
		titles := map[string][]string{}
		rank := map[check.Status]int{check.Pass: 1, check.Info: 1, check.Warn: 2, check.Error: 2, check.Fail: 3}
		if s.Checks != nil {
			row.Checked = true
			if !s.Checks.Time.IsZero() {
				row.CheckedAt = r.stamp(s.Checks.Time)
			}
			hp.Checked++
			for _, res := range s.Checks.Results {
				col := healthColumn(res)
				if col == "" {
					continue
				}
				st := res.Status
				if st == check.Fail && res.IsAdvice() {
					st = check.Warn // Blackbox's advice is never a STIG gap (COMP2)
				}
				if rank[st] > rank[worst[col]] {
					worst[col] = st
				}
				if res.Status == check.Fail || res.Status == check.Warn || res.Status == check.Error {
					titles[col] = append(titles[col], res.Item+": "+res.Have)
				}
			}
		}
		fails, ws := 0, 0
		for _, col := range healthCols {
			c := Cell{Mark: "n/a", Class: "na"}
			switch col {
			case "Reporting":
				switch {
				case s.LastRun.IsZero() && s.Status != "silent":
					// Not collected live (a report from saved logs).
				case s.Status == "silent":
					c = Cell{Mark: "✕", Class: "bad", Title: "No collection received in this period"}
				case len(blocked[h]) > 0:
					b := blocked[h][0]
					c = Cell{Mark: "✕", Class: "bad", Title: "Collection blocked " + r.stamp(b.From) + " to " + r.stamp(b.To)}
				case s.VM && s.Runs == 0:
					c = Cell{Mark: "!", Class: "warn", Title: s.StatusMsg}
				case s.VM:
					c = Cell{Mark: "✓", Class: "ok", Title: "A VM reports whenever it is on"}
				case r.WindowEnd.Sub(s.LastRun) > silentAfter:
					c = Cell{Mark: "!", Class: "warn", Title: "Last collection " + s.LastRun.In(r.Location).Format("2 Jan 15:04")}
				default:
					c = Cell{Mark: "✓", Class: "ok"}
				}
			case "Logs intact":
				switch {
				case len(cleared[h]) > 0:
					c = Cell{Mark: "✕", Class: "bad", Title: "Log cleared"}
				case lost[h] > 0:
					c = Cell{Mark: "✕", Class: "bad", Title: lostTitle(gapsOn[h], true)}
				case otherLost[h] > 0:
					c = Cell{Mark: "!", Class: "warn", Title: lostTitle(gapsOn[h], false)}
				default:
					c = Cell{Mark: "✓", Class: "ok"}
				}
			default:
				if !row.Checked {
					break
				}
				switch worst[col] {
				case check.Pass, check.Info:
					c = Cell{Mark: "✓", Class: "ok"}
				case check.Fail:
					c = Cell{Mark: "✕", Class: "bad", Title: strings.Join(titles[col], "; ")}
				case check.Warn, check.Error:
					c = Cell{Mark: "!", Class: "warn", Title: strings.Join(titles[col], "; ")}
				}
			}
			switch c.Class {
			case "bad":
				fails++
			case "warn":
				ws++
			}
			row.Cells = append(row.Cells, c)
		}
		switch {
		case fails > 0:
			row.Level, row.Note = "bad", plural(fails, "gap")
		case ws > 0:
			row.Level, row.Note = "warn", "warning"
		case !row.Checked:
			row.Note = "not checked"
		default:
			row.Note = "OK"
		}
		// Only STIG rules count towards matching the STIG; Blackbox's
		// advice is counted on its own (COMP2).
		if row.Checked && s.Checks.STIGFail == 0 {
			matching++
		}

		// Settings to fix (UI-R1): one row per setting, every system it is
		// on. Cleared logs, silent systems, blocked collections and the
		// original logs are on Overview, Systems, Detections and Original
		// logs; lost events on the Log sizes tab; antivirus on its own tab.
		if lost[h] > 0 {
			totalLost += lost[h]
		}
		if otherLost[h] > 0 {
			totalOther += otherLost[h]
		}
		if s.Checks != nil {
			for _, res := range s.Checks.Results {
				if res.Status != check.Fail && res.Status != check.Warn || res.Area == "Antivirus" {
					continue
				}
				lv := "bad"
				adv := res.IsAdvice()
				if res.Status == check.Warn || adv {
					lv = "warn"
				}
				explain := ""
				if res.Have != "" || res.Want != "" {
					// A check with no STIG rule is never worded as the
					// STIG's (COMP2).
					if adv {
						explain = fmt.Sprintf("Set to %s; Blackbox recommends %s. This is Blackbox's advice, not a STIG rule.", orDash(res.Have), orDash(res.Want))
					} else {
						explain = fmt.Sprintf("Set to %s; the STIG requires %s.", orDash(res.Have), orDash(res.Want))
					}
				}
				key, stig := "check|"+res.Item, res.STIG
				if adv {
					// Kept apart from the same setting where a STIG
					// requires it (File System: advice on Windows 11, a
					// rule on Server 2025).
					key, stig = key+"|advice", ""
				}
				addGap(key, GapCard{Title: res.Item, STIG: stig, Explain: explain, Fix: res.Fix, Level: lv, Advice: adv, Affects: res.Affects}, s.Name)
				addSTIG(key, osLabel(s), stig)
				c := gapCards[key]
				if fam := osFamily(s); !slices.Contains(c.os, fam) {
					c.os = append(c.os, fam)
				}
				if c.Affects == "" {
					c.Affects = res.Affects
				}
			}
		}

		// The system's own table (A3).
		row.Line = osLabel(s)
		if s.Checks != nil {
			if s.Checks.Baseline != "" {
				row.Line += " · compared with " + s.Checks.Baseline
			}
			row.Line += " · checked " + s.Checks.Time.In(r.Location).Format("2 Jan 15:04")
			for _, res := range s.Checks.Results {
				if res.Area == "Baseline" {
					continue
				}
				l := SettingLine{Check: res.Item, STIG: res.STIG, Want: orDash(res.Want), Have: orDash(res.Have), Fix: res.Fix, Advice: res.IsAdvice()}
				if res.Area == "Audit policy" {
					switch winevt.SubcategoryReviewed(res.Item) {
					case "counted":
						l.Note = "Not reviewed: Blackbox only counts these events (see Other Security-log events below). The original logs are in the archive."
					case "other":
						l.Note = "Not translated: these events are listed only as \"Security event <ID>\" rows on Other security."
					}
				}
				switch res.Status {
				case check.Pass:
					l.Result, l.Class = "Matches", "ok"
				case check.Fail:
					l.Result, l.Class = "Gap", "bad"
					if l.Advice {
						l.Result, l.Class = "Advice", "warn"
					}
				case check.Warn, check.Error:
					l.Result, l.Class = "Warning", "warn"
				default:
					l.Result, l.Class = "Info", "na"
				}
				row.Table = append(row.Table, l)
			}
		}
		intact := SettingLine{Check: "Logs intact", STIG: "—", Want: "Not cleared, nothing lost", Have: "Intact", Result: "Matches", Class: "ok"}
		switch c := row.Cells[len(row.Cells)-1]; c.Class {
		case "bad":
			intact.Have, intact.Result, intact.Class = c.Title, "Gap", "bad"
		case "warn":
			intact.Have, intact.Result, intact.Class = c.Title, "Warning", "warn"
		}
		rep := SettingLine{Check: "Reporting", STIG: "—", Want: "At each scheduled collection", Result: "Matches", Class: "ok",
			Have: fmt.Sprintf("%s, last %s", plural(len(s.runTimes), "run"), stampOrDash(s.LastRun, r.Location))}
		if c := row.Cells[len(row.Cells)-2]; c.Class == "na" {
			rep.Want, rep.Have, rep.Result, rep.Class = "—", "Not collected live", "—", "na"
		} else if c.Class != "ok" {
			rep.Result, rep.Class = map[string]string{"bad": "Gap", "warn": "Warning"}[c.Class], c.Class
		}
		// A blocked collection is told here, on the system's own table
		// (it was a gap of its own before UI-R1).
		for _, b := range blocked[h] {
			rep.Note = strings.TrimSpace(rep.Note + fmt.Sprintf(" Collection blocked %s to %s: %s refused because another Blackbox run held its lock (PID %d). The next run collected what the logs still held.",
				r.stamp(b.From), r.stamp(b.To), plural(b.Refused, "run"), b.PID))
		}
		if s.AuditOff != "" {
			intact.Note = "Auditing was off at the last collection: " + s.AuditOff + "."
		}
		row.Table = append(row.Table, intact, rep)
		if l, ok := r.scapSetting(h); ok {
			row.Table = append(row.Table, l)
			row.Scap = r.scapOpen(h)
		}

		// Blackbox's advice is counted on its own, not as a STIG gap (COMP2).
		checks, match, advice := 0, 0, 0
		for _, l := range row.Table {
			switch {
			case l.Advice && l.Class != "na" && l.Class != "ok":
				advice++
			case l.Advice:
			case l.Class != "na":
				checks++
				if l.Class == "ok" {
					match++
				}
			}
		}
		hold := "—"
		if d := holds[h]; d > 0 {
			hold = plural(int(d.Hours()/24), "day")
		}
		last := "—"
		if s.Checks != nil {
			last = s.Checks.Time.In(r.Location).Format("2 Jan 15:04")
		}
		row.Facts = []Fact{{Label: "Checks", Value: commas(checks)}, {Label: "Matching", Value: commas(match)},
			{Label: "Gaps", Value: commas(checks - match), Bad: checks > match}, {Label: "Log holds", Value: hold}, {Label: "Last check", Value: last}}
		if advice > 0 {
			row.Facts = append(row.Facts[:3:3], append([]Fact{{Label: "Blackbox's advice", Value: commas(advice)}}, row.Facts[3:]...)...)
		}
		if sc, ok := r.scapGlance(s.Name); ok {
			// The SCAP score up front: on a one-computer report this view
			// is all Audit health shows.
			f := Fact{Label: "SCAP score", Value: "no scan", Bad: true, Href: r.scapLink(s.Name)}
			if !sc.Missing {
				f.Value, f.Bad = "—", sc.Cat[1] > 0
				if sc.Score != "" {
					f.Value = sc.Score
				}
				if sc.Cat[1] > 0 {
					f.Value += fmt.Sprintf(" · %d CAT I", sc.Cat[1])
				}
			}
			row.Facts = append(row.Facts, f)
		}
		g.Rows = append(g.Rows, row)
	}
	for _, g := range groups {
		sort.SliceStable(g.Rows, func(i, j int) bool {
			a, b := g.Rows[i], g.Rows[j]
			ra, rb := map[string]int{"bad": 0, "warn": 1}[a.Level], map[string]int{"bad": 0, "warn": 1}[b.Level]
			if a.Level == "" {
				ra = 2
			}
			if b.Level == "" {
				rb = 2
			}
			if ra != rb {
				return ra < rb
			}
			return naturalLess(a.Name, b.Name)
		})
		if len(g.Rows) > 0 {
			hp.Groups = append(hp.Groups, *g)
		}
	}
	hp.Excluded = r.excludedText()
	for _, k := range gapOrder {
		c := gapCards[k]
		if ids := gapSTIGs[k]; len(ids) > 1 {
			var parts []string
			for _, s := range ids {
				parts = append(parts, s.ids+" ("+s.label+")")
			}
			c.STIG, c.STIGs = strings.Join(parts, " · "), parts
		}
		for _, id := range gapSTIGs[k] {
			c.IDs = append(c.IDs, id.ids)
		}
		c.OS = strings.Join(c.os, " · ")
		c.OneFix = oneFix(*c)
		c.FixDot = c.OneFix != "" && !strings.HasSuffix(c.Fix, ".")
		hp.Gaps = append(hp.Gaps, *c)
	}
	// The setting on most systems first; STIG gaps before warnings and
	// Blackbox's advice.
	sort.SliceStable(hp.Gaps, func(i, j int) bool {
		a, b := hp.Gaps[i], hp.Gaps[j]
		if len(a.Systems) != len(b.Systems) {
			return len(a.Systems) > len(b.Systems)
		}
		return a.Level == "bad" && b.Level != "bad"
	})
	hp.Top = hp.Gaps
	if len(hp.Gaps) > settingsShown {
		hp.Top, hp.More = hp.Gaps[:settingsShown], hp.Gaps[settingsShown:]
		hi, lo := len(hp.More[0].Systems), len(hp.More[len(hp.More)-1].Systems)
		on := plural(hi, "system")
		if lo != hi {
			on = fmt.Sprintf("%d–%d systems", lo, hi)
		}
		hp.MoreText = fmt.Sprintf("%d more settings, each on %s", len(hp.More), on)
		if len(hp.More) == 1 {
			hp.MoreText = "1 more setting, on " + on
		}
	}
	if len(systems) == 1 {
		hp.Single = systems[0].Name
	}
	hp.Losses, hp.LossNote = r.lossRows(), rollover.NotInExports
	hp.LostCritical = totalLost > 0
	hp.cards(r, len(systems), matching, totalLost, totalOther)
	hp.fold()
	return hp
}

// settingsShown is how many settings to fix are listed before the rest
// are folded.
const settingsShown = 8

// osFamily is a system's operating system without its version: Windows,
// Ubuntu, RHEL.
func osFamily(s SystemRow) string {
	l := osLabel(s)
	if f, _, ok := strings.Cut(l, " "); ok {
		return f
	}
	return l
}

// oneFix says how one change clears a setting on every system listed: a
// Group Policy path is one GPO on their OU.
func oneFix(g GapCard) string {
	n := len(g.Systems)
	if n < 2 || g.Fix == "" {
		return ""
	}
	if g.OS == "Windows" && strings.HasPrefix(g.Fix, "Computer Configuration") {
		return fmt.Sprintf("One GPO on the OU fixes all %d.", n)
	}
	return fmt.Sprintf("The same fix on all %d.", n)
}

// lossRows are the logs that overwrote events before Blackbox read them,
// one row per system and log: the audit record first, then by how many.
func (r *Report) lossRows() []LossRow {
	type key struct{ host, ch string }
	n := map[key]uint64{}
	first, last, fast := map[key]time.Time{}, map[key]time.Time{}, map[key]GapItem{}
	var order []key
	for _, g := range r.Health.Gaps {
		if g.Lost == 0 {
			continue
		}
		k := key{g.Host, g.Channel}
		if _, ok := n[k]; !ok {
			order = append(order, k)
		}
		n[k] += g.Lost
		if first[k].IsZero() || g.From.Before(first[k]) {
			first[k] = g.From
		}
		if g.To.After(last[k]) {
			last[k] = g.To
		}
		if prev := fast[k]; prev.Host == "" || prev.Held == 0 || (g.Held > 0 && g.Held < prev.Held) {
			fast[k] = g // the fastest turnover says most
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if ca, cb := rollover.Critical(a.ch), rollover.Critical(b.ch); ca != cb {
			return ca
		}
		if n[a] != n[b] {
			return n[a] > n[b]
		}
		return naturalLess(a.host, b.host)
	})
	var out []LossRow
	for _, k := range order {
		row := LossRow{Host: k.host, Log: rollover.Name(k.ch), Lost: commas(int(n[k])), Advice: fast[k].Loss().Advice(true), Level: "warn"}
		if rollover.Critical(k.ch) {
			row.Level = "bad"
		}
		if !first[k].IsZero() {
			row.When = first[k].In(r.Location).Format("2 Jan 15:04")
			if !last[k].IsZero() {
				row.When += " – " + last[k].In(r.Location).Format("15:04")
			}
		}
		out = append(out, row)
	}
	return out
}

// cards builds Audit health's four cards and its tabs (design 08).
func (hp *HealthPage) cards(r *Report, total, matching int, lost, other uint64) {
	lvl := func(bad bool, l string) string {
		if bad {
			return l
		}
		return ""
	}
	n, on := 0, map[string]bool{}
	for _, g := range hp.Gaps {
		n += len(g.Systems)
		for _, s := range g.Systems {
			on[s] = true
		}
	}
	note := "every system matches"
	if n > 0 {
		note = fmt.Sprintf("%s to fix on %s", plural(n, "setting"), plural(len(on), "system"))
	}
	pct := 0
	if total > 0 {
		pct = matching * 100 / total
	}
	hp.Cards = []HealthCard{{Label: "Audit settings match the STIG", Value: fmt.Sprintf("%d / %d", matching, total), Note: note,
		Level: lvl(matching < total, "bad"), Meter: pct, HasMeter: true, Tab: "settings"}}
	settingsLevel := ""
	if len(hp.Gaps) > 0 {
		settingsLevel = "warn"
		for _, g := range hp.Gaps {
			if g.Level == "bad" {
				settingsLevel = "bad"
			}
		}
	}
	hp.Tabs = []HealthTab{{ID: "settings", Label: "Settings to fix", Count: commas(len(hp.Gaps)), Level: settingsLevel},
		{ID: "systems", Label: "By system", Count: commas(total)}}

	if v := hp.Scap; v != nil {
		cat1, cat1On, stale := 0, 0, len(v.Missing)
		low, lowV, scored := "", 101.0, 0
		for _, row := range v.Main {
			cat1 += row.Cat[1]
			if row.Cat[1] > 0 {
				cat1On++
			}
			if row.Stale {
				stale++
			}
			var f float64
			if _, err := fmt.Sscanf(row.Score, "%f%%", &f); err == nil {
				scored++
				if f < lowV {
					lowV, low = f, row.Score
				}
			}
		}
		c := HealthCard{Label: "SCAP (latest scans)", Value: "—", Tab: "scap", Level: lvl(cat1 > 0, "bad")}
		var parts []string
		if scored > 0 {
			c.Value = low
			if scored > 1 {
				parts = append(parts, "lowest")
			}
		}
		if cat1 > 0 {
			parts = append(parts, fmt.Sprintf("%d open CAT I on %s", cat1, plural(cat1On, "system")))
		} else {
			parts = append(parts, "no open CAT I")
		}
		if stale > 0 {
			days := r.ScapMaxAgeDays
			if days <= 0 {
				days = 30
			}
			parts = append(parts, fmt.Sprintf("%d not scanned in %d days", stale, days))
			if c.Level == "" {
				c.Level = "warn"
			}
		}
		c.Note = strings.Join(parts, " · ")
		hp.Cards = append(hp.Cards, c)
		hp.Tabs = append(hp.Tabs, HealthTab{ID: "scap", Label: "SCAP", Count: fmt.Sprintf("%d CAT I", cat1), Level: lvl(cat1 > 0, "bad")})
	}

	if len(hp.AV) > 0 {
		// UI13: "not checked" (no antivirus found, or nothing read) is
		// counted too, never "current".
		ok, bad, unchecked := 0, 0, 0
		for _, a := range hp.AV {
			switch a.Level {
			case "ok":
				ok++
			case "bad":
				bad++
			default:
				unchecked++
			}
		}
		parts := []string{"current"}
		if bad > 0 {
			parts = append(parts, fmt.Sprintf("%d out of date", bad))
		}
		if unchecked > 0 {
			parts = append(parts, fmt.Sprintf("%d not checked", unchecked))
		}
		level := lvl(unchecked > 0, "warn")
		if bad > 0 {
			level = "bad"
		}
		hp.Cards = append(hp.Cards, HealthCard{Label: "Antivirus", Value: fmt.Sprintf("%d / %d", ok, len(hp.AV)), Note: strings.Join(parts, " · "), Level: level, Tab: "av"})
		hp.Tabs = append(hp.Tabs, HealthTab{ID: "av", Label: "Antivirus", Count: commas(bad + unchecked), Level: level})
	}

	hosts, logs := map[string]bool{}, []string{}
	for _, l := range hp.Losses {
		hosts[strings.ToLower(l.Host)] = true
		if l.Level != "bad" && !slices.Contains(logs, l.Log) {
			logs = append(logs, l.Log)
		}
	}
	c := HealthCard{Label: "Logs", Value: commas(len(hosts)), Tab: "logs", Level: lvl(other > 0, "warn")}
	if lost > 0 {
		c.Level = "bad"
	}
	switch {
	case len(hosts) == 0:
		c.Note = "no log overwrote events · " + lostNote(0, r.Health.Runs)
	default:
		c.Note = map[bool]string{true: "system", false: "systems"}[len(hosts) == 1] + " overwrote events"
		if lost == 0 && len(logs) > 0 {
			c.Note += " (" + strings.Join(logs, ", ") + ")"
		}
		c.Note += " · " + commas(int(lost)) + " Security/audit lost"
	}
	hp.Cards = append(hp.Cards, c)
	hp.Tabs = append(hp.Tabs, HealthTab{ID: "logs", Label: "Log sizes", Count: commas(len(hosts)), Level: c.Level})
}

func set(l []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range l {
		m[s] = true
	}
	return m
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func stampOrDash(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "never"
	}
	return t.In(loc).Format("2 Jan 15:04")
}

// fold splits the grid into systems that need attention and those that
// match on every check.
func (hp *HealthPage) fold() {
	for _, g := range hp.Groups {
		var att, pass []*HealthRow
		for _, row := range g.Rows {
			ok := true
			for _, c := range row.Cells {
				if c.Class == "bad" || c.Class == "warn" {
					ok = false
				}
			}
			if ok {
				pass = append(pass, row)
			} else {
				att = append(att, row)
			}
		}
		if len(att) > 0 {
			hp.Attention = append(hp.Attention, HealthGroup{Title: g.Title, Rows: att})
		}
		if len(pass) > 0 {
			hp.Passing = append(hp.Passing, HealthGroup{Title: g.Title, Rows: pass})
		}
		hp.PassingN += len(pass)
	}
}

// lostTitle names the logs that lost events on a system, with how many:
// "PowerShell log: 447 events overwritten".
func lostTitle(gaps []GapItem, critical bool) string {
	n := map[string]uint64{}
	var order []string
	for _, g := range gaps {
		if rollover.Critical(g.Channel) != critical {
			continue
		}
		name := rollover.Name(g.Channel)
		if _, ok := n[name]; !ok {
			order = append(order, name)
		}
		n[name] += g.Lost
	}
	var parts []string
	for _, name := range order {
		if n[name] == 0 {
			parts = append(parts, name+": events overwritten (how many is not known)")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s overwritten", name, plural(int(n[name]), "event")))
	}
	return strings.Join(parts, "; ")
}

// lostNote says what the count covers: the collections whose record
// numbers were checked for overwritten events (UX10).
func lostNote(other uint64, runs int) string {
	if other > 0 {
		return commas(int(other)) + " from other logs"
	}
	if runs == 1 {
		return "checked at 1 collection"
	}
	return "checked at " + commas(runs) + " collections"
}
