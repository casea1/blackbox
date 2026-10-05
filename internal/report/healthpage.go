package report

import (
	"github.com/casea1/blackbox/internal/winevt"

	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
)

// The Audit health page (designs A1 and A3): every system against every
// check in a grid, the gaps as cards with how to fix them, and for one
// system the full table of its settings. Blackbox only reports audit
// settings; it never changes them.

// healthCols are the grid's columns, in order.
var healthCols = []string{"Logon", "Account mgmt", "Policy change", "Privilege use", "Process creation",
	"Removable storage", "PowerShell logging", "Antivirus", "Log size", "Reporting", "Logs intact"}

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
	Note                                        string // how the report covers it, when it doesn't review it
	Href                                        string // where the check's details are, if elsewhere
}

// GapCard is one gap on the Audit health page.
type GapCard struct {
	Title, STIG, Explain, Fix string
	Systems                   []string
	Level                     string
}

// HealthPage is the Audit health page.
type HealthPage struct {
	Stats   []EventCard
	Cols    []string
	Groups  []HealthGroup
	Gaps    []GapCard
	Single  string // a report of one system opens its table directly
	Checked int
	Other   []OtherRow // Security-log events Blackbox doesn't translate
	Scap    []ScapRow  // STIG compliance from SCAP scans
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
	hp := &HealthPage{Cols: healthCols, Other: r.otherEvents(), Scap: r.scapTable}
	cleared := map[string][]*Row{}
	for _, row := range r.rows {
		if row.Action == "log_cleared" {
			cleared[strings.ToLower(row.Host)] = append(cleared[strings.ToLower(row.Host)], row)
		}
	}
	lost := map[string]uint64{}
	holds := map[string]time.Duration{}
	for _, c := range r.Health.Channels {
		h := strings.ToLower(c.Host)
		lost[h] += c.Lost
		if strings.EqualFold(c.Channel, "Security") || strings.Contains(strings.ToLower(c.Channel), "audit") {
			if c.History > 0 && (holds[h] == 0 || c.History < holds[h]) {
				holds[h] = c.History
			}
		}
	}

	matching, gaps, warns, clearedN, small := 0, 0, 0, 0, 0
	var totalLost uint64
	var clearedWho, smallWho []string
	gapCards := map[string]*GapCard{}
	var gapOrder []string
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
		case s.Via != "":
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
				if rank[res.Status] > rank[worst[col]] {
					worst[col] = res.Status
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
				case s.Via != "":
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
					c = Cell{Mark: "✕", Class: "bad", Title: plural(int(lost[h]), "event") + " lost to log rollover"}
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
		if row.Checked && s.Checks.Fail == 0 {
			matching++
		}
		if s.Checks != nil {
			gaps += s.Checks.Fail
			warns += s.Checks.Warn
		}

		// Gaps, as cards.
		if n := len(cleared[h]); n > 0 {
			clearedN++
			clearedWho = append(clearedWho, s.Name)
			by := ""
			if u := cleared[h][0].User; u != "" {
				by = " by " + u
			}
			addGap("cleared", GapCard{Title: "Security log was cleared", Level: "bad",
				Explain: fmt.Sprintf("Cleared%s on %s%s. Events from before then are only in the original-log archive.", times(n),
					cleared[h][0].Time.In(r.Location).Format("2 Jan 15:04"), by)}, s.Name)
		}
		if s.AuditOff != "" {
			addGap("auditoff", GapCard{Title: "Auditing is off", Level: "bad",
				Explain: "At the last collection auditing was not running (the audit service stopped, or kernel auditing switched off), so nothing was being recorded. Start it with systemctl start auditd, and auditctl -e 1 if kernel auditing is off. The system's own page says which."}, s.Name)
		}
		if s.Status == "silent" {
			addGap("silent", GapCard{Title: "No data received", Level: "bad",
				Explain: "No collection arrived in this period. Check the system is on and can reach the collector."}, s.Name)
		}
		if lost[h] > 0 {
			totalLost += lost[h]
			addGap("lost", GapCard{Title: "Events lost to log rollover", Level: "bad",
				Explain: "The log filled up and overwrote events before Blackbox read them. A larger log, or collecting more often, prevents this."}, s.Name)
		}
		if s.Checks != nil {
			for _, res := range s.Checks.Results {
				if res.Status != check.Fail && res.Status != check.Warn {
					continue
				}
				if healthColumn(res) == "Log size" {
					small++
					smallWho = append(smallWho, s.Name+" "+res.Have)
				}
				lv := "bad"
				if res.Status == check.Warn {
					lv = "warn"
				}
				explain := ""
				if res.Have != "" || res.Want != "" {
					explain = fmt.Sprintf("Set to %s; the STIG requires %s.", orDash(res.Have), orDash(res.Want))
				}
				if res.Affects != "" {
					explain = strings.TrimSpace(explain + " Without it the report is missing: " + res.Affects + ".")
				}
				addGap("check|"+res.Item, GapCard{Title: res.Item, STIG: res.STIG, Explain: explain, Fix: res.Fix, Level: lv}, s.Name)
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
				l := SettingLine{Check: res.Item, STIG: res.STIG, Want: orDash(res.Want), Have: orDash(res.Have), Fix: res.Fix}
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
				case check.Warn, check.Error:
					l.Result, l.Class = "Warning", "warn"
				default:
					l.Result, l.Class = "Info", "na"
				}
				row.Table = append(row.Table, l)
			}
		}
		intact := SettingLine{Check: "Logs intact", STIG: "—", Want: "Not cleared, nothing lost", Have: "Intact", Result: "Matches", Class: "ok"}
		if c := row.Cells[len(row.Cells)-1]; c.Class == "bad" {
			intact.Have, intact.Result, intact.Class = c.Title, "Gap", "bad"
		}
		rep := SettingLine{Check: "Reporting", STIG: "—", Want: "At each scheduled collection", Result: "Matches", Class: "ok",
			Have: fmt.Sprintf("%s, last %s", plural(len(s.runTimes), "run"), stampOrDash(s.LastRun, r.Location))}
		if c := row.Cells[len(row.Cells)-2]; c.Class == "na" {
			rep.Want, rep.Have, rep.Result, rep.Class = "—", "Not collected live", "—", "na"
		} else if c.Class != "ok" {
			rep.Result, rep.Class = map[string]string{"bad": "Gap", "warn": "Warning"}[c.Class], c.Class
		}
		row.Table = append(row.Table, intact, rep)
		if l, ok := r.scapSetting(h); ok {
			row.Table = append(row.Table, l)
			row.Scap = r.scapOpen(h)
		}

		checks, match := 0, 0
		for _, l := range row.Table {
			if l.Class != "na" {
				checks++
			}
			if l.Class == "ok" {
				match++
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
	if t := r.excludedText(); t != "" {
		var on []string
		for h := range r.ExcludedOn {
			on = append(on, h)
		}
		sort.Slice(on, func(i, j int) bool { return naturalLess(on[i], on[j]) })
		hp.Gaps = append(hp.Gaps, GapCard{Title: "Left out by your settings", Level: "warn", Systems: on,
			Explain: "Not in this report: " + t + ". Failed logons against these accounts, changes to them, log clears and audit changes, and anything of Medium severity or above are always included."})
	}
	for _, k := range gapOrder {
		hp.Gaps = append(hp.Gaps, *gapCards[k])
	}
	// Cleared logs, silence and lost events first, then settings; gaps
	// before warnings.
	prio := map[string]int{"Security log was cleared": 0, "No data received": 1, "Events lost to log rollover": 2}
	p := func(g GapCard) int {
		n, ok := prio[g.Title]
		if !ok {
			n = 3
		}
		if g.Level != "bad" {
			n += 10
		}
		return n
	}
	sort.SliceStable(hp.Gaps, func(i, j int) bool { return p(hp.Gaps[i]) < p(hp.Gaps[j]) })
	if len(systems) == 1 {
		hp.Single = systems[0].Name
	}

	total := len(systems)
	lvl := func(bad bool, l string) string {
		if bad {
			return l
		}
		return ""
	}
	hp.Stats = []EventCard{
		{Icon: "shield-check", Label: "Systems matching STIG", Value: fmt.Sprintf("%d / %d", matching, total),
			Note: plural(gaps, "gap") + " · " + plural(warns, "warning"), Level: lvl(matching < total, "bad")},
		{Icon: "eraser", Label: "Logs cleared", Href: searchLink("page", "integrity", "text", "cleared"), Value: commas(clearedN), Note: short(set(clearedWho), 2), Level: lvl(clearedN > 0, "bad")},
		{Icon: "circle-check", Label: "Events lost to rollover", Value: commas(int(totalLost)), Note: plural(r.Health.Runs, "run"), Level: lvl(totalLost > 0, "bad")},
		{Icon: "hard-drive", Label: "Logs too small", Value: commas(small), Note: short(set(smallWho), 1), Level: lvl(small > 0, "warn")},
	}
	return hp
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
