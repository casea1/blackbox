package report

import (
	"fmt"
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

// healthFull is a heading's name on hover, where it says more than the column.
var healthFull = map[string]string{"Log size": "Log size and space settings"}

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
}

// HealthPage is the Audit health page.
type HealthPage struct {
	Stats   []EventCard
	Cols    []HealthCol
	Groups  []HealthGroup
	Gaps    []GapCard
	Single  string // a report of one system opens its table directly
	Checked int
	Other   []OtherRow // Security-log events Blackbox doesn't translate
	Scap    *ScapView  // STIG compliance from SCAP scans
	AV      []AVRow    // antivirus definitions and protection, by system

	// The grid lists systems with a gap or warning; those that match on
	// every check are folded away (Passing), so the sections below are
	// in reach. Jump links to each section.
	Attention, Passing []HealthGroup
	PassingN           int
	Jump               []JumpLink
}

// JumpLink is one section of the Audit health page in the bar at its top.
type JumpLink struct {
	Label, Note, Target, Level string
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

	matching, gaps, warns, clearedN, small := 0, 0, 0, 0, 0
	var totalLost, totalOther uint64
	var clearedWho, smallWho []string
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
		if row.Checked && s.Checks.Fail == 0 {
			matching++
		}
		if s.Checks != nil {
			gaps += s.Checks.Fail
			warns += s.Checks.Warn
		}

		// Gaps, as rows of the Gaps table.
		if n := len(cleared[h]); n > 0 {
			clearedN++
			clearedWho = append(clearedWho, s.Name)
			by := ""
			if u := cleared[h][0].User; u != "" {
				by = " by " + u
			}
			addGap("cleared", GapCard{Title: "Logs cleared", Level: "bad",
				Explain: fmt.Sprintf("%s cleared%s on %s%s. Events from before then are only in the original-log archive.", clearedWhat(cleared[h]), times(n),
					cleared[h][0].Time.In(r.Location).Format("2 Jan 15:04"), by)}, s.Name)
		}
		if s.AuditOff != "" {
			addGap("auditoff", GapCard{Title: "Auditing is off", Level: "bad",
				Explain: "At the last collection auditing was not running (the audit service stopped, or kernel auditing switched off), so nothing was being recorded. Start it with systemctl start auditd, and auditctl -e 1 if kernel auditing is off. The system's own page says which."}, s.Name)
		}
		if s.Status == "silent" {
			addGap("silent", GapCard{Title: "No data received", Level: "bad",
				Explain: "No collection arrived in this period. Check the system is on and can reach the collector. If it no longer sends here (it was made standalone, or retired), remove it from the report with: blackbox systems remove <name>."}, s.Name)
		}
		if bs := blocked[h]; len(bs) > 0 {
			addGap("blocked", GapCard{Title: "Collection was blocked", Level: "bad",
				Explain: "Scheduled runs were refused because another Blackbox run held its lock, so nothing was collected or sent in that time. " +
					"The next run collected what the logs still held. A run that dies no longer leaves the lock behind; a run that hangs still holds it, and blackbox status says so."}, s.Name)
			c := gapCards["blocked"]
			for _, b := range bs {
				c.Explain += fmt.Sprintf(" %s: %s to %s, %s refused (PID %d).", s.Name, r.stamp(b.From), r.stamp(b.To), plural(b.Refused, "run"), b.PID)
			}
		}
		if lost[h] > 0 {
			totalLost += lost[h]
			addGap("lost", GapCard{Title: "Events lost to log rollover", Level: "bad",
				Explain: "The audit log filled up and overwrote events before Blackbox read them. " + rollover.NotInExports}, s.Name)
			gapCards["lost"].Explain += " " + lostAdvice(gapsOn[h], true)
		}
		if otherLost[h] > 0 {
			totalOther += otherLost[h]
			addGap("otherlost", GapCard{Title: "Other logs overwrote events", Level: "warn",
				Explain: "Not the audit record: a log Blackbox also reads (such as the PowerShell log, where script block logging writes large events) filled up and overwrote events before Blackbox read them. " + rollover.NotInExports}, s.Name)
			gapCards["otherlost"].Explain += " " + lostAdvice(gapsOn[h], false)
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
					if res.STIG == "" && res.Area == "Event log size" {
						explain = fmt.Sprintf("Set to %s; Blackbox recommends %s.", orDash(res.Have), orDash(res.Want))
					}
				}
				if res.Affects != "" {
					explain = strings.TrimSpace(explain + " Without it the report is missing: " + res.Affects + ".")
				}
				addGap("check|"+res.Item, GapCard{Title: res.Item, STIG: res.STIG, Explain: explain, Fix: res.Fix, Level: lv}, s.Name)
				addSTIG("check|"+res.Item, osLabel(s), res.STIG)
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
		if sc, ok := r.scapGlance(s.Name); ok {
			// The SCAP score up front: on a one-computer report this view
			// is all Audit health shows.
			f := Fact{Label: "SCAP score", Value: "no scan", Bad: true, Href: ScapHref(s.Name)}
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
		if ids := gapSTIGs[k]; len(ids) > 1 {
			var parts []string
			for _, s := range ids {
				parts = append(parts, s.ids+" ("+s.label+")")
			}
			gapCards[k].STIG, gapCards[k].STIGs = strings.Join(parts, " · "), parts
		}
		hp.Gaps = append(hp.Gaps, *gapCards[k])
	}
	// The original logs: not being archived, or parts lost or changed
	// before they were (AR5, AR6).
	if f := r.PackFailing; f != nil {
		hp.Gaps = append(hp.Gaps, GapCard{Title: "Original logs not archived", Level: "bad", Systems: []string{f.Host},
			Explain: f.Text(r.stamp),
			Fix:     "make the archive folder writable again (blackbox status shows the reason at every run); nothing is lost while the exports are kept."})
	}
	for _, l := range r.LeftOut {
		hp.Gaps = append(hp.Gaps, GapCard{Title: "Original logs not in the report", Level: "bad", Systems: []string{l.Host},
			Explain: l.Text(r.stamp),
			Fix:     "check the file set aside (blackbox status names it): a damaged disk or someone changing Blackbox's folder. Keep it with the report if it is sound."})
	}
	for _, a := range r.Archives {
		var lost, changed []string
		var missing []string
		for _, g := range a.Gaps {
			switch {
			case g.Records != "":
				missing = append(missing, g.Source+": "+g.Records)
			case g.Reason != "":
				lost = append(lost, g.Reason)
			}
		}
		if len(missing) > 0 {
			hp.Gaps = append(hp.Gaps, GapCard{Title: "Original logs incomplete", Level: "bad", Systems: []string{a.Host},
				Explain: "Records not in the log when it was exported, so not in " + a.Name + ": " + strings.Join(missing, "; ") + ". The logs are exported in record order, so this is not the clock: the log overwrote them first, or they were never written.",
				Fix:     "make the log larger (blackbox check gives the size); for audit serials, check auditd's lost count (auditctl -s)."})
		}
		for _, f := range a.Changed {
			changed = append(changed, f.Name)
		}
		if len(lost) > 0 {
			hp.Gaps = append(hp.Gaps, GapCard{Title: "Original logs incomplete", Level: "bad", Systems: []string{a.Host},
				Explain: "Exports deleted or unreadable before they were archived: " + strings.Join(lost, "; ") + ". Their events are in this report; the original copy of that time is not in " + a.Name + ".",
				Fix:     "find who or what removed them: Blackbox's own folder is only changed by Blackbox."})
		}
		if len(changed) > 0 {
			hp.Gaps = append(hp.Gaps, GapCard{Title: "Original logs changed before archiving", Level: "bad", Systems: []string{a.Host},
				Explain: "Changed after they were exported, and archived as found: " + strings.Join(changed, ", ") + " in " + a.Name + ". See Detections.",
				Fix:     "compare them with the events in this report, and find who could write to the Blackbox data folder."})
		}
	}
	if len(r.MissingReports) > 0 {
		g := GapCard{Title: "Earlier reports missing or changed", Level: "bad",
			Explain: "A scheduled report holds the only copy of its period's original logs and their hashes. These were deleted, moved or changed after they were written:"}
		for _, m := range r.MissingReports {
			what := "missing"
			if m.Problem == "changed" {
				what = "changed (its manifest no longer matches)"
				if m.What != "" {
					what = "changed (" + m.What + ")"
				}
			}
			g.Explain += fmt.Sprintf(" %s (%s to %s), %s;", m.Name, r.stamp(m.From), r.stamp(m.To), what)
		}
		g.Explain = strings.TrimSuffix(g.Explain, ";") + "."
		g.Fix = "restore them from the backup. If they were moved or removed on purpose, record why: blackbox reports accept <name> \"why\"."
		hp.Gaps = append(hp.Gaps, g)
	}
	// Cleared logs, silence and lost events first, then settings; gaps
	// before warnings.
	prio := map[string]int{"Earlier reports missing or changed": 0, "Original logs changed before archiving": 0, "Original logs not archived": 1, "Original logs incomplete": 1, "Logs cleared": 0, "No data received": 1, "Collection was blocked": 2, "Events lost to log rollover": 2, "Other logs overwrote events": 3}
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
		{Icon: "shield-check", Label: "Systems matching STIG", Scroll: "h-matrix", Value: fmt.Sprintf("%d / %d", matching, total),
			Note: plural(gaps, "gap") + " · " + plural(warns, "warning"), Level: lvl(matching < total, "bad")},
		{Icon: "eraser", Label: "Logs cleared", Href: searchLink("page", "integrity", "text", "cleared"), Value: commas(clearedN), Note: short(set(clearedWho), 2), Level: lvl(clearedN > 0, "bad")},
		{Icon: "circle-check", Label: "Events lost to rollover", Scroll: "h-gaps", Value: commas(int(totalLost)), Note: lostNote(totalOther, r.Health.Runs), Level: lvl(totalLost > 0, "bad")},
		{Icon: "hard-drive", Label: "Log size and space settings", Scroll: "h-gaps", Value: commas(small), Note: short(set(smallWho), 1), Level: lvl(small > 0, "warn")},
	}
	hp.fold()
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

// fold splits the grid into systems that need attention and those that
// match on every check, and builds the jump bar.
func (hp *HealthPage) fold() {
	needs := 0
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
		needs += len(att)
		hp.PassingN += len(pass)
	}
	lvl := func(bad bool, l string) string {
		if bad {
			return l
		}
		return ""
	}
	note := "all match"
	if needs > 0 {
		note = fmt.Sprintf("%d of %d need attention", needs, needs+hp.PassingN)
	}
	hp.Jump = append(hp.Jump, JumpLink{Label: "Audit settings by system", Note: note, Target: "h-matrix", Level: lvl(needs > 0, "bad")},
		JumpLink{Label: "Gaps", Note: commas(len(hp.Gaps)), Target: "h-gaps", Level: lvl(len(hp.Gaps) > 0, "bad")})
	if len(hp.AV) > 0 {
		// UI13: "not checked" (no antivirus found, or nothing read) is
		// counted too, never "all current".
		bad, unchecked := 0, 0
		for _, a := range hp.AV {
			switch a.Level {
			case "bad":
				bad++
			case "warn":
				unchecked++
			}
		}
		var parts []string
		if bad > 0 {
			parts = append(parts, fmt.Sprintf("%d out of date", bad))
		}
		if unchecked > 0 {
			parts = append(parts, fmt.Sprintf("%d not checked", unchecked))
		}
		n := "all current"
		if len(parts) > 0 {
			n = strings.Join(parts, " · ")
		}
		level := lvl(unchecked > 0, "warn")
		if bad > 0 {
			level = "bad"
		}
		hp.Jump = append(hp.Jump, JumpLink{Label: "Antivirus", Note: n, Target: "h-av", Level: level})
	}
	if hp.Scap != nil {
		cat1, missing := 0, len(hp.Scap.Missing)
		for _, row := range hp.Scap.Main {
			cat1 += row.Cat[1]
		}
		n := fmt.Sprintf("%d open CAT I", cat1)
		var low string
		lowV, scored := 101.0, 0
		for _, row := range hp.Scap.Main {
			var v float64
			if _, err := fmt.Sscanf(row.Score, "%f%%", &v); err == nil {
				scored++
				if v < lowV {
					lowV, low = v, row.Score
				}
			}
		}
		switch {
		case scored == 1:
			n = "score " + low + " · " + n
		case scored > 1:
			n = "lowest score " + low + " · " + n
		}
		if missing > 0 {
			n += fmt.Sprintf(" · %d not scanned", missing)
		}
		hp.Jump = append(hp.Jump, JumpLink{Label: "STIG compliance (SCAP)", Note: n, Target: "h-scap", Level: lvl(cat1 > 0, "bad")})
	}
	if len(hp.Other) > 0 {
		hp.Jump = append(hp.Jump, JumpLink{Label: "Other Security-log events", Note: commas(len(hp.Other)) + " kinds", Target: "h-other"})
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

// lostAdvice is, for each log on a system that lost events, how many and
// what to do (the latest gap's advice: the log's size and rate then).
func lostAdvice(gaps []GapItem, critical bool) string {
	last := map[string]GapItem{}
	total := map[string]uint64{}
	var order []string
	for _, g := range gaps {
		if rollover.Critical(g.Channel) != critical {
			continue
		}
		if _, ok := last[g.Channel]; !ok {
			order = append(order, g.Channel)
		}
		total[g.Channel] += g.Lost
		if prev := last[g.Channel]; prev.Held == 0 || (g.Held > 0 && g.Held < prev.Held) {
			last[g.Channel] = g // the fastest turnover says most
		}
	}
	var parts []string
	for _, ch := range order {
		g := last[ch]
		parts = append(parts, fmt.Sprintf("%s on %s: %s overwritten. %s", rollover.Name(ch), g.Host, plural(int(total[ch]), "event"), g.Loss().Advice(false)))
	}
	return strings.Join(parts, " ")
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
