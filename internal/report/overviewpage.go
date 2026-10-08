package report

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/rollover"
)

// The Overview page (UI-R1, design 01 layout A): what needs review in one
// line, the report's numbers in one row, the detections and the things
// that need attention one line each, events per hour, and the systems
// with a problem.

// Overview is everything the Overview page shows.
type Overview struct {
	// PeriodNoun is "week" or "period" (see Report.periodNoun).
	PeriodNoun string
	Standalone bool

	// Review is "Needs review: 4 high detections, 2 systems not
	// reporting", or "Nothing needs review" (Clean); ReviewDetail the
	// most serious facts in a sentence or two.
	Review, ReviewDetail string
	Clean                bool

	Strip []StripCell

	// Dets are up to eight detections, high first then newest; DetMore
	// the link to all of them.
	Dets      []ListItem
	High, Med int
	DetMore   string

	// Attention is one line per kind of problem; Fine what is fine, in
	// one line.
	Attention []AttnLine
	Fine      string
	// Checks are the health checklist's lines (the printed summary).
	Checks []CheckLine

	Activity *ActivityChart

	// Glance are the systems with a problem (a red check or a high
	// detection, systemLevel), grouped;
	// GlanceMore says how many others there are.
	Glance     []Group[GlanceRow]
	GlanceMore string
	levels     map[string]string // each system's level (systemLevel), as Systems has it
	SystemsN   int
}

// StripCell is one number of the Overview's number strip.
type StripCell struct {
	Label, Value, Note, Href string
	Bad                      bool
}

// AttnLine is one line of Needs attention: a kind of problem, a short
// reason, and the systems (named when one or two, else counted).
type AttnLine struct {
	Level, Title, Reason, Count, Href string
}

// GlanceRow is one system in Systems at a glance.
type GlanceRow struct {
	Name, Href, Line, Events string
	Reason                   string // why it is a problem when no check is red: its high detection
	Cells                    []CheckCell
	Level                    string
}

// ActivityChart is events per hour (or per day, over a long period),
// Windows and Linux stacked, a red dot where a detection was.
type ActivityChart struct {
	Unit   string // "hour" or "day"
	Bars   []HourBar
	Labels []AxisLabel
	Dense  bool // too many bars for gaps between them
	Total  int
}

// HourBar is one bar of the activity chart. Href opens Search for its
// time; Win and Lin are the two parts' heights (template.CSS).
type HourBar struct {
	Href, Title string
	Win, Lin    template.CSS
	N           int
	Det         bool
}

// AxisLabel is a label under the chart, at Left (template.CSS).
type AxisLabel struct {
	Text string
	Left template.CSS
}

// GlanceCol is a column of Systems at a glance: its heading, and the
// short one a phone shows.
type GlanceCol struct{ Name, Short string }

// glanceChecks are the columns of Systems at a glance.
var glanceChecks = []GlanceCol{{"Reporting", "Rep."}, {"Logs intact", "Logs"}, {"Settings", "Set."}, {"Antivirus", "AV"}, {"Orig. logs", "Orig."}, {"SCAP", "SCAP"}}

// GlanceChecks are the column headings, for the template.
func (o *Overview) GlanceChecks() []GlanceCol { return glanceChecks }

// overview builds the Overview page.
func (r *Report) overview(pages []*EventPage) *Overview {
	o := &Overview{PeriodNoun: r.periodNoun(), Standalone: !r.IsLAN(), levels: map[string]string{}}
	systems := r.SystemRows
	if len(systems) == 0 {
		for _, h := range r.Hosts {
			systems = append(systems, SystemRow{SystemInfo: SystemInfo{Name: h}, Status: "ok"})
		}
	}
	clearRows := map[string][]*Row{}
	for _, row := range r.rows {
		if row.Action == "log_cleared" {
			// By lower-case name: a system's name and its rows' can
			// differ in case (UX10).
			h := strings.ToLower(row.Host)
			clearRows[h] = append(clearRows[h], row)
		}
	}
	for _, f := range r.Findings {
		if f.Severity == event.SevHigh {
			o.High++
		} else {
			o.Med++
		}
	}
	o.Checks = r.checklist(systems, clearRows)
	cells := r.glanceCells(systems, clearRows)

	o.review(r, systems)
	o.Strip = r.overviewStrip(systems, pages, o.High, o.Med)
	o.Dets, o.DetMore = r.overviewDetections()
	o.Attention, o.Fine = r.attention(o.Checks, systems, cells)
	o.Activity = r.activityChart()

	// Systems at a glance: only those with a problem, a red check or a
	// high detection (systemLevel, as the Systems page counts them).
	var rows []GlanceRow
	warn, ok := 0, 0
	dets := r.detsBySystem()
	for _, s := range systems {
		cs := cells[s.Name]
		d := dets[strings.ToLower(s.Name)]
		if d == nil {
			d = &sysDets{}
		}
		level := systemLevel(cs, d.High, d.Med)
		o.levels[s.Name] = level
		switch level {
		case "bad":
		case "warn":
			warn++
			continue
		default:
			ok++
			continue
		}
		// A system that is a problem only for a high detection says so.
		reason := ""
		red := false
		for _, c := range cs {
			red = red || c.Level == "bad"
		}
		if !red && d.FirstHigh != "" {
			reason = "High detection: " + strings.TrimSuffix(d.FirstHigh, " on "+s.Name)
			if d.High > 1 {
				reason += fmt.Sprintf(" +%d more", d.High-1)
			}
		}
		line := osLabel(s) + " · " + map[string]string{"server": "Server", "workstation": "Workstation", "vm": "Virtual machine"}[systemKind(s)]
		if n := d.High + d.Med; n > 0 {
			line += fmt.Sprintf(" · %d det.", n)
		}
		ev := commas(s.Events)
		if s.Events == 0 && !s.reporting() {
			ev = "—"
		}
		rows = append(rows, GlanceRow{Name: s.Name, Href: systemLink(s.Name), Line: line, Reason: reason, Events: ev, Cells: cs, Level: level})
	}
	sort.SliceStable(rows, func(i, j int) bool { return naturalLess(rows[i].Name, rows[j].Name) })
	o.Glance = groupByKind(rows, func(g GlanceRow) string { return r.hostKind(g.Name) })
	CountProblems(o.Glance, func(g GlanceRow) string { return g.Level })
	o.SystemsN = len(systems)
	if n := warn + ok; n > 0 {
		var what []string
		if warn > 0 {
			what = append(what, fmt.Sprintf("%d with %s", warn, map[bool]string{true: "a warning", false: "warnings"}[warn == 1]))
		}
		if ok > 0 {
			what = append(what, fmt.Sprintf("%d all OK", ok))
		}
		if len(rows) == 0 {
			o.GlanceMore = fmt.Sprintf("No system has a problem (%s).", strings.Join(what, ", "))
		} else {
			o.GlanceMore = foldText(n, "systems", "with no problems", strings.Join(what, ", ")) + "."
		}
	}
	return o
}

// review sets the summary line: what needs review, and the most serious
// facts in a sentence or two.
func (o *Overview) review(r *Report, systems []SystemRow) {
	var parts, facts []string
	if o.High > 0 {
		parts = append(parts, plural(o.High, "high detection"))
		// The most serious two: hiding tracks first, then new access,
		// newest first within each.
		var hi []Finding
		for _, f := range r.Findings {
			if f.Severity == event.SevHigh {
				hi = append(hi, f)
			}
		}
		sort.SliceStable(hi, func(i, j int) bool {
			a, b := r.detRank(hi[i]), r.detRank(hi[j])
			if a != b {
				return a < b
			}
			return hi[i].Time.After(hi[j].Time)
		})
		for _, f := range hi {
			if len(facts) == 2 {
				break
			}
			if s := firstSentence(f.Detail); s != "" {
				facts = append(facts, s)
			}
		}
	}
	var silent []string
	var last time.Time
	for _, s := range systems {
		if !s.reporting() {
			silent = append(silent, s.Name)
			if s.LastRun.After(last) {
				last = s.LastRun
			}
		}
	}
	if len(silent) > 0 {
		parts = append(parts, plural(len(silent), "system")+" not reporting")
		verb := "has"
		if len(silent) > 1 {
			verb = "have"
		}
		since := "in this " + r.periodNoun()
		if !last.IsZero() {
			since = "since " + last.In(r.Location).Format("2 Jan")
		}
		facts = append(facts, fmt.Sprintf("%s %s sent nothing %s.", nameList(silent, 2), verb, since))
	}
	var lostOn []string
	for _, g := range r.Health.Gaps {
		if g.Lost > 0 && rollover.Critical(g.Channel) && !containsFold(lostOn, g.Host) {
			lostOn = append(lostOn, g.Host)
		}
	}
	if len(lostOn) > 0 {
		parts = append(parts, "audit events lost on "+plural(len(lostOn), "system"))
	}
	if r.PackFailing != nil {
		parts = append(parts, "original logs not archived")
	}
	if len(parts) == 0 && o.Med > 0 {
		parts = append(parts, plural(o.Med, "medium detection"))
	}
	if len(parts) == 0 {
		o.Clean = true
		o.Review = "Nothing needs review"
		o.ReviewDetail = "No detection rule matched, every system reported and no audit events were lost this " + r.periodNoun() + "."
		return
	}
	o.Review = "Needs review: " + strings.Join(parts, ", ")
	o.ReviewDetail = strings.Join(facts, " ")
}

// detRank orders detections for the summary sentence: logs cleared or
// auditing changed (0), new access (1), anything else (2).
func (r *Report) detRank(f Finding) int {
	rank := 2
	for _, id := range append([]string{f.RowID}, f.RowIDs...) {
		i := rowIndex(id)
		if i < 0 || i >= len(r.rows) {
			continue
		}
		a := r.rows[i].Action
		switch {
		case a == "log_cleared" || a == "log_tampered" || strings.HasPrefix(a, "audit_"):
			return 0
		case a == "group_member_added" || a == "account_created" || a == "sudoers_changed":
			rank = 1
		}
	}
	return rank
}

// overviewStrip is the number strip: detections, systems reporting,
// events, audit settings.
func (r *Report) overviewStrip(systems []SystemRow, pages []*EventPage, high, med int) []StripCell {
	var out []StripCell
	n := len(r.Findings)
	d := StripCell{Label: "Detections", Value: commas(n), Href: "#detections", Bad: n > 0, Note: fmt.Sprintf("%d high · %d medium", high, med)}
	if n == 0 {
		d.Note = "none this " + r.periodNoun()
	}
	out = append(out, d)
	rep := 0
	for _, s := range systems {
		if s.reporting() {
			rep++
		}
	}
	sr := StripCell{Label: "Systems reporting", Value: fmt.Sprintf("%d / %d", rep, len(systems)), Href: "#systems", Bad: rep < len(systems), Note: "all reporting"}
	if rep < len(systems) {
		sr.Note = fmt.Sprintf("%d silent", len(systems)-rep)
	}
	out = append(out, sr)
	total := map[string]int{} // as the sidebar's kinds of event count them
	for _, k := range eventKinds(pages) {
		total[k.ID] = k.Total
	}
	out = append(out, StripCell{Label: "Events", Value: commas(len(r.Events)), Href: "#search",
		Note: fmt.Sprintf("%s privileged · %s logons", commas(total["privileged"]), commas(total["logons"]))})
	checked, matching, fix := 0, 0, 0
	for _, s := range systems {
		if s.Checks != nil {
			checked++
			fix += s.Checks.STIGFail
			if s.Checks.STIGFail == 0 { // STIG rules only, not Blackbox's advice (COMP2)
				matching++
			}
		}
	}
	a := StripCell{Label: "Audit settings", Value: fmt.Sprintf("%d / %d", matching, checked), Href: "#health", Bad: matching < checked, Note: "match the STIG"}
	if fix > 0 {
		a.Note += " · " + commas(fix) + " to fix"
	}
	if checked == 0 {
		a.Value, a.Note = "—", "not checked in this report"
	}
	return append(out, a)
}

// overviewDetections are the Overview's detections: up to eight, high
// first then newest, each one line; and the link to all of them.
func (r *Report) overviewDetections() ([]ListItem, string) {
	cards := r.detectionCards() // newest first
	sort.SliceStable(cards, func(i, j int) bool { return cards[i].Severity == "high" && cards[j].Severity != "high" })
	multiDay := len(r.periodDays()) > 1
	var out []ListItem
	moreHigh, moreMed := 0, 0
	for i, c := range cards {
		if i >= 8 {
			if c.Severity == "high" {
				moreHigh++
			} else {
				moreMed++
			}
			continue
		}
		f := r.Findings[c.Index]
		out = append(out, ListItem{Title: shortTitle(f.Title, f.Host), Reason: shortReason(f.Detail), System: f.Host,
			Time: r.detTime(f, c, multiDay), Href: fmt.Sprintf("#detections/%d", c.Index), Level: map[bool]string{true: "bad", false: "warn"}[c.Severity == "high"]})
	}
	if len(cards) == 0 {
		return nil, ""
	}
	more := fmt.Sprintf("All %s →", plural(len(cards), "detection"))
	var m []string
	if moreHigh > 0 {
		m = append(m, fmt.Sprintf("%d more high", moreHigh))
	}
	if moreMed > 0 {
		m = append(m, fmt.Sprintf("%d more medium", moreMed))
	}
	if len(m) > 0 {
		more = fmt.Sprintf("All %s (%s) →", plural(len(cards), "detection"), strings.Join(m, ", "))
	}
	return out, more
}

// detTime is a detection's time in a list: "14:22", with the day when
// the period has more than one ("7 Oct 14:22"), or "at report" for one
// Blackbox's own check found when the report was made.
func (r *Report) detTime(f Finding, c DetectionCard, multiDay bool) string {
	if c.Day == FoundAtReport {
		return "at report"
	}
	if multiDay {
		return f.Time.In(r.Location).Format("2 Jan 15:04")
	}
	return f.Time.In(r.Location).Format("15:04")
}

// shortTitle is a detection's title without " on <its system>", which a
// list shows in its own column.
func shortTitle(title, host string) string {
	if host != "" {
		if t, ok := strings.CutSuffix(title, " on "+host); ok && t != "" {
			return t
		}
	}
	return title
}

// shortReason is a detection's detail cut to a short phrase for a
// one-line list: its first clause, at most about 70 characters.
func shortReason(s string) string {
	s = firstSentence(s)
	for _, cut := range []string{" (", "; "} {
		if i := strings.Index(s, cut); i > 20 {
			s = s[:i]
		}
	}
	s = strings.TrimSuffix(s, ".")
	if len(s) > 72 {
		i := strings.LastIndex(s[:70], " ")
		if i < 30 {
			i = 70
		}
		s = strings.TrimRight(s[:i], ",;:") + "…"
	}
	return s
}

// firstSentence is a text's first sentence, with its full stop.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i+1]
	}
	if s != "" && !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, ")") {
		s += "."
	}
	return s
}

// nameList is "a and b", or "a, b and 3 more" past max names.
func nameList(names []string, max int) string {
	switch {
	case len(names) == 0:
		return ""
	case len(names) == 1:
		return names[0]
	case len(names) <= max:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
	return strings.Join(names[:max], ", ") + fmt.Sprintf(" and %d more", len(names)-max)
}

func containsFold(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// glanceCells are each system's six check cells, the same squares as
// on the Systems page (sysChecks).
func (r *Report) glanceCells(systems []SystemRow, cleared map[string][]*Row) map[string][]CheckCell {
	cx := r.newCheckCtx(cleared)
	out := map[string][]CheckCell{}
	for _, s := range systems {
		got, want := r.collections(s)
		var cells []CheckCell
		for _, c := range r.sysChecks(s, cx, got, want) {
			cells = append(cells, c.CheckCell)
		}
		out[s.Name] = cells
	}
	return out
}

// attention is Needs attention, one line per kind of problem from the
// health checklist, and what is fine in one line.
func (r *Report) attention(checks []CheckLine, systems []SystemRow, cells map[string][]CheckCell) ([]AttnLine, string) {
	split := func(who string) []string {
		if who == "" {
			return nil
		}
		return strings.Split(who, ", ")
	}
	silent := map[string]bool{}
	var lastRun time.Time
	for _, s := range systems {
		if !s.reporting() {
			silent[strings.ToLower(s.Name)] = true
			if s.LastRun.After(lastRun) {
				lastRun = s.LastRun
			}
		}
	}
	var out []AttnLine
	var fine []string
	for _, c := range checks {
		if c.Level == "ok" {
			fine = append(fine, fineName(c.Title))
			continue
		}
		l := AttnLine{Level: c.Level, Title: c.Title, Reason: c.What, Href: c.Href}
		who := split(c.Who)
		switch c.Title {
		case "Logs cleared":
			l.Reason = strings.TrimSuffix(c.What, " cleared")
		case "Not every system reporting":
			l.Title = "Not reporting"
			if c.Level == "warn" {
				l.Reason = "a virtual machine sent nothing this " + r.periodNoun()
			} else if !lastRun.IsZero() {
				l.Reason = "nothing since " + lastRun.In(r.Location).Format("2 Jan")
			} else {
				l.Reason = "nothing this " + r.periodNoun()
			}
		case "Audit settings to fix":
			l.Title = "Audit settings"
			l.Reason, _, _ = strings.Cut(c.What, " · ")
		case "Audit settings not checked":
			l.Reason = "not checked this " + r.periodNoun()
		case "Events lost to log rollover":
			l.Title = "Events lost"
			l.Reason = strings.TrimSuffix(c.What, " before they were collected")
		case "Other logs overwrote events":
			l.Title = "Events overwritten"
			var names []string
			for _, g := range r.Health.Gaps {
				if g.Lost > 0 && !rollover.Critical(g.Channel) {
					if n := rollover.Name(g.Channel); !containsFold(names, n) {
						names = append(names, n)
					}
				}
			}
			l.Reason = strings.Join(names, ", ") + " too small"
			if len(names) == 1 && len(who) > 1 {
				l.Reason = strings.TrimSuffix(names[0], " log") + " logs too small"
			}
		case "Antivirus definitions":
			who = nil
			bad, out := false, 0
			for _, row := range r.avRows() {
				if row.Level != "ok" {
					who = append(who, row.Host)
					bad = bad || row.ProtectionBad
					if row.Status == "Out of date" {
						out++
					}
				}
			}
			l.Title, l.Reason, l.Level = "Antivirus out of date", "definitions out of date", "warn"
			if bad {
				l.Title, l.Reason, l.Level = "Antivirus not protecting", "protection off, or definitions out of date", "bad"
			} else if out == 0 {
				l.Title, l.Reason = "Antivirus not confirmed", "definitions date unknown, or none found"
			}
		case "Open CAT I findings", "STIG compliance (SCAP)":
			who = nil
			n := 0
			for _, row := range r.scapTable {
				switch {
				case c.Level == "bad" && row.Cat[1] > 0:
					n += row.Cat[1]
					who = append(who, row.Host)
				case c.Level != "bad" && (row.Missing || row.Stale):
					who = append(who, row.Host)
				}
			}
			who = uniq(who)
			if c.Level == "bad" {
				l.Title, l.Reason = "CAT I findings", fmt.Sprintf("%d open (SCAP)", n)
			} else {
				l.Title, l.Reason = "SCAP scans", "missing or out of date"
			}
		case "Original logs missing":
			all := len(who) > 0
			for _, h := range who {
				all = all && silent[strings.ToLower(h)]
			}
			l.Reason = "none for this " + r.periodNoun()
			if all {
				l.Reason = "the " + map[bool]string{true: "one", false: commas(len(who))}[len(who) == 1] + " not reporting"
			}
		case "Original logs not archived", "Original logs not in this report", "Original logs left out of a report":
			l.Reason = "archive failed its check"
		case "Earlier reports missing or changed":
			l.Reason = plural(len(r.MissingReports), "scheduled report") + " deleted, moved or changed"
		case "Older reports removed":
			l.Reason = fmt.Sprintf("%s deleted under retention_days = %d", plural(len(r.Removed), "report"), r.RetentionDays)
		case "Events arrived late":
			l.Reason = c.What
		case "Senders waiting for a decision":
			who = r.deliveryHosts(func(d *Delivery) bool { return d.Signed && (d.Held || d.NewKeyFP != "") })
			l.Reason = "deliveries not imported until approved or rekeyed (blackbox senders)"
		case "Two computers, one key":
			who = r.deliveryHosts(func(d *Delivery) bool { return d.Signed && d.SharedWith != "" })
			l.Reason = "one was copied from the other: blackbox send --new-id on the copy"
		case "New senders":
			who = r.deliveryHosts(func(d *Delivery) bool { return d.Signed && d.New && !d.Held && d.NewKeyFP == "" })
			l.Reason = "first delivery: compare each key with blackbox status there"
		case "Unsigned senders":
			l.Reason = "Blackbox before 0.24: upgrade them"
		}
		if strings.HasPrefix(l.Href, "#systems") && len(who) == 1 {
			l.Href = "#systems/" + who[0] // its page has the Delivery line
		}
		switch {
		case len(who) == 0:
		case len(who) <= 2:
			l.Count = strings.Join(who, ", ")
		default:
			l.Count = plural(len(who), "system")
		}
		out = append(out, l)
	}
	sort.SliceStable(out, func(i, j int) bool { return levelRank(out[i].Level) < levelRank(out[j].Level) })
	// Systems reporting normally: reporting, with their logs intact.
	normal := 0
	for _, s := range systems {
		if cs := cells[s.Name]; len(cs) > 1 && cs[0].Level != "bad" && cs[0].Level != "warn" && cs[1].Level == "ok" {
			normal++
		}
	}
	var keep []string
	for _, f := range fine {
		if f != "" {
			keep = append(keep, f)
		}
	}
	if len(systems) > 1 && normal > 0 {
		keep = append(keep, plural(normal, "system")+" reporting normally")
	}
	if len(keep) == 0 {
		return out, ""
	}
	return out, strings.Join(keep, " · ")
}

// fineName is a health line that is fine, as Needs attention's "Fine:"
// line names it ("" to leave it out: the systems reporting normally are
// counted instead).
func fineName(title string) string {
	switch title {
	case "Every system reporting":
		return ""
	case "No events lost from the audit logs":
		return "No Security or audit-log events lost"
	case "Antivirus definitions":
		return "Antivirus current"
	case "STIG compliance (SCAP)":
		return "No open CAT I findings"
	case "Audit settings match STIG":
		return "Audit settings match the STIG"
	case "Deliveries signed":
		return "All deliveries signed"
	}
	return title
}

// activityChart is the period's events per hour (per day over more than
// eight days), Windows and Linux stacked, with the hours that had a
// detection marked. Each bar opens Search for its time.
func (r *Report) activityChart() *ActivityChart {
	start, end := r.PeriodStart(), r.WindowEnd
	if end.IsZero() {
		end = r.LastEvent
	}
	if start.IsZero() || !end.After(start) {
		return nil
	}
	loc := r.Location
	step, unit := time.Hour, "hour"
	if end.Sub(start) > 8*24*time.Hour {
		step, unit = 24*time.Hour, "day"
	}
	first := start.In(loc).Truncate(time.Hour)
	if step > time.Hour {
		y, m, d := start.In(loc).Date()
		first = time.Date(y, m, d, 0, 0, 0, 0, loc)
	}
	n := int((end.Sub(first) + step - 1) / step)
	if n < 1 || n > 400 {
		return nil
	}
	at := func(t time.Time) int {
		if t.Before(first) || !t.Before(end) {
			return -1
		}
		if step > time.Hour { // calendar days, whatever the clock change
			y, m, d := t.In(loc).Date()
			return int(time.Date(y, m, d, 12, 0, 0, 0, loc).Sub(first) / step)
		}
		return int(t.Sub(first) / step)
	}
	win, lin := make([]int, n), make([]int, n)
	det := make([]bool, n)
	for _, row := range r.rows {
		i := at(row.Time)
		if i < 0 || i >= n {
			continue
		}
		if row.OS == "windows" {
			win[i]++
		} else {
			lin[i]++
		}
	}
	for _, f := range r.Findings {
		if i := at(f.Time); i >= 0 && i < n {
			det[i] = true
		}
	}
	top := 1
	for i := range win {
		top = max(top, win[i]+lin[i])
	}
	c := &ActivityChart{Unit: unit, Dense: n > 48}
	for i := 0; i < n; i++ {
		a := first.Add(time.Duration(i) * step)
		z := a.Add(step)
		if step > time.Hour {
			a = time.Date(first.Year(), first.Month(), first.Day()+i, 0, 0, 0, 0, loc)
			z = time.Date(first.Year(), first.Month(), first.Day()+i+1, 0, 0, 0, 0, loc)
		}
		b := HourBar{N: win[i] + lin[i], Det: det[i],
			Win: template.CSS(fmt.Sprintf("height:%.1f%%", float64(win[i])*100/float64(top))),
			Lin: template.CSS(fmt.Sprintf("height:%.1f%%", float64(lin[i])*100/float64(top)))}
		c.Total += b.N
		label := a.In(loc).Format("Mon 2 Jan 15:04") + "–" + z.In(loc).Format("15:04")
		if step > time.Hour {
			label = a.In(loc).Format("Mon 2 Jan")
		}
		b.Title = fmt.Sprintf("%s: %s (%s Windows, %s Linux)", label, plural(b.N, "event"), commas(win[i]), commas(lin[i]))
		if b.Det {
			b.Title += " · a detection"
		}
		if b.N > 0 {
			// Search's when: the hour (YYYYMMDDHH), or the day for a per-day bar.
			when := a.In(loc).Format("2006010215")
			if step > time.Hour {
				when = a.In(loc).Format("20060102")
			}
			b.Href = searchLink("when", when)
		}
		c.Bars = append(c.Bars, b)
	}
	// Labels: the times of day over a day or two, else up to eight days.
	pos := func(i int) template.CSS { return template.CSS(fmt.Sprintf("left:%.2f%%", float64(i)*100/float64(n))) }
	switch {
	case step == time.Hour && n <= 48:
		for i := 0; i <= n; i++ {
			t := first.Add(time.Duration(i) * time.Hour).In(loc)
			if t.Hour()%6 == 0 {
				txt := t.Format("15:04")
				if i == n && t.Hour() == 0 {
					txt = "24:00"
				}
				if n > 24 && t.Hour() == 0 && i < n {
					txt = t.Format("2 Jan")
				}
				c.Labels = append(c.Labels, AxisLabel{Text: txt, Left: pos(i)})
			}
		}
	default:
		per := 1
		if step == time.Hour {
			per = 24
		}
		days := (n + per - 1) / per
		every := max(1, (days+7)/8)
		for d := 0; d < days; d += every {
			i := d * per
			if step == time.Hour {
				// The day starts at local midnight.
				t := first.In(loc)
				day := time.Date(t.Year(), t.Month(), t.Day()+d, 0, 0, 0, 0, loc)
				if d == 0 && t.Hour() != 0 {
					day = t
				}
				i = int(day.Sub(first) / time.Hour)
				c.Labels = append(c.Labels, AxisLabel{Text: day.Format("Mon 2 Jan"), Left: pos(i)})
				continue
			}
			c.Labels = append(c.Labels, AxisLabel{Text: first.AddDate(0, 0, d).Format("2 Jan"), Left: pos(i)})
		}
	}
	return c
}
