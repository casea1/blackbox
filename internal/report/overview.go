package report

import (
	"fmt"
	"github.com/casea1/blackbox/internal/rollover"
	"html/template"
	"slices"
	"sort"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// The Overview page (design M2, docs/redesign/SPEC.md).

// KPI is one of the four main stat cards.
type KPI struct {
	Label, Value, Note, Href string
	Bad                      bool
	Spark                    template.HTML
}

// EventCard is one of the important-event cards.
type EventCard struct {
	Icon, Label, Value, Note string
	Level                    string // "bad", "warn", "" or "zero"
	Href                     string
	// Filter, on an event page, filters the table below instead of going
	// elsewhere: a query string of kind, sev, host, user, day, text or
	// flag ("all" clears the filters). Scroll goes to an element on the
	// same page.
	Filter, Scroll string
}

// CheckLine is one line of a health checklist.
type CheckLine struct {
	Level string // ok | warn | bad
	Icon  string
	Title string
	Who   string // the system named, if one fails
	What  string
	Count string // e.g. "23/24"
	Href  string // where it leads
	Ev    string // or: an event to open (see evRef)
}

// MapTile is one system on the system map.
type MapTile struct {
	Name, OS, Level string
	VM              bool
}

// MapGroup is a group of tiles: Servers, Workstations or Virtual machines.
type MapGroup struct {
	Title string
	Tiles []MapTile
}

// DetectionCard is one detection in a list grouped by day.
type DetectionCard struct {
	Day                           string
	Severity, Title, Detail, Host string
	Time                          string
	Index                         int    // position in Findings, for links
	Slots                         string // on a person's page: the weekday-hour slots (heatmap) it involved them
}

// SmallTrend is one of the Overview's twelve-week charts.
type SmallTrend struct {
	Title, Note string
	From, To    string // the x-axis ends: the first week shown, and this week
	Chart       template.HTML
}

// Overview is everything the Overview page shows.
type Overview struct {
	Alert       string
	AlertDetail string
	KPIs        []KPI
	Cards       []EventCard
	OK, Warn    int
	Bad         int
	Checks      []CheckLine
	Map         []MapGroup
	Systems     []SystemCard // standalone: one card per system
	Detections  []DetectionCard
	High, Med   int
	Trends      []SmallTrend
	Changes     []Change // What changed: the biggest moves against earlier weeks
	HistoryN    int      // complete weeks compared with (0: not enough history)
	TrendSpan   string   // "last 6 weeks · 1 Sep – 12 Oct 2026"
	Standalone  bool
}

// SystemCard is a standalone report's card for its computer or VM.
type SystemCard struct {
	Name, OS, Role, Status string
	Bad, VM                bool
	Events, Detections     string
	DetectionsBad          bool
	Collected, Settings    string
	SettingsBad            bool
}

func osLabel(s SystemRow) string {
	if s.Checks != nil && s.Checks.Baseline != "" {
		b := s.Checks.Baseline
		if i := strings.Index(b, " STIG"); i > 0 {
			b = b[:i]
			if j := strings.Index(b, " ("); j > 0 && !strings.Contains(b[j:], ")") {
				b = b[:j] // "Alma 8 (RHEL 8 STIG)" → "Alma 8"
			}
			return b
		}
		return b
	}
	return s.OSName()
}

// isServer reports a Windows Server or an Alma/RHEL computer.
func isServer(s SystemRow) bool {
	if s.Checks == nil {
		return false
	}
	b := s.Checks.Baseline
	return strings.Contains(b, "Server") || strings.Contains(b, "RHEL") || strings.Contains(b, "Alma")
}

// overview builds the Overview page.
func (r *Report) overview(pages []*EventPage) *Overview {
	o := &Overview{}
	m := r.metrics()
	byHost := map[string]int{} // logs cleared, per computer
	people := map[string]bool{}
	for _, row := range r.rows {
		if row.Action == "log_cleared" {
			byHost[row.Host]++
		}
		if row.Category == event.CatPrivileged && person(row.User) {
			people[strings.ToLower(row.User)] = true
		}
	}
	systems := r.SystemRows
	if len(systems) == 0 {
		for _, h := range r.Hosts {
			systems = append(systems, SystemRow{SystemInfo: SystemInfo{Name: h}, Status: "ok"})
		}
	}
	o.Standalone = !r.IsLAN()

	// Level of each computer: a cleared log or silence is a problem.
	level := map[string]string{}
	for _, s := range systems {
		switch {
		case s.Status == "silent" || byHost[s.Name] > 0:
			level[s.Name] = "bad"
			o.Bad++
		case s.Status == "warn":
			level[s.Name] = "warn"
			o.Warn++
		default:
			level[s.Name] = "ok"
			o.OK++
		}
	}

	// Alert bar: the problems, in a sentence.
	var probs []string
	for _, s := range systems {
		switch {
		case byHost[s.Name] > 0:
			probs = append(probs, fmt.Sprintf("%s: Security log cleared%s", s.Name, times(byHost[s.Name])))
		case s.Status == "silent":
			probs = append(probs, s.Name+": no collection received")
		}
	}
	if len(probs) > 0 {
		o.Alert = fmt.Sprintf("%d %s attention.", len(probs), map[bool]string{true: "system needs", false: "systems need"}[len(probs) == 1])
		o.AlertDetail = strings.Join(probs, " · ")
	}

	// Main stat cards.
	total := len(systems)
	rep := m[MSystems]
	o.KPIs = append(o.KPIs, KPI{Label: "Systems reporting", Href: "#systems", Value: fmt.Sprintf("%d / %d", rep, total), Bad: rep < total,
		Note: silentNote(systems), Spark: r.weekSpark(MSystems, rep < total)})
	high, med := 0, 0
	for _, f := range r.Findings {
		if f.Severity == event.SevHigh {
			high++
		} else {
			med++
		}
	}
	o.High, o.Med = high, med
	o.KPIs = append(o.KPIs, KPI{Label: "Detections", Href: "#detections", Value: commas(len(r.Findings)), Bad: len(r.Findings) > 0,
		Note: map[bool]string{true: "none this " + map[bool]string{true: "week", false: "period"}[r.Period == "weekly" || r.Period == ""], false: fmt.Sprintf("%d high · %d medium", high, med)}[len(r.Findings) == 0], Spark: r.weekSpark(MDetections, len(r.Findings) > 0)})
	o.KPIs = append(o.KPIs, KPI{Label: "Events collected", Href: "#search", Value: shortCount(len(r.Events)), Note: r.vsAverage(MEvents),
		Spark: r.weekSpark(MEvents, false)})
	o.KPIs = append(o.KPIs, KPI{Label: "Privileged actions", Href: "#privileged", Value: commas(m[MPrivileged]),
		Note:  fmt.Sprintf("by %d %s", len(people), map[bool]string{true: "person", false: "people"}[len(people) == 1]),
		Spark: r.weekSpark(MPrivileged, false)})

	// Important-event cards.
	where := func(action string, newAdmin bool) string {
		hosts := map[string]bool{}
		var last string
		for _, row := range r.rows {
			if row.Action == action && (!newAdmin || row.Severity == event.SevHigh) {
				hosts[row.Host] = true
				last = row.Host
			}
		}
		switch len(hosts) {
		case 0:
			return ""
		case 1:
			return last
		}
		return fmt.Sprintf("%d systems", len(hosts))
	}
	card := func(icon, label, metric, level, note, href string) {
		v := m[metric]
		lv := level
		if v == 0 {
			lv = "zero"
		}
		o.Cards = append(o.Cards, EventCard{Icon: icon, Label: label, Value: commas(v), Note: note, Level: lv, Href: href})
	}
	card("eraser", "Logs cleared", MLogsCleared, "bad", where("log_cleared", false), "#integrity")
	card("user-plus", "New admins", MNewAdmins, "bad", where("group_member_added", true), "#accounts")
	card("settings", "Policy changes", MPolicyChanges, "warn", where("audit_policy_changed", false), "#integrity")
	lockNote := where("account_locked", false)
	if t := r.metricTrend(MLockouts); t.OK && lockNote == "" {
		lockNote = fmt.Sprintf("normal: %.0f a week", t.Avg)
	}
	card("lock", "Lockouts", MLockouts, "warn", lockNote, "#failed")
	card("moon", "After-hours admin", MAfterHours, "warn", afterHoursNote(r), "#privileged")
	card("usb", "New USB devices", MNewUSB, "", commas(m[MUSB])+" events", "#usb")

	// Health checklist.
	o.Checks = r.checklist(systems, byHost)

	// System map or (standalone) system cards.
	if o.Standalone {
		for _, s := range systems {
			c := SystemCard{Name: s.Name, OS: osLabel(s), VM: s.VM, Events: commas(s.Events)}
			c.Role = "standalone"
			if s.VM {
				c.Role = "virtual machine on " + r.MainSystem()
			}
			c.Bad = level[s.Name] != "ok"
			c.Status = map[bool]string{true: "Needs attention", false: "Healthy"}[c.Bad]
			n := 0
			for _, f := range r.Findings {
				if strings.EqualFold(f.Host, s.Name) {
					n++
				}
			}
			c.Detections, c.DetectionsBad = commas(n), n > 0
			c.Collected = "this period"
			if s.Status == "silent" {
				c.Collected = "nothing received"
			} else if s.VM && s.Runs == 0 {
				c.Collected = "nothing received"
			} else if s.VM {
				c.Collected = "while on"
			}
			c.Settings = "not checked"
			if s.Checks != nil {
				if s.Checks.Fail > 0 {
					c.Settings, c.SettingsBad = fmt.Sprintf("%d %s", s.Checks.Fail, map[bool]string{true: "gap", false: "gaps"}[s.Checks.Fail == 1]), true
				} else {
					c.Settings = "Match STIG"
				}
			}
			o.Systems = append(o.Systems, c)
		}
	} else {
		groups := []*MapGroup{{Title: "Servers"}, {Title: "Workstations"}, {Title: "Virtual machines"}}
		for _, s := range systems {
			t := MapTile{Name: s.Name, OS: shortOS(s), Level: level[s.Name], VM: s.VM}
			if t.Level == "ok" {
				t.Level = ""
			}
			g := groups[1]
			switch {
			case s.VM:
				g = groups[2]
			case isServer(s):
				g = groups[0]
			}
			g.Tiles = append(g.Tiles, t)
		}
		for _, g := range groups {
			sort.SliceStable(g.Tiles, func(i, j int) bool { return naturalLess(g.Tiles[i].Name, g.Tiles[j].Name) })
			if len(g.Tiles) > 0 {
				o.Map = append(o.Map, *g)
			}
		}
	}

	// Detections, newest first, grouped by day.
	o.Detections = r.detectionCards()

	// Trends, by calendar week (UI1).
	o.Changes = r.whatChanged()
	if t := r.metricTrend(MEvents); t.OK {
		o.HistoryN = t.Complete
	}
	ws := r.weeks()
	o.TrendSpan = "last " + r.weeksCrumb()
	if c := ws[len(ws)-1]; c.Current {
		o.TrendSpan += " · this week: " + trimFloat(c.Days) + " of 7 days so far"
	}
	small := func(title, metric string, bad bool) SmallTrend {
		t := r.metricTrend(metric)
		st := SmallTrend{Title: title, From: "Week of " + ws[0].Start.In(r.Location).Format("2 Jan"), To: "This week (so far)",
			Note: commas(t.Now) + " so far"}
		if !ws[len(ws)-1].Current {
			st.Note = commas(t.Now) + " last week"
		}
		if t.OK {
			st.Note += " · avg " + shortNum(t.Avg) + "/wk"
			st.Chart = sparkline(t.Values, bad, 300, 70)
		}
		return st
	}
	o.Trends = []SmallTrend{small("High-severity events", MHighEvents, true), small("Failed logons", MFailedLogons, false),
		small("Privileged actions", MPrivileged, false)}
	return o
}

// checklist is the six-line health checklist.
func (r *Report) checklist(systems []SystemRow, cleared map[string]int) []CheckLine {
	total := len(systems)
	frac := func(bad int) string { return fmt.Sprintf("%d/%d", total-bad, total) }
	var lines []CheckLine

	var who []string
	for _, s := range systems {
		if cleared[s.Name] > 0 {
			who = append(who, s.Name)
		}
	}
	if len(who) > 0 {
		lines = append(lines, CheckLine{Level: "bad", Icon: "file-warning", Title: "Logs cleared", Who: strings.Join(who, ", "), What: "Security log cleared", Count: frac(len(who))})
	} else {
		lines = append(lines, CheckLine{Level: "ok", Icon: "file-warning", Title: "Logs intact", What: "No logs cleared", Count: frac(0)})
	}

	who = nil
	var since string
	for _, s := range systems {
		if s.Status == "silent" {
			who = append(who, s.Name)
			if !s.LastRun.IsZero() {
				since = "no data since " + s.LastRun.In(r.Location).Format("2 Jan 15:04")
			}
		}
	}
	if len(who) > 0 {
		if since == "" || len(who) > 1 {
			since = "no data in this period"
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "clock-alert", Title: "Not every system reporting", Who: strings.Join(who, ", "), What: since, Count: frac(len(who))})
	} else {
		what := "Every system sent its events"
		var quiet []string
		for _, s := range systems {
			if s.VM && s.Runs == 0 {
				quiet = append(quiet, s.Name)
			} else if s.VM {
				what = "VMs reported whenever they were on"
			}
		}
		if len(quiet) > 0 {
			lines = append(lines, CheckLine{Level: "warn", Icon: "clock-alert", Title: "Not every system reporting", Who: strings.Join(quiet, ", "),
				What: "Worth a look: a virtual machine sent nothing this period", Count: frac(len(quiet))})
		} else {
			lines = append(lines, CheckLine{Level: "ok", Icon: "clock-alert", Title: "Every system reporting", What: what, Count: frac(0)})
		}
	}

	if r.Late > 0 {
		lines = append(lines, CheckLine{Level: "warn", Icon: "history", Title: "Events arrived late", What: fmt.Sprintf("%s arrived late · nothing lost", plural(r.Late, "event")), Count: ""})
	} else {
		lines = append(lines, CheckLine{Level: "ok", Icon: "history", Title: "Reports on time", What: "All on time", Count: frac(0)})
	}

	who = nil
	gaps := 0
	checked := 0
	for _, s := range systems {
		if s.Checks != nil {
			checked++
			if s.Checks.Fail > 0 {
				who = append(who, s.Name)
				gaps += s.Checks.Fail
			}
		}
	}
	switch {
	case len(who) > 0:
		lines = append(lines, CheckLine{Level: "warn", Icon: "shield-check", Title: "Audit settings to fix", Who: strings.Join(who, ", "),
			What: fmt.Sprintf("%s to fix · see Audit health", plural(gaps, "setting")), Count: frac(len(who))})
	case checked == 0:
		lines = append(lines, CheckLine{Level: "warn", Icon: "shield-check", Title: "Audit settings not checked", What: "Not checked in this period", Count: ""})
	default:
		lines = append(lines, CheckLine{Level: "ok", Icon: "shield-check", Title: "Audit settings match STIG", What: "All systems checked", Count: frac(0)})
	}

	// Events lost from the audit record are a failing line; from other
	// logs (the PowerShell log), a warning of their own, named (LOG1).
	lost, other := uint64(0), uint64(0)
	var lostOn, otherOn []string
	otherBy := map[string]uint64{}
	var otherNames []string
	for _, g := range r.Health.Gaps {
		if g.Lost == 0 {
			continue
		}
		if !rollover.Critical(g.Channel) {
			other += g.Lost
			if !slices.Contains(otherOn, g.Host) {
				otherOn = append(otherOn, g.Host)
			}
			k := g.Host + "\x00" + rollover.Name(g.Channel)
			if _, ok := otherBy[k]; !ok {
				otherNames = append(otherNames, k)
			}
			otherBy[k] += g.Lost
			continue
		}
		lost += g.Lost
		if !slices.Contains(lostOn, g.Host) {
			lostOn = append(lostOn, g.Host)
		}
	}
	if lost > 0 {
		// A failing line says what went wrong, not what was checked: never
		// "No events lost" above "95,229 events were overwritten".
		var names []string
		seen := map[string]bool{}
		for _, g := range r.Health.Gaps {
			if g.Lost > 0 && rollover.Critical(g.Channel) && !seen[g.Channel] {
				seen[g.Channel] = true
				names = append(names, rollover.Name(g.Channel))
			}
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "circle-check", Title: "Events lost to log rollover", Who: strings.Join(lostOn, ", "),
			What: fmt.Sprintf("%s: %s overwritten before they were collected", strings.Join(names, ", "), plural(int(lost), "event")), Count: frac(len(lostOn))})
	} else {
		lines = append(lines, CheckLine{Level: "ok", Icon: "circle-check", Title: "No events lost from the audit logs", What: fmt.Sprintf("%s collection runs", commas(r.Health.Runs)), Count: frac(0)})
	}
	if other > 0 {
		var parts []string
		for _, k := range otherNames {
			host, name, _ := strings.Cut(k, "\x00")
			if len(otherOn) > 1 {
				name += " on " + host // the line names the systems once
			}
			parts = append(parts, fmt.Sprintf("%s: %s overwritten", name, plural(int(otherBy[k]), "event")))
		}
		lines = append(lines, CheckLine{Level: "warn", Icon: "circle-check", Title: "Other logs overwrote events", Who: strings.Join(otherOn, ", "),
			What: strings.Join(parts, "; ") + " · see Audit health", Href: "#health", Count: frac(len(otherOn))})
	}

	if n := len(r.MissingReports); n > 0 {
		var names []string
		for _, m := range r.MissingReports {
			names = append(names, m.Name)
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "history", Title: "Earlier reports missing or changed",
			What: plural(n, "scheduled report") + " deleted, moved or changed, with the only copy of their original logs: " + strings.Join(names, ", "), Href: "#health", Count: ""})
	}
	if l, ok := r.avCheckLine(r.avRows()); ok {
		lines = append(lines, l)
	}
	if l, ok := r.scapCheckLine(); ok {
		lines = append(lines, l)
	}
	if len(r.Removed) > 0 {
		lines = append(lines, CheckLine{Level: "warn", Icon: "history", Title: "Older reports removed",
			What: fmt.Sprintf("%s deleted under retention_days = %d, with their original logs: %s", plural(len(r.Removed), "report"), r.RetentionDays, strings.Join(r.Removed, ", ")), Count: ""})
	}
	if t := r.excludedText(); t != "" {
		lines = append(lines, CheckLine{Level: "warn", Icon: "user-x", Title: "Left out by your settings", What: t, Href: "#health", Count: ""})
	}

	if len(r.NoArchive) > 0 {
		lines = append(lines, CheckLine{Level: "warn", Icon: "hard-drive", Title: "Original logs missing", Who: strings.Join(r.NoArchive, ", "), What: "no original logs for this period", Count: frac(len(r.NoArchive))})
	} else if len(r.Archives) > 0 {
		var size uint64
		for _, a := range r.Archives {
			size += a.Bytes
		}
		lines = append(lines, CheckLine{Level: "ok", Icon: "hard-drive", Title: "Original logs archived", What: fmt.Sprintf("%s · %s · SHA-256 in manifest", plural(len(r.Archives), "zip"), humanBytes(size)), Count: frac(0)})
	} else {
		what := "Kept with the scheduled report"
		if w := r.Waiting; w != nil && w.Dir != "" {
			what = "Waiting in " + w.Dir + " for the next scheduled report"
		}
		lines = append(lines, CheckLine{Level: "ok", Icon: "hard-drive", Title: "Original logs archived", What: what, Count: ""})
	}
	for i := range lines {
		lines[i].Href = checklistLink(lines[i])
	}
	return lines
}

// detectionCards lists the detections newest first, labelled by day.
func (r *Report) detectionCards() []DetectionCard {
	idx := make([]int, len(r.Findings))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return r.Findings[idx[a]].Time.After(r.Findings[idx[b]].Time) })
	var out []DetectionCard
	for _, i := range idx {
		f := r.Findings[i]
		t := f.Time.In(r.Location)
		out = append(out, DetectionCard{Day: t.Format("Mon 2 Jan"), Severity: string(f.Severity), Title: f.Title, Detail: f.Detail,
			Host: f.Host, Time: t.Format("15:04"), Index: i})
	}
	return out
}

func times(n int) string {
	if n == 1 {
		return ""
	}
	if n == 2 {
		return " twice"
	}
	return fmt.Sprintf(" %d times", n)
}

func silentNote(systems []SystemRow) string {
	var silent []string
	for _, s := range systems {
		if !s.reporting() {
			silent = append(silent, s.Name)
		}
	}
	switch len(silent) {
	case 0:
		return "all reporting"
	case 1:
		return silent[0] + ": nothing received"
	}
	return fmt.Sprintf("%d sent nothing", len(silent))
}

// average is the mean of the earlier values in a series (not the last),
// or -1 when there are none.
// weekSpark is a KPI tile's small chart: the metric by calendar week,
// drawn once there is enough history (UI1).
func (r *Report) weekSpark(metric string, bad bool) template.HTML {
	t := r.metricTrend(metric)
	if !t.OK {
		return ""
	}
	return sparkline(t.Values, bad, 120, 34)
}

// vsAverage compares this week so far with the same part of an average
// complete week.
func (r *Report) vsAverage(metric string) string {
	t := r.metricTrend(metric)
	if !t.OK {
		return "trends start after 2 full weeks"
	}
	if t.Expected <= 0 {
		return "normal"
	}
	d := (float64(t.Now) - t.Expected) / t.Expected * 100
	switch {
	case d > -15 && d < 15:
		return "normal for this point of the week"
	case d > 0:
		return fmt.Sprintf("+%.0f%% on an average week so far", d)
	}
	return fmt.Sprintf("%.0f%% on an average week so far", d)
}

func afterHoursNote(r *Report) string {
	if !r.WorkingHours.Set() {
		return "set working_hours"
	}
	users := map[string]bool{}
	var last, host string
	for _, row := range r.rows {
		for _, f := range row.Flags {
			if f == "Outside working hours" {
				users[row.User] = true
				last, host = row.User, row.Host
			}
		}
	}
	switch len(users) {
	case 0:
		return ""
	case 1:
		return last + " · " + host
	}
	return fmt.Sprintf("%d people", len(users))
}

func shortCount(n int) string {
	if n >= 10000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return commas(n)
}

func shortOS(s SystemRow) string {
	b := ""
	if s.Checks != nil {
		b = s.Checks.Baseline
	}
	switch {
	case strings.Contains(b, "Server 2025"):
		return "WS 2025"
	case strings.Contains(b, "Windows 11"):
		return "WIN 11"
	case strings.Contains(b, "Ubuntu"):
		if strings.Contains(b, "22") {
			return "UBU 22"
		}
		return "UBU 24"
	case strings.Contains(b, "Alma") || strings.Contains(b, "RHEL"):
		return "ALMA 8"
	}
	return strings.ToUpper(s.OSName())
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%d MB", b>>20)
	}
	return fmt.Sprintf("%d KB", (b+1023)>>10)
}

// naturalLess sorts WS-2 before WS-10.
func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		da, db := digits(a), digits(b)
		if da != "" && db != "" {
			if len(da) != len(db) {
				return len(da) < len(db)
			}
			if da != db {
				return da < db
			}
			a, b = a[len(da):], b[len(db):]
			continue
		}
		ca, cb := strings.ToLower(a[:1]), strings.ToLower(b[:1])
		if ca != cb {
			return ca < cb
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func digits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// checklistLink is where a health checklist line leads: the system named,
// or the page with the detail.
func checklistLink(l CheckLine) string {
	first := strings.SplitN(l.Who, ", ", 2)[0]
	switch l.Title {
	case "Logs intact", "Logs cleared":
		if first != "" {
			return searchLink("page", "integrity", "host", first)
		}
		return "#integrity"
	case "Every system reporting", "Not every system reporting":
		if first != "" {
			return "#systems/" + first
		}
		return "#systems"
	case "Audit settings match STIG", "Audit settings to fix", "Audit settings not checked":
		if first != "" && !strings.Contains(l.Who, ", ") {
			return "#health/" + first
		}
		return "#health"
	case "Original logs archived", "Original logs missing":
		if first != "" {
			return "#logs/" + first
		}
		return "#logs"
	}
	return "#health"
}
