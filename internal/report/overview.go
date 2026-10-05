package report

import (
	"fmt"
	"html/template"
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
		Note: silentNote(systems), Spark: sparkline(r.series(MSystems, rep), rep < total, 120, 34)})
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
		Note: map[bool]string{true: "none this " + map[bool]string{true: "week", false: "period"}[r.Period == "weekly" || r.Period == ""], false: fmt.Sprintf("%d high · %d medium", high, med)}[len(r.Findings) == 0], Spark: sparkline(r.series(MDetections, len(r.Findings)), len(r.Findings) > 0, 120, 34)})
	ev := r.series(MEvents, len(r.Events))
	o.KPIs = append(o.KPIs, KPI{Label: "Events collected", Href: "#search", Value: shortCount(len(r.Events)), Note: vsAverage(ev),
		Spark: sparkline(ev, false, 120, 34)})
	o.KPIs = append(o.KPIs, KPI{Label: "Privileged actions", Href: "#privileged", Value: commas(m[MPrivileged]),
		Note:  fmt.Sprintf("by %d %s", len(people), map[bool]string{true: "person", false: "people"}[len(people) == 1]),
		Spark: sparkline(r.series(MPrivileged, m[MPrivileged]), false, 120, 34)})

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
	if avg := average(r.series(MLockouts, m[MLockouts])); avg >= 0 {
		lockNote = fmt.Sprintf("normal: %.0f", avg)
	}
	card("lock", "Lockouts", MLockouts, "warn", lockNote, "#failed")
	card("moon", "After-hours admin", MAfterHours, "warn", afterHoursNote(r), "#privileged")
	card("usb", "New USB devices", MNewUSB, "", fmt.Sprintf("%d events", m[MUSB]), "#usb")

	// Health checklist.
	o.Checks = r.checklist(systems, byHost)

	// System map or (standalone) system cards.
	if o.Standalone {
		for _, s := range systems {
			c := SystemCard{Name: s.Name, OS: osLabel(s), VM: s.Via != "", Events: commas(s.Events)}
			c.Role = "standalone"
			if s.Via != "" {
				c.Role = "virtual machine on " + s.Via
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
			} else if s.Via != "" {
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
			t := MapTile{Name: s.Name, OS: shortOS(s), Level: level[s.Name], VM: s.Via != ""}
			if t.Level == "ok" {
				t.Level = ""
			}
			g := groups[1]
			switch {
			case s.Via != "":
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

	// Trends.
	hs := r.series(MHighEvents, m[MHighEvents])
	fl := r.series(MFailedLogons, m[MFailedLogons])
	pa := r.series(MPrivileged, m[MPrivileged])
	o.Trends = []SmallTrend{
		{Title: "High-severity events", Note: trendNote(hs), Chart: sparkline(hs, true, 300, 70)},
		{Title: "Failed logons", Note: trendNote(fl), Chart: sparkline(fl, false, 300, 70)},
		{Title: "Privileged actions", Note: trendNote(pa), Chart: sparkline(pa, false, 300, 70)},
	}
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
		lines = append(lines, CheckLine{Level: "bad", Icon: "file-warning", Title: "Logs intact", Who: strings.Join(who, ", "), What: "Security log cleared", Count: frac(len(who))})
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
		lines = append(lines, CheckLine{Level: "bad", Icon: "clock-alert", Title: "Every system reporting", Who: strings.Join(who, ", "), What: since, Count: frac(len(who))})
	} else {
		what := "Every system sent its events"
		for _, s := range systems {
			if s.Via != "" {
				what = "VMs reported whenever they were on"
			}
		}
		lines = append(lines, CheckLine{Level: "ok", Icon: "clock-alert", Title: "Every system reporting", What: what, Count: frac(0)})
	}

	if r.Late > 0 {
		lines = append(lines, CheckLine{Level: "warn", Icon: "history", Title: "Reports on time", What: fmt.Sprintf("%s arrived late · nothing lost", plural(r.Late, "event")), Count: ""})
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
		lines = append(lines, CheckLine{Level: "warn", Icon: "shield-check", Title: "Audit settings match STIG", Who: strings.Join(who, ", "),
			What: fmt.Sprintf("%s to fix · see Audit health", plural(gaps, "setting")), Count: frac(len(who))})
	case checked == 0:
		lines = append(lines, CheckLine{Level: "warn", Icon: "shield-check", Title: "Audit settings match STIG", What: "Not checked in this period", Count: ""})
	default:
		lines = append(lines, CheckLine{Level: "ok", Icon: "shield-check", Title: "Audit settings match STIG", What: "All systems checked", Count: frac(0)})
	}

	lost := uint64(0)
	for _, g := range r.Health.Gaps {
		lost += g.Lost
	}
	if lost > 0 {
		lines = append(lines, CheckLine{Level: "bad", Icon: "circle-check", Title: "No events lost to log rollover", What: commas(lost) + " events were overwritten before they were collected", Count: ""})
	} else {
		lines = append(lines, CheckLine{Level: "ok", Icon: "circle-check", Title: "No events lost to log rollover", What: fmt.Sprintf("%s collection runs", commas(r.Health.Runs)), Count: frac(0)})
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
		lines = append(lines, CheckLine{Level: "warn", Icon: "hard-drive", Title: "Original logs archived", Who: strings.Join(r.NoArchive, ", "), What: "no original logs for this period", Count: frac(len(r.NoArchive))})
	} else if len(r.Archives) > 0 {
		var size uint64
		for _, a := range r.Archives {
			size += a.Bytes
		}
		lines = append(lines, CheckLine{Level: "ok", Icon: "hard-drive", Title: "Original logs archived", What: fmt.Sprintf("%s · %s · SHA-256 in manifest", plural(len(r.Archives), "zip"), humanBytes(size)), Count: frac(0)})
	} else {
		lines = append(lines, CheckLine{Level: "ok", Icon: "hard-drive", Title: "Original logs archived", What: "Kept with the scheduled report", Count: ""})
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
		if s.Status == "silent" {
			silent = append(silent, s.Name)
		}
	}
	switch len(silent) {
	case 0:
		return "all reporting"
	case 1:
		return silent[0] + " silent"
	}
	return fmt.Sprintf("%d silent", len(silent))
}

// average is the mean of the earlier values in a series (not the last),
// or -1 when there are none.
func average(vals []int) float64 {
	sum, n := 0, 0
	for _, v := range vals[:len(vals)-1] {
		if v >= 0 {
			sum += v
			n++
		}
	}
	if n == 0 {
		return -1
	}
	return float64(sum) / float64(n)
}

func vsAverage(vals []int) string {
	avg := average(vals)
	if avg <= 0 {
		return "first weeks: no average yet"
	}
	d := (float64(vals[len(vals)-1]) - avg) / avg * 100
	switch {
	case d > -15 && d < 15:
		return "normal"
	case d > 0:
		return fmt.Sprintf("+%.0f%% vs. avg", d)
	}
	return fmt.Sprintf("%.0f%% vs. avg", d)
}

func trendNote(vals []int) string {
	now := vals[len(vals)-1]
	avg := average(vals)
	if avg < 0 {
		return fmt.Sprintf("%s this week", commas(now))
	}
	return fmt.Sprintf("%s this week · avg %s", commas(now), shortNum(avg))
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
	case "Logs intact":
		if first != "" {
			return searchLink("page", "integrity", "host", first)
		}
		return "#integrity"
	case "Every system reporting":
		if first != "" {
			return "#systems/" + first
		}
		return "#systems"
	case "Audit settings match STIG":
		if first != "" && !strings.Contains(l.Who, ", ") {
			return "#health/" + first
		}
		return "#health"
	case "Original logs archived":
		if first != "" {
			return "#logs/" + first
		}
		return "#logs"
	}
	return "#health"
}
