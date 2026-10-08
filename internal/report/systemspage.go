package report

import (
	"fmt"
	"html/template"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/rollover"
)

// The Systems page (UI-R1, designs 04 and 05).
//
// The list (#systems): every system in one table grouped Servers /
// Workstations, worst first, with a filter bar (find, All / Problems /
// Warnings / OK, OS, role). Each row: a status dot and the name, the OS,
// the six checks as squares (Reporting, Logs intact, Settings, Antivirus,
// Orig. logs, SCAP), events, detections and when it was last seen.
//
// One system (#systems/NAME): its problem as one chip, what it is (OS ·
// role · model · where it sends), six facts, a strip of the collections
// expected in the period (a red mark at a log clear, grey for a missed
// one), the six checks in one line each, its detections, its activity
// per hour, who was active, and its events by kind.

// SystemGroup is one group of the Systems list: "Servers · 11".
type SystemGroup struct {
	Kind    string // server | workstation | vm | retired
	Title   string
	Systems []*SystemView
}

// Label is the group's heading, "Servers · 11".
func (g SystemGroup) Label() string { return fmt.Sprintf("%s · %d", g.Title, len(g.Systems)) }

// Fact is one of a page's headline facts.
type Fact struct {
	Label, Value string
	Bad          bool
	Href         string // where it leads
	Scroll       string // or: an element on the same page to scroll to
}

// ActivityBar is one kind of event on a system against the typical
// system on the network (the median): Events by kind notes a kind well
// above it.
type ActivityBar struct {
	Label   string
	N       int
	Pct     int // bar length
	Median  int // where the median line sits, as a percentage
	Above   bool
	PageID  string
	Href    string
	Missing bool // no events of this kind on the network
}

// SysCheck is one of a system's six checks: a square on the list and a
// line on its page (Title says what was found, in a few words). Short
// names a problem for the page's chip: "Security log cleared".
type SysCheck struct {
	CheckCell
	Short string
}

// SysFact is one of the six facts at the top of a system's page.
type SysFact struct {
	Label, Value, Note string
	Level              string // bad | warn | "" (as is)
	Href               string
}

// CollCell is one cell of the collection strip: Class "" (collected),
// bad (a log cleared), warn (events lost), miss (no collection), part
// (some of the collections it stands for missing), pre (not expected:
// before the system was first seen, or after it was retired).
type CollCell struct {
	Class, Title string
}

// WhoRow is one account of "Who was active" on a system.
type WhoRow struct {
	Name, Role, Href string
	N                int
}

// KindRow is one line of a system's "Events by kind".
type KindRow struct {
	Title, Href, Note string
	N                 int
}

// SystemView is one computer on the Systems page.
type SystemView struct {
	Name, Tag string // Tag: short OS, or "on 41%" for a VM
	Level     string // bad | warn | ok | retired
	Status    string // the level in words: Problem, Warning, OK, Retired
	Line      string // OS · role · model · where it sends
	// Delivery is how its collections reach the collector, one line
	// under Line ("Delivery: signed · key SHA256:… since 3 Oct"); empty
	// until the report knows it.
	Delivery    string
	Kind, Group string // server | workstation | vm | retired; the group's title
	OS, OSKey   string // "Server 2025"; the OS filter's value
	Chip        string // the problem in one chip: "Problem: Security log cleared"
	ChipLevel   string
	Cells       []SysCheck // the six checks, in the list's column order
	Checks      []SysCheck // the same, problems first, for the page
	Events, Det int
	LastSeen    string
	Facts       []SysFact
	Strip       []CollCell
	StripNote   string // "24 of 24"
	StripName   string // the strip in words, for a screen reader
	// StripKey says which marks the strip has, for its legend.
	StripKey   struct{ Clear, Miss, Lost bool }
	Every      string // "every hour", from the collections
	Detections []ListItem
	Hours      template.HTML
	HoursNote  string // "events per hour"
	Who        []WhoRow
	WhoMore    int
	Kinds      []KindRow
	Prev, Next string // the systems before and after it in the list
	SearchHref string
	// Health is the full checklist the six checks sum up (the reasons in
	// detail); Activity each kind against the typical system.
	Health      []CheckLine
	Activity    []ActivityBar
	Message     string // why it is silent, if it is
	FailedItems []check.Result
}

// SysOpt is one choice of a filter.
type SysOpt struct{ Value, Label string }

// SystemsPage is the Systems page.
type SystemsPage struct {
	Groups             []SystemGroup
	Count              int
	LAN                bool // standalone reports have no "typical system" to compare with
	All, Bad, Warn, OK int
	OSes               []string // the OS filter's choices
	Roles              []SysOpt // the role filter's choices: Servers, Workstations, …
	Cols               []string // the six checks' column headings
	Period             string   // the period and zone, for a system's breadcrumb
	Crumb              string   // the list's breadcrumb: "30 systems · 28 reporting"
}

// activityKinds are the kinds compared with the typical system.
var activityKinds = []struct{ Label, Page string }{
	{"Privileged actions", "privileged"}, {"Failed logons", "failed"}, {"Logons", "logons"},
	{"USB events", "usb"}, {"Account changes", "accounts"}, {"PowerShell", "powershell"},
}

// sysChecks are the six checks' labels on the list's columns.
var sysCheckCols = []string{"Reporting", "Logs intact", "Settings", "Antivirus", "Orig. logs", "SCAP"}

func (r *Report) systemsPage() *SystemsPage {
	if len(r.SystemRows) == 0 && len(r.Retired) == 0 {
		return nil
	}
	sp := &SystemsPage{Count: len(r.SystemRows), LAN: r.IsLAN(), Period: r.periodText() + " " + zoneName(r.Generated, r.Location), Cols: sysCheckCols}
	pages := eventPages()
	byID := map[string]*EventPage{}
	for _, p := range pages {
		byID[p.ID] = p
	}
	// Events of each kind per computer, log clears, accounts, and events
	// per hour.
	counts := map[string]map[string]int{}
	cleared := map[string][]*Row{}
	users := map[string]map[string]int{}
	byHost := map[string][]*Row{}
	for _, row := range r.rows {
		h := strings.ToLower(row.Host)
		if counts[h] == nil {
			counts[h], users[h] = map[string]int{}, map[string]int{}
		}
		for _, p := range pages {
			if p.on(row.Event) {
				counts[h][p.ID]++
			}
		}
		if row.Action == "log_cleared" {
			cleared[h] = append(cleared[h], row)
		}
		if row.User != "" {
			users[h][row.User]++
		}
		byHost[h] = append(byHost[h], row)
	}
	median := map[string]int{}
	for _, p := range pages {
		var vals []int
		for _, s := range r.SystemRows {
			if s.Status != "silent" {
				vals = append(vals, counts[strings.ToLower(s.Name)][p.ID])
			}
		}
		sort.Ints(vals)
		if len(vals) > 0 {
			median[p.ID] = vals[len(vals)/2]
		}
	}
	cards := r.detectionCards()
	cx := r.newCheckCtx(cleared)

	var views []*SystemView
	oses := map[string]bool{}
	for _, s := range append(append([]SystemRow(nil), r.SystemRows...), r.Retired...) {
		h := strings.ToLower(s.Name)
		retired := s.Status == "retired"
		v := &SystemView{Name: s.Name, Tag: strings.ToUpper(shortOS(s)), Message: s.StatusMsg, Kind: systemKind(s),
			OS: listOS(s), OSKey: listOS(s), Events: s.Events, SearchHref: searchLink("host", s.Name)}
		if retired {
			v.Kind = "retired"
		} else {
			oses[v.OS] = true
		}
		v.Line = r.systemLine(s)

		// Detections on this computer, newest first.
		high, med := 0, 0
		var first *DetectionCard
		for i, c := range cards {
			if !strings.EqualFold(c.Host, s.Name) {
				continue
			}
			lv := "warn"
			if c.Severity == "high" {
				lv = "bad"
				high++
			} else {
				med++
			}
			if first == nil || c.Severity == "high" && first.Severity != "high" {
				first = &cards[i]
			}
			when := c.Time
			if len(r.periodDays()) > 1 && c.Time != "" {
				when = c.Day + " " + c.Time
			} else if c.Time == "" {
				when = c.Day
			}
			v.Detections = append(v.Detections, ListItem{Title: c.Title, Reason: c.Detail, Time: when, Href: fmt.Sprintf("#detections/%d", c.Index), Level: lv})
		}
		v.Det = high + med

		iv := collectInterval(s.runTimes)
		v.Every = "every " + intervalWord(iv)
		var clears []time.Time
		for _, c := range cleared[h] {
			clears = append(clears, c.Time)
		}
		got, want := r.collectionStrip(v, s, iv, append(clears, s.resets...))
		v.Cells = r.sysChecks(s, cx, got, want)

		// The level: the worst check, or a detection (systemLevel, as
		// Overview's Systems at a glance).
		v.Level = systemLevel(checkCells(v.Cells), high, med)
		v.Checks = append([]SysCheck(nil), v.Cells...)
		sort.SliceStable(v.Checks, func(i, j int) bool { return levelRank(v.Checks[i].Level) < levelRank(v.Checks[j].Level) })
		var shorts []string
		for _, c := range v.Checks {
			if c.Level == v.Level && c.Short != "" {
				shorts = append(shorts, c.Short)
			}
		}
		switch v.Level {
		case "bad":
			v.Status = "Problem"
			if high > 0 && first != nil && len(shorts) == 0 {
				shorts = append(shorts, first.Title)
			}
		case "warn":
			v.Status = "Warning"
			if med > 0 && first != nil && len(shorts) == 0 {
				shorts = append(shorts, first.Title)
			}
		default:
			v.Status = "OK"
		}
		v.ChipLevel = v.Level
		switch {
		case v.Level == "ok":
			v.Chip = "No problems"
		case len(shorts) > 2:
			v.Chip = fmt.Sprintf("%s: %s · %d more", v.Status, shorts[0], len(shorts)-1)
		default:
			v.Chip = v.Status + ": " + strings.Join(shorts, " · ")
		}
		if retired {
			v.Level, v.Status, v.Tag, v.ChipLevel = "retired", "Retired", "RETIRED", "retired"
			v.Chip = "Retired " + s.Removed.In(r.Location).Format("2 Jan")
			for i := range v.Cells {
				if v.Cells[i].Label != "Reporting" {
					continue
				}
				v.Cells[i].Level, v.Cells[i].Title = "", "retired "+s.Removed.In(r.Location).Format("2 Jan 15:04")
			}
		}

		if !s.LastRun.IsZero() {
			v.LastSeen = r.shortStamp(s.LastRun)
			if s.LastRunAhead {
				v.LastSeen += " (clock ahead)"
			}
		}
		v.Facts = r.sysFacts(s, v, high, med, first)

		on, _, _ := r.coverage(s)
		v.Health = r.systemHealth(s, cleared[h], on)
		if retired {
			v.Health = []CheckLine{{Level: "ok", Icon: "server", Title: "Retired", What: s.StatusMsg}}
			v.Message = ""
		}
		if s.Checks != nil {
			for _, res := range s.Checks.Results {
				if res.Status == check.Fail && res.Area != "Antivirus" {
					v.FailedItems = append(v.FailedItems, res)
				}
			}
		}

		// Each kind against the network's median: Events by kind says
		// when this system is well above the typical one.
		for _, k := range activityKinds {
			n, m := counts[h][k.Page], median[k.Page]
			top := max(n, 2*m, 1)
			a := ActivityBar{Label: k.Label, N: n, Pct: n * 100 / top, Median: m * 100 / top, PageID: k.Page,
				Href: searchLink("page", k.Page, "host", s.Name)}
			a.Above = sp.LAN && float64(n) > float64(m)*1.5 && n >= m+5
			v.Activity = append(v.Activity, a)
		}
		for _, p := range pages {
			n := counts[h][p.ID]
			if n == 0 {
				continue
			}
			k := KindRow{Title: p.Title, N: n, Href: searchLink("page", p.ID, "host", s.Name)}
			if m := median[p.ID]; sp.LAN && float64(n) > float64(m)*1.5 && n >= m+5 {
				k.Note = "typical system " + commas(m)
			}
			v.Kinds = append(v.Kinds, k)
		}
		sort.SliceStable(v.Kinds, func(i, j int) bool { return v.Kinds[i].N > v.Kinds[j].N })

		v.Hours, v.HoursNote = r.hourBars(byHost[h], s.Name)
		v.Who, v.WhoMore = r.whoActive(s, users[h])
		views = append(views, v)
	}

	// Grouped Servers / Workstations (and virtual machines), worst first;
	// retired systems last.
	for _, g := range groupByKind(views, func(v *SystemView) string { return v.Kind }) {
		sortNatural(g.Items)
		sp.Groups = append(sp.Groups, SystemGroup{Kind: g.Kind, Title: g.Title, Systems: g.Items})
		sp.Roles = append(sp.Roles, SysOpt{g.Kind, g.Title})
	}
	var gone []*SystemView
	for _, v := range views {
		if v.Kind == "retired" {
			gone = append(gone, v)
		}
	}
	if len(gone) > 0 {
		sortNatural(gone)
		sp.Groups = append(sp.Groups, SystemGroup{Kind: "retired", Title: "Retired", Systems: gone})
	}
	var order []*SystemView
	for gi := range sp.Groups {
		sp.Groups[gi].setGroup()
		order = append(order, sp.Groups[gi].Systems...)
	}
	for i, v := range order {
		if i > 0 {
			v.Prev = order[i-1].Name
		}
		if i+1 < len(order) {
			v.Next = order[i+1].Name
		}
		switch v.Level {
		case "bad":
			sp.Bad++
		case "warn":
			sp.Warn++
		case "ok":
			sp.OK++
		}
	}
	sp.All = sp.Bad + sp.Warn + sp.OK
	reporting := 0
	for _, s := range r.SystemRows {
		if s.Status != "silent" {
			reporting++
		}
	}
	sp.Crumb = plural(len(r.SystemRows), "system")
	if reporting < len(r.SystemRows) {
		sp.Crumb += fmt.Sprintf(" · %d reporting", reporting)
	}
	for o := range oses {
		sp.OSes = append(sp.OSes, o)
	}
	sort.Strings(sp.OSes)
	return sp
}

// setGroup notes each system's group title, for its breadcrumb.
func (g *SystemGroup) setGroup() {
	for _, v := range g.Systems {
		v.Group = g.Title
	}
}

// sortNatural keeps the level order and sorts WS-2 before WS-10 within it.
func sortNatural(l []*SystemView) {
	sort.SliceStable(l, func(i, j int) bool {
		a, b := levelRank(l[i].Level), levelRank(l[j].Level)
		if a != b {
			return a < b
		}
		return naturalLess(l[i].Name, l[j].Name)
	})
}

// listOS is a system's OS on the list: "Server 2025", "Windows 11",
// "Ubuntu 24.04".
func listOS(s SystemRow) string {
	if l := osLabel(s); strings.HasPrefix(l, "Windows Server") {
		return strings.TrimPrefix(l, "Windows ")
	}
	return osLabel(s)
}

// systemLine is what a system is: "Windows Server 2025 · server · Dell
// PowerEdge R650 · sends to SRV-LOG01".
func (r *Report) systemLine(s SystemRow) string {
	parts := []string{osLabel(s)}
	role := strings.ToLower(kindWord(systemKind(s)))
	if s.VM {
		role = "virtual machine"
		if host := r.vmHost(s); host != "" {
			role += " on " + host
		}
	} else if !r.IsLAN() {
		role = "standalone"
	}
	parts = append(parts, role)
	if s.Checks != nil && s.Checks.Inventory != nil {
		inv := s.Checks.Inventory
		if m := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(inv.Manufacturer, "Inc.")), ",") + " " + inv.Model); m != "" {
			parts = append(parts, m)
		}
	}
	switch {
	case s.Status == "retired":
		w := "retired " + s.Removed.In(r.Location).Format("2 Jan")
		if s.RemovedBy != "" {
			w += " by " + s.RemovedBy
		}
		parts = append(parts, w)
	case s.Via != "" && !s.VM:
		parts = append(parts, "sends to "+s.Via)
	// Only what the data shows: a system whose collections arrived from
	// it over the network sends to the collector (the one that received).
	case r.Collector && !s.LastReceived.IsZero() && r.collectorName() != "" && !s.VM:
		parts = append(parts, "sends to "+r.collectorName())
	case r.Collector && s.LastReceived.IsZero() && strings.EqualFold(s.Name, r.collectorName()) && r.receivedAny():
		parts = append(parts, "collector")
	}
	return strings.Join(parts, " · ")
}

// receivedAny says whether any system's collections arrived over the
// network (so the collector is known).
func (r *Report) receivedAny() bool {
	for _, s := range r.SystemRows {
		if !s.LastReceived.IsZero() {
			return true
		}
	}
	return false
}

// shortStamp is a time on the Systems page: "23:58" on the period's last
// day, else "6 Oct 04:00".
func (r *Report) shortStamp(t time.Time) string {
	l := t.In(r.Location)
	if last := r.WindowEnd.Add(-time.Second).In(r.Location); l.Format("20060102") == last.Format("20060102") {
		return l.Format("15:04")
	}
	return l.Format("2 Jan 15:04")
}

// collectInterval is how often a system collects: the usual time between
// its collections, rounded to a whole interval; an hour (the default)
// when there are too few to tell.
func collectInterval(runs []time.Time) time.Duration {
	if len(runs) < 3 {
		return expectedInterval
	}
	t := append([]time.Time(nil), runs...)
	sort.Slice(t, func(i, j int) bool { return t[i].Before(t[j]) })
	var d []float64
	for i := 1; i < len(t); i++ {
		if g := t[i].Sub(t[i-1]).Minutes(); g > 0.5 {
			d = append(d, g)
		}
	}
	if len(d) == 0 {
		return expectedInterval
	}
	sort.Float64s(d)
	m := d[len(d)/2]
	best, err := 60.0, math.Inf(1)
	for _, n := range []float64{1, 2, 5, 10, 15, 20, 30, 60, 120, 180, 240, 360, 480, 720, 1440} {
		if e := math.Abs(math.Log(m / n)); e < err {
			best, err = n, e
		}
	}
	return time.Duration(best) * time.Minute
}

// intervalWord is "15 min", "hour", "6 hours", "day".
func intervalWord(d time.Duration) string {
	switch {
	case d == time.Hour:
		return "hour"
	case d == 24*time.Hour:
		return "day"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return fmt.Sprintf("%d hours", int(d.Hours()))
}

// maxStripCells is the most cells a collection strip draws; a longer
// period puts several collections in one cell.
const maxStripCells = 192

// collectionStrip fills in v's collection strip: one cell per collection
// expected in the period (every iv), and returns how many were expected
// and how many came. marks are log clears.
func (r *Report) collectionStrip(v *SystemView, s SystemRow, iv time.Duration, marks []time.Time) (got, want int) {
	start, end := r.PeriodStart(), r.WindowEnd
	if !end.After(start) || iv <= 0 {
		return 0, 0
	}
	n := int(math.Ceil(float64(end.Sub(start)) / float64(iv)))
	slot := func(t time.Time) int {
		i := int(t.Sub(start) / iv)
		if t.Before(start) || i >= n {
			return -1
		}
		return i
	}
	filled, pre, lost := make([]bool, n), make([]bool, n), make([]bool, n)
	red := map[int]time.Time{}
	for _, t := range s.runTimes {
		if i := slot(t); i >= 0 {
			filled[i] = true
		} else if t.Equal(end) {
			filled[n-1] = true
		}
	}
	for _, t := range marks {
		if i := slot(t); i >= 0 {
			red[i] = t
		}
	}
	for _, g := range s.gaps {
		if g.From.IsZero() || g.To.IsZero() {
			continue
		}
		for i := max(0, slot(g.From)); i >= 0 && i < n && !start.Add(time.Duration(i)*iv).After(g.To); i++ {
			lost[i] = true
		}
	}
	for i := range n {
		a := start.Add(time.Duration(i) * iv)
		if !s.FirstSeen.IsZero() && a.Add(iv).Before(s.FirstSeen) || !s.Removed.IsZero() && a.After(s.Removed) {
			pre[i] = !filled[i]
		}
		if !pre[i] {
			want++
			if filled[i] {
				got++
			}
		}
	}
	k := (n + maxStripCells - 1) / maxStripCells
	at := func(i int) string { return start.Add(time.Duration(i) * iv).In(r.Location).Format("2 Jan 15:04") }
	for j := 0; j*k < n; j++ {
		a, z := j*k, min(n, (j+1)*k)
		var c CollCell
		nf, np, nl := 0, 0, 0
		var cl time.Time
		for i := a; i < z; i++ {
			if filled[i] {
				nf++
			}
			if pre[i] {
				np++
			}
			if lost[i] {
				nl++
			}
			if t, ok := red[i]; ok && cl.IsZero() {
				cl = t
			}
		}
		switch {
		case !cl.IsZero():
			v.StripKey.Clear = true
			c = CollCell{Class: "bad", Title: "Log cleared " + cl.In(r.Location).Format("2 Jan 15:04")}
		case np == z-a:
			c = CollCell{Class: "pre", Title: at(a) + ": not expected"}
		case nf == 0:
			v.StripKey.Miss = true
			c = CollCell{Class: "miss", Title: at(a) + ": no collection"}
		case nl > 0:
			v.StripKey.Lost = true
			c = CollCell{Class: "warn", Title: at(a) + ": events overwritten before they were collected"}
		case nf+np < z-a:
			v.StripKey.Miss = true
			c = CollCell{Class: "part", Title: fmt.Sprintf("%s: %d of %d collections", at(a), nf, z-a-np)}
		}
		v.Strip = append(v.Strip, c)
	}
	v.StripNote = fmt.Sprintf("%d of %d", got, want)
	v.StripName = fmt.Sprintf("Collections this period: %d of %d expected, one every %s", got, want, intervalWord(iv))
	if len(marks) > 0 {
		v.StripName += fmt.Sprintf("; a log cleared %s", plural(len(marks), "time"))
	}
	if len(s.gaps) > 0 {
		v.StripName += fmt.Sprintf("; events overwritten %s", plural(len(s.gaps), "time"))
	}
	return got, want
}

// checkCtx is what a system's six checks read beyond its SystemRow: the
// log clears per system (by lower-case name), the antivirus rows, and
// which systems' original logs are missing or in the report. Built once
// per page by newCheckCtx.
type checkCtx struct {
	cleared   map[string][]*Row
	av        map[string]AVRow
	noArchive map[string]bool
	archives  map[string]*ArchiveRef
}

// newCheckCtx gathers what sysChecks reads for every system; cleared is
// the log_cleared rows by lower-case system name.
func (r *Report) newCheckCtx(cleared map[string][]*Row) *checkCtx {
	cx := &checkCtx{cleared: cleared, av: map[string]AVRow{}, noArchive: map[string]bool{}, archives: map[string]*ArchiveRef{}}
	for _, a := range r.avRows() {
		cx.av[strings.ToLower(a.Host)] = a
	}
	for _, h := range append(append([]string(nil), r.NoArchive...), r.leftOutHosts()...) {
		cx.noArchive[strings.ToLower(h)] = true
	}
	for i := range r.Archives {
		cx.archives[strings.ToLower(r.Archives[i].Host)] = &r.Archives[i]
	}
	return cx
}

// collections is how many collections came of those expected in the
// period, as the collection strip counts them.
func (r *Report) collections(s SystemRow) (got, want int) {
	return r.collectionStrip(&SystemView{}, s, collectInterval(s.runTimes), nil)
}

// sysChecks are a system's six checks, in the column order of the
// Systems list and the Overview's Systems at a glance (both pages show
// these same squares): Reporting, Logs intact, Audit settings,
// Antivirus, Original logs, SCAP. got and want are its collections
// (r.collections).
func (r *Report) sysChecks(s SystemRow, cx *checkCtx, got, want int) []SysCheck {
	name := s.Name
	h := strings.ToLower(name)
	cleared := cx.cleared[h]
	reporting := SysCheck{CheckCell: CheckCell{Level: "ok", Label: "Reporting", Href: "#logs/" + name}}
	switch {
	case s.Status == "silent":
		reporting.Level, reporting.Short = "bad", "not reporting"
		reporting.Title = "nothing received this " + r.periodNoun()
		if !s.LastRun.IsZero() {
			reporting.Title = "nothing since " + s.LastRun.In(r.Location).Format("2 Jan 15:04")
		}
	case s.VM && len(s.runTimes) == 0:
		reporting.Level, reporting.Short, reporting.Title = "warn", "nothing received", "nothing this period (a virtual machine sends only while it is on)"
	case s.VM:
		on, _, _ := r.coverage(s)
		reporting.Title = fmt.Sprintf("on %d%% of the period · %s while on", on, plural(len(s.runTimes), "collection"))
	case len(s.runTimes) == 0 || s.LastRun.IsZero():
		reporting.Level, reporting.Title = "", "no collection in this period" // or a report from saved logs
	default:
		reporting.Title = fmt.Sprintf("%d of %d collections · last %s", got, want, r.shortStamp(s.LastRun))
		if got < want {
			reporting.Level, reporting.Short = "warn", plural(want-got, "missed collection")
		}
		if !r.WindowEnd.IsZero() && r.WindowEnd.Sub(s.LastRun) > silentAfter {
			reporting.Level, reporting.Short = "warn", "late"
		}
	}
	if s.LastRunAhead {
		reporting.Level, reporting.Short = "warn", "clock ahead"
		reporting.Title += " (recorded by a clock that was ahead)"
	}

	// Logs intact: events lost count only when some were (as on Audit
	// health); a lost count of 0 is a log reset, below.
	logs := SysCheck{CheckCell: CheckCell{Level: "ok", Label: "Logs intact", Href: searchLink("page", "integrity", "host", name)}}
	var critical, other []GapItem
	for _, g := range s.gaps {
		switch {
		case g.Lost == 0:
		case rollover.Critical(g.Channel):
			critical = append(critical, g)
		default:
			other = append(other, g)
		}
	}
	switch {
	case len(cleared) > 0:
		var at, by []string
		seen := map[string]bool{}
		for _, c := range cleared {
			at = append(at, c.Time.In(r.Location).Format("15:04"))
			if c.User != "" && !seen[c.User] {
				seen[c.User] = true
				by = append(by, c.User)
			}
		}
		what := clearedWhat(cleared)
		logs.Level, logs.Short = "bad", what+" cleared"
		logs.Title = fmt.Sprintf("%s cleared at %s", what, joinAnd(at))
		if len(r.periodDays()) > 1 {
			logs.Title += " on " + cleared[0].Time.In(r.Location).Format("2 Jan")
		}
		if len(by) > 0 {
			logs.Title += " by " + joinAnd(by)
		}
	case len(s.resets) > 0:
		logs.Level, logs.Short = "bad", "a log cleared"
		logs.Title = "a log was cleared or recreated (found by the collection at " + r.shortStamp(s.resets[0]) + ")"
	case len(critical) > 0:
		logs.Level, logs.Short = "bad", "events lost"
		logs.Title = lostTitle(critical, true) + " before they were collected"
	case len(other) > 0:
		logs.Level, logs.Short = "warn", "events overwritten"
		logs.Title = lostTitle(other, false)
	case s.Status == "silent":
		logs.Level, logs.Title = "", "no collection to check"
	case len(s.runTimes) == 0:
		logs.Title = "none cleared"
	default:
		logs.Title = "none cleared, nothing overwritten"
		for _, log := range []string{"Security", "audit", "auth"} {
			for ch, t := range s.holds {
				if strings.Contains(strings.ToLower(ch), strings.ToLower(log)) && !s.LastRun.IsZero() {
					logs.Title += fmt.Sprintf(" · %s log holds %s", ch, plural(int(s.LastRun.Sub(t).Hours()/24), "day"))
				}
			}
		}
	}

	// Audit settings: auditing off red, settings to fix amber.
	settings := SysCheck{CheckCell: CheckCell{Label: "Audit settings", Href: "#health/" + name}}
	switch {
	case s.AuditOff != "":
		settings.Level, settings.Short, settings.Title = "bad", "auditing off", "auditing off at the last collection: "+s.AuditOff
	case s.Checks == nil:
		settings.Title = "not checked yet"
	case s.Checks.STIGFail > 0:
		var items []string
		for _, res := range s.Checks.Results {
			if res.Status == check.Fail && res.Area != "Antivirus" && !res.IsAdvice() {
				items = append(items, res.Item)
			}
		}
		settings.Level, settings.Short = "warn", plural(s.Checks.STIGFail, "audit setting")+" to fix"
		settings.Title = fmt.Sprintf("%d to fix", s.Checks.STIGFail)
		if len(items) > 0 {
			settings.Title += ": " + strings.Join(items[:min(2, len(items))], ", ")
		}
		if len(items) > 2 {
			settings.Title += fmt.Sprintf(" and %d more", len(items)-2)
		}
	default:
		settings.Level, settings.Title = "ok", fmt.Sprintf("all %d match the STIG", s.Checks.Pass+s.Checks.Fail+s.Checks.Warn-s.Checks.Advice)
		if s.Checks.Advice > 0 {
			settings.Title += fmt.Sprintf(" · %d Blackbox advice", s.Checks.Advice)
		}
	}

	// Antivirus: protection off red; out of date (or not checked) amber.
	avc := SysCheck{CheckCell: CheckCell{Label: "Antivirus", Href: "#health/@av"}}
	av, haveAV := cx.av[h]
	product := strings.TrimPrefix(av.Product, "Microsoft ")
	switch {
	case !haveAV:
		avc.Title = "not checked"
	case av.ProtectionBad:
		avc.Level, avc.Short, avc.Title = "bad", "antivirus off", product+": "+av.Protection
	case av.Level == "ok":
		avc.Level, avc.Title = "ok", product+", definitions current"
		if d := strings.Fields(av.Dated); len(d) >= 2 { // "5 Oct 2026 21:00"
			avc.Title = product + ", definitions " + d[0] + " " + d[1]
		}
	case av.Status == "Out of date":
		avc.Level, avc.Short, avc.Title = "warn", "antivirus out of date", product+", definitions "+av.Age
	default:
		avc.Level, avc.Short, avc.Title = "warn", "antivirus not checked", product+": "+strings.ToLower(av.Status)
	}

	orig := SysCheck{CheckCell: CheckCell{Label: "Original logs", Href: "#logs/" + name}}
	arch := cx.archives[h]
	switch {
	case s.Status == "retired":
		orig.Title = "not expected after it was retired"
	case r.PackFailing != nil && strings.EqualFold(r.PackFailing.Host, name):
		orig.Level, orig.Short, orig.Title = "bad", "original logs not archived", "not archived"
	case cx.noArchive[h]:
		orig.Level, orig.Short, orig.Title = "warn", "original logs missing", "missing for this "+r.periodNoun()
	case arch != nil:
		orig.Level, orig.Title = "ok", "in this report ("+humanBytes(arch.Bytes)+")"
		if st, ok := r.archiveState[arch.Name]; ok && !st.Verified {
			orig.Level, orig.Short, orig.Title = "bad", "original logs changed", arch.Name+" does not match its SHA-256"
		}
	case r.Interim && len(r.Archives) == 0:
		orig.Title = "kept by the next scheduled report"
	default:
		orig.Title = "not kept"
	}

	// SCAP: no scan found (when SCAP results are in the report) amber.
	sc := SysCheck{CheckCell: CheckCell{Label: "SCAP", Href: r.scapLink(name)}}
	g, ok := r.scapGlance(name)
	switch {
	case !ok:
		sc.Title = "no SCAP scan"
	case g.Missing:
		sc.Level, sc.Short, sc.Title = "warn", "no SCAP scan", "no scan found"
	default:
		sc.Level = "ok"
		sc.Title = fmt.Sprintf("%d CAT I · %s", g.Cat[1], g.Benchmark)
		if g.Score != "" {
			sc.Title = g.Score + " · " + sc.Title
		}
		switch {
		case g.Cat[1] > 0:
			sc.Level, sc.Short = "bad", plural(g.Cat[1], "open CAT I finding")
		case g.Stale:
			sc.Level, sc.Short = "warn", "SCAP scan out of date"
			sc.Title += " · out of date"
		}
	}
	return []SysCheck{reporting, logs, settings, avc, orig, sc}
}

// sysFacts are the six facts at the top of a system's page.
func (r *Report) sysFacts(s SystemRow, v *SystemView, high, med int, first *DetectionCard) []SysFact {
	f := []SysFact{{Label: "Events", Value: commas(s.Events), Note: "this period", Href: searchLink("host", s.Name)}}

	det := SysFact{Label: "Detections", Value: "None", Note: "this period"}
	switch {
	case high > 0:
		det.Value, det.Level = fmt.Sprintf("%d high", high), "bad"
		if med > 0 {
			det.Value += fmt.Sprintf(" · %d med", med)
		}
	case med > 0:
		det.Value, det.Level = fmt.Sprintf("%d medium", med), "warn"
	}
	if first != nil {
		det.Note, det.Href = first.Title, fmt.Sprintf("#detections/%d", first.Index)
		if high+med > 1 {
			det.Note = fmt.Sprintf("%s and %d more", first.Title, high+med-1)
		}
	}
	f = append(f, det)

	last := SysFact{Label: "Last collection", Value: "—", Note: v.Every, Href: "#logs/" + s.Name}
	if !s.LastRun.IsZero() {
		last.Value = r.shortStamp(s.LastRun)
	}
	switch {
	case s.Status == "retired":
		last.Note = "retired " + s.Removed.In(r.Location).Format("2 Jan")
	case s.Status == "silent":
		last.Level, last.Note = "bad", "nothing this period"
	case s.VM:
		on, _, _ := r.coverage(s)
		last.Note = fmt.Sprintf("on %d%% of the period", on)
		v.Tag = fmt.Sprintf("on %d%%", on)
	}
	f = append(f, last)

	set := SysFact{Label: "Audit settings", Value: "Not checked", Note: "no settings check yet", Href: "#health/" + s.Name}
	if c := s.Checks; c != nil {
		total := c.Pass + c.Fail + c.Warn
		set.Value, set.Note = "All match", fmt.Sprintf("of %d", total)
		if c.STIGFail > 0 {
			set.Value, set.Level = fmt.Sprintf("%d to fix", c.STIGFail), "warn"
		}
		if c.Advice > 0 {
			set.Note += fmt.Sprintf(" · %d advice", c.Advice)
		}
	}
	if s.AuditOff != "" {
		set.Value, set.Level, set.Note = "Auditing off", "bad", "at the last collection"
	}
	f = append(f, set)

	sc := SysFact{Label: "SCAP", Value: "—", Note: "no scan", Href: r.scapLink(s.Name)}
	if g, ok := r.scapGlance(s.Name); ok && !g.Missing {
		sc.Value, sc.Note = g.Score, fmt.Sprintf("%d CAT I", g.Cat[1])
		if sc.Value == "" {
			sc.Value = "Scanned"
		}
		if g.Cat[1] > 0 {
			sc.Level = "bad"
		} else if g.Stale {
			sc.Level, sc.Note = "warn", sc.Note+" · out of date"
		}
	}
	f = append(f, sc)

	orig := SysFact{Label: "Original logs", Value: "None", Note: "in this report", Href: "#logs/" + s.Name}
	for _, c := range v.Cells {
		if c.Label != "Original logs" {
			continue
		}
		switch c.Level {
		case "ok", "bad":
			for _, a := range r.Archives {
				if strings.EqualFold(a.Host, s.Name) {
					orig.Value = humanBytes(a.Bytes)
				}
			}
			if c.Level == "bad" {
				orig.Level, orig.Note = "bad", "changed since it was made"
			}
		case "warn":
			orig.Level, orig.Note = "warn", "missing"
		default:
			orig.Note = c.Title
		}
	}
	return append(f, orig)
}

// hourBars draws a system's events per hour across the period, with a
// red dot on each hour that has a detection on it. A long period puts
// several hours in one bar.
func (r *Report) hourBars(rows []*Row, host string) (template.HTML, string) {
	start, end := r.PeriodStart(), r.WindowEnd
	if !end.After(start) {
		return "", ""
	}
	step := time.Hour
	hours := int(math.Ceil(end.Sub(start).Hours()))
	if hours > maxStripCells {
		step = time.Duration((hours+maxStripCells-1)/maxStripCells) * time.Hour
	}
	n := int(math.Ceil(float64(end.Sub(start)) / float64(step)))
	vals, hot := make([]int, n), make([]bool, n)
	idx := func(t time.Time) int {
		if t.Before(start) || !t.Before(end) {
			return -1
		}
		return int(t.Sub(start) / step)
	}
	for _, row := range rows {
		if i := idx(row.Time); i >= 0 {
			vals[i]++
		}
	}
	for _, f := range r.Findings {
		if i := idx(f.Time); i >= 0 && strings.EqualFold(f.Host, host) {
			hot[i] = true
		}
	}
	top := 1
	for _, v := range vals {
		top = max(top, v)
	}
	const w, h, base = 480.0, 96.0, 78.0
	bw := w / float64(n)
	var b strings.Builder
	for i, v := range vals {
		if v == 0 {
			continue
		}
		bh := max(1.5, float64(v)/float64(top)*(base-12))
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s"/>`, float64(i)*bw+bw*.12, base-bh, max(.8, bw*.76), bh, colAccent)
		if hot[i] {
			fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="3.5" fill="%s"/>`, float64(i)*bw+bw/2, base-bh-6, colBad)
		}
	}
	for i, v := range vals {
		if hot[i] && v == 0 {
			fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="3.5" fill="%s"/>`, float64(i)*bw+bw/2, base-6, colBad)
		}
	}
	fmt.Fprintf(&b, `<line x1="0" x2="%.0f" y1="%.1f" y2="%.1f" stroke="%s"/>`, w, base+.5, base+.5, colGrid)
	days := len(r.periodDays())
	for q := 0; q <= 4; q++ {
		t := start.Add(time.Duration(float64(end.Sub(start)) * float64(q) / 4))
		label := t.In(r.Location).Format("15:04")
		if q == 4 && days <= 1 {
			label = "24:00"
		}
		if days > 1 {
			label = t.In(r.Location).Format("2 Jan")
		}
		anchor := "middle"
		if q == 0 {
			anchor = "start"
		} else if q == 4 {
			anchor = "end"
		}
		fmt.Fprintf(&b, `<text x="%.1f" y="%.0f" text-anchor="%s" class="ax">%s</text>`, w*float64(q)/4, h-2, anchor, label)
	}
	busiest := 0
	for i, v := range vals {
		if v > vals[busiest] {
			busiest = i
		}
	}
	unit, note := "hour", "events per hour"
	if step > time.Hour {
		unit, note = intervalWord(step), "events per "+intervalWord(step)
	}
	name := fmt.Sprintf("Events per %s on %s: busiest %s with %s", unit, host, start.Add(time.Duration(busiest)*step).In(r.Location).Format("2 Jan 15:04"), commas(vals[busiest]))
	var hotAt []string
	for i := range hot {
		if hot[i] {
			hotAt = append(hotAt, start.Add(time.Duration(i)*step).In(r.Location).Format("15:04"))
		}
	}
	if len(hotAt) > 0 {
		name += "; a detection at " + joinAnd(hotAt)
	}
	return template.HTML(fmt.Sprintf(`<svg class="hbars" viewBox="0 0 %.0f %.0f" width="100%%" role="img" aria-label="%s">%s</svg>`, w, h, template.HTMLEscapeString(name), b.String())), note
}

// whoActive is who was active on a system: its five busiest accounts
// with what they are, and how many more there were.
func (r *Report) whoActive(s SystemRow, users map[string]int) ([]WhoRow, int) {
	admin := map[string]bool{}
	if s.Checks != nil && s.Checks.Inventory != nil {
		for _, a := range s.Checks.Inventory.Accounts {
			if a.Admin {
				admin[personKey(a.Name)] = true
			}
		}
	}
	var out []WhoRow
	for u, n := range users {
		name := u
		if i := strings.LastIndex(u, `\`); i >= 0 && strings.EqualFold(u[:i], s.Name) {
			name = u[i+1:]
		}
		k := personKey(u)
		role := "user"
		switch {
		case strings.HasSuffix(k, "$"):
			role = "computer"
		case k == "system" || k == "local service" || k == "network service":
			role = "services"
		case admin[k] || k == "root" || k == "administrator":
			role = "administrator"
		case serviceAccount(k):
			role = "service account"
		}
		out = append(out, WhoRow{Name: name, Role: role, N: n, Href: searchLink("user", k, "host", s.Name)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	if len(out) > 5 {
		return out[:5], len(out) - 5
	}
	return out, 0
}

// vmHost is the PC a VM runs on: the computer it sent through, else the
// collector, or a standalone report's own computer.
func (r *Report) vmHost(s SystemRow) string {
	if s.Via != "" {
		return s.Via
	}
	if c := r.collectorName(); r.Collector && c != "" {
		return c
	}
	return r.MainSystem()
}

// since is a short time for "nothing received since …": "5 Oct 06:31".
func (r *Report) since(t time.Time) string {
	return t.In(r.Location).Format("2 Jan 15:04")
}

// collectorName is the collector computer's name: the one other systems'
// collections arrived at (a system that is not a VM and received nothing).
func (r *Report) collectorName() string {
	for _, s := range r.SystemRows {
		if s.Via == "" && s.LastReceived.IsZero() && isServer(s) {
			return s.Name
		}
	}
	return ""
}

// coverage is how much of the period a computer was collected: the share
// of hours with a collection run, and days with at least one.
func (r *Report) coverage(s SystemRow) (pct, days, total int) {
	start, end := r.PeriodStart(), r.WindowEnd
	total = len(r.periodDays())
	if total == 0 || len(s.runTimes) == 0 {
		return 0, 0, total
	}
	hours := map[int64]bool{}
	seen := map[string]bool{}
	for _, t := range s.runTimes {
		hours[t.Unix()/3600] = true
		seen[t.In(r.Location).Format("20060102")] = true
	}
	span := int(end.Sub(start).Hours())
	if span < 1 {
		span = 1
	}
	pct = min(100, len(hours)*100/span)
	return pct, min(len(seen), total), total
}

// systemHealth is one computer's health checklist.
func (r *Report) systemHealth(s SystemRow, cleared []*Row, on int) []CheckLine {
	var lines []CheckLine
	if len(cleared) > 0 {
		var at, by []string
		seenBy := map[string]bool{}
		for _, c := range cleared {
			at = append(at, c.Time.In(r.Location).Format("15:04"))
			if c.User != "" && !seenBy[c.User] {
				seenBy[c.User] = true
				by = append(by, c.User)
			}
		}
		what := fmt.Sprintf("%s cleared at %s on %s", clearedWhat(cleared), joinAnd(at), cleared[0].Time.In(r.Location).Format("2 Jan"))
		if len(by) > 0 {
			what += " by " + joinAnd(by)
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "file-warning", Title: "Logs cleared", What: what})
	} else {
		lines = append(lines, CheckLine{Level: "ok", Icon: "file-warning", Title: "Logs intact", What: "No logs cleared this period"})
	}

	switch {
	case s.Checks == nil:
		lines = append(lines, CheckLine{Level: "warn", Icon: "shield-check", Title: "Audit settings not checked", What: "Not checked yet"})
	case s.Checks.Fail > 0:
		var items []string
		for _, res := range s.Checks.Results {
			if res.Status == check.Fail && res.Area != "Antivirus" {
				t := res.Item
				switch {
				case res.IsAdvice():
					t += " (Blackbox's advice)"
				case res.STIG != "":
					t += " (" + res.STIG + ")"
				}
				items = append(items, t)
			}
		}
		what := strings.Join(items[:min(2, len(items))], "; ")
		if len(items) > 2 {
			what += fmt.Sprintf("; and %d more", len(items)-2)
		}
		// A count and a link; the list is on Audit health (UX3).
		lines = append(lines, CheckLine{Level: "bad", Icon: "shield-check", Title: "Audit settings to fix", What: plural(len(items), "setting") + " (" + what + ")", Href: "#health/" + s.Name})
	default:
		what := "All match"
		if s.Checks.Baseline != "" {
			what += " · " + s.Checks.Baseline
		}
		lines = append(lines, CheckLine{Level: "ok", Icon: "shield-check", Title: "Audit settings match STIG", What: what})
	}

	switch {
	case s.Status == "silent":
		lines = append(lines, CheckLine{Level: "bad", Icon: "clock-alert", Title: "Reporting", What: s.StatusMsg})
	case s.VM && len(s.runTimes) == 0:
		lines = append(lines, CheckLine{Level: "warn", Icon: "clock-alert", Title: "Reporting", What: s.StatusMsg})
	case s.VM:
		lines = append(lines, CheckLine{Level: "ok", Icon: "clock-alert", Title: "Reporting",
			What: fmt.Sprintf("On %d%% of the period; collected whenever it was on (%s)", on, plural(len(s.runTimes), "run"))})
	default:
		lv := "ok"
		if s.Status == "warn" && r.WindowEnd.Sub(s.LastRun) > silentAfter {
			lv = "warn"
		}
		lines = append(lines, CheckLine{Level: lv, Icon: "clock-alert", Title: "Reporting",
			What: fmt.Sprintf("%s this period, last %s", plural(len(s.runTimes), "collection run"), s.LastRun.In(r.Location).Format("2 Jan 15:04"))})
	}

	if s.Checks != nil {
		for _, res := range s.Checks.Results {
			product := ""
			switch {
			case res.Area != "Antivirus":
			case strings.HasPrefix(res.Item, "Defender security"):
				product = "Defender "
			case res.Item == "ClamAV definitions":
				product = "ClamAV "
			}
			if product == "" || res.Status == check.Info {
				continue
			}
			lv := map[check.Status]string{check.Pass: "ok", check.Fail: "bad"}[res.Status]
			if lv == "" {
				lv = "warn"
			}
			what := product + res.Have
			if !res.Dated.IsZero() {
				what = product + "definitions dated " + res.Dated.In(r.Location).Format("2 Jan 2006 15:04") + " (" + roughDuration(r.WindowEnd.Sub(res.Dated)) + " old)"
			}
			title := "Antivirus definitions current"
			if lv != "ok" {
				title = "Antivirus needs attention"
			}
			lines = append(lines, CheckLine{Level: lv, Icon: "shield", Title: title, What: what, Href: "#health/@av"})
		}
	}

	if sc, ok := r.scapGlance(s.Name); ok {
		l := CheckLine{Level: "ok", Icon: "shield-check", Title: "STIG compliance (SCAP)", Href: r.scapLink(s.Name)}
		switch {
		case sc.Missing:
			l.Level, l.Title, l.What = "warn", "No SCAP scan", "Put this system's SCC or OpenSCAP results in the scap_results folder"
		default:
			l.What = fmt.Sprintf("%d CAT I, %d CAT II, %d CAT III open · %s", sc.Cat[1], sc.Cat[2], sc.Cat[3], sc.Benchmark)
			if sc.Score != "" {
				l.What = "Score " + sc.Score + " · " + l.What
			}
			switch {
			case sc.Cat[1] > 0:
				l.Level, l.Title = "bad", "Open CAT I findings (SCAP)"
			case sc.Stale:
				l.Level, l.Title, l.What = "warn", "SCAP scan out of date", l.What+" · stale scan"
			case sc.Cat[2] > 0:
				l.Level, l.Title = "warn", "Open CAT II findings (SCAP)"
			}
		}
		lines = append(lines, l)
	}

	// The audit record's losses fail; other logs' (the PowerShell log)
	// are a warning of their own, named (LOG1).
	var critical []GapItem
	if other := lostTitle(s.gaps, false); other != "" {
		lines = append(lines, CheckLine{Level: "warn", Icon: "history", Title: "Other logs overwrote events", What: other})
	}
	for _, g := range s.gaps {
		if rollover.Critical(g.Channel) {
			critical = append(critical, g)
		}
	}
	if len(critical) > 0 {
		what := "Some events were overwritten before they were collected"
		if t := lostTitle(critical, true); t != "" {
			what = t + " before they were collected"
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "history", Title: "Events lost to log rollover", What: what})
	} else {
		what := "Nothing overwritten before it was collected"
		for _, log := range []string{"Security", "audit", "auth"} {
			for ch, t := range s.holds {
				if strings.Contains(strings.ToLower(ch), strings.ToLower(log)) && !s.LastRun.IsZero() {
					days := int(s.LastRun.Sub(t).Hours() / 24)
					what = fmt.Sprintf("%s log holds %s", ch, plural(days, "day"))
				}
			}
		}
		lines = append(lines, CheckLine{Level: "ok", Icon: "history", Title: "No events lost to log rollover", What: what})
	}
	return lines
}

// clearedWhat names the logs cleared (LC1): "Security log", "PowerShell
// log", "Security and PowerShell logs". A Security clear is 1102; any
// other log's is System 104.
func clearedWhat(rows []*Row) string {
	var names []string
	seen := map[string]bool{}
	for _, row := range rows {
		n := "an event log"
		if row.Target == "" && row.EventID == 1102 {
			n = "Security"
		} else if row.Target != "" {
			n = strings.TrimSuffix(rollover.Name(row.Target), " log")
		}
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.SliceStable(names, func(i, j int) bool { return logRank(names[i]) < logRank(names[j]) })
	switch {
	case len(names) == 1 && names[0] == "an event log":
		return "An event log"
	case len(names) == 1:
		return names[0] + " log"
	}
	return joinAnd(names) + " logs"
}

func joinAnd(l []string) string {
	switch len(l) {
	case 0:
		return ""
	case 1:
		return l[0]
	}
	return strings.Join(l[:len(l)-1], ", ") + " and " + l[len(l)-1]
}
