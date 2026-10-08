package report

import (
	"fmt"
	"github.com/casea1/blackbox/internal/rollover"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
)

// The Systems page (design S2): a list grouped into servers, workstations
// and virtual machines, problems first; and for the one selected, five
// facts, this week's collection, a health checklist, its activity against
// a typical system on the network, and its detections.

// SystemGroup is one group of the Systems page's list.
type SystemGroup struct {
	Title   string
	Systems []*SystemView
}

// Fact is one of a page's headline facts.
type Fact struct {
	Label, Value string
	Bad          bool
	Href         string // where it leads
	Scroll       string // or: an element on the same page to scroll to
}

// ActivityBar is one line of "Activity vs. typical system".
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

// SystemView is one computer on the Systems page.
type SystemView struct {
	Name, Tag   string // Tag: short OS, or "on 41%" for a VM
	Level       string // bad | warn | ""
	Line        string // OS · role
	Status      string
	Facts       []Fact
	Bar         template.HTML
	Health      []CheckLine
	Activity    []ActivityBar
	Detections  []DetectionCard
	Message     string // why it is silent, if it is
	FailedItems []check.Result
}

// SystemsPage is the Systems page.
type SystemsPage struct {
	Groups []SystemGroup
	Count  int
	LAN    bool // standalone reports have no "typical system" to compare with
}

// activityKinds are the lines of "Activity vs. typical system".
var activityKinds = []struct{ Label, Page string }{
	{"Privileged actions", "privileged"}, {"Failed logons", "failed"}, {"Logons", "logons"},
	{"USB events", "usb"}, {"Account changes", "accounts"}, {"PowerShell", "powershell"},
}

func (r *Report) systemsPage() *SystemsPage {
	if len(r.SystemRows) == 0 && len(r.Retired) == 0 {
		return nil
	}
	sp := &SystemsPage{Count: len(r.SystemRows), LAN: r.IsLAN()}
	pages := map[string]*EventPage{}
	for _, p := range eventPages() {
		pages[p.ID] = p
	}
	// Events of each kind per computer, and log clears.
	counts := map[string]map[string]int{}
	cleared := map[string][]*Row{}
	for _, row := range r.rows {
		h := strings.ToLower(row.Host)
		if counts[h] == nil {
			counts[h] = map[string]int{}
		}
		for _, k := range activityKinds {
			if pages[k.Page].on(row.Event) {
				counts[h][k.Page]++
			}
		}
		if row.Action == "log_cleared" {
			cleared[h] = append(cleared[h], row)
		}
	}
	median := map[string]int{}
	for _, k := range activityKinds {
		var vals []int
		for _, s := range r.SystemRows {
			if s.Status != "silent" {
				vals = append(vals, counts[strings.ToLower(s.Name)][k.Page])
			}
		}
		sort.Ints(vals)
		if len(vals) > 0 {
			median[k.Page] = vals[len(vals)/2]
		}
	}
	cards := r.detectionCards()

	groups := []*SystemGroup{{Title: "Servers"}, {Title: "Workstations"}, {Title: "Virtual machines"}, {Title: "Retired"}}
	for _, s := range append(append([]SystemRow(nil), r.SystemRows...), r.Retired...) {
		h := strings.ToLower(s.Name)
		v := &SystemView{Name: s.Name, Tag: strings.ToUpper(shortOS(s)), Message: s.StatusMsg}
		retired := s.Status == "retired"
		role := "Workstation"
		g := groups[1]
		switch {
		case retired:
			g = groups[3]
			if isServer(s) {
				role = "Server"
			}
			if s.VM {
				role = "Virtual machine"
			}
		case s.VM:
			role, g = "Virtual machine", groups[2]
			if host := r.vmHost(s); host != "" {
				role += " on " + host
			}
		case isServer(s):
			role, g = "Server", groups[0]
		}
		if !r.IsLAN() && !s.VM {
			role = "Standalone"
		}
		v.Line = osLabel(s) + " · " + role
		if retired {
			v.Line += " · retired " + s.Removed.In(r.Location).Format("2 Jan")
			if s.RemovedBy != "" {
				v.Line += " by " + s.RemovedBy
			}
		}
		if s.Via != "" && !s.VM {
			v.Line += " · data via " + s.Via
		}
		if r.Collector && s.Via == "" && strings.EqualFold(s.Name, r.collectorName()) {
			v.Line += " · collector"
		}
		if l := r.scapLine(s.Name); l != "" {
			v.Line += " · " + l
		}

		// Detections on this computer.
		high, med := 0, 0
		for _, c := range cards {
			if strings.EqualFold(c.Host, s.Name) {
				v.Detections = append(v.Detections, c)
				if c.Severity == "high" {
					high++
				} else {
					med++
				}
			}
		}
		switch {
		case s.Status == "silent" || s.AuditOff != "" || len(cleared[h]) > 0 || high > 0:
			v.Level, v.Status = "bad", "Needs attention"
		case s.Status == "warn" || med > 0:
			v.Level, v.Status = "warn", "Worth a look"
		default:
			v.Status = "Healthy"
		}
		if s.Status == "silent" {
			v.Status = "Silent"
		} else if s.AuditOff != "" {
			v.Status = "Auditing off"
		}
		if retired {
			v.Level, v.Status, v.Tag = "retired", "Retired", "RETIRED"
		}

		// Five facts.
		det := "None"
		if high+med > 0 {
			var p []string
			if high > 0 {
				p = append(p, fmt.Sprintf("%d high", high))
			}
			if med > 0 {
				p = append(p, fmt.Sprintf("%d med", med))
			}
			det = strings.Join(p, " · ")
		}
		on, days, total := r.coverage(s)
		collected := fmt.Sprintf("%d of %d days", days, total)
		if s.VM {
			collected = fmt.Sprintf("on %d%%", on)
			v.Tag = collected
		}
		switch {
		case retired:
			// Not "nothing" next to its events (ROLE1b): it stopped.
			collected = "until " + s.Removed.In(r.Location).Format("2 Jan")
		case s.Status == "silent", s.VM && len(s.runTimes) == 0:
			collected = "nothing"
		}
		settings, settingsBad := "not checked", false
		if s.Checks != nil {
			settings = "match STIG"
			if s.Checks.STIGFail > 0 {
				settings, settingsBad = plural(s.Checks.STIGFail, "gap"), true
			}
			if s.Checks.Advice > 0 {
				// Blackbox's advice is not a STIG gap (COMP2).
				settings += fmt.Sprintf(" · %d Blackbox advice", s.Checks.Advice)
			}
		}
		last := "—"
		if !s.LastRun.IsZero() {
			last = s.LastRun.In(r.Location).Format("2 Jan 15:04")
			if s.LastRunAhead {
				last += " (clock was ahead)"
			}
		}
		v.Facts = []Fact{
			{Label: "Events", Value: commas(s.Events), Href: searchLink("host", s.Name)},
			{Label: "Detections", Value: det, Bad: high+med > 0, Scroll: "sysdet-" + s.Name},
			{Label: "Collected", Value: collected, Bad: !retired && (s.Status == "silent" || (!s.VM && days < total) || (s.VM && len(s.runTimes) == 0)), Href: "#logs/" + s.Name},
			{Label: "Audit settings", Value: settings, Bad: settingsBad, Href: "#health/" + s.Name},
			{Label: "Last report", Value: last, Bad: s.Status != "ok" && s.Status != "warn" && !retired, Href: "#logs/" + s.Name},
		}
		if retired {
			// Retired: what it was is shown, not what is wrong with it.
			v.Facts[3] = Fact{Label: "Retired", Value: s.Removed.In(r.Location).Format("2 Jan 15:04")}
			if s.RemovedBy != "" {
				v.Facts[3].Value += " by " + s.RemovedBy
			}
		}

		v.Bar = r.collectionBar(s, cleared[h])
		v.Health = r.systemHealth(s, cleared[h], on)
		if retired {
			v.Health = []CheckLine{{Level: "ok", Icon: "server", Title: "Retired", What: s.StatusMsg}}
			v.Message = ""
		}
		// The reason it is silent is said once: in Health › Reporting
		// when that line says it, not also in a box above (UX3).
		for _, l := range v.Health {
			if l.Level != "ok" && v.Message != "" && strings.Contains(l.What, v.Message) {
				v.Message = ""
			}
		}
		for i := range v.Health {
			switch v.Health[i].Title {
			case "Logs intact", "Logs cleared":
				v.Health[i].Href = searchLink("page", "integrity", "host", s.Name)
			case "STIG compliance (SCAP)", "No SCAP scan", "SCAP scan out of date", "Open CAT I findings (SCAP)", "Open CAT II findings (SCAP)":
				v.Health[i].Href = ScapHref(s.Name)
			case "Reporting":
				v.Health[i].Href = "#logs/" + s.Name
			default:
				v.Health[i].Href = "#health/" + s.Name
			}
		}
		if s.Checks != nil {
			for _, res := range s.Checks.Results {
				if res.Status == check.Fail && res.Area != "Antivirus" {
					v.FailedItems = append(v.FailedItems, res)
				}
			}
		}

		// Activity against the network's median.
		for _, k := range activityKinds {
			n, m := counts[h][k.Page], median[k.Page]
			if !sp.LAN {
				m = 0
			}
			top := max(n, 2*m, 1)
			a := ActivityBar{Label: k.Label, N: n, Pct: n * 100 / top, Median: m * 100 / top, PageID: k.Page,
				Href: searchLink("page", k.Page, "host", s.Name)}
			a.Above = r.IsLAN() && float64(n) > float64(m)*1.5 && n >= m+5
			v.Activity = append(v.Activity, a)
		}
		if !sp.LAN { // scale against this system's busiest kind
			top := 1
			for _, a := range v.Activity {
				top = max(top, a.N)
			}
			for i := range v.Activity {
				v.Activity[i].Pct = v.Activity[i].N * 100 / top
			}
		}
		g.Systems = append(g.Systems, v)
	}
	rank := map[string]int{"bad": 0, "warn": 1, "": 2, "retired": 3}
	for _, g := range groups {
		sort.SliceStable(g.Systems, func(i, j int) bool {
			a, b := g.Systems[i], g.Systems[j]
			if rank[a.Level] != rank[b.Level] {
				return rank[a.Level] < rank[b.Level]
			}
			return naturalLess(a.Name, b.Name)
		})
		if len(g.Systems) > 0 {
			sp.Groups = append(sp.Groups, *g)
		}
	}
	return sp
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

// collectionBar draws the period as a strip: covered hours in light blue,
// lost events and cleared logs in red.
func (r *Report) collectionBar(s SystemRow, cleared []*Row) template.HTML {
	start, end := r.PeriodStart(), r.WindowEnd
	if !end.After(start) {
		return ""
	}
	const w, h = 808.0, 30.0
	span := end.Sub(start).Seconds()
	x := func(t time.Time) float64 {
		v := t.Sub(start).Seconds() / span * w
		return max(0, min(w, v))
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<rect x="0" y="16" width="%.0f" height="10" fill="rgba(0,30,98,.06)"/>`, w)
	// Each run covers the hour before it.
	runs := append([]time.Time(nil), s.runTimes...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].Before(runs[j]) })
	var segStart, segEnd time.Time
	flush := func() {
		if !segStart.IsZero() {
			fmt.Fprintf(&b, `<rect x="%.1f" y="16" width="%.1f" height="10" fill="#C9D7F2"/>`, x(segStart), max(1.5, x(segEnd)-x(segStart)))
		}
	}
	for _, t := range runs {
		from := t.Add(-75 * time.Minute)
		if segStart.IsZero() || from.After(segEnd) {
			flush()
			segStart = t.Add(-time.Hour)
		}
		segEnd = t
	}
	flush()
	for _, g := range s.gaps {
		a, z := g.From, g.To
		if a.IsZero() || z.IsZero() {
			continue
		}
		fmt.Fprintf(&b, `<rect x="%.1f" y="16" width="%.1f" height="10" fill="%s"><title>Events lost</title></rect>`, x(a), max(3, x(z)-x(a)), colBad)
	}
	for _, c := range cleared {
		fmt.Fprintf(&b, `<rect x="%.1f" y="13" width="4" height="16" fill="%s"><title>Log cleared %s</title></rect>`, x(c.Time)-2, colBad,
			c.Time.In(r.Location).Format("2 Jan 15:04"))
	}
	for _, t := range s.resets {
		fmt.Fprintf(&b, `<rect x="%.1f" y="13" width="4" height="16" fill="%s"/>`, x(t)-2, colBad)
	}
	// Day labels are text above the strip (not inside the stretched
	// drawing), at most about eight of them so they never overlap.
	days := r.periodDays()
	step := max(1, (len(days)+7)/8)
	layout := "Mon 2"
	if len(days) > 10 {
		layout = "2 Jan"
	}
	var labels strings.Builder
	for i, d := range days {
		if i%step != 0 {
			continue
		}
		t, _ := time.ParseInLocation("20060102", d, r.Location)
		fmt.Fprintf(&labels, `<span style="left:%.2f%%">%s</span>`, x(t)/w*100, t.Format(layout))
	}
	return template.HTML(fmt.Sprintf(`<div class="cbar"><div class="cbar-l">%s</div><svg viewBox="0 13 %.0f %.0f" width="100%%" height="16" preserveAspectRatio="none" role="img">%s</svg></div>`,
		labels.String(), w, h-13, b.String()))
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
		l := CheckLine{Level: "ok", Icon: "shield-check", Title: "STIG compliance (SCAP)", Href: ScapHref(s.Name)}
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
