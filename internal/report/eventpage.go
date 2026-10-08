package report

import (
	"fmt"
	"html/template"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/event"
)

// The top part of each event page (design V1): four stat cards, events
// per day by kind, a top-six list, and the detections the page's events
// are part of. Each page also names its table's columns and the kind
// filter, which app.js reads from the page's settings.

// Column is one column of an event page's table. Field names a value
// app.js knows: time, host, user, account, src, kind, x, sum, cmd, sev.
type Column struct {
	Label string `json:"l"`
	Field string `json:"f"`
}

// TopItem is one line of a top-six list.
type TopItem struct {
	Label   string
	Href    string
	N       int
	Pct     int
	Flagged bool
}

// pageKind is one part of a page's per-day chart.
type pageKind struct {
	Name, Color string
}

// pageSpec says how one event page is split up and shown.
type pageSpec struct {
	kinds     []pageKind
	kindOf    func(e *event.Event) string // one of kinds' names
	kindLabel string                      // the kind filter and column, e.g. "Reason"
	extra     func(e *event.Event) string // page-specific column
	topTitle  string
	top       func(e *event.Event) string
	unit      string // "failed logons", for "n of N failed logons…"
	metric    string // for the normal range, if kept
	cols      []Column
}

const colKind2, colKind3, colKind4, colKind5 = colLight, colWarn, "#0A2A7A", "#8A94A8"

func detail(e *event.Event, label string) string {
	for _, d := range e.Details {
		if d.Label == label {
			return d.Value
		}
	}
	return ""
}

func account(e *event.Event) string {
	if e.Target != "" {
		return e.Target
	}
	return e.User
}

func logonSource(e *event.Event) string {
	if e.SourceIP != "" && !localAddress(e.SourceIP) {
		return e.SourceIP
	}
	if w := detail(e, "Source workstation"); w != "" && w != "-" {
		return w
	}
	return e.Host + " console"
}

func logonHow(e *event.Event) string {
	t := strings.ToLower(detail(e, "Logon type") + " " + e.Process + " " + e.RecordType + " " + e.Summary)
	switch {
	case strings.Contains(t, "remote"):
		return "Remote Desktop"
	case strings.Contains(t, "ssh"):
		return "SSH"
	case strings.Contains(t, "network"):
		return "Network"
	case strings.Contains(t, "sudo"):
		return "sudo"
	}
	return "Console"
}

func has(a string, list ...string) bool {
	for _, s := range list {
		if strings.HasPrefix(a, s) {
			return true
		}
	}
	return false
}

var pageSpecs = map[string]pageSpec{
	"failed": {
		kinds: []pageKind{{"Bad password", colAccent}, {"Expired", colKind2}, {"Locked out", colKind3}},
		kindOf: func(e *event.Event) string {
			r := strings.ToLower(detail(e, "Reason") + " " + e.Summary)
			switch {
			case e.Action == "account_locked" || strings.Contains(r, "locked"):
				return "Locked out"
			case strings.Contains(r, "expired"):
				return "Expired"
			}
			return "Bad password"
		},
		kindLabel: "Reason", extra: logonHow, topTitle: "Top sources", top: logonSource, unit: "failed logons", metric: MFailedLogons,
		cols: []Column{{"Time", "time"}, {"System", "host"}, {"Account", "account"}, {"Source", "src"}, {"Logon type", "x"}, {"Reason", "kind"}, {"Severity", "sev"}},
	},
	"privileged": {
		kinds: []pageKind{{"Admin logon", colAccent}, {"sudo / run as admin", colKind2}, {"Security settings", colKind3}},
		kindOf: func(e *event.Event) string {
			switch {
			case has(e.Action, "admin_logon", "explicit_credentials", "switch_user"):
				return "Admin logon"
			case has(e.Action, "sudo", "elevated_process", "pkexec", "root_command", "privileged_program"):
				return "sudo / run as admin"
			}
			return "Security settings"
		},
		kindLabel: "Kind", topTitle: "Top people", top: func(e *event.Event) string { return e.User }, unit: "privileged actions", metric: MPrivileged,
		cols: []Column{{"Time", "time"}, {"System", "host"}, {"Person", "user"}, {"Kind", "kind"}, {"What they did", "sum"}, {"Severity", "sev"}},
	},
	"usb": {
		kinds: []pageKind{{"Connected or removed", colAccent}, {"Files copied", colKind2}, {"Blocked", colBad}},
		kindOf: func(e *event.Event) string {
			switch {
			case strings.Contains(e.Action, "blocked") || e.Outcome == "failure":
				return "Blocked"
			case detail(e, "File") != "" || strings.Contains(e.Action, "file"):
				return "Files copied"
			}
			return "Connected or removed"
		},
		kindLabel: "What happened", extra: usbDevice, topTitle: "Top devices", top: usbDevice, unit: "USB events", metric: MUSB,
		cols: []Column{{"Time", "time"}, {"System", "host"}, {"Person", "user"}, {"Device", "x"}, {"What happened", "sum"}, {"Severity", "sev"}},
	},
	"accounts": {
		kinds: []pageKind{{"Created", colAccent}, {"Changed", colKind2}, {"Added to group", colKind3}, {"Disabled", colKind4}},
		kindOf: func(e *event.Event) string {
			switch {
			case strings.HasSuffix(e.Action, "_created"):
				return "Created"
			case e.Action == "group_member_added":
				return "Added to group"
			case has(e.Action, "account_disabled", "account_deleted", "group_deleted"):
				return "Disabled"
			}
			return "Changed"
		},
		kindLabel: "Kind", topTitle: "Changed accounts", top: account, unit: "account changes", metric: MAccountChanges,
		cols:  []Column{{"Time", "time"}, {"System", "host"}, {"Changed by", "user"}, {"Account", "x"}, {"What changed", "sum"}, {"Severity", "sev"}},
		extra: func(e *event.Event) string { return e.Target },
	},
	"integrity": {
		// Each kind its own label (UX2): "Logging stopped" is only the
		// event log or audit service stopping, the log full or dropping
		// records.
		kinds: []pageKind{{"Log cleared", colBad}, {"Audit policy changed", colKind3}, {"Logging stopped", colKind4}, {"Blackbox", colAccent},
			{"Firewall", colKind2}, {"Clock", colKind5}, {"Startup and shutdown", colKind5}, {"Other", colKind5}},
		kindOf: func(e *event.Event) string {
			switch {
			case has(e.Action, "log_cleared", "log_tampered", "audit_tamper"):
				return "Log cleared"
			case has(e.Action, "audit_policy", "audit_disabled", "audit_enabled", "audit_locked", "audit_rules", "object_audit"):
				return "Audit policy changed"
			case has(e.Action, "audit_stopped", "audit_events_dropped", "eventlog_shutdown", "eventlog_error", "log_full"):
				return "Logging stopped"
			case has(e.Action, "blackbox_"):
				return "Blackbox"
			case has(e.Action, "firewall_"):
				return "Firewall"
			case e.Action == "time_changed":
				return "Clock"
			case has(e.Action, "system_start", "system_stop", "shutdown_initiated", "unexpected_shutdown", "audit_started"):
				return "Startup and shutdown"
			}
			return "Other"
		},
		kindLabel: "Kind", topTitle: "Top systems", top: func(e *event.Event) string { return e.Host }, unit: "audit integrity events",
		cols: []Column{{"Time", "time"}, {"System", "host"}, {"Person", "user"}, {"Kind", "kind"}, {"What changed", "sum"}, {"Severity", "sev"}},
	},
	"powershell": {
		kinds: []pageKind{{"Routine", colAccent}, {"Warning", colKind3}, {"Suspicious", colBad}},
		kindOf: func(e *event.Event) string {
			switch {
			case e.Action == "powershell_suspicious" || e.Severity == event.SevHigh:
				return "Suspicious"
			case e.Severity == event.SevMedium:
				return "Warning"
			}
			return "Routine"
		},
		kindLabel: "Kind", topTitle: "Top systems", top: func(e *event.Event) string { return e.Host }, unit: "PowerShell scripts", metric: MSuspiciousPS,
		cols: []Column{{"Time", "time"}, {"System", "host"}, {"Person", "user"}, {"Script", "cmd"}, {"Kind", "kind"}, {"Severity", "sev"}},
	},
	"other": {
		kinds: []pageKind{{"Services and tasks", colAccent}, {"Malware and antivirus", colBad}, {"Kernel and access control", colKind3}, {"System", colKind2}, {"Not translated", colKind4}},
		kindOf: func(e *event.Event) string {
			switch {
			case has(e.Action, "service_", "scheduled_task"):
				return "Services and tasks"
			case has(e.Action, "malware", "av_"):
				return "Malware and antivirus"
			case has(e.Action, "module_", "mac_", "selinux", "apparmor", "promiscuous", "file_"):
				return "Kernel and access control"
			case e.Action == "other_security":
				return "Not translated"
			}
			return "System"
		},
		kindLabel: "Kind", topTitle: "Top systems", top: func(e *event.Event) string { return e.Host }, unit: "other security events",
		cols: []Column{{"Time", "time"}, {"System", "host"}, {"Person", "user"}, {"Kind", "kind"}, {"What happened", "sum"}, {"Severity", "sev"}},
	},
	"logons": {
		kinds: []pageKind{{"Console", colAccent}, {"Remote Desktop", colKind2}, {"SSH", colKind3}, {"Network", colKind4}},
		kindOf: func(e *event.Event) string {
			if h := logonHow(e); h != "sudo" {
				return h
			}
			return "Console"
		},
		kindLabel: "How", topTitle: "Top people", top: func(e *event.Event) string { return e.User }, unit: "logons",
		cols: []Column{{"Time", "time"}, {"System", "host"}, {"Person", "user"}, {"From", "src"}, {"How", "kind"}, {"Session", "x"}, {"Severity", "sev"}},
	},
}

// sessions finds how long each logon lasted, by pairing it with the
// logoff for the same logon ID on the same computer.
func (r *Report) sessions() map[int]string {
	open := map[string]int{}
	out := map[int]string{}
	for i, e := range r.Events {
		id := detail(e, "Logon ID")
		if id == "" || e.Category != event.CatLogon {
			continue
		}
		key := e.Host + "|" + strings.ToLower(id)
		switch e.Action {
		case "logon":
			open[key] = i
		case "logoff":
			if j, ok := open[key]; ok {
				out[j] = duration(e.Time.Sub(r.Events[j].Time))
				delete(open, key)
			}
		}
	}
	return out
}

func duration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
}

func usbDevice(e *event.Event) string {
	if e.Target != "" {
		return e.Target
	}
	for _, l := range []string{"Device", "Product", "Device ID"} {
		if v := detail(e, l); v != "" {
			return v
		}
	}
	return ""
}

// searchCols are the Search results' columns.
var searchCols = []Column{{"Time", "time"}, {"System", "host"}, {"Event", "event"}, {"Person", "user"}, {"Details", "sum"}, {"Severity", "sev"}}

// colWidth is each table field's width in the grid.
var colWidth = map[string]string{
	"time": "150px", "sev": "90px", "event": "minmax(0,1.3fr)", "sum": "minmax(0,3fr)", "cmd": "minmax(0,3fr)",
}

// gridCols is the CSS for a table's column widths.
func gridCols(cols []Column) template.CSS {
	if len(cols) == 0 {
		return ""
	}
	var w []string
	for _, c := range cols {
		if x, ok := colWidth[c.Field]; ok {
			w = append(w, x)
		} else {
			w = append(w, "minmax(0,1fr)")
		}
	}
	return template.CSS("--cols:" + strings.Join(w, " "))
}

// pageTop is what the template shows above an event page's table.
type pageTop struct {
	Stats       []EventCard
	ChartTitle  string
	KindWord    string // "Reason", for "By reason"
	Chart       template.HTML
	Legend      []pageKind
	Hot         bool // some day is outlined
	TopTitle    string
	Top         []TopItem
	Flagged     []DetectionCard
	FlaggedNote string
}

// fillPages adds each event page's top part, table columns and the kind
// and extra values its table rows carry.
func (r *Report) fillPages(pages []*EventPage) {
	inFinding := map[int][]int{} // event index → findings
	for fi, f := range r.Findings {
		for _, id := range f.RowIDs {
			i := rowIndex(id)
			inFinding[i] = append(inFinding[i], fi)
		}
	}
	days := r.periodDays()
	cards := map[int]DetectionCard{}
	for _, c := range r.detectionCards() {
		cards[c.Index] = c
	}
	for _, p := range pages {
		spec, ok := pageSpecs[p.ID]
		if !ok {
			continue
		}
		p.Cols, p.KindLabel = spec.cols, spec.kindLabel
		perDay := map[string][]int{}
		for _, d := range days {
			perDay[d] = make([]int, len(spec.kinds))
		}
		tops := map[string]int{}
		flaggedTop := map[string]bool{}
		findings := map[int]int{}
		flaggedRows := 0
		users, hosts, sources := map[string]bool{}, map[string]bool{}, map[string]bool{}
		count := map[string]int{}
		// A period of a day or less is charted by hour (UX4).
		start := r.PeriodStart()
		span := r.WindowEnd.Sub(start)
		hourly := !start.IsZero() && span > 0 && span <= 24*time.Hour
		var perHour [][]int
		if hourly {
			perHour = make([][]int, int(math.Ceil(r.WindowEnd.Sub(start).Hours())))
			for h := range perHour {
				perHour[h] = make([]int, len(spec.kinds))
			}
		}
		for i, e := range r.Events {
			if !p.on(e) {
				continue
			}
			k := spec.kindOf(e)
			if hourly {
				if h := int(e.Time.Sub(start).Hours()); h >= 0 && h < len(perHour) {
					for ki, pk := range spec.kinds {
						if pk.Name == k {
							perHour[h][ki]++
						}
					}
				}
			}
			if day := e.Time.In(r.Location).Format("20060102"); perDay[day] != nil {
				for ki, pk := range spec.kinds {
					if pk.Name == k {
						perDay[day][ki]++
					}
				}
			}
			count[k]++
			if t := spec.top(e); t != "" {
				tops[t]++
				if len(inFinding[i]) > 0 {
					flaggedTop[t] = true
				}
			}
			if len(inFinding[i]) > 0 {
				flaggedRows++
				for _, fi := range inFinding[i] {
					findings[fi]++
				}
			}
			if person(e.User) {
				users[e.User] = true
			}
			hosts[e.Host] = true
			sources[logonSource(e)] = true
		}
		// The legend names the kinds this page has (all of them when it
		// has none), so a page with many kinds stays on one line or two.
		var legend []pageKind
		for _, k := range spec.kinds {
			if count[k.Name] > 0 {
				legend = append(legend, k)
			}
		}
		if len(legend) == 0 {
			legend = spec.kinds
		}
		top := &pageTop{ChartTitle: p.Title + " per day", TopTitle: spec.topTitle, Legend: legend, KindWord: spec.kindLabel}
		switch p.ID {
		case "failed":
			top.ChartTitle = "Failed logons per day"
		case "privileged":
			top.ChartTitle = "Privileged actions per day"
		case "usb":
			top.ChartTitle = "USB events per day"
		case "accounts":
			top.ChartTitle = "Account changes per day"
		case "integrity":
			top.ChartTitle = "Audit integrity events per day"
		case "powershell":
			top.ChartTitle = "Scripts per day"
		case "other":
			top.ChartTitle = "Other security events per day"
		case "logons":
			top.ChartTitle = "Logons per day"
		}
		// Chart: one bar per day, outlined when well above the week's average.
		var labels []string
		series := make([]Series, len(spec.kinds))
		for ki, k := range spec.kinds {
			series[ki] = Series{Name: k.Name, Color: k.Color}
		}
		var tot []int
		sum := 0
		if hourly {
			top.ChartTitle = strings.Replace(top.ChartTitle, " per day", " per hour", 1)
			for h := range perHour {
				labels = append(labels, start.Add(time.Duration(h)*time.Hour).In(r.Location).Format("15:04"))
				n := 0
				for ki := range spec.kinds {
					series[ki].Values = append(series[ki].Values, perHour[h][ki])
					n += perHour[h][ki]
				}
				tot = append(tot, n)
				sum += n
			}
		} else {
			for _, d := range days {
				t, _ := time.ParseInLocation("20060102", d, r.Location)
				if len(days) > 10 {
					labels = append(labels, t.Format("2 Jan"))
				} else {
					labels = append(labels, t.Format("Mon"))
				}
				n := 0
				for ki := range spec.kinds {
					series[ki].Values = append(series[ki].Values, perDay[d][ki])
					n += perDay[d][ki]
				}
				tot = append(tot, n)
				sum += n
			}
		}
		hot := make([]bool, len(tot))
		active := 0 // days with events: quiet weekends don't make weekdays look busy
		for _, v := range tot {
			if v > 0 {
				active++
			}
		}
		// "Above normal" needs something to compare with: at least two
		// other days with events, and never by hour (UX4).
		for di, v := range tot {
			if hourly || active < 3 {
				break
			}
			others := float64(sum-v) / float64(max(1, active-1))
			if float64(v) > others*1.5 && float64(v) >= others+10 {
				hot[di], top.Hot = true, true
			}
		}
		top.Chart = stackedBars(labels, series, hot, false, 640, 190)
		// Top six.
		type kv struct {
			k string
			n int
		}
		var tl []kv
		for k, n := range tops {
			tl = append(tl, kv{k, n})
		}
		sort.Slice(tl, func(a, b int) bool { return tl[a].n > tl[b].n || tl[a].n == tl[b].n && naturalLess(tl[a].k, tl[b].k) })
		for i, x := range tl {
			if i == 6 {
				break
			}
			item := TopItem{Label: x.k, N: x.n, Pct: x.n * 100 / max(1, tl[0].n), Flagged: flaggedTop[x.k]}
			switch p.ID {
			case "privileged", "logons":
				item.Href = searchLink("page", p.ID, "user", r.pkey(x.k))
			case "integrity", "powershell", "other":
				item.Href = searchLink("page", p.ID, "host", x.k)
			case "failed":
				item.Href = searchLink("page", p.ID, "text", strings.TrimSuffix(x.k, " console"))
			default:
				item.Href = searchLink("page", p.ID, "text", x.k)
			}
			top.Top = append(top.Top, item)
		}
		// Detections with most of this page's events (none: no panel).
		var fl []int
		for fi := range findings {
			fl = append(fl, fi)
		}
		sort.Slice(fl, func(a, b int) bool {
			fa, fb := r.Findings[fl[a]], r.Findings[fl[b]]
			if fa.Severity != fb.Severity {
				return fa.Severity == event.SevHigh
			}
			return fa.Time.After(fb.Time)
		})
		for _, fi := range fl {
			if len(top.Flagged) < 3 {
				top.Flagged = append(top.Flagged, cards[fi])
			}
		}
		if p.Total > 0 {
			top.FlaggedNote = fmt.Sprintf("%s of %s %s are in a detection", commas(flaggedRows), commas(p.Total), spec.unit)
		}
		top.Stats = r.pageStats(p, spec, count, users, hosts, sources, findings)
		p.Top = top
	}
}

// periodDays lists the report period's days (YYYYMMDD), oldest first.
func (r *Report) periodDays() []string {
	start, end := r.PeriodStart().In(r.Location), r.WindowEnd.In(r.Location)
	if start.IsZero() || !end.After(start) {
		return nil
	}
	var out []string
	d := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, r.Location)
	for ; d.Before(end) && len(out) < 62; d = d.AddDate(0, 0, 1) {
		out = append(out, d.Format("20060102"))
	}
	return out
}

// normalRange is "normal: a–b" from the metric's complete calendar weeks,
// shown only for a report that covers about a week, which those numbers
// can be compared with (UI1).
func (r *Report) normalRange(metric string) string {
	if metric == "" || r.WindowEnd.Sub(r.PeriodStart()) < 6*24*time.Hour {
		return ""
	}
	lo, hi, n := 0, 0, 0
	ws := r.weeks()
	for _, w := range ws[:len(ws)-1] {
		if !w.Complete {
			continue
		}
		v := w.value(metric)
		if n == 0 || v < lo {
			lo = v
		}
		if n == 0 || v > hi {
			hi = v
		}
		n++
	}
	switch {
	case n < 3:
		return ""
	case lo == hi:
		return "normal: " + commas(lo) + " a week"
	}
	return "normal: " + commas(lo) + "–" + commas(hi) + " a week"
}

// aboveNormal says whether a count for this report's period is well above
// the average complete week, scaled to the period's length.
func (r *Report) aboveNormal(metric string, v int) bool {
	t := r.metricTrend(metric)
	if !t.OK || t.Complete < 3 {
		return false
	}
	days := r.WindowEnd.Sub(r.PeriodStart()).Hours() / 24
	return float64(v) > t.Avg*days/7*1.4 && v > 2
}

func short(m map[string]bool, max int) string {
	var l []string
	for k := range m {
		l = append(l, k)
	}
	sort.Slice(l, func(a, b int) bool { return naturalLess(l[a], l[b]) })
	if len(l) > max {
		return strings.Join(l[:max], ", ") + fmt.Sprintf(" +%d", len(l)-max)
	}
	return strings.Join(l, ", ")
}

// pageStats is an event page's four stat cards.
func (r *Report) pageStats(p *EventPage, spec pageSpec, count map[string]int, users, hosts, sources map[string]bool, findings map[int]int) []EventCard {
	level := func(n int, l string) string {
		if n > 0 {
			return l
		}
		return "zero"
	}
	label := strings.ToUpper(spec.unit[:1]) + spec.unit[1:]
	if p.ID == "powershell" {
		label = "Scripts logged"
	}
	total := EventCard{Icon: p.Icon, Label: label, Value: commas(p.Total), Note: r.normalRange(spec.metric), Filter: "all"}
	if spec.metric != "" && r.aboveNormal(spec.metric, p.Total) {
		total.Level, total.Note = "warn", "above normal; "+total.Note
	}
	titled := func(words ...string) (int, map[string]bool) {
		n, who := 0, map[string]bool{}
		for fi := range findings {
			f := r.Findings[fi]
			for _, w := range words {
				if strings.Contains(f.Title, w) {
					n++
					who[f.Host] = true
					break
				}
			}
		}
		return n, who
	}
	match := func(f func(e *event.Event) bool) (int, map[string]bool) {
		n, who := 0, map[string]bool{}
		for _, e := range r.Events {
			if p.on(e) && f(e) {
				n++
				if e.User != "" {
					who[e.User] = true
				} else {
					who[e.Host] = true
				}
			}
		}
		return n, who
	}
	people := EventCard{Icon: "users", Label: "People", Href: "#people", Value: commas(len(users)), Note: "on " + commas(len(hosts)) + " " + map[bool]string{true: "system", false: "systems"}[len(hosts) == 1]}
	systems := EventCard{Icon: "server", Label: "Systems", Href: "#systems", Value: commas(len(hosts)), Note: fmt.Sprintf("of %d reporting", len(r.Hosts))}
	switch p.ID {
	case "failed":
		bursts, who := titled("guessing", "several accounts", "several computers")
		locked := count["Locked out"]
		lockNote := r.normalRange(MLockouts)
		return []EventCard{total,
			{Icon: "triangle-alert", Label: "Password-guessing bursts", Href: "#detections", Value: commas(bursts), Note: short(who, 2), Level: level(bursts, "bad")},
			{Icon: "lock", Label: "Accounts locked out", Filter: cardFilter("kind", "Locked out"), Value: commas(locked), Note: lockNote, Level: level(locked, "warn")},
			{Icon: "server", Label: "Sources", Href: searchLink("page", "failed", "sort", "src"), Value: commas(len(sources)), Note: "addresses and consoles"}}
	case "privileged":
		after, who := match(func(e *event.Event) bool { return r.outsideHours(e) })
		admins, aw := 0, map[string]bool{}
		for _, e := range r.Events {
			if e.Action == "group_member_added" && e.Severity == event.SevHigh {
				admins++
				aw[e.Target] = true
			}
		}
		return []EventCard{total,
			{Icon: "moon", Label: "After hours", Href: searchLink("page", "privileged", "when", "@after"), Value: commas(after), Note: short(who, 2), Level: level(after, "warn")},
			{Icon: "user-plus", Label: "New admins", Href: searchLink("page", "accounts", "text", "privileged group"), Value: commas(admins), Note: short(aw, 2), Level: level(admins, "bad")},
			people}
	case "usb":
		files := count["Files copied"]
		blocked := count["Blocked"]
		nd := map[string]bool{}
		for k := range r.NewDevices {
			nd[k] = true
		}
		return []EventCard{total,
			{Icon: "usb", Label: "New devices", Filter: cardFilter("flag", "New device"), Value: commas(len(r.NewDevices)), Note: short(nd, 1), Level: level(len(r.NewDevices), "warn")},
			{Icon: "hard-drive-download", Label: "Files copied to USB", Filter: cardFilter("kind", "Files copied|Blocked"), Value: commas(files), Note: fmt.Sprintf("%d blocked", blocked), Level: level(files, "warn")},
			systems}
	case "accounts":
		created := count["Created"]
		added, aw := 0, map[string]bool{}
		for _, e := range r.Events {
			if e.Action == "group_member_added" && e.Severity == event.SevHigh {
				added++
				aw[account(e)] = true
			}
		}
		off := count["Disabled"]
		return []EventCard{total,
			{Icon: "user-plus", Label: "New admins", Href: searchLink("page", "accounts", "text", "privileged group"), Value: commas(added), Note: short(aw, 2), Level: level(added, "bad")},
			{Icon: "user-check", Label: "Accounts created", Filter: cardFilter("kind", "Created"), Value: commas(created), Note: "", Level: level(created, "warn")},
			{Icon: "user-x", Label: "Disabled or deleted", Filter: cardFilter("kind", "Disabled"), Value: commas(off), Note: ""}}
	case "integrity":
		cleared, cw := match(func(e *event.Event) bool { return spec.kindOf(e) == "Log cleared" })
		pol := count["Audit policy changed"]
		// Only real stops: the event log service stopping at a shutdown,
		// or auditd as a restart ends, is Low and not counted (UX2).
		stopped, _ := match(func(e *event.Event) bool {
			return spec.kindOf(e) == "Logging stopped" && e.Severity.Rank() >= event.SevMedium.Rank()
		})
		return []EventCard{
			{Icon: "eraser", Label: "Logs cleared", Filter: cardFilter("kind", "Log cleared"), Value: commas(cleared), Note: short(cw, 2), Level: level(cleared, "bad")},
			{Icon: "settings", Label: "Audit policy changes", Filter: cardFilter("kind", "Audit policy changed"), Value: commas(pol), Level: level(pol, "warn")},
			{Icon: "circle-x", Label: "Logging stopped", Filter: cardFilter("kind", "Logging stopped"), Value: commas(stopped), Level: level(stopped, "warn")},
			systems}
	case "powershell":
		sus := count["Suspicious"]
		off := 0
		for _, cs := range r.CheckSets {
			for _, res := range cs.Results {
				if strings.Contains(res.Item, "PowerShell") && res.Status == check.Fail {
					off++
					break
				}
			}
		}
		return []EventCard{total,
			{Icon: "triangle-alert", Label: "Suspicious", Filter: cardFilter("kind", "Suspicious"), Value: commas(sus), Level: level(sus, "bad")},
			systems,
			{Icon: "circle-x", Label: "Logging off", Href: "#health", Value: commas(off), Note: "systems not logging scripts", Level: level(off, "warn")}}
	case "other":
		mal := count["Malware and antivirus"]
		svc := count["Services and tasks"]
		return []EventCard{total,
			{Icon: "shield-alert", Label: "Malware and antivirus", Filter: cardFilter("kind", "Malware and antivirus"), Value: commas(mal), Level: level(mal, "bad")},
			{Icon: "server-cog", Label: "New services and tasks", Filter: cardFilter("kind", "Services and tasks"), Value: commas(svc), Level: level(svc, "warn")},
			systems}
	case "logons":
		after, who := match(func(e *event.Event) bool { return r.outsideHours(e) })
		remote := count["Remote Desktop"] + count["SSH"]
		return []EventCard{total, people,
			{Icon: "monitor-smartphone", Label: "Remote", Filter: cardFilter("kind", "Remote Desktop|SSH"), Value: commas(remote), Note: "Remote Desktop and SSH"},
			{Icon: "moon", Label: "Outside working hours", Href: searchLink("page", "logons", "when", "@after"), Value: commas(after), Note: short(who, 2), Level: level(after, "warn")}}
	}
	return []EventCard{total, people, systems}
}

// outsideHours says whether e happened outside the site's working hours.
func (r *Report) outsideHours(e *event.Event) bool {
	if !r.WorkingHours.Set() {
		return false
	}
	return !r.WorkingHours.Contains(e.Time.In(r.Location))
}
