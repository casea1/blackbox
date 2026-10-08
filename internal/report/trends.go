package report

import (
	"fmt"
	"html/template"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// The Trends page (UI-R1, design 12 B): six small charts of this week
// against the usual week, the biggest changes this week, detections by
// system by week, and what is new this week. Everything is by calendar
// week (weeks.go) and is made for 4, 8 and 12 weeks; the range switch
// shows one.

// trendRanges are the range switch's choices, in weeks (this one
// included); trendRangeOn is shown first.
var trendRanges = []int{4, 8, 12}

const trendRangeOn = 8

// TrendsPage is the Trends page.
type TrendsPage struct {
	Ranges    []TrendRange
	NotEnough bool // fewer than minWeeks complete weeks in all the history
}

// TrendRange is the page for one choice of the range switch.
type TrendRange struct {
	Weeks   int    // weeks shown, this one included (fewer when there is less history)
	Choice  int    // the switch's choice: 4, 8 or 12
	On      bool   // shown first
	Crumb   string // "8 weeks · 18 Aug – 7 Oct 2026 · by calendar week"
	Cards   []TrendCard
	Changes []ChangeRow
	// ChangesNote says why there are no changes to show.
	ChangesNote string
	Grid        HeatGrid
	New         []NewItem
	NewFold     []NewItem // beyond the first maxNew, folded
	NewSpan     string    // "never seen in 8 weeks"
	NewNote     string    // why there is no list
	NewMore     FoldRow   // "4 more new things · Show"
}

// TrendCard is one small chart: this week's number, the usual week's, and
// a bar per week, this week's red when worse than usual, green when
// better, blue otherwise.
type TrendCard struct {
	Title, Value, Usual string
	Class               string // bad | ok | "" (blue)
	Sub, Note           string // the current week ("so far: 2 of 7 days"); why there is no chart
	Href                string
	First, Last         string // the first week's label and this week's, under the chart
	Chart               template.HTML
}

// ChangeRow is one line of "Biggest changes this week".
type ChangeRow struct {
	Level, Name, Href, Measure, Usual, Now, Why string
	weight                                      float64
}

// HeatGrid is detections by system by week.
type HeatGrid struct {
	Weeks  []string // column headings: each week's Monday, "6 Oct"
	Rows   []WeekRow
	Others []WeekRow // the systems with none, folded
	All    int       // every system
	ID     string    // ties "All 30" to the folded rows
}

// WeekRow is one system's detections by week.
type WeekRow struct {
	Name  string
	Href  string
	Cells []WeekCell
}

// WeekCell is one week of a WeekRow.
type WeekCell struct {
	N     int
	Week  string
	Style template.CSS
}

// NewItem is one line of "New this week".
type NewItem struct {
	Kind, Label, Text, Href, Level string
}

// maxNew is how many lines of "New this week" show before the rest fold.
const maxNew = 8

// trendMetrics are the network's measures by week: the six charts
// (Chart), and the rest compared in "Biggest changes" and kept in the
// CSV. Better is +1 when more is better, -1 when more is worse, 0 neither.
var trendMetrics = []struct {
	Title, Metric string
	BadUp         bool
	Href          string
	Chart         bool
}{
	{"Detections", MDetections, true, "#detections", true},
	{"Failed logons", MFailedLogons, true, "#failed", true},
	{"Privileged actions (people)", MPrivileged, true, "#privileged", true},
	{"Systems matching the STIG", MSTIGMatching, false, "#health", true},
	{"Events lost to rollover", MLost, true, "#health", true},
	{"After-hours admin actions", MAfterHours, true, searchLink("page", "privileged", "when", "@after"), true},
	{"High-severity events", MHighEvents, true, "#detections", false},
	{"USB events", MUSB, true, "#usb", false},
	{"Account changes", MAccountChanges, true, "#accounts", false},
	{"Systems reporting", MSystems, false, "#systems", false},
}

// level metrics are a state at the end of a week, not a count of its
// days: this week is compared with the whole usual week.
func levelMetric(m string) bool { return m == MSTIGMatching || m == MSystems }

// Crumb is the breadcrumb's part for the range shown first.
func (tp *TrendsPage) Crumb() string {
	for _, r := range tp.Ranges {
		if r.On {
			return r.Crumb
		}
	}
	return ""
}

func (r *Report) trendsPage() *TrendsPage {
	ws := r.weeks()
	tp := &TrendsPage{NotEnough: !r.metricTrend(MEvents).OK}
	for _, n := range trendRanges {
		k := min(n, len(ws))
		tr := r.trendRange(ws[len(ws)-k:])
		tr.Choice, tr.On = n, n == trendRangeOn
		tr.Grid.ID = fmt.Sprintf("trgrid%d", n)
		if len(tr.NewFold) > 0 {
			tr.NewMore = FoldRow{ID: fmt.Sprintf("trnew%d", n), Text: foldText(len(tr.NewFold), "new things", "", "")}
		}
		tp.Ranges = append(tp.Ranges, tr)
	}
	return tp
}

// usual is the median of the earlier complete weeks with a value, and
// how many there were.
func usual(vals []int, complete []bool) (float64, int) {
	var xs []int
	for i := 0; i < len(vals)-1; i++ {
		if complete[i] && vals[i] >= 0 {
			xs = append(xs, vals[i])
		}
	}
	return median(xs), len(xs)
}

// median of xs (0 for none).
func median(xs []int) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int(nil), xs...)
	sort.Ints(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return float64(s[m])
	}
	return float64(s[m-1]+s[m]) / 2
}

// series is one measure across weeks: each week's value (-1 none), the
// usual week, and this week against it.
type series struct {
	Vals     []int
	Usual    float64
	N        int     // earlier complete weeks in the usual
	Expected float64 // the usual by this point of the current week
	Now      int
	Class    string // up | dn | flat, from change()
}

func seriesOf(ws []trendWeek, level bool, value func(trendWeek) int) series {
	var s series
	complete := make([]bool, len(ws))
	for i, w := range ws {
		v := value(w)
		if !w.Complete && i < len(ws)-1 {
			v = -1
		}
		complete[i] = w.Complete
		s.Vals = append(s.Vals, v)
	}
	s.Usual, s.N = usual(s.Vals, complete)
	s.Now = max(s.Vals[len(s.Vals)-1], 0)
	s.Expected = s.Usual
	if c := ws[len(ws)-1]; c.Current && !level {
		s.Expected = s.Usual * c.Days / 7
	}
	s.Class = "flat"
	if s.N >= minWeeks {
		_, s.Class = change(float64(s.Now), s.Expected)
	}
	return s
}

// verdict is this week against usual for a measure: bad (worse), ok
// (better) or "".
func (s series) verdict(badUp bool) string {
	switch {
	case s.Class == "up" && badUp, s.Class == "dn" && !badUp:
		return "bad"
	case s.Class == "dn" && badUp, s.Class == "up" && !badUp:
		return "ok"
	}
	return ""
}

func (r *Report) trendRange(ws []trendWeek) TrendRange {
	loc := r.Location
	cur := ws[len(ws)-1]
	tr := TrendRange{Weeks: len(ws)}
	last := cur.End
	if r.WindowEnd.Before(last) {
		last = r.WindowEnd
	}
	tr.Crumb = fmt.Sprintf("%s · %s – %s · by calendar week", plural(len(ws), "week"), ws[0].Start.In(loc).Format("2 Jan"),
		last.Add(-time.Second).In(loc).Format("2 Jan 2006"))
	sub := "this week"
	if cur.Current {
		sub = fmt.Sprintf("this week so far (%s of 7 days)", trimFloat(cur.Days))
	}
	first := ws[0].Start.In(loc).Format("2 Jan")
	lastLabel := "this week"
	if cur.Current {
		lastLabel = fmt.Sprintf("this week · %s of 7 days", trimFloat(cur.Days))
	}

	for _, m := range trendMetrics {
		if !m.Chart {
			continue
		}
		metric := m.Metric
		s := seriesOf(ws, levelMetric(metric), func(w trendWeek) int { return w.value(metric) })
		c := TrendCard{Title: m.Title, Value: commas(s.Now), Href: m.Href, Sub: sub, First: first, Last: lastLabel, Usual: "usual —"}
		switch {
		case metric == MAfterHours && !r.WorkingHours.Set():
			c.Value, c.Note = "—", "Set working_hours to see this" // UI7
		case metric == MSTIGMatching && !cur.HasMatching:
			c.Value, c.Note = "—", "No audit settings checked this week"
		default:
			if s.N >= minWeeks {
				c.Usual = "usual " + commas(int(math.Round(s.Usual)))
				c.Class = s.verdict(m.BadUp)
			}
			c.Chart = trendBars(m.Title, s.Vals, c.Class, ws, loc)
		}
		tr.Cards = append(tr.Cards, c)
	}
	tr.Changes, tr.ChangesNote = r.biggestChanges(ws)
	tr.Grid = r.heatGrid(ws)
	tr.New, tr.NewSpan, tr.NewNote = r.newThisWeek(ws)
	if len(tr.New) > maxNew {
		tr.New, tr.NewFold = tr.New[:maxNew], tr.New[maxNew:]
	}
	return tr
}

// trendBars draws a small chart, one bar per week: earlier weeks light,
// this week red (bad), green (ok) or blue; a week with no data a stub.
func trendBars(title string, vals []int, class string, ws []trendWeek, loc *time.Location) template.HTML {
	const w, h = 300, 54
	n := len(vals)
	top := 1
	for _, v := range vals {
		top = max(top, v)
	}
	bw := float64(w) / float64(n)
	var b strings.Builder
	var words []string
	for i, v := range vals {
		x := float64(i)*bw + 1
		label := ws[i].Start.In(loc).Format("2 Jan")
		if i == n-1 {
			label = "this week"
		}
		if v < 0 {
			fmt.Fprintf(&b, `<rect x="%.1f" y="%d" width="%.1f" height="2" class="tb-na"/>`, x, h-2, bw-2)
			words = append(words, label+" no data")
			continue
		}
		bh := math.Max(float64(v)/float64(top)*float64(h-4), 2)
		cls := "tb-old"
		if i == n-1 {
			cls = "tb-now " + map[string]string{"bad": "bad", "ok": "ok", "": "flat"}[class]
		}
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" class="%s"/>`, x, float64(h)-bh, bw-2, bh, cls)
		words = append(words, label+" "+commas(v))
	}
	name := title + " by week: " + strings.Join(words, ", ")
	return template.HTML(fmt.Sprintf(`<svg class="tbars" viewBox="0 0 %d %d" preserveAspectRatio="none" role="img" aria-label="%s">%s</svg>`, w, h,
		template.HTMLEscapeString(name), b.String()))
}

// biggestChanges are this week's largest moves against each measure's
// usual week: the network's totals, each system's detections and failed
// logons, and each person's activity, with a short why.
func (r *Report) biggestChanges(ws []trendWeek) ([]ChangeRow, string) {
	cur := ws[len(ws)-1]
	var out []ChangeRow
	add := func(name, href, measure string, s series, badUp bool, why string) {
		if s.N < minWeeks {
			return
		}
		lvl := s.verdict(badUp)
		isNew := s.Usual == 0 && s.Now > 0 && badUp
		if lvl == "" && !isNew {
			return
		}
		if isNew {
			lvl = "bad"
		}
		wt := math.Abs(float64(s.Now)-s.Expected) / math.Max(s.Expected, 1)
		if lvl == "bad" && wt < 3 && !isNew {
			lvl = "warn"
		}
		out = append(out, ChangeRow{Level: lvl, Name: name, Href: href, Measure: measure, Usual: commas(int(math.Round(s.Usual))),
			Now: commas(s.Now), Why: why, weight: wt})
	}

	// The network's totals.
	for _, m := range trendMetrics {
		if m.Metric == MAfterHours && !r.WorkingHours.Set() {
			continue
		}
		metric := m.Metric
		s := seriesOf(ws, levelMetric(metric), func(w trendWeek) int { return w.value(metric) })
		if metric == MSTIGMatching && !cur.HasMatching {
			continue
		}
		add("All systems", m.Href, m.Title, s, m.BadUp, r.networkWhy(metric, ws))
	}

	// Each system's detections and failed logons.
	hosts := map[string]bool{}
	for _, w := range ws {
		for h := range w.HostDet {
			hosts[h] = true
		}
		for h := range w.HostFailed {
			hosts[h] = true
		}
	}
	for _, h := range sortedKeys(hosts) {
		host := h
		s := seriesOf(ws, false, func(w trendWeek) int { return w.HostDet[host] })
		add(host, "#systems/"+host, "Detections", s, true, strings.Join(firstN(cur.HostTitles[host], 2), " · "))
		s = seriesOf(ws, false, func(w trendWeek) int {
			if !w.HasData {
				return -1
			}
			return w.HostFailed[host]
		})
		add(host, searchLink("page", "failed", "host", host), "Failed logons", s, true, r.failedWhy(host))
	}

	// Each person's activity, from the weeks that kept it.
	people := map[string]string{}
	for _, w := range ws {
		for k, p := range w.People {
			people[k] = p.Name
		}
	}
	for _, k := range sortedKeys(people) {
		key := k
		get := func(f func(PersonSummary) int) func(trendWeek) int {
			return func(w trendWeek) int {
				if !w.HasPeople {
					return -1
				}
				return f(w.People[key])
			}
		}
		add(people[k], "#people/"+key, "Privileged actions", seriesOf(ws, false, get(func(p PersonSummary) int { return p.Privileged })), true, "")
		if r.WorkingHours.Set() {
			add(people[k], "#people/"+key, "After hours", seriesOf(ws, false, get(func(p PersonSummary) int { return p.AfterHours })), true, "")
		}
	}
	// Systems each person used, from what the weeks saw.
	for _, k := range r.peopleSeen(ws) {
		key := k
		s := seriesOf(ws, false, func(w trendWeek) int {
			if !w.SeenKept {
				return -1
			}
			return len(systemsUsed(w.Seen, key))
		})
		if s.Class != "up" || s.N < minWeeks {
			continue
		}
		before := map[string]bool{}
		for _, w := range ws[:len(ws)-1] {
			for h := range systemsUsed(w.Seen, key) {
				before[h] = true
			}
		}
		var fresh []string
		for h := range systemsUsed(cur.Seen, key) {
			if !before[h] {
				fresh = append(fresh, h)
			}
		}
		sort.Strings(fresh)
		why := ""
		if len(fresh) > 0 {
			why = "first time on " + andList(firstN(fresh, 3), len(fresh))
		}
		name := key
		if n := people[key]; n != "" {
			name = n
		}
		out = append(out, ChangeRow{Level: "warn", Name: name, Href: "#people/" + key, Measure: "Systems used", Usual: commas(int(math.Round(s.Usual))),
			Now: commas(s.Now), Why: why, weight: math.Abs(float64(s.Now)-s.Usual) / math.Max(s.Usual, 1)})
	}

	if len(out) == 0 {
		if seriesOf(ws, false, func(w trendWeek) int { return w.value(MEvents) }).N < minWeeks {
			return nil, notEnoughHistory
		}
		return nil, "Nothing moved much: every measure is close to its usual week."
	}
	sort.SliceStable(out, func(i, j int) bool {
		if levelRank(out[i].Level) != levelRank(out[j].Level) && (out[i].Level == "bad" || out[j].Level == "bad") {
			return levelRank(out[i].Level) < levelRank(out[j].Level)
		}
		if out[i].weight != out[j].weight {
			return out[i].weight > out[j].weight
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > 6 {
		// Six lines, the best improvement among them when there is one.
		better := -1
		for i, c := range out {
			if c.Level == "ok" {
				better = i
				break
			}
		}
		if better > 5 {
			out[5] = out[better]
		}
		out = out[:6]
	}
	return out, ""
}

// networkWhy is a short reason for a change in a network total, from this
// report's events.
func (r *Report) networkWhy(metric string, ws []trendWeek) string {
	switch metric {
	case MFailedLogons:
		if ip, host, n, _ := r.topFailedSource(""); ip != "" {
			return fmt.Sprintf("%s from %s on %s", commas(n), ip, host)
		}
	case MDetections:
		high, med := 0, 0
		for _, f := range r.Findings {
			if f.Severity == event.SevHigh {
				high++
			} else {
				med++
			}
		}
		return fmt.Sprintf("%d high · %d medium in this report", high, med)
	case MLost:
		by := map[string]bool{}
		for _, g := range r.Health.Gaps {
			if g.Lost > 0 {
				by[g.Host] = true
			}
		}
		hosts := sortedKeys(by)
		if len(hosts) > 0 {
			return "on " + andList(firstN(hosts, 3), len(hosts))
		}
	case MSTIGMatching:
		cur := ws[len(ws)-1]
		var prev *trendWeek
		for i := len(ws) - 2; i >= 0; i-- {
			if ws[i].HasMatching {
				prev = &ws[i]
				break
			}
		}
		if prev == nil {
			return ""
		}
		was, is := toSet(prev.MatchingSet), toSet(cur.MatchingSet)
		var fixed, lost []string
		for h := range is {
			if !was[h] {
				fixed = append(fixed, h)
			}
		}
		for h := range was {
			if !is[h] {
				lost = append(lost, h)
			}
		}
		sort.Strings(fixed)
		sort.Strings(lost)
		var parts []string
		if len(fixed) > 0 {
			parts = append(parts, andList(firstN(fixed, 3), len(fixed))+" fixed")
		}
		if len(lost) > 0 {
			parts = append(parts, andList(firstN(lost, 3), len(lost))+" no longer match")
		}
		return strings.Join(parts, " · ")
	}
	return ""
}

// failedWhy is why a system's failed logons rose: "SSH guessing from
// 203.0.113.50 on 7 Oct" when most came from one address.
func (r *Report) failedWhy(host string) string {
	ip, _, n, at := r.topFailedSource(host)
	if ip == "" {
		return ""
	}
	what := "failed logons"
	if strings.Contains(at.how, "SSH") {
		what = "SSH guessing"
	}
	return fmt.Sprintf("%s from %s on %s (%s)", what, ip, at.t.In(r.Location).Format("2 Jan"), commas(n))
}

type firstFail struct {
	t   time.Time
	how string
}

// topFailedSource is the address most failed logons came from in this
// report (on host, or anywhere), when it is at least half of them: the
// address, its system, how many, and when it began.
func (r *Report) topFailedSource(host string) (ip, onHost string, n int, at firstFail) {
	count, hostOf, first := map[string]int{}, map[string]string{}, map[string]firstFail{}
	total := 0
	for _, row := range r.rows {
		if row.Category != event.CatFailedLogon || (host != "" && row.Host != host) {
			continue
		}
		total++
		a := sourceAddr(row.SourceIP)
		if a == "" {
			continue
		}
		count[a]++
		hostOf[a] = row.Host
		if f, ok := first[a]; !ok || row.Time.Before(f.t) {
			how := ""
			if strings.EqualFold(row.RecordType, "sshd") || strings.Contains(row.Summary, "SSH") {
				how = "SSH"
			}
			first[a] = firstFail{row.Time, how}
		}
	}
	for a, c := range count {
		if c > n || c == n && a < ip {
			ip, n = a, c
		}
	}
	if ip == "" || n*2 < total || n < 10 {
		return "", "", 0, firstFail{}
	}
	return ip, hostOf[ip], n, first[ip]
}

// heatGrid is detections by system by week: the systems with any in
// the range, this week's most first, then the others folded.
func (r *Report) heatGrid(ws []trendWeek) HeatGrid {
	g := HeatGrid{ID: fmt.Sprintf("trgrid%d", len(ws))}
	for _, w := range ws {
		g.Weeks = append(g.Weeks, w.Start.In(r.Location).Format("2 Jan"))
	}
	n := len(ws)
	counts := map[string][]int{}
	for i, w := range ws {
		for h, c := range w.HostDet {
			if h == "" {
				continue
			}
			if counts[h] == nil {
				counts[h] = make([]int, n)
			}
			counts[h][i] += c
		}
	}
	all := map[string]bool{}
	for _, s := range r.SystemRows {
		all[s.Name] = true
	}
	for h := range counts {
		all[h] = true
	}
	g.All = len(all)
	var names []string
	top := 1
	for h, v := range counts {
		names = append(names, h)
		for _, x := range v {
			top = max(top, x)
		}
	}
	sum := func(v []int) int {
		t := 0
		for _, x := range v {
			t += x
		}
		return t
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := counts[names[i]], counts[names[j]]
		if a[n-1] != b[n-1] {
			return a[n-1] > b[n-1]
		}
		if sum(a) != sum(b) {
			return sum(a) > sum(b)
		}
		return naturalLess(names[i], names[j])
	})
	row := func(h string, v []int) WeekRow {
		wr := WeekRow{Name: h, Href: "#systems/" + h}
		for i := 0; i < n; i++ {
			c := 0
			if v != nil {
				c = v[i]
			}
			wr.Cells = append(wr.Cells, WeekCell{N: c, Week: g.Weeks[i], Style: heatStyle(c, top)})
		}
		return wr
	}
	for _, h := range names {
		g.Rows = append(g.Rows, row(h, counts[h]))
	}
	var rest []string
	for h := range all {
		if counts[h] == nil {
			rest = append(rest, h)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return naturalLess(rest[i], rest[j]) })
	for _, h := range rest {
		g.Others = append(g.Others, row(h, nil))
	}
	return g
}

// heatStyle shades a count of detections, darker red for more.
func heatStyle(v, top int) template.CSS {
	if v <= 0 {
		return ""
	}
	t := 0.3 + 0.7*float64(v)/float64(top)
	return template.CSS(fmt.Sprintf("background:rgba(209,44,44,%.2f)", t))
}

// newThisWeek is what this week's reports saw that no earlier week of
// the range did, "never seen in 8 weeks".
func (r *Report) newThisWeek(ws []trendWeek) (items []NewItem, span, note string) {
	cur := ws[len(ws)-1]
	before := seenSet{}
	kept := 0
	for _, w := range ws[:len(ws)-1] {
		if w.SeenKept {
			kept++
			before.addAll(w.Seen)
		}
	}
	if !cur.SeenKept {
		return nil, "", "Nothing kept this week."
	}
	if kept == 0 {
		return nil, "", "Starts next week: each report now keeps the accounts, logons, addresses, services and USB devices it saw, and the next week is compared with this one."
	}
	span = "never seen in " + plural(kept, "week")
	if kept < len(ws)-1 {
		span += fmt.Sprintf(" (the %d before kept no list)", len(ws)-1-kept)
	}
	what := r.seenWhat()
	for _, k := range seenKinds {
		var keys []string
		for key := range cur.Seen[k.Kind] {
			if !before[k.Kind][key] {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			items = append(items, newItem(k.Kind, k.Label, k.Level, key, what))
		}
	}
	if len(items) == 0 {
		note = "Nothing new: no new administrator, account, logon path, source address, service or USB device."
	}
	return items, span, note
}

// newItem describes one new thing.
func newItem(kind, label, level, key string, what map[string]string) NewItem {
	it := NewItem{Kind: kind, Label: label, Level: level}
	switch kind {
	case SeenAdmin, SeenAccount, SeenService:
		h, n, _ := strings.Cut(key, `\`)
		if d := what[kind+" "+key]; d != "" {
			n = d
		}
		it.Text = n + " on " + h
		it.Href = searchLink("host", h, "text", n)
	case SeenPath:
		f := strings.SplitN(key, "|", 3)
		if len(f) == 3 {
			it.Text = fmt.Sprintf("%s → %s (%s)", f[0], f[1], f[2])
			it.Href = searchLink("page", "logons", "user", f[0], "host", f[1])
		}
	case SeenSource:
		it.Text = key
		if d := what[kind+" "+key]; d != "" {
			it.Text += " (" + d + ")"
		}
		it.Href = searchLink("text", key)
	case SeenUSB:
		h, id, _ := strings.Cut(key, "|")
		n := id
		if d := what[kind+" "+key]; d != "" {
			n = d
		}
		it.Text = n + " on " + h
		it.Href = searchLink("page", "usb", "host", h)
	}
	if it.Text == "" {
		it.Text = key
	}
	return it
}

// seenWhat names what this report saw in words, by "kind key": a USB
// device's name, a service's name as written, what an address did.
func (r *Report) seenWhat() map[string]string {
	out := map[string]string{}
	type did struct {
		failed, logons, other int
		ssh                   bool
		hosts                 map[string]bool
	}
	by := map[string]*did{}
	for _, row := range r.rows {
		e := row.Event
		for kind, key := range seenKeys(e) {
			switch kind {
			case SeenUSB:
				if e.Target != "" {
					out[kind+" "+key] = e.Target
				}
			case SeenService:
				out[kind+" "+key] = serviceName(e)
			case SeenAdmin, SeenAccount:
				if e.Target != "" {
					out[kind+" "+key] = e.Target
				}
			case SeenSource:
				d := by[key]
				if d == nil {
					d = &did{hosts: map[string]bool{}}
					by[key] = d
				}
				d.hosts[e.Host] = true
				switch {
				case e.Category == event.CatFailedLogon:
					d.failed++
					d.ssh = d.ssh || strings.EqualFold(e.RecordType, "sshd") || strings.Contains(e.Summary, "SSH")
				case e.Category == event.CatLogon && e.Action == "logon":
					d.logons++
				default:
					d.other++
				}
			}
		}
	}
	for ip, d := range by {
		var parts []string
		if d.failed > 0 {
			w := "failure"
			if d.ssh {
				w = "SSH failure"
			}
			parts = append(parts, plural(d.failed, w))
		}
		if d.logons > 0 {
			parts = append(parts, plural(d.logons, "logon"))
		}
		if d.other > 0 && len(parts) == 0 {
			parts = append(parts, plural(d.other, "event"))
		}
		hosts := sortedKeys(d.hosts)
		if len(hosts) == 1 {
			parts[len(parts)-1] += " on " + hosts[0]
		} else {
			parts[len(parts)-1] += fmt.Sprintf(" on %d systems", len(hosts))
		}
		out[SeenSource+" "+ip] = strings.Join(parts, ", ")
	}
	return out
}

// peopleSeen are the people in what the weeks saw.
func (r *Report) peopleSeen(ws []trendWeek) []string {
	m := map[string]bool{}
	for _, k := range sortedKeys(ws[len(ws)-1].Seen[SeenActive]) {
		p, _, _ := strings.Cut(k, "|")
		m[p] = true
	}
	return sortedKeys(m)
}

// systemsUsed are the systems a person did anything on, in a week's set.
func systemsUsed(s seenSet, person string) map[string]bool {
	out := map[string]bool{}
	for k := range s[SeenActive] {
		if p, h, ok := strings.Cut(k, "|"); ok && p == person {
			out[h] = true
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func toSet(l []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range l {
		m[s] = true
	}
	return m
}

func firstN(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

// andList is "a, b and c", or "a, b and 4 more" when total is more than
// shown.
func andList(shown []string, total int) string {
	if total > len(shown) {
		return strings.Join(shown, ", ") + " and " + strconv.Itoa(total-len(shown)) + " more"
	}
	switch len(shown) {
	case 0:
		return ""
	case 1:
		return shown[0]
	}
	return strings.Join(shown[:len(shown)-1], ", ") + " and " + shown[len(shown)-1]
}

// lost is the events this report lost to rollover.
func (r *Report) lost() uint64 {
	var n uint64
	for _, g := range r.Health.Gaps {
		n += g.Lost
	}
	return n
}

// stigMatching are the systems whose audit settings match the STIG (STIG
// rules only, as the Overview counts them).
func (r *Report) stigMatching() []string {
	var out []string
	for _, s := range r.SystemRows {
		if s.Checks != nil && s.Checks.STIGFail == 0 {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

// stigMetrics are the systems checked and matching, for summary.json.
func (r *Report) stigMetrics() map[string]int {
	checked := 0
	for _, s := range r.SystemRows {
		if s.Checks != nil {
			checked++
		}
	}
	if checked == 0 {
		return nil
	}
	return map[string]int{MSTIGChecked: checked, MSTIGMatching: len(r.stigMatching())}
}

// trendsRows are the Trends page's CSV: one row per week, every measure.
func (r *Report) trendsRows() [][]string {
	ws := r.weeks()
	head := []string{"week_start", "week_end", "complete"}
	for _, m := range trendMetrics {
		head = append(head, m.Metric)
	}
	rows := [][]string{head}
	for _, w := range ws {
		state := "yes"
		switch {
		case w.Current:
			state = "so far"
		case !w.Complete:
			state = "part"
		}
		row := []string{w.Start.In(r.Location).Format("2006-01-02"), w.End.Add(-time.Second).In(r.Location).Format("2006-01-02"), state}
		for _, m := range trendMetrics {
			v := w.value(m.Metric)
			if v < 0 || !w.HasData && !w.HasMatching && !w.Current {
				row = append(row, "")
				continue
			}
			row = append(row, strconv.Itoa(v))
		}
		rows = append(rows, row)
	}
	return rows
}
