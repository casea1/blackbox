package report

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// Trends by calendar week (UI1). Each report keeps its counts day by day
// (summary.json "days"), so later reports can add them up by calendar
// week, Monday to Sunday, whatever period each report covered: two
// reports in one week make one week, and a report spanning two weeks is
// split between them. Only complete weeks, fully covered by scheduled
// reports, go into averages; the week the report ends in is shown "so
// far". Manual reports are never history, and the first report, which
// reads back through the logs from before Blackbox was installed, only
// fills partial weeks.

// DayCounts is one calendar day of a report, in summary.json.
type DayCounts struct {
	Date    string          `json:"date"` // 2006-01-02, in the report's time zone
	Metrics map[string]int  `json:"metrics,omitempty"`
	Hosts   []string        `json:"hosts,omitempty"` // systems with events that day
	People  []PersonSummary `json:"people,omitempty"`
	// Failed are the failed logons on each system that day (UI-R1).
	Failed map[string]int `json:"failed_by_system,omitempty"`
}

// minWeeks is how many complete weeks trends need before they compare.
const minWeeks = 2

// shownWeeks is how many weeks the charts show, this one included.
const shownWeeks = 13

// notEnoughHistory is said wherever a trend needs more weeks.
const notEnoughHistory = "Not enough history yet: trends start after 2 full weeks"

// trendWeek is one calendar week of counts.
type trendWeek struct {
	Start, End time.Time
	Complete   bool    // fully covered by scheduled reports
	Current    bool    // the week this report ends in, not over yet (the last week is always "now")
	Days       float64 // days of it covered so far (Current)
	Metrics    map[string]int
	Hosts      map[string]bool
	HostDet    map[string]int // detections by system
	High, Med  int            // detections by severity
	People     map[string]PersonSummary
	HasPeople  bool // some day of it kept counts by person
	HasData    bool
	// UI-R1: what the week's reports saw (SeenKept: some report of it
	// kept it), the systems matching the STIG at its last report, events
	// lost, failed logons and detection titles by system.
	Seen        seenSet
	SeenKept    bool
	Matching    int
	MatchingSet []string
	MatchingAt  time.Time
	HasMatching bool
	Lost        int
	HostFailed  map[string]int
	HostTitles  map[string][]string
}

// weekStart is the Monday 00:00 of t's week in loc.
func weekStart(t time.Time, loc *time.Location) time.Time {
	t = t.In(loc)
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
	off := (int(d.Weekday()) + 6) % 7 // days since Monday
	return d.AddDate(0, 0, -off)
}

// WeekLabel names a week by its dates: "29 Sep – 5 Oct".
func WeekLabel(start time.Time, loc *time.Location) string {
	a, b := start.In(loc), start.AddDate(0, 0, 6).In(loc)
	if a.Month() == b.Month() {
		return a.Format("2") + "–" + b.Format("2 Jan")
	}
	return a.Format("2 Jan") + " – " + b.Format("2 Jan")
}

// weekShort is a column heading: "29 Sep", "29 Sep (part)" for a week
// not fully covered by scheduled reports.
func weekShort(w trendWeek, loc *time.Location) string {
	if w.Current {
		return "This week"
	}
	if !w.Complete {
		return w.Start.In(loc).Format("2 Jan") + " (part)"
	}
	return w.Start.In(loc).Format("2 Jan")
}

// buildWeeks adds up the days of the scheduled reports in hist (oldest
// first) and of cur, the report being made (it may be manual), by
// calendar week up to the week cur ends in, at most shownWeeks. Weeks
// before the first one with data are left out.
//
// pk keys people (r.pkey: people_aliases applied, so an earlier report's
// "j.lee" counts as jlee); nil keeps the keys the summaries have.
func buildWeeks(hist []Summary, cur Summary, loc *time.Location, pk func(string) string) []trendWeek {
	if loc == nil {
		loc = time.Local
	}
	if pk == nil {
		pk = func(k string) string { return k }
	}
	end := cur.WindowEnd
	last := weekStart(end.Add(-time.Second), loc)
	first := last.AddDate(0, 0, -7*(shownWeeks-1))
	weeks := make([]trendWeek, shownWeeks)
	for i := range weeks {
		s := first.AddDate(0, 0, 7*i)
		weeks[i] = trendWeek{Start: s, End: s.AddDate(0, 0, 7), Metrics: map[string]int{}, Hosts: map[string]bool{},
			HostDet: map[string]int{}, People: map[string]PersonSummary{}, Seen: seenSet{}, HostFailed: map[string]int{}, HostTitles: map[string][]string{}}
	}
	weeks[len(weeks)-1].Current = true
	at := func(t time.Time) *trendWeek {
		for i := range weeks {
			if !t.Before(weeks[i].Start) && t.Before(weeks[i].End) {
				return &weeks[i]
			}
		}
		return nil
	}

	type span struct {
		from, to time.Time
		first    bool
	}
	var spans []span
	sums := append(append([]Summary(nil), hist...), cur)
	for i, s := range sums {
		isCur := i == len(sums)-1
		if s.Interim && !isCur {
			continue
		}
		days := s.Days
		if days == nil {
			days = oldDays(s, loc)
		}
		for _, d := range days {
			t, err := time.ParseInLocation("2006-01-02", d.Date, loc)
			if err != nil {
				continue
			}
			w := at(t)
			if w == nil {
				continue
			}
			w.HasData = true
			for k, v := range d.Metrics {
				w.Metrics[k] += v
			}
			for _, h := range d.Hosts {
				w.Hosts[strings.ToUpper(h)] = true
			}
			for h, n := range d.Failed {
				w.HostFailed[h] += n
			}
			if d.People != nil || s.Days == nil && s.People != nil {
				w.HasPeople = true
			}
			for _, p := range d.People {
				k := pk(p.Key)
				q := w.People[k]
				q.Key = k
				if q.Name == "" {
					q.Name = p.Name
				}
				q.Privileged += p.Privileged
				q.Logons += p.Logons
				q.Failed += p.Failed
				q.AfterHours += p.AfterHours
				q.Detections += p.Detections
				w.People[k] = q
			}
		}
		for _, d := range s.Detections {
			if w := at(d.Time); w != nil {
				w.HostDet[d.Host]++
				if d.Title != "" && !slices.Contains(w.HostTitles[d.Host], d.Title) {
					w.HostTitles[d.Host] = append(w.HostTitles[d.Host], d.Title)
				}
				if d.Severity == "high" {
					w.High++
				} else {
					w.Med++
				}
			}
		}
		if w := at(s.WindowEnd.Add(-time.Second)); w != nil {
			w.Lost += int(s.Lost)
			if s.Seen != nil {
				w.Seen.addAll(s.Seen.setKeyed(pk))
				w.SeenKept = true
			}
			if s.Metrics[MSTIGChecked] > 0 && !s.WindowEnd.Before(w.MatchingAt) {
				w.Matching, w.MatchingSet, w.MatchingAt, w.HasMatching = s.Metrics[MSTIGMatching], s.Matching, s.WindowEnd, true
			}
		}
		if s.Interim || days == nil {
			continue // a manual report, or one too old to split by day: not coverage
		}
		spans = append(spans, span{s.WindowStart, s.WindowEnd, s.First})
	}

	// A week is complete when scheduled reports cover all of it and none
	// of it is the first report's read-back.
	sort.Slice(spans, func(i, j int) bool { return spans[i].from.Before(spans[j].from) })
	for i := range weeks {
		w := &weeks[i]
		if w.Current {
			w.Days = end.Sub(w.Start).Hours() / 24
			if w.Days > 7 {
				w.Days = 7
			}
		}
		if w.End.After(end) {
			continue
		}
		covered := w.Start
		ok := true
		for _, s := range spans {
			if !s.to.After(w.Start) || !s.from.Before(w.End) {
				continue
			}
			if s.first {
				ok = false
				break
			}
			if s.from.After(covered.Add(time.Minute)) {
				break // a gap
			}
			if s.to.After(covered) {
				covered = s.to
			}
		}
		w.Complete = ok && !covered.Before(w.End.Add(-time.Minute))
	}
	// The current week counts as complete once it has ended.
	if c := &weeks[len(weeks)-1]; c.Days >= 7 {
		c.Current = false
	}

	// Drop the weeks before the first with data.
	for len(weeks) > 1 && !weeks[0].HasData && !weeks[0].Complete {
		weeks = weeks[1:]
	}
	return weeks
}

// oldDays stands in for the day counts of a report made before they were
// kept: when its whole period lies in one calendar week, its totals go on
// its last day; otherwise it can't be split, and is left out.
func oldDays(s Summary, loc *time.Location) []DayCounts {
	if s.WindowStart.IsZero() || weekStart(s.WindowStart, loc) != weekStart(s.WindowEnd.Add(-time.Second), loc) {
		return nil
	}
	m := map[string]int{}
	for k, v := range s.Metrics {
		m[k] = v
	}
	return []DayCounts{{Date: s.WindowEnd.Add(-time.Second).In(loc).Format("2006-01-02"), Metrics: m, Hosts: s.Hosts, People: s.People}}
}

// days counts this report day by day, for summary.json.
func (r *Report) days() []DayCounts {
	loc := r.Location
	by := map[string]*DayCounts{}
	var order []string
	day := func(t time.Time) *DayCounts {
		k := t.In(loc).Format("2006-01-02")
		d := by[k]
		if d == nil {
			d = &DayCounts{Date: k, Metrics: map[string]int{}}
			by[k] = d
			order = append(order, k)
		}
		return d
	}
	hosts := map[string]map[string]bool{}
	for _, row := range r.rows {
		d := day(row.Time)
		addRowMetrics(d.Metrics, row)
		if row.Category == event.CatFailedLogon {
			if d.Failed == nil {
				d.Failed = map[string]int{}
			}
			d.Failed[row.Host]++
		}
		if hosts[d.Date] == nil {
			hosts[d.Date] = map[string]bool{}
		}
		hosts[d.Date][row.Host] = true
	}
	for _, f := range r.Findings {
		day(f.Time).Metrics[MDetections]++
	}
	sort.Strings(order)
	out := make([]DayCounts, 0, len(order))
	for _, k := range order {
		d := by[k]
		for h := range hosts[k] {
			d.Hosts = append(d.Hosts, h)
		}
		sort.Strings(d.Hosts)
		key := k
		d.People = r.peopleCounts(func(row *Row) bool { return row.Time.In(loc).Format("2006-01-02") == key })
		if d.People == nil {
			d.People = []PersonSummary{}
		}
		for m, v := range d.Metrics {
			if v == 0 {
				delete(d.Metrics, m)
			}
		}
		out = append(out, *d)
	}
	return out
}

// weeks are this report's trend weeks (see buildWeeks), made once.
func (r *Report) weeks() []trendWeek {
	if r.weeksCache == nil {
		cur := Summary{WindowStart: r.WindowStart, WindowEnd: r.WindowEnd, Interim: r.Interim, First: r.WindowStart.IsZero() && !r.Interim,
			Days: r.days(), Lost: r.lost(), Seen: seenOf(r.seenNow()), Matching: r.stigMatching(), Metrics: r.stigMetrics()}
		if cur.WindowStart.IsZero() {
			cur.WindowStart = r.FirstEvent
		}
		for _, f := range r.Findings {
			cur.Detections = append(cur.Detections, Detection{Severity: string(f.Severity), Time: f.Time, Host: f.Host, Title: f.Title})
		}
		r.weeksCache = buildWeeks(r.History, cur, r.Location, r.pkey)
	}
	return r.weeksCache
}

// weekValue is one week's value of a metric: the sum of its days, or for
// systems reporting, the systems with events in it.
func (w trendWeek) value(metric string) int {
	switch metric {
	case MSystems:
		return len(w.Hosts)
	case MDetections:
		return w.High + w.Med
	case MSTIGMatching:
		if !w.HasMatching {
			return -1
		}
		return w.Matching
	case MLost:
		return w.Lost
	}
	return w.Metrics[metric]
}

// trend is a metric across the weeks: the values, the average of the
// complete earlier weeks (ok false with fewer than minWeeks), and the
// current week's value with what the average would be at the same point
// of a week.
type trend struct {
	Values   []int // -1 for a week with no data
	Avg      float64
	Expected float64 // the average scaled to the days of the current week so far
	Now      int
	OK       bool
	Complete int // complete earlier weeks
}

func trendOf(weeks []trendWeek, value func(trendWeek) int) trend {
	var t trend
	sum := 0
	for i, w := range weeks {
		v := value(w)
		if !w.Complete && i < len(weeks)-1 {
			v = -1 // a partial week (the first report's, or a gap) is not drawn
		}
		t.Values = append(t.Values, v)
		if i < len(weeks)-1 && w.Complete { // the last week is "now", never its own average
			sum += max(v, 0)
			t.Complete++
		}
	}
	cur := weeks[len(weeks)-1]
	t.Now = max(value(cur), 0)
	if t.Complete >= minWeeks {
		t.OK = true
		t.Avg = float64(sum) / float64(t.Complete)
		t.Expected = t.Avg
		if cur.Current {
			t.Expected = t.Avg * cur.Days / 7
		}
	}
	return t
}

// metricTrend is trendOf for a metric. Systems reporting is a count of
// systems, not of events, so this week is compared with the whole average.
func (r *Report) metricTrend(metric string) trend {
	t := trendOf(r.weeks(), func(w trendWeek) int { return w.value(metric) })
	if metric == MSystems {
		t.Expected = t.Avg
	}
	return t
}

// trimFloat is a number of days for "3 of 7 days": "2.5", "3", "under 1".
func trimFloat(d float64) string {
	switch {
	case d < 1:
		return "under 1"
	case math.Abs(d-math.Round(d)) < 0.05:
		return fmt.Sprintf("%.0f", d)
	}
	return fmt.Sprintf("%.1f", d)
}

// weekLabels are the charts' x-axis labels.
func (r *Report) weekLabels() []string {
	var out []string
	for _, w := range r.weeks() {
		out = append(out, weekShort(w, r.Location))
	}
	return out
}

// weeksCrumb says which weeks are shown: "6 weeks · 1 Sep – 12 Oct 2026".
func (r *Report) weeksCrumb() string {
	ws := r.weeks()
	return fmt.Sprintf("%s · %s – %s", plural(len(ws), "week"), ws[0].Start.In(r.Location).Format("2 Jan"),
		ws[len(ws)-1].End.Add(-time.Second).In(r.Location).Format("2 Jan 2006"))
}
