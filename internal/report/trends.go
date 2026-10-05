package report

import (
	"fmt"
	"html/template"
	"math"
	"sort"
	"time"
)

// The Trends page (design T1): eight small charts of this week against the
// last twelve, from the summary.json of each earlier report, and
// detections per system by week.

// TrendCard is one small chart.
type TrendCard struct {
	Title, Value, Avg, Delta, Class string
	Href                            string
	Chart                           template.HTML
}

// WeekRow is one system's detections by week.
type WeekRow struct {
	Name  string
	Href  string // where the name leads (a person's page)
	Cells []WeekCell
}

// WeekCell is one week of a WeekRow.
type WeekCell struct {
	N     int
	Style template.CSS
}

// TrendsPage is the Trends page.
type TrendsPage struct {
	Cards  []TrendCard
	Weeks  []string
	Rows   []WeekRow
	People []WeekRow // privileged actions by person, by week
	// PeopleOld: some earlier reports were made before counts by person
	// were kept, so their weeks are blank.
	PeopleOld bool
	Crumb     string
	Weeks1    bool // only this report so far
}

var trendMetrics = []struct {
	Title, Metric string
	BadUp         bool
	Href          string
}{
	{"Detections", MDetections, true, "#detections"}, {"High-severity events", MHighEvents, true, "#detections"},
	{"Failed logons", MFailedLogons, true, "#failed"}, {"Privileged actions", MPrivileged, true, "#privileged"},
	{"USB events", MUSB, true, "#usb"}, {"After-hours admin", MAfterHours, true, searchLink("page", "privileged", "when", "@after")},
	{"Account changes", MAccountChanges, true, "#accounts"}, {"Systems reporting", MSystems, false, "#systems"},
}

func weekLabel(end time.Time) string {
	_, w := end.Add(-time.Hour).ISOWeek()
	return fmt.Sprintf("W%d", w)
}

// weekLabels names the earlier reports and this one, for charts.
func (r *Report) weekLabels() []string {
	var labels []string
	for _, s := range r.History {
		labels = append(labels, weekLabel(s.WindowEnd))
	}
	return append(labels, "This wk")
}

func (r *Report) trendsPage() *TrendsPage {
	tp := &TrendsPage{Weeks1: len(r.History) == 0}
	labels := r.weekLabels()
	tp.Weeks = labels
	start := r.PeriodStart()
	if len(r.History) > 0 {
		start = r.History[0].WindowEnd.AddDate(0, 0, -7)
	}
	tp.Crumb = fmt.Sprintf("Last %s · %s – %s · built from the summary in each earlier report", plural(len(labels), "week"),
		start.In(r.Location).Format("2 Jan"), r.WindowEnd.Add(-time.Second).In(r.Location).Format("2 Jan 2006"))

	m := r.metrics()
	for _, t := range trendMetrics {
		vals := r.series(t.Metric, m[t.Metric])
		now := vals[len(vals)-1]
		c := TrendCard{Title: t.Title, Value: commas(now), Class: "flat", Href: t.Href}
		if avg := average(vals); avg >= 0 {
			c.Avg = "avg " + commas(int(math.Round(avg)))
			if avg > 0 {
				d := (float64(now) - avg) / avg * 100
				c.Delta = fmt.Sprintf("%+.0f%%", d)
				if math.Abs(d) < 0.5 {
					c.Delta = "0%"
				}
				switch {
				case !t.BadUp || math.Abs(d) < 15:
				case d > 0:
					c.Class = "up"
				default:
					c.Class = "dn"
				}
			}
		}
		c.Chart = weekBars(vals, labels, t.BadUp, 300, 90)
		tp.Cards = append(tp.Cards, c)
	}

	// Detections per system, by week.
	counts := map[string][]int{}
	n := len(r.History) + 1
	add := func(host string, week int) {
		if host == "" {
			return
		}
		if counts[host] == nil {
			counts[host] = make([]int, n)
		}
		counts[host][week]++
	}
	for w, s := range r.History {
		for _, d := range s.Detections {
			add(d.Host, w)
		}
	}
	for _, f := range r.Findings {
		add(f.Host, n-1)
	}
	var names []string
	for h := range counts {
		names = append(names, h)
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
	if len(names) > 20 {
		names = names[:20]
	}
	for _, h := range names {
		row := WeekRow{Name: h}
		for _, v := range counts[h] {
			st := "background:rgba(0,30,98,.03)"
			if v > 0 {
				col := lerpColor(0xEE, 0xF2, 0xFA, 0x0A, 0x2A, 0x7A, 0.25+0.75*math.Min(float64(v)/3, 1))
				fg := "#3A4766"
				if v >= 2 {
					fg = "#fff"
				}
				st = "background:" + col + ";color:" + fg
			}
			row.Cells = append(row.Cells, WeekCell{N: v, Style: template.CSS(st)})
		}
		tp.Rows = append(tp.Rows, row)
	}
	tp.People = r.peopleByWeek()
	for _, s := range r.History {
		tp.PeopleOld = tp.PeopleOld || s.People == nil
	}
	return tp
}

// heatCell shades a count in a by-week table, darker for more.
func heatCell(v, top int) WeekCell {
	if v <= 0 {
		return WeekCell{Style: "background:rgba(0,30,98,.03)"}
	}
	col := lerpColor(0xEE, 0xF2, 0xFA, 0x0A, 0x2A, 0x7A, 0.25+0.75*float64(v)/float64(top))
	fg := "#3A4766"
	if float64(v) >= 0.5*float64(top) {
		fg = "#fff"
	}
	return WeekCell{N: v, Style: template.CSS("background:" + col + ";color:" + fg)}
}
