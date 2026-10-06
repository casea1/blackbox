package report

import (
	"fmt"
	"html/template"
	"math"
	"sort"
)

// The Trends page (design T1): eight small charts of this week against
// earlier calendar weeks (see weeks.go), and detections per system and
// privileged actions per person by week.

// TrendCard is one small chart.
type TrendCard struct {
	Title, Value, Avg, Delta, Class string
	Sub, Note                       string // the current week ("so far this week (3 of 7 days)"); why there is no chart
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
	NotEnough bool // fewer than minWeeks complete weeks
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

func (r *Report) trendsPage() *TrendsPage {
	ws := r.weeks()
	labels := r.weekLabels()
	tp := &TrendsPage{Weeks: labels}
	tp.Crumb = "Last " + r.weeksCrumb() + " · by calendar week (Monday to Sunday) · manual reports not included"

	for _, t := range trendMetrics {
		tr := r.metricTrend(t.Metric)
		c := TrendCard{Title: t.Title, Value: commas(tr.Now), Class: "flat", Href: t.Href, Sub: r.nowLabel()}
		switch {
		case t.Metric == MAfterHours && !r.WorkingHours.Set():
			c.Value, c.Note = "—", "Set working_hours to see this" // UI7
		case !tr.OK:
			c.Note = notEnoughHistory
		default:
			c.Avg = "avg " + commas(int(math.Round(tr.Avg))) + "/wk"
			c.Delta, c.Class = trendDelta(float64(tr.Now), tr.Expected, t.BadUp)
		}
		if c.Note == "" {
			c.Chart = weekBars(tr.Values, labels, t.BadUp, 300, 90)
		}
		tp.Cards = append(tp.Cards, c)
	}
	tp.NotEnough = !r.metricTrend(MEvents).OK

	// Detections per system, by week.
	counts := map[string][]int{}
	for i, w := range ws {
		for h, n := range w.HostDet {
			if h == "" {
				continue
			}
			if counts[h] == nil {
				counts[h] = make([]int, len(ws))
			}
			counts[h][i] += n
		}
	}
	n := len(ws)
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
	for _, w := range ws {
		tp.PeopleOld = tp.PeopleOld || (w.HasData && !w.HasPeople)
	}
	return tp
}

// trendDelta compares a week's count with what the average would be at
// the same point of a week: "+80%" and up/dn/flat.
func trendDelta(now, expected float64, badUp bool) (string, string) {
	if expected <= 0 {
		if now == 0 {
			return "0%", "flat"
		}
		return "new", map[bool]string{true: "up", false: "flat"}[badUp && now >= 3]
	}
	d := (now - expected) / expected * 100
	text := fmt.Sprintf("%+.0f%%", d)
	if math.Abs(d) < 0.5 {
		text = "0%"
	}
	switch {
	case !badUp || math.Abs(d) < 15:
		return text, "flat"
	case d > 0:
		return text, "up"
	}
	return text, "dn"
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
