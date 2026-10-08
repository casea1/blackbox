package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// dayOf is the date of t, as summary.json's days have it.
func dayOf(t time.Time) string { return t.UTC().Format("2006-01-02") }

// dailyReport is a scheduled report covering one day, from its day counts.
func dailyReport(day time.Time, privileged int, people []PersonSummary) Summary {
	return Summary{WindowStart: day, WindowEnd: day.AddDate(0, 0, 1), People: people,
		Days: []DayCounts{{Date: dayOf(day), Metrics: map[string]int{MPrivileged: privileged, MEvents: privileged}, People: people, Hosts: []string{"ubuntu-server"}}}}
}

// privileged makes n privileged actions by user, spread over [from, to).
func privileged(n int, user string, from, to time.Time) []*event.Event {
	var out []*event.Event
	step := to.Sub(from) / time.Duration(n+1)
	for i := 0; i < n; i++ {
		out = append(out, &event.Event{Time: from.Add(step * time.Duration(i+1)), Host: "ubuntu-server", OS: "linux", Category: event.CatPrivileged,
			Severity: event.SevLow, Action: "sudo", User: user, Summary: user + " ran a command with sudo."})
	}
	return out
}

// UI1: trends add up days by calendar week. The first report reads back
// 2.7 days and only fills a partial week; daily reports make complete
// weeks (seven reports, one week); a manual report is not history; the
// current, manual report is "so far this week" and is compared with the
// same part of an average week.
func TestTrendsByCalendarWeek(t *testing.T) {
	mon := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC) // a Monday
	first := Summary{First: true, WindowStart: mon.Add(-4*24*time.Hour + 6*time.Hour), WindowEnd: mon.Add(-24*time.Hour + 13*time.Hour)}
	for d := 0; d < 3; d++ {
		first.Days = append(first.Days, DayCounts{Date: dayOf(first.WindowStart.AddDate(0, 0, d)), Metrics: map[string]int{MPrivileged: 605, MEvents: 605}})
	}
	hist := []Summary{first}
	// The rest of that Sunday, then daily reports for three weeks.
	hist = append(hist, Summary{WindowStart: first.WindowEnd, WindowEnd: mon, Days: []DayCounts{{Date: dayOf(mon.Add(-time.Hour)), Metrics: map[string]int{MPrivileged: 5, MEvents: 5}}}})
	for d := 0; d < 21; d++ {
		hist = append(hist, dailyReport(mon.AddDate(0, 0, d), 10, nil))
	}
	// A manual report in the middle: never history.
	hist = append(hist, Summary{Interim: true, WindowStart: mon.AddDate(0, 0, 8), WindowEnd: mon.AddDate(0, 0, 8).Add(12 * time.Hour),
		Days: []DayCounts{{Date: dayOf(mon.AddDate(0, 0, 8)), Metrics: map[string]int{MPrivileged: 900}}}})

	// Now: a manual report on Wednesday 12:00, two and a half days in.
	now := mon.AddDate(0, 0, 23).Add(12 * time.Hour)
	weekStart := mon.AddDate(0, 0, 21)
	r := Build(privileged(25, "claude", weekStart, now), nil, Options{WindowStart: weekStart, WindowEnd: now, Location: time.UTC, History: hist, Interim: true})

	ws := r.weeks()
	var complete []string
	for _, w := range ws {
		if w.Complete && !w.Current {
			complete = append(complete, w.Start.Format("2 Jan"))
		}
	}
	if strings.Join(complete, ",") != "14 Sep,21 Sep,28 Sep" {
		t.Errorf("complete weeks: %v (the first report's week is partial, the current one so far)", complete)
	}
	tr := r.metricTrend(MPrivileged)
	if !tr.OK || tr.Avg != 70 || tr.Now != 25 || tr.Expected != 25 || tr.Complete != 3 { // 70 a week: 25 by Wednesday noon
		t.Errorf("privileged actions: %+v", tr)
	}
	if got := r.nowLabel(); got != "so far this week (2.5 of 7 days)" {
		t.Errorf("now: %q", got)
	}
	if l := r.weekLabels(); l[len(l)-1] != "This week" || l[len(l)-2] != "28 Sep" || l[0] != "7 Sep (part)" {
		t.Errorf("labels: %v", l)
	}
	// Two and a half days against an average week is not "down 96%".
	for _, c := range r.whatChanged() {
		if strings.Contains(c.Text, "Privileged actions") {
			t.Errorf("a normal week so far reported as a change: %s", c.Text)
		}
	}
	tp := r.trendsPage()
	// UI-R1: "usual" is the median of the complete earlier weeks; 25 by
	// Wednesday noon is a usual week so far, so the bar is blue.
	if c := tp.Ranges[1].Cards[2]; tp.NotEnough || c.Title != "Privileged actions (people)" || c.Usual != "usual 70" || c.Class != "" ||
		!strings.Contains(tp.Crumb(), "5 weeks · 7 Sep – 7 Oct 2026") || tp.Ranges[1].Weeks != 5 || tp.Ranges[0].Weeks != 4 {
		t.Errorf("trends page: %+v %q", c, tp.Crumb())
	}

	// The manual report's 900 are nowhere.
	for _, w := range ws {
		if w.Metrics[MPrivileged] > 300 && !strings.HasPrefix(w.Start.Format("2 Jan"), "7 Sep") {
			t.Errorf("week of %s has %d: a manual report counted", w.Start.Format("2 Jan"), w.Metrics[MPrivileged])
		}
	}
}

// UI1: with fewer than two complete weeks, every trend says so instead of
// drawing one or two points.
func TestTrendsNotEnoughHistory(t *testing.T) {
	mon := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	hist := []Summary{
		{First: true, WindowStart: mon.Add(-62 * time.Hour), WindowEnd: mon.Add(2 * time.Hour), Days: []DayCounts{{Date: "2026-10-03", Metrics: map[string]int{MPrivileged: 1814}}}},
		dailyReport(mon.AddDate(0, 0, 1), 78, nil),
	}
	now := mon.AddDate(0, 0, 2).Add(12 * time.Hour)
	r := Build(privileged(42, "claude", mon.AddDate(0, 0, 2), now), nil, Options{WindowStart: mon.AddDate(0, 0, 2), WindowEnd: now, Location: time.UTC, History: hist, Interim: true})
	if c := r.whatChanged(); c != nil {
		t.Errorf("what changed with no complete week: %+v", c)
	}
	o := r.overview(nil)
	if o.HistoryN != 0 || o.Trends[2].Chart != "" || !strings.Contains(o.Trends[2].Note, "120 so far") || !strings.Contains(o.TrendSpan, "2.5 of 7 days so far") || strings.Contains(o.Trends[2].Note, "avg") {
		t.Errorf("overview: %d %+v", o.HistoryN, o.Trends[2])
	}
	if tp := r.trendsPage(); !tp.NotEnough || tp.Ranges[1].Cards[2].Usual != "usual —" || tp.Ranges[1].Cards[2].Class != "" || tp.Ranges[1].ChangesNote != notEnoughHistory {
		t.Errorf("trends page: %+v", tp.Ranges[1])
	}
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	if strings.Count(string(html), "Not enough history yet: trends start after 2 full weeks") < 3 {
		t.Error("the report does not say there is not enough history")
	}
}

// Each report keeps per-person counts by day; later reports show a
// person's activity over time, privileged actions by person on Trends, and
// the biggest changes on the Overview, by calendar week.
func TestPeopleTrendsAndWhatChanged(t *testing.T) {
	mon := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	jd := func(n int) []PersonSummary {
		return []PersonSummary{{Key: "admin_jd", Name: "admin_jd", Privileged: n}}
	}
	var hist []Summary
	for d := 0; d < 21; d++ { // three complete weeks, admin_jd 2 a day
		hist = append(hist, dailyReport(mon.AddDate(0, 0, d), 3, jd(2)))
	}
	// A whole scheduled week to Sunday night: this week has ended.
	weekStart := mon.AddDate(0, 0, 21)
	end := weekStart.AddDate(0, 0, 7)
	evs := append(privileged(60, `CORP\admin_jd`, weekStart, end), privileged(4, "tempuser", weekStart, end)...)
	r := Build(evs, nil, Options{WindowStart: weekStart, WindowEnd: end, Location: time.UTC, History: hist})

	s := r.summary()
	if len(s.Days) != 7 || s.First {
		t.Fatalf("summary days: %d, first %v", len(s.Days), s.First)
	}
	var jdNow PersonSummary
	for _, p := range s.People {
		if p.Key == "admin_jd" {
			jdNow = p
		}
	}
	pt := r.personTrend(jdNow, r.weekLabels())
	if pt.Weeks != 3 || pt.Rows[0].Now != "60" || pt.Rows[0].Avg != "14" || pt.Rows[0].Class != "up" {
		t.Errorf("person trend: %d %+v", pt.Weeks, pt.Rows[0])
	}

	var texts []string
	for _, c := range r.whatChanged() {
		texts = append(texts, c.Class+" "+c.Text)
	}
	all := strings.Join(texts, "\n")
	for _, want := range []string{
		`up CORP\admin_jd: 60 privileged actions in the week to 11 Oct (average 14 by this point of a week)`,
		"new tempuser: 4 privileged actions in the week to 11 Oct, none in the 3 complete weeks before",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("what changed lacks %q:\n%s", want, all)
		}
	}

	// UI-R1: Trends' biggest changes have each person's activity against
	// their usual week.
	tp := r.trendsPage()
	found := false
	for _, c := range tp.Ranges[1].Changes {
		if c.Href == "#people/admin_jd" && c.Measure == "Privileged actions" && c.Usual == "14" && c.Now == "60" {
			found = true
		}
	}
	if !found {
		t.Errorf("biggest changes: %+v", tp.Ranges[1].Changes)
	}
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, want := range []string{"What changed", "Over time", "Biggest changes this week", "tempuser: 4 privileged actions"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report lacks %q", want)
		}
	}
}
