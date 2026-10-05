package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// Each report keeps per-person counts; later reports show a person's
// activity over time, privileged actions by person on Trends, and the
// biggest changes on the Overview.
func TestPeopleTrendsAndWhatChanged(t *testing.T) {
	end := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	var evs []*event.Event
	for i := 0; i < 12; i++ { // admin_jd: 12 privileged actions this week
		evs = append(evs, &event.Event{Time: end.Add(-time.Duration(i+1) * time.Hour), Host: "WS-07", OS: "windows", Category: event.CatPrivileged,
			Severity: event.SevLow, Action: "special_logon", User: `CORP\admin_jd`, Summary: "admin"})
	}
	for i := 0; i < 4; i++ { // tempuser: never privileged before
		evs = append(evs, &event.Event{Time: end.Add(-time.Duration(i+1) * time.Hour), Host: "WS-07", OS: "windows", Category: event.CatPrivileged,
			Severity: event.SevLow, Action: "special_logon", User: "tempuser", Summary: "admin"})
	}
	week := func(n int, people []PersonSummary) Summary {
		return Summary{WindowEnd: end.AddDate(0, 0, -7*n), Events: 10, People: people,
			Metrics: map[string]int{MPrivileged: 3, MFailedLogons: 5, MDetections: 0, MSystems: 1}}
	}
	history := []Summary{
		{WindowEnd: end.AddDate(0, 0, -21), Events: 10}, // before people were kept
		week(2, []PersonSummary{{Key: "admin_jd", Name: "admin_jd", Privileged: 2}}),
		week(1, []PersonSummary{{Key: "admin_jd", Name: "admin_jd", Privileged: 4}}),
	}
	r := Build(evs, nil, Options{WindowEnd: end, Location: time.UTC, History: history})

	s := r.summary()
	var jd PersonSummary
	for _, p := range s.People {
		if p.Key == "admin_jd" {
			jd = p
		}
	}
	if jd.Privileged != 12 || jd.Name != `CORP\admin_jd` {
		t.Fatalf("summary people: %+v", s.People)
	}

	pt := r.personTrend(jd, r.weekLabels())
	if pt.Weeks != 3 || pt.Rows[0].Label != "Privileged actions" || pt.Rows[0].Now != "12" || pt.Rows[0].Avg != "3" || pt.Rows[0].Class != "up" || pt.Rows[0].Delta != "+300%" {
		t.Errorf("person trend: %+v %+v", pt.Weeks, pt.Rows[0])
	}

	changes := r.whatChanged()
	var texts []string
	for _, c := range changes {
		texts = append(texts, c.Class+" "+c.Text)
	}
	all := strings.Join(texts, "\n")
	for _, want := range []string{
		"up Privileged actions: 16 this week, up 433% on the average of the last 3 reports (3)",
		`up CORP\admin_jd: 12 privileged actions this week (average 3)`,
		"new tempuser: 4 privileged actions, none in the last 3 reports",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("what changed lacks %q:\n%s", want, all)
		}
	}

	tp := r.trendsPage()
	if len(tp.People) != 2 || tp.People[0].Name != `CORP\admin_jd` || tp.People[0].Href != "#people/admin_jd" || !tp.PeopleOld ||
		tp.People[0].Cells[0].N != 0 || tp.People[0].Cells[1].N != 2 || tp.People[0].Cells[3].N != 12 {
		t.Errorf("people by week: %+v (old %v)", tp.People, tp.PeopleOld)
	}

	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, want := range []string{"What changed", "Over time", "Privileged actions by person, by week", "tempuser: 4 privileged actions"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report lacks %q", want)
		}
	}

	// The first report: nothing to compare.
	if c := Build(evs, nil, Options{WindowEnd: end, Location: time.UTC}).whatChanged(); c != nil {
		t.Errorf("first report: %+v", c)
	}
}
