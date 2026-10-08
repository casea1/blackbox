package report

import (
	"fmt"
	"html/template"
	"math"
	"sort"

	"github.com/casea1/blackbox/internal/event"
)

// Each person's activity over time (ISSO request): every report keeps
// per-account counts in summary.json (people), so later reports can show a
// person's privileged actions, logons, failed logons, after-hours actions
// and detections week by week.

// PersonSummary is one account's counts in summary.json.
type PersonSummary struct {
	Key        string `json:"key"` // lower case, without its domain (personKey)
	Name       string `json:"name"`
	Privileged int    `json:"privileged_actions,omitempty"`
	Logons     int    `json:"logons,omitempty"`
	Failed     int    `json:"failed_logons,omitempty"`
	AfterHours int    `json:"after_hours,omitempty"`
	Detections int    `json:"detections,omitempty"`
}

// maxPeopleKept bounds summary.json on a large network: the most active
// accounts are kept.
const maxPeopleKept = 500

// peopleTotals counts this report's activity by person.
func (r *Report) peopleTotals() []PersonSummary { return r.peopleCounts(nil) }

// peopleCounts counts activity by person in the rows keep accepts (all
// rows when keep is nil).
func (r *Report) peopleCounts(keep func(*Row) bool) []PersonSummary {
	by := map[string]*PersonSummary{}
	get := func(u string) *PersonSummary {
		k := r.pkey(u)
		p := by[k]
		if p == nil {
			p = &PersonSummary{Key: k, Name: u}
			by[k] = p
		}
		return p
	}
	findingRows := map[int][]int{}
	for fi, f := range r.Findings {
		for _, id := range f.RowIDs {
			findingRows[rowIndex(id)] = append(findingRows[rowIndex(id)], fi)
		}
	}
	inFinding := map[string]map[int]bool{}
	for i, row := range r.rows {
		if keep != nil && !keep(row) {
			continue
		}
		e := row.Event
		switch {
		case e.Category == event.CatFailedLogon:
			who := e.Target
			if who == "" {
				who = e.User
			}
			if person(who) {
				get(who).Failed++
			}
		case person(e.User):
			p := get(e.User)
			switch {
			case e.Category == event.CatLogon && e.Action == "logon":
				p.Logons++
			case e.Category == event.CatPrivileged:
				p.Privileged++
				if r.outsideHours(e) {
					p.AfterHours++
				}
			}
		}
		if person(e.User) {
			k := r.pkey(e.User)
			for _, fi := range findingRows[i] {
				if inFinding[k] == nil {
					inFinding[k] = map[int]bool{}
				}
				inFinding[k][fi] = true
			}
		}
	}
	for k, fs := range inFinding {
		if p := by[k]; p != nil {
			p.Detections = len(fs)
		}
	}
	out := make([]PersonSummary, 0, len(by))
	for _, p := range by {
		out = append(out, *p)
	}
	activity := func(p PersonSummary) int { return p.Privileged + p.Logons + p.Failed + 10*p.Detections }
	sort.Slice(out, func(i, j int) bool {
		if activity(out[i]) != activity(out[j]) {
			return activity(out[i]) > activity(out[j])
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > maxPeopleKept {
		out = out[:maxPeopleKept]
	}
	return out
}

// PersonTrend is a person's "Over time" panel.
type PersonTrend struct {
	Weeks int // reports with people kept, this one included
	Rows  []PersonTrendRow
	Chart template.HTML // privileged actions by week
}

// PersonTrendRow is one measure of a person's activity over time.
type PersonTrendRow struct {
	Label, Now, Avg, Delta, Class, Href string
}

var personMeasures = []struct {
	Label string
	Get   func(PersonSummary) int
	Href  func(key string) string
}{
	{"Privileged actions", func(p PersonSummary) int { return p.Privileged }, func(k string) string { return searchLink("page", "privileged", "user", k) }},
	{"After hours", func(p PersonSummary) int { return p.AfterHours }, func(k string) string { return searchLink("user", k, "when", "@after") }},
	{"Logons", func(p PersonSummary) int { return p.Logons }, func(k string) string { return searchLink("page", "logons", "user", k) }},
	{"Failed logons", func(p PersonSummary) int { return p.Failed }, func(k string) string { return searchLink("page", "failed", "text", k) }},
	{"Detections", func(p PersonSummary) int { return p.Detections }, func(k string) string { return "#detections" }},
}

// personTrend builds a person's "Over time" panel from the calendar
// weeks that kept counts by person.
func (r *Report) personTrend(now PersonSummary, labels []string) *PersonTrend {
	ws := r.weeks()
	t := &PersonTrend{}
	for _, m := range personMeasures {
		get := m.Get
		tr := trendOf(ws, func(w trendWeek) int {
			if !w.HasPeople {
				return -1
			}
			return get(w.People[now.Key])
		})
		row := PersonTrendRow{Label: m.Label, Now: commas(tr.Now), Class: "flat", Href: m.Href(now.Key), Avg: "—"}
		if tr.OK {
			row.Avg = fmt.Sprintf("%.0f", tr.Avg)
			row.Delta, row.Class = change(float64(tr.Now), tr.Expected)
		}
		t.Rows = append(t.Rows, row)
		if m.Label == "Privileged actions" {
			if tr.OK {
				t.Weeks = tr.Complete
				t.Chart = weekBars(tr.Values, labels, true, 300, 80)
			}
		}
	}
	return t
}

// change describes now against an average: "+80%" and up/dn/flat (a
// change under 25%, or of fewer than 3, is flat).
func change(now, avg float64) (string, string) {
	switch {
	case avg == 0 && now == 0:
		return "0%", "flat"
	case avg == 0:
		return "new", map[bool]string{true: "up", false: "flat"}[now >= 3]
	}
	d := (now - avg) / avg * 100
	text := fmt.Sprintf("%+.0f%%", d)
	if math.Abs(d) < 0.5 {
		text = "0%"
	}
	switch {
	case math.Abs(d) < 25 || math.Abs(now-avg) < 3:
		return text, "flat"
	case d > 0:
		return text, "up"
	}
	return text, "dn"
}
