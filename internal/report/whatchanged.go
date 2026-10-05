package report

import (
	"fmt"
	"math"
	"sort"
)

// The Overview's "What changed" panel (ISSO request): the biggest moves
// this week against the average of the earlier reports, across the
// network's totals, each system's detections and each person's
// privileged actions, in plain sentences.

// Change is one line of "What changed".
type Change struct {
	Text, Class, Href string // Class: up (worse) | dn (better) | new
	weight            float64
}

// maxChanges is how many lines the panel shows.
const maxChanges = 8

func (r *Report) whatChanged() []Change {
	if len(r.History) == 0 {
		return nil
	}
	var out []Change
	add := func(text, class, href string, now, avg float64) {
		out = append(out, Change{Text: text, Class: class, Href: href, weight: math.Abs(now-avg) / math.Max(avg, 1)})
	}
	weeks := fmt.Sprintf("the last %s", plural(len(r.History), "report"))

	// The network's totals.
	m := r.metrics()
	for _, t := range trendMetrics {
		vals := r.series(t.Metric, m[t.Metric])
		now, avg := float64(vals[len(vals)-1]), average(vals)
		if avg < 0 {
			continue
		}
		d, class := change(now, avg)
		if class == "flat" {
			continue
		}
		dir := "up"
		if now < avg {
			dir = "down"
		}
		if !t.BadUp && class != "new" { // fewer systems reporting is worse
			class = map[string]string{"up": "dn", "dn": "up"}[class]
		}
		add(fmt.Sprintf("%s: %s this week, %s %s on the average of %s (%.0f)", t.Title, commas(int(now)), dir, trimSign(d), weeks, avg), class, t.Href, now, avg)
	}

	// Each system's detections.
	hosts := map[string][]int{}
	n := len(r.History) + 1
	for w, s := range r.History {
		for _, d := range s.Detections {
			if hosts[d.Host] == nil {
				hosts[d.Host] = make([]int, n)
			}
			hosts[d.Host][w]++
		}
	}
	for _, f := range r.Findings {
		if hosts[f.Host] == nil {
			hosts[f.Host] = make([]int, n)
		}
		hosts[f.Host][n-1]++
	}
	for h, vals := range hosts {
		now, avg := float64(vals[n-1]), average(vals)
		if _, class := change(now, avg); class == "up" || class == "new" {
			add(fmt.Sprintf("%s: %s this week (average %.0f)", h, plural(int(now), "detection"), avg), "up", "#systems/"+h, now, avg)
		}
	}

	// Each person's privileged actions.
	kept := false
	for _, s := range r.History {
		kept = kept || s.People != nil
	}
	if kept {
		for _, p := range r.peopleTotals() {
			vals := r.personSeries(p.Key, p, func(x PersonSummary) int { return x.Privileged })
			now, avg := float64(p.Privileged), average(vals)
			seen := false
			for _, v := range vals[:len(vals)-1] {
				seen = seen || v > 0
			}
			switch _, class := change(now, avg); {
			case !seen && now >= 3:
				add(fmt.Sprintf("%s: %s, none in %s", p.Name, plural(int(now), "privileged action"), weeks), "new", "#people/"+p.Key, now, 0)
			case class == "up":
				add(fmt.Sprintf("%s: %s this week (average %.0f)", p.Name, plural(int(now), "privileged action"), avg), "up", "#people/"+p.Key, now, avg)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].weight != out[j].weight {
			return out[i].weight > out[j].weight
		}
		return out[i].Text < out[j].Text
	})
	if len(out) > maxChanges {
		out = out[:maxChanges]
	}
	return out
}

func trimSign(d string) string {
	if len(d) > 0 && (d[0] == '+' || d[0] == '-') {
		return d[1:]
	}
	return d
}

// peopleByWeek is the Trends page's privileged actions by person, by
// week: the 20 most active people this week and before.
func (r *Report) peopleByWeek() []WeekRow {
	n := len(r.History) + 1
	counts := map[string][]int{}
	names := map[string]string{}
	set := func(key, name string, w, v int) {
		if v == 0 {
			return
		}
		if counts[key] == nil {
			counts[key] = make([]int, n)
		}
		counts[key][w] = v
		if names[key] == "" {
			names[key] = name
		}
	}
	for _, p := range r.peopleTotals() {
		set(p.Key, p.Name, n-1, p.Privileged)
	}
	for w, s := range r.History {
		for _, p := range s.People {
			set(p.Key, p.Name, w, p.Privileged)
		}
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	total := func(v []int) int {
		t := 0
		for _, x := range v {
			t += x
		}
		return t
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := counts[keys[i]], counts[keys[j]]
		if a[n-1] != b[n-1] {
			return a[n-1] > b[n-1]
		}
		if total(a) != total(b) {
			return total(a) > total(b)
		}
		return keys[i] < keys[j]
	})
	if len(keys) > 20 {
		keys = keys[:20]
	}
	top := 1
	for _, k := range keys {
		for _, v := range counts[k] {
			top = max(top, v)
		}
	}
	var rows []WeekRow
	for _, k := range keys {
		row := WeekRow{Name: names[k], Href: "#people/" + k}
		for _, v := range counts[k] {
			row.Cells = append(row.Cells, heatCell(v, top))
		}
		rows = append(rows, row)
	}
	return rows
}
