package report

import (
	"fmt"
	"math"
	"sort"
)

// The Overview's "What changed" panel (ISSO request): the biggest moves
// this week so far against the same part of an average complete week (see
// weeks.go), across the network's totals, each system's detections and
// each person's privileged actions, in plain sentences.

// Change is one line of "What changed".
type Change struct {
	Text, Class, Href string // Class: up (worse) | dn (better) | new
	weight            float64
}

// maxChanges is how many lines the panel shows.
const maxChanges = 8

func (r *Report) whatChanged() []Change {
	ws := r.weeks()
	base := r.metricTrend(MEvents)
	if !base.OK {
		return nil // not enough history: the panel says so
	}
	var out []Change
	add := func(text, class, href string, now, avg float64) {
		out = append(out, Change{Text: text, Class: class, Href: href, weight: math.Abs(now-avg) / math.Max(avg, 1)})
	}
	now := r.nowLabel()
	weeks := plural(base.Complete, "complete week")

	// The network's totals.
	for _, t := range trendMetrics {
		if t.Metric == MAfterHours && !r.WorkingHours.Set() || t.Metric == MSTIGMatching || t.Metric == MLost {
			continue
		}
		tr := r.metricTrend(t.Metric)
		if !tr.OK {
			continue
		}
		d, class := change(float64(tr.Now), tr.Expected)
		if class == "flat" {
			continue
		}
		dir := "up"
		if float64(tr.Now) < tr.Expected {
			dir = "down"
		}
		if !t.BadUp && class != "new" { // fewer systems reporting is worse
			class = map[string]string{"up": "dn", "dn": "up"}[class]
		}
		add(fmt.Sprintf("%s: %s %s, %s %s on the average of %s (%.0f by this point of a week)", t.Title, commas(tr.Now), now, dir, trimSign(d), weeks, tr.Expected),
			class, t.Href, float64(tr.Now), tr.Expected)
	}

	// Each system's detections.
	hosts := map[string]bool{}
	for _, w := range ws {
		for h := range w.HostDet {
			hosts[h] = true
		}
	}
	for h := range hosts {
		host := h
		tr := trendOf(ws, func(w trendWeek) int { return w.HostDet[host] })
		if !tr.OK {
			continue
		}
		if _, class := change(float64(tr.Now), tr.Expected); class == "up" || class == "new" {
			add(fmt.Sprintf("%s: %s %s (average %.0f by this point of a week)", h, plural(tr.Now, "detection"), now, tr.Expected), "up", "#systems/"+h, float64(tr.Now), tr.Expected)
		}
	}

	// Each person's privileged actions, from the weeks that kept them.
	people := map[string]string{}
	for _, w := range ws {
		for k, p := range w.People {
			people[k] = p.Name
		}
	}
	for k, name := range people {
		key := k
		tr := trendOf(ws, func(w trendWeek) int {
			if !w.HasPeople {
				return -1
			}
			return w.People[key].Privileged
		})
		if !tr.OK {
			continue
		}
		seen := false
		for _, v := range tr.Values[:len(tr.Values)-1] {
			seen = seen || v > 0
		}
		switch _, class := change(float64(tr.Now), tr.Expected); {
		case !seen && tr.Now >= 3:
			add(fmt.Sprintf("%s: %s %s, none in the %s before", name, plural(tr.Now, "privileged action"), now, weeks), "new", "#people/"+key, float64(tr.Now), 0)
		case class == "up":
			add(fmt.Sprintf("%s: %s %s (average %.0f by this point of a week)", name, plural(tr.Now, "privileged action"), now, tr.Expected), "up", "#people/"+key, float64(tr.Now), tr.Expected)
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
