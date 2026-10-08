package report

import (
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// demo30History is twelve weeks of earlier daily reports for the 30-system
// network (UI-R1 Trends), the last one the day before start: each day's
// counts near the routine activity's (evs, the period's routine events,
// without the mockups' story), a few detections on a handful of systems,
// some events lost, five systems matching the STIG (three more this
// week), and what each report saw: every account, administrator, logon
// path and address of the routine activity, except jlee on SRV-DC02. So
// this week's new things are the story's: svc-backup and labadmin made
// administrators, the labadmin account, jlee → SRV-DC02, 203.0.113.50,
// the UpdaterSvc service and the SanDisk USB stick.
func demo30History(start time.Time, systems []demo30System, evs []*event.Event, checks []CheckSet) []Summary {
	rnd := rand.New(rand.NewSource(3012)) // its own, so the rest of demo30 is unchanged
	loc := demo30Zone

	// The routine day's counts.
	base := map[string]int{}
	failedBy := map[string]int{}
	people := map[string]*PersonSummary{}
	for _, e := range evs {
		m := map[string]int{}
		addRowMetrics(m, &Row{Event: e})
		for k, v := range m {
			base[k] += v
		}
		base[MEvents]++
		if e.Category == event.CatFailedLogon {
			failedBy[e.Host]++
		}
		if person(e.User) {
			k := personKey(e.User)
			p := people[k]
			if p == nil {
				p = &PersonSummary{Key: k, Name: e.User}
				people[k] = p
			}
			switch {
			case e.Category == event.CatPrivileged:
				p.Privileged++
			case e.Category == event.CatLogon && e.Action == "logon":
				p.Logons++
			}
		}
	}
	keys := make([]string, 0, len(people))
	for k := range people {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// What every report saw.
	seen := seenSet{}
	for _, cs := range checks {
		if cs.Inventory == nil {
			continue
		}
		for _, a := range cs.Inventory.Accounts {
			seen.add(SeenAccount, cs.Host+`\`+strings.ToLower(a.Name))
			if a.Admin {
				seen.add(SeenAdmin, cs.Host+`\`+strings.ToLower(a.Name))
			}
		}
	}
	for _, e := range evs {
		for kind, key := range seenKeys(e) {
			if strings.HasPrefix(key, "jlee|SRV-DC02") {
				continue
			}
			seen.add(kind, key)
		}
	}
	saw := seenOf(seen)

	// The systems matching the STIG: this week's, less three fixed now.
	var matching []string
	for _, cs := range checks {
		if cs.STIGFail == 0 && cs.Host != "ubu-git01" && cs.Host != "ubu-ws-01" && cs.Host != "ubu-ws-05" {
			matching = append(matching, cs.Host)
		}
	}
	sort.Strings(matching)

	detHosts := []string{"ubu-web01", "SRV-APP01", "WS-LAB-01", "ubu-db01", "WS-ENG-04", "SRV-DC01", "ubu-ws-03"}
	titles := []string{"Many failed logons from one address", "Privileged command outside working hours", "USB storage connected", "Audit policy changed"}
	scale := func(n int) int { return n * (85 + rnd.Intn(31)) / 100 }

	var out []Summary
	first := start.AddDate(0, 0, -84)
	for d := 0; d < 84; d++ {
		ws := first.AddDate(0, 0, d)
		we := ws.AddDate(0, 0, 1)
		day := DayCounts{Date: ws.In(loc).Format("2006-01-02"), Metrics: map[string]int{}, Failed: map[string]int{}}
		for _, k := range sortedKeys(base) {
			v := base[k]
			day.Metrics[k] = scale(v)
		}
		day.Metrics[MAfterHours] = rnd.Intn(3)
		for _, h := range sortedKeys(failedBy) {
			n := failedBy[h]
			day.Failed[h] = scale(n)
		}
		for _, s := range systems {
			if !s.Silent || we.Before(start) {
				day.Hosts = append(day.Hosts, s.Name)
			}
		}
		day.Metrics[MSystems] = len(day.Hosts)
		for _, k := range keys {
			p := *people[k]
			p.Privileged, p.Logons = scale(p.Privileged), scale(p.Logons)
			day.People = append(day.People, p)
		}
		s := Summary{Site: "ENG-NET", WindowStart: ws, WindowEnd: we, Generated: we.Add(2 * time.Minute), Hosts: day.Hosts,
			Events: day.Metrics[MEvents], Days: []DayCounts{day}, People: day.People, Seen: saw, Matching: matching,
			Metrics: map[string]int{MSTIGChecked: len(checks), MSTIGMatching: len(matching), MSystems: len(day.Hosts)}}
		for k, v := range day.Metrics {
			s.Metrics[k] = v
		}
		// About ten detections a week, on a handful of systems.
		for n := rnd.Intn(3); n > 0; n-- {
			sev := "medium"
			if rnd.Intn(4) == 0 {
				sev = "high"
			}
			s.Detections = append(s.Detections, Detection{Severity: sev, Time: ws.Add(time.Duration(8+rnd.Intn(10)) * time.Hour),
				Host: detHosts[rnd.Intn(len(detHosts))], Title: titles[rnd.Intn(len(titles))]})
		}
		if rnd.Intn(4) == 0 {
			s.Lost = uint64(80 + rnd.Intn(240))
		}
		out = append(out, s)
	}
	return out
}
