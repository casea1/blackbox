package report

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// The People page (design P1): everyone whose account did something in
// the period, grouped Needs a look / Administrators / Service accounts /
// Users; and for the one selected, five facts, notable actions in plain
// sentences, when they were active, and the systems they used.

// PersonView is one account on the People page.
type PersonView struct {
	Key, Name, Initials string
	Kind                string // Administrator, Service account, User, …
	Level               string // bad | warn | ""
	Line                string
	Systems             int
	Facts               []Fact
	Notable             []CheckLine
	NotableCount        int
	Heat                template.HTML
	Trend               *PersonTrend // activity over the earlier reports
	Used                []TopItem
	Detections          []DetectionCard
	group               int
}

// PeopleGroup is one group of the People page's list.
type PeopleGroup struct {
	Title  string
	People []*PersonView
}

// PeoplePage is the People page.
type PeoplePage struct {
	Groups []PeopleGroup
	Count  int
}

// personKey is how an account is matched across events: lower case,
// without its domain.
func personKey(u string) string {
	l := strings.ToLower(strings.TrimSpace(u))
	if i := strings.LastIndex(l, `\`); i >= 0 {
		l = l[i+1:]
	}
	if i := strings.Index(l, "@"); i > 0 {
		l = l[:i]
	}
	return l
}

func serviceAccount(k string) bool {
	return strings.HasPrefix(k, "svc") || strings.HasPrefix(k, "service") || strings.HasSuffix(k, "_svc") || strings.HasPrefix(k, "sa_")
}

type personData struct {
	name, domainName string
	first            time.Time
	hosts            map[string]int
	logons, admin    int
	afterHours       int
	high, med        int
	created, admined bool
	heat             [7][24]int
	hot              [7][24]bool
	slots            map[int][]string // detection → weekday-hour slots it involved this person
	notable          []*Row
	inFinding        bool
}

func (r *Report) peoplePage() *PeoplePage {
	totals := map[string]PersonSummary{}
	for _, t := range r.peopleTotals() {
		totals[t.Key] = t
	}
	labels := r.weekLabels()
	people := map[string]*personData{}
	get := func(u string) *personData {
		k := personKey(u)
		p := people[k]
		if p == nil {
			p = &personData{name: u, hosts: map[string]int{}, slots: map[int][]string{}}
			if i := strings.LastIndex(u, `\`); i >= 0 {
				p.name = u[i+1:]
			}
			people[k] = p
		}
		if strings.Contains(u, `\`) && p.domainName == "" {
			p.domainName = u
		}
		return p
	}
	// Accounts in a detection: by who did it, and who it was done to.
	findingRows := map[int][]int{}
	for fi, f := range r.Findings {
		for _, id := range f.RowIDs {
			findingRows[rowIndex(id)] = append(findingRows[rowIndex(id)], fi)
		}
	}
	findingsOf := map[string]map[int]bool{}
	mark := func(k string, fi int) {
		if findingsOf[k] == nil {
			findingsOf[k] = map[int]bool{}
		}
		findingsOf[k][fi] = true
	}
	for i, row := range r.rows {
		e := row.Event
		fis := findingRows[i]
		if person(e.User) {
			p := get(e.User)
			if p.first.IsZero() {
				p.first = e.Time
			}
			p.hosts[e.Host]++
			t := e.Time.In(r.Location)
			d := (int(t.Weekday()) + 6) % 7 // Monday first
			p.heat[d][t.Hour()]++
			switch {
			case e.Category == event.CatLogon && e.Action == "logon":
				p.logons++
			case e.Category == event.CatPrivileged:
				p.admin++
				if r.outsideHours(e) {
					p.afterHours++
				}
			}
			if len(fis) > 0 {
				p.hot[d][t.Hour()] = true
				p.inFinding = true
				for _, fi := range fis {
					mark(personKey(e.User), fi)
					p.slots[fi] = append(p.slots[fi], fmt.Sprintf("%d-%d", d, t.Hour()))
				}
			}
			if notableRow(row, len(fis) > 0) {
				p.notable = append(p.notable, row)
			}
		}
		// The account something was done to.
		if e.Target != "" && person(e.Target) && personKey(e.Target) != personKey(e.User) {
			k := personKey(e.Target)
			switch {
			case strings.HasSuffix(e.Action, "account_created"):
				get(e.Target).created = true
			case e.Action == "group_member_added" && e.Severity == event.SevHigh:
				get(e.Target).admined = true
			}
			if len(fis) > 0 && people[k] == nil && e.Category == event.CatFailedLogon {
				get(e.Target) // a guessed-at account
			}
			if people[k] != nil && len(fis) > 0 {
				people[k].inFinding = true
				for _, fi := range fis {
					mark(k, fi)
				}
			}
		}
	}
	if len(people) == 0 {
		return nil
	}
	for k, fs := range findingsOf {
		if p := people[k]; p != nil {
			for fi := range fs {
				if r.Findings[fi].Severity == event.SevHigh {
					p.high++
				} else {
					p.med++
				}
			}
		}
	}

	pp := &PeoplePage{Count: len(people)}
	cards := r.detectionCards()
	groups := []*PeopleGroup{{Title: "Needs a look"}, {Title: "Administrators"}, {Title: "Service accounts"}, {Title: "Users"}}
	for k, p := range people {
		v := &PersonView{Key: k, Name: p.name, Initials: initials(p.name), Systems: len(p.hosts)}
		builtin := k == "administrator" || k == "root" || k == "admin"
		switch {
		case builtin:
			v.Kind, v.group = "Built-in admin", 1
		case serviceAccount(k):
			v.Kind, v.group = "Service account", 2
		case p.admin > 0 || p.admined:
			v.Kind, v.group = "Administrator", 1
		default:
			v.Kind, v.group = "User", 3
		}
		switch {
		case p.created:
			v.Kind = "New account"
		case p.admined && v.Kind == "User":
			v.Kind = "User · new admin"
		}
		switch {
		case p.high > 0:
			v.Level, v.group = "bad", 0
		case p.med > 0 || p.afterHours > 0 || p.created || p.admined:
			v.Level, v.group = "warn", 0
		}
		line := []string{v.Kind}
		if p.domainName != "" {
			line = append(line, "domain account "+p.domainName)
		}
		if !p.first.IsZero() {
			line = append(line, "first event this period "+p.first.In(r.Location).Format("2 Jan 15:04"))
		}
		v.Line = strings.Join(line, " · ")

		det := "None"
		if p.high+p.med > 0 {
			var l []string
			if p.high > 0 {
				l = append(l, fmt.Sprintf("%d high", p.high))
			}
			if p.med > 0 {
				l = append(l, fmt.Sprintf("%d med", p.med))
			}
			det = strings.Join(l, " · ")
		}
		v.Facts = []Fact{
			{Label: "Systems used", Value: commas(len(p.hosts)), Scroll: "pused-" + k},
			{Label: "Logons", Value: commas(p.logons), Href: searchLink("page", "logons", "user", k)},
			{Label: "Admin actions", Value: commas(p.admin), Href: searchLink("page", "privileged", "user", k)},
			{Label: "After hours", Value: commas(p.afterHours), Bad: p.afterHours > 0, Href: searchLink("user", k, "when", "@after")},
			{Label: "Detections", Value: det, Bad: p.high+p.med > 0, Scroll: "pdet-" + k},
		}
		for _, c := range cards {
			if findingsOf[k][c.Index] {
				c.Slots = strings.Join(p.slots[c.Index], " ")
				v.Detections = append(v.Detections, c)
			}
		}
		v.Notable, v.NotableCount = r.notable(p.notable)
		v.Heat = heatmap(p.heat, p.hot, k)
		now, ok := totals[k]
		if !ok {
			now = PersonSummary{Key: k}
		}
		v.Trend = r.personTrend(now, labels)
		type hc struct {
			h string
			n int
		}
		var hl []hc
		for h, n := range p.hosts {
			hl = append(hl, hc{h, n})
		}
		sort.Slice(hl, func(a, b int) bool { return hl[a].n > hl[b].n || hl[a].n == hl[b].n && naturalLess(hl[a].h, hl[b].h) })
		for i, x := range hl {
			if i == 6 {
				break
			}
			v.Used = append(v.Used, TopItem{Label: x.h, N: x.n, Pct: x.n * 100 / max(1, hl[0].n)})
		}
		groups[v.group].People = append(groups[v.group].People, v)
	}
	rank := map[string]int{"bad": 0, "warn": 1, "": 2}
	for _, g := range groups {
		sort.SliceStable(g.People, func(i, j int) bool {
			a, b := g.People[i], g.People[j]
			if rank[a.Level] != rank[b.Level] {
				return rank[a.Level] < rank[b.Level]
			}
			return naturalLess(a.Key, b.Key)
		})
		if len(g.People) > 0 {
			pp.Groups = append(pp.Groups, *g)
		}
	}
	return pp
}

// notableRow says whether one of a person's events is worth a line of its
// own: High events, events in a detection or flagged, and changes to
// accounts and auditing. Routine Medium events (a USB stick plugged in)
// are on their own pages.
func notableRow(x *Row, inFinding bool) bool {
	if x.Severity == event.SevHigh || inFinding {
		return true
	}
	for _, f := range x.Flags {
		if f == "New device" || f == "First time" || f == "Outside working hours" {
			return true
		}
	}
	return x.Severity == event.SevMedium && (x.Category == event.CatAccount || x.Category == event.CatIntegrity)
}

func initials(name string) string {
	var out []rune
	parts := strings.FieldsFunc(name, func(c rune) bool { return c == '_' || c == '.' || c == '-' || c == ' ' })
	for _, p := range parts {
		if len(out) == 2 {
			break
		}
		out = append(out, []rune(strings.ToUpper(p))[0])
	}
	if len(out) == 1 && len([]rune(name)) > 1 {
		out = append(out, []rune(strings.ToUpper(name))[1])
	}
	return string(out)
}

// notable turns a person's High and Medium events into short lines, the
// same thing on the same system counted once ("… twice").
func (r *Report) notable(rows []*Row) ([]CheckLine, int) {
	type group struct {
		first *Row
		times []string
		n     int
	}
	var order []string
	groups := map[string]*group{}
	for _, x := range rows {
		k := x.Action + "|" + x.Host + "|" + x.Target
		g := groups[k]
		if g == nil {
			g = &group{first: x}
			groups[k] = g
			order = append(order, k)
		}
		g.n++
		if len(g.times) < 3 {
			g.times = append(g.times, x.Time.In(r.Location).Format("15:04"))
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := groups[order[i]].first, groups[order[j]].first
		if a.Severity != b.Severity {
			return a.Severity == event.SevHigh
		}
		return a.Time.Before(b.Time)
	})
	var out []CheckLine
	for _, k := range order {
		if len(out) == 8 {
			break
		}
		g := groups[k]
		x := g.first
		title := strings.TrimSuffix(x.Summary, ".")
		if u := x.User + " "; x.User != "" && strings.HasPrefix(title, u) { // "admin_jd added…" → "Added…"
			title = strings.TrimPrefix(title, u)
			title = strings.ToUpper(title[:1]) + title[1:]
		}
		title += times(g.n)
		when := x.Host + " · " + x.Time.In(r.Location).Format("Mon") + " " + strings.Join(g.times, ", ")
		if g.n > len(g.times) {
			when += " …"
		}
		lv := "warn"
		if x.Severity == event.SevHigh {
			lv = "bad"
		}
		out = append(out, CheckLine{Level: lv, Icon: actionIcon(x.Action), Title: title, What: when, Ev: r.evRef(x)})
	}
	return out, len(order)
}

func actionIcon(a string) string {
	switch {
	case strings.Contains(a, "log_cleared"):
		return "eraser"
	case strings.HasPrefix(a, "group_member"), strings.HasSuffix(a, "_created"):
		return "user-plus"
	case strings.HasPrefix(a, "audit"):
		return "settings"
	case strings.HasPrefix(a, "usb"), strings.HasPrefix(a, "removable"):
		return "usb"
	case strings.HasPrefix(a, "logon"), a == "account_locked":
		return "log-in"
	case strings.HasPrefix(a, "powershell"):
		return "terminal"
	}
	return "triangle-alert"
}

// heatmap draws a week by hour of day, darker for more events and red
// where a detection happened. A red hour shows the person's detections in
// it; any other hour with events opens them in Search.
func heatmap(heat [7][24]int, hot [7][24]bool, person string) template.HTML {
	const w = 360.0
	cw := (w - 40) / 24
	top := 1
	for _, d := range heat {
		for _, v := range d {
			top = max(top, v)
		}
	}
	var b strings.Builder
	for d, day := range []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"} {
		fmt.Fprintf(&b, `<text x="32" y="%d" text-anchor="end" class="ax">%s</text>`, d*18+25, day)
		for h := 0; h < 24; h++ {
			col := "rgba(0,30,98,.04)"
			if v := heat[d][h]; v > 0 {
				// A log scale, so a busy hour does not wash out the rest.
				col = lerpColor(0xEE, 0xF2, 0xFA, 0x0A, 0x2A, 0x7A, 0.15+0.85*math.Log1p(float64(v))/math.Log1p(float64(top)))
			}
			if hot[d][h] {
				col = colBad
			}
			rect := fmt.Sprintf(`<rect x="%.1f" y="%d" width="%.1f" height="15" fill="%s"><title>%s %02d:00 · %d</title></rect>`, 40+float64(h)*cw, d*18+13, cw-2, col, day, h, heat[d][h])
			switch slot := fmt.Sprintf("%d-%d", d, h); {
			case hot[d][h]:
				fmt.Fprintf(&b, `<a href="#" class="hs" data-hslot="%s" data-person="%s">%s</a>`, slot, html.EscapeString(person), rect)
			case heat[d][h] > 0:
				fmt.Fprintf(&b, `<a href="%s" class="hs">%s</a>`, html.EscapeString(searchLink("user", person, "when", "@slot:"+slot)), rect)
			default:
				b.WriteString(rect)
			}
		}
	}
	for h := 0; h < 24; h += 6 {
		fmt.Fprintf(&b, `<text x="%.0f" y="9" class="ax">%02d:00</text>`, 40+float64(h)*cw, h)
	}
	// A group, not an image: its hours are links (UI19).
	return template.HTML(fmt.Sprintf(`<svg viewBox="0 0 %.0f 142" width="100%%" role="group" aria-label="When they were active, by day of the week and hour">%s</svg>`, w, b.String()))
}

func lerpColor(r1, g1, b1, r2, g2, b2 int, t float64) string {
	t = math.Max(0, math.Min(1, t))
	f := func(a, b int) int { return int(math.Round(float64(a) + (float64(b)-float64(a))*t)) }
	return fmt.Sprintf("#%02X%02X%02X", f(r1, r2), f(g1, g2), f(b1, b2))
}
