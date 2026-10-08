package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// Where and when (UI-R1 §5): one lane per system a person used, across
// the period, with their sessions as bars and red marks at detections.
// Sessions are built from logon and logoff events: a logon opens one, the
// logoff with the same logon ID (or the next logoff) closes it; a session
// with no logoff in the period ends at the last thing the person did in
// it. Activity outside any session (sudo with no logon in the period, a
// scheduled job) is shown as short bars, events within 20 minutes of each
// other joined.

// Lanes is the chart.
type Lanes struct {
	Rows  []Lane
	Ticks []LaneTick
}

// Lane is one system's row.
type Lane struct {
	Label, Href, Note string
	Segs              []LaneSeg
	Marks             []LaneMark
}

// LaneSeg is a session or a stretch of activity; Left and Width are
// percentages of the period.
type LaneSeg struct {
	Left, Width, Title string
}

// LaneMark is a detection.
type LaneMark struct {
	Left, Title, Href, Level string
}

// LaneTick is a label under the chart.
type LaneTick struct {
	Left, Label string
}

// laneEvent is one event in a person's lanes: their own (own) or one
// acting as the account (sudo by someone else, on a shared account's
// page); finds are the detections it is part of.
type laneEvent struct {
	row   *Row
	own   bool
	finds []int
}

type span struct {
	from, to time.Time
	what     string
}

// maxLanes is how many systems get a lane of their own; the rest share
// one ("… 11 more").
const maxLanes = 6

func (r *Report) lanes(p *personData, ps, pe time.Time) *Lanes {
	byHost := map[string][]laneEvent{}
	for _, le := range p.lane {
		byHost[le.row.Host] = append(byHost[le.row.Host], le)
	}
	if len(byHost) == 0 {
		return nil
	}
	type hostLane struct {
		host  string
		spans []span
		marks map[int]time.Time
		n     int
	}
	var hl []*hostLane
	for h, evs := range byHost {
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].row.Time.Before(evs[j].row.Time) })
		x := &hostLane{host: h, marks: map[int]time.Time{}, n: len(evs)}
		x.spans = sessions(evs)
		for _, le := range evs {
			for _, fi := range le.finds {
				if t, ok := x.marks[fi]; !ok || le.row.Time.Before(t) {
					x.marks[fi] = le.row.Time
				}
			}
		}
		hl = append(hl, x)
	}
	sort.Slice(hl, func(i, j int) bool {
		a, b := hl[i], hl[j]
		if (len(a.marks) > 0) != (len(b.marks) > 0) {
			return len(a.marks) > 0
		}
		if a.n != b.n {
			return a.n > b.n
		}
		return naturalLess(a.host, b.host)
	})
	total := pe.Sub(ps).Seconds()
	pct := func(t time.Time) float64 {
		v := t.Sub(ps).Seconds() / total * 100
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	}
	lane := func(label, href string, spans []span, marks map[int]time.Time) Lane {
		l := Lane{Label: label, Href: href}
		sort.Slice(spans, func(i, j int) bool { return spans[i].from.Before(spans[j].from) })
		sessionsN := 0
		for _, s := range spans {
			if s.to.Before(ps) || s.from.After(pe) {
				continue
			}
			left := pct(s.from)
			w := pct(s.to) - left
			if w < 0.6 {
				w = 0.6
			}
			if left+w > 100 {
				left = 100 - w
			}
			title := s.what + " " + r.shortTime(s.from, ps, pe)
			if s.to.Sub(s.from) >= time.Minute {
				title += "–" + r.shortTime(s.to, ps, pe)
			}
			if s.what == "Session" {
				sessionsN++
			}
			l.Segs = append(l.Segs, LaneSeg{Left: fmt.Sprintf("%.2f", left), Width: fmt.Sprintf("%.2f", w), Title: title})
		}
		fis := make([]int, 0, len(marks))
		for fi := range marks {
			fis = append(fis, fi)
		}
		sort.Ints(fis)
		for _, fi := range fis {
			t := marks[fi]
			f := r.Findings[fi]
			lv := "warn"
			if f.Severity == event.SevHigh {
				lv = "bad"
			}
			l.Marks = append(l.Marks, LaneMark{Left: fmt.Sprintf("%.2f", pct(t)), Href: fmt.Sprintf("#detections/%d", fi), Level: lv,
				Title: f.Title + " · " + r.shortTime(t, ps, pe)})
		}
		var note []string
		if sessionsN > 0 {
			note = append(note, plural(sessionsN, "session"))
		}
		if n := len(spans) - sessionsN; n > 0 {
			note = append(note, map[bool]string{true: "1 stretch", false: commas(n) + " stretches"}[n == 1]+" of activity")
		}
		if len(l.Marks) > 0 {
			note = append(note, plural(len(l.Marks), "detection"))
		}
		l.Note = label + ": " + strings.Join(note, ", ")
		return l
	}
	out := &Lanes{}
	for i, x := range hl {
		if i == maxLanes && len(hl) > maxLanes+1 {
			var spans []span
			marks := map[int]time.Time{}
			for _, y := range hl[i:] {
				spans = append(spans, y.spans...)
				for fi, t := range y.marks {
					marks[fi] = t
				}
			}
			out.Rows = append(out.Rows, lane(fmt.Sprintf("… %d more", len(hl)-i), searchLink("user", p.key), spans, marks))
			break
		}
		out.Rows = append(out.Rows, lane(x.host, searchLink("user", p.key, "host", x.host), x.spans, x.marks))
	}
	out.Ticks = r.laneTicks(ps, pe, pct)
	return out
}

// sessions builds one system's sessions and stretches of activity from a
// person's events there, in time order.
func sessions(evs []laneEvent) []span {
	type ses struct {
		span
		id     string
		closed bool
	}
	var all []*ses
	open := map[string]*ses{}
	var cur *ses
	var acts []time.Time
	for _, le := range evs {
		e := le.row.Event
		id := strings.ToLower(detail(e, "Logon ID"))
		switch {
		case le.own && e.Category == event.CatLogon && e.Action == "logon":
			s := &ses{span: span{from: e.Time, to: e.Time, what: "Session"}, id: id}
			if logonWay(e) == "job" || logonWay(e) == "service" {
				s.what = "Job"
			}
			all = append(all, s)
			open[id] = s
			cur = s
		case le.own && e.Category == event.CatLogon && e.Action == "logoff":
			s := open[id]
			if s == nil && id != "" {
				s = open[""]
			}
			if s == nil && id == "" {
				s = cur
			}
			if s != nil && !s.closed {
				s.to, s.closed = e.Time, true
				delete(open, s.id)
				if cur == s {
					cur = nil
				}
			}
		default:
			if cur != nil && !cur.closed {
				cur.to = e.Time
			} else {
				acts = append(acts, e.Time)
			}
		}
	}
	var out []span
	for _, s := range all {
		out = append(out, s.span)
	}
	// Activity outside sessions: events within 20 minutes joined.
	for i := 0; i < len(acts); {
		j := i
		for j+1 < len(acts) && acts[j+1].Sub(acts[j]) <= 20*time.Minute {
			j++
		}
		out = append(out, span{from: acts[i], to: acts[j], what: "Activity"})
		i = j + 1
	}
	return out
}

// laneTicks label the chart's time axis: every six hours in a one-day
// period ("00:00 … 24:00"), each day in a week, else five dates.
func (r *Report) laneTicks(ps, pe time.Time, pct func(time.Time) float64) []LaneTick {
	var out []LaneTick
	d := pe.Sub(ps)
	switch {
	case d <= 26*time.Hour:
		step := 6 * time.Hour
		if d <= 8*time.Hour {
			step = 2 * time.Hour
		}
		start := ps.In(r.Location).Truncate(time.Hour)
		for t := start; !t.After(pe); t = t.Add(step) {
			if t.Before(ps) {
				continue
			}
			lb := t.In(r.Location).Format("15:04")
			if t.Equal(pe) && lb == "00:00" {
				lb = "24:00"
			}
			out = append(out, LaneTick{Left: fmt.Sprintf("%.2f", pct(t)), Label: lb})
		}
	case d <= 8*24*time.Hour:
		lt := ps.In(r.Location)
		day := time.Date(lt.Year(), lt.Month(), lt.Day(), 0, 0, 0, 0, r.Location)
		for t := day; t.Before(pe); t = t.AddDate(0, 0, 1) {
			if t.Before(ps) {
				continue
			}
			out = append(out, LaneTick{Left: fmt.Sprintf("%.2f", pct(t)), Label: t.Format("Mon 2")})
		}
	default:
		for i := 0; i <= 4; i++ {
			t := ps.Add(time.Duration(float64(d) * float64(i) / 4))
			out = append(out, LaneTick{Left: fmt.Sprintf("%.2f", pct(t)), Label: t.In(r.Location).Format("2 Jan")})
		}
	}
	return out
}
