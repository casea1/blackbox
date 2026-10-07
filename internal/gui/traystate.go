package gui

import (
	"fmt"
	"image"
	"image/color"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/app"
	"github.com/casea1/blackbox/internal/brand"
	"github.com/casea1/blackbox/internal/install"
	"github.com/casea1/blackbox/internal/rollover"
)

// trayState is the status icon's colour (SETUP-SPEC.md, "What it shows").
type trayState int

const (
	stateOK      trayState = iota // green: collecting on schedule
	stateLook                     // amber: something to look at
	stateStopped                  // red: collection stopped or failed, or auditing is off
	stateUnknown                  // grey: status can't be read
)

// trayView is what the icon, its tooltip and its menu show.
type trayView struct {
	State   trayState
	Tip     string   // tooltip
	Status  string   // first menu line
	Items   []string // one line per thing to look at
	Report  string   // latest report.html ("" if none)
	Reports string   // reports folder
	Down    bool     // collection has stopped or the last run failed
}

// overdue is how long without a run before collection counts as stopped:
// twice the interval plus 15 minutes.
func overdue(every time.Duration) time.Duration { return 2*every + 15*time.Minute }

func clock(t time.Time) string { return t.Local().Format("15:04") }

// when is a short time: "14:05" today, "Tue 14:05" this week, else "29 Sep".
func when(t, now time.Time) string {
	t, now = t.Local(), now.Local()
	switch {
	case t.YearDay() == now.YearDay() && t.Year() == now.Year():
		return t.Format("15:04")
	case now.Sub(t) < 6*24*time.Hour && t.Before(now):
		return t.Format("Mon 15:04")
	case t.After(now) && t.Sub(now) < 6*24*time.Hour:
		return t.Format("Mon 15:04")
	}
	return t.Format("2 Jan")
}

// nextWhen is when the next report is due: a weekday and time ("Wed
// 00:00"), with the date when it is more than a week away.
func nextWhen(t, now time.Time) string {
	if t.Sub(now) < 8*24*time.Hour {
		return t.Local().Format("Mon 15:04")
	}
	return t.Local().Format("Mon 2 Jan 15:04")
}

// classify turns the state into the icon and menu.
func classify(h app.Health, err error, now time.Time) trayView {
	v := trayView{Reports: h.ReportsDir}
	if h.Latest != nil {
		v.Report = filepath.Join(h.Latest.Dir, "report.html")
	}
	if err != nil {
		v.State, v.Status = stateUnknown, "Status can't be read: "+err.Error()
		v.Tip = "Blackbox: status can't be read"
		return v
	}
	every := strings.TrimPrefix(install.EveryText(h.Every), "every ")
	switch {
	case h.LastCollect.IsZero() && h.LastRun.Time.IsZero():
		v.Status = "Waiting for the first collection"
		v.Tip = "Blackbox: waiting for the first collection"
	case h.LastRun.Error != "" && !h.LastRun.Time.Before(h.LastCollect):
		v.State, v.Down = stateStopped, true
		v.Status = "The last run failed (" + when(h.LastRun.Time, now) + "): " + h.LastRun.Error
		v.Tip = "Blackbox: the last run failed"
	case now.Sub(h.LastCollect) > overdue(h.Every):
		v.State, v.Down = stateStopped, true
		v.Status = "Collection has stopped: last run " + when(h.LastCollect, now)
		v.Tip = "Blackbox: collection has stopped"
	default:
		v.Status = "Collecting every " + every + " · last " + clock(h.LastCollect)
		if h.ReportsDir != "" {
			if h.NextReport.IsZero() {
				v.Status += " · report at the next run"
			} else {
				v.Status += " · next report " + nextWhen(h.NextReport, now)
			}
		}
		v.Tip = "Blackbox: collecting · last " + clock(h.LastCollect)
	}

	// Auditing not running is red: nothing is being recorded.
	var off []string
	for host := range h.AuditOff {
		off = append(off, host)
	}
	sort.Strings(off)
	for _, host := range off {
		v.Items = append(v.Items, "Auditing is off on "+host)
	}
	if len(off) > 0 {
		v.State = stateStopped
		if !v.Down {
			v.Tip = "Blackbox: auditing is off on " + strings.Join(off, ", ")
		}
	}

	// Things to look at, by system name.
	var hosts []string
	for host := range h.AuditGaps {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		v.Items = append(v.Items, fmt.Sprintf("Audit settings: %s to fix on %s", plural(h.AuditGaps[host], "setting"), host))
	}
	for _, host := range h.AVOld {
		v.Items = append(v.Items, "Antivirus definitions out of date on "+host)
	}
	var quiet []string
	for host := range h.Quiet {
		quiet = append(quiet, host)
	}
	sort.Strings(quiet)
	for _, host := range quiet {
		v.Items = append(v.Items, fmt.Sprintf("%s has not sent since %s", host, when(h.Quiet[host], now)))
	}
	for _, l := range h.Lost {
		v.Items = append(v.Items, fmt.Sprintf("%s on %s: %s events overwritten since %s", rollover.Name(l.Channel), l.Host, commaNum(l.Count), when(l.Since, now)))
	}
	if !h.WaitingSince.IsZero() && now.Sub(h.WaitingSince) > app.SendStaleAfter {
		v.Items = append(v.Items, "Data has waited to be sent to the collector since "+when(h.WaitingSince, now))
	}
	if h.LowSpace != "" {
		v.Items = append(v.Items, "Low disk space: "+h.LowSpace)
	}
	if n := len(h.Unreadable); n > 0 {
		v.Items = append(v.Items, fmt.Sprintf("%s in the inbox can't be read", plural(n, "file")))
	}
	if h.Rejected > 0 {
		v.Items = append(v.Items, fmt.Sprintf("%s set aside in the inbox", plural(h.Rejected, "file")))
	}
	if len(v.Items) > 0 && v.State == stateOK {
		v.State = stateLook
		v.Tip += " · " + plural(len(v.Items), "thing") + " to look at"
	}
	if len(v.Tip) > 127 {
		v.Tip = v.Tip[:124] + "..."
	}
	return v
}

func commaNum(n uint64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// trayMemory is what has already been notified, kept per person so each
// notification is shown once.
type trayMemory struct {
	Seen    bool              `json:"seen"`    // the first look has been taken
	Report  string            `json:"report"`  // latest scheduled report notified
	Stopped string            `json:"stopped"` // outage notified (its last run)
	Quiet   map[string]string `json:"quiet"`   // host → last run notified
	Gaps    map[string]bool   `json:"gaps"`    // hosts whose settings didn't match
	Version string            `json:"version"` // version last running
	Lost    string            `json:"lost"`    // report period whose lost events were notified
	Off     map[string]string `json:"off"`     // host → auditing-off reason notified
}

// notice is one notification.
type notice struct {
	Title, Text string
	Warn        bool
	Open        string // report to open when it is clicked
}

// notices works out what to notify, and what to remember. On the first
// look nothing is notified: only what changes after it.
func notices(m trayMemory, h app.Health, v trayView, version string, now time.Time) ([]notice, trayMemory) {
	var out []notice
	next := trayMemory{Seen: true, Report: m.Report, Stopped: m.Stopped, Quiet: map[string]string{}, Gaps: map[string]bool{}, Version: version, Lost: m.Lost,
		Off: map[string]string{}}
	first := !m.Seen

	if m.Version != "" && m.Version != version {
		out = append(out, notice{Title: "Blackbox updated", Text: "Blackbox updated to " + version + "."})
	}

	if l := h.Latest; l != nil && !l.Interim {
		if l.Dir != m.Report && !first {
			kind := "Scheduled"
			if h.ReportEvery != "" {
				kind = strings.ToUpper(h.ReportEvery[:1]) + h.ReportEvery[1:]
			}
			d := len(l.Detections)
			text := kind + " report ready: " + plural(d, "detection")
			high := 0
			for _, x := range l.Detections {
				if x.Severity == "high" {
					high++
				}
			}
			if high > 0 {
				text += fmt.Sprintf(", %d high", high)
			}
			out = append(out, notice{Title: "Blackbox", Text: text + ".", Open: filepath.Join(l.Dir, "report.html")})
		}
		next.Report = l.Dir
	}

	var off []string
	for host := range h.AuditOff {
		off = append(off, host)
	}
	sort.Strings(off)
	for _, host := range off {
		if m.Off[host] != h.AuditOff[host] && !first {
			out = append(out, notice{Title: "Blackbox", Warn: true, Text: fmt.Sprintf("Auditing is off on %s: %s.", host, h.AuditOff[host])})
		}
		next.Off[host] = h.AuditOff[host]
	}

	if v.Down {
		key := h.LastCollect.String() + "|" + h.LastRun.Error
		if key != m.Stopped && !first {
			out = append(out, notice{Title: "Blackbox", Text: v.Status, Warn: true})
		}
		next.Stopped = key
	} else {
		next.Stopped = ""
	}

	for host, last := range h.Quiet {
		key := last.String()
		if m.Quiet[host] != key && !first {
			out = append(out, notice{Title: "Blackbox", Text: fmt.Sprintf("%s has not sent its events since %s.", host, when(last, now)), Warn: true})
		}
		next.Quiet[host] = key
	}

	// Events lost to rollover: once per report period.
	if len(h.Lost) > 0 {
		period := h.PeriodStart.String()
		if m.Lost != period && !first {
			l := h.Lost[0]
			text := fmt.Sprintf("Events are being lost: the %s on %s overwrote %s events before they could be collected: %s.",
				rollover.Name(l.Channel), l.Host, commaNum(l.Count), l.Short())
			if len(h.Lost) > 1 {
				text += fmt.Sprintf(" (%s in all.)", plural(len(h.Lost), "log"))
			}
			out = append(out, notice{Title: "Blackbox", Text: text, Warn: true})
		}
		next.Lost = period
	}

	var hosts []string
	for host := range h.AuditGaps {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		if !m.Gaps[host] && !first {
			out = append(out, notice{Title: "Blackbox", Warn: true,
				Text: fmt.Sprintf("Audit settings on %s no longer match the STIG: %s to fix.", host, plural(h.AuditGaps[host], "setting"))})
		}
		next.Gaps[host] = true
	}
	return out, next
}

// Icon colours.
var (
	dotOK      = color.NRGBA{0x1E, 0x9E, 0x4A, 0xFF}
	dotLook    = color.NRGBA{0xE0, 0x8A, 0x00, 0xFF}
	dotStopped = color.NRGBA{0xD0, 0x2B, 0x2B, 0xFF}
)

// trayImage is the logo with a coloured dot in the corner, or the logo in
// grey when the status can't be read.
func trayImage(size int, s trayState) *image.NRGBA {
	img := brand.Logo(size)
	if s == stateUnknown {
		for i := 0; i < len(img.Pix); i += 4 {
			g := uint8((uint16(img.Pix[i])*30 + uint16(img.Pix[i+1])*59 + uint16(img.Pix[i+2])*11) / 100)
			img.Pix[i], img.Pix[i+1], img.Pix[i+2] = g, g, g
		}
		return img
	}
	dot := map[trayState]color.NRGBA{stateOK: dotOK, stateLook: dotLook, stateStopped: dotStopped}[s]
	r := float64(size) * 0.25 // dot radius
	ring := r + float64(size)*0.06
	cx, cy := float64(size)-r-1, float64(size)-r-1
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			d2 := dx*dx + dy*dy
			switch {
			case d2 <= r*r:
				img.SetNRGBA(x, y, dot)
			case d2 <= ring*ring:
				img.SetNRGBA(x, y, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF})
			}
		}
	}
	return img
}

// noticeQueue shows notifications one after another: Windows shows one at
// a time, and a second sent straight away replaces the first, so several
// found together would hide all but the last.
type noticeQueue struct {
	items   []notice
	showing bool
}

// add queues n and says whether to show it now (nothing is showing).
func (q *noticeQueue) add(n notice) (show bool) {
	if !q.showing {
		q.showing = true
		return true
	}
	q.items = append(q.items, n)
	return false
}

// next is the notification to show when the one showing has had its
// time, if any.
func (q *noticeQueue) next() (notice, bool) {
	if len(q.items) == 0 {
		q.showing = false
		return notice{}, false
	}
	n := q.items[0]
	q.items = q.items[1:]
	return n, true
}
