package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/casea1/blackbox/internal/brand"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

//go:embed template.html
var reportTemplate string

//go:embed index.html
var indexTemplate string

//go:embed style.css
var styleCSS string

//go:embed app.js
var appJS string

// pageData is what the report template is rendered from. Section is set
// while rendering one category's view.
type pageData struct {
	*Report
	Section     *Section
	Pages       []*EventPage
	Overview    *Overview
	Detections  []DetectionView
	SystemsPage *SystemsPage
	PeoplePage  *PeoplePage
	HealthPage  *HealthPage
	TrendsPage  *TrendsPage
	LogsPage    *LogsPage
	Inventory   *InventoryPage
	Verify      Verification
	Print       PrintOut
	Meta        template.JS // settings for app.js, as JSON
}

// headData is a page's heading.
type headData struct {
	Crumb, Title, Range string
	Index               bool // the date range links to the list of all reports
	// Manual is the chip by the title of a page after the Overview in a
	// manual report ("Manual", "Chosen period").
	Manual string
}

// periodNoun is "week" for a report that covers about a week on a weekly
// schedule, else "period": a one-day manual report is not a week (UI18).
func (r *Report) periodNoun() string {
	span := r.WindowEnd.Sub(r.PeriodStart())
	if (r.Period == "weekly" || r.Period == "") && (r.WindowEnd.IsZero() || span >= 6*24*time.Hour && span <= 8*24*time.Hour) {
		return "week"
	}
	return "period"
}

func overviewTitleOf(p pageData) string {
	if p.IsLAN() && !p.Overview.Standalone {
		return "Network overview"
	}
	return "Overview"
}

// IsLAN says whether this is a network report (a collector's, or more
// than three computers); otherwise it is a standalone computer's, with
// any virtual machines on it.
func (r *Report) IsLAN() bool { return r.Collector || len(r.Hosts) > 3 }

// MainSystem is a standalone report's computer (not its VMs), or the
// collector: a computer whose data did not come through another one, and
// that reported (not a silent one listed first).
func (r *Report) MainSystem() string {
	for _, s := range r.SystemRows {
		if !s.VM && s.Via == "" && s.reporting() {
			return s.Name
		}
	}
	for _, s := range r.SystemRows {
		if !s.VM && s.Via == "" {
			return s.Name
		}
	}
	for _, s := range r.SystemRows {
		if !s.VM {
			return s.Name
		}
	}
	if len(r.Hosts) > 0 {
		return r.Hosts[0]
	}
	return ""
}

// PeriodStart is the start of the report period (the oldest event on a
// first report).
func (r *Report) PeriodStart() time.Time {
	if r.WindowStart.IsZero() {
		return r.FirstEvent
	}
	return r.WindowStart
}

func funcs(loc *time.Location) template.FuncMap {
	if loc == nil {
		loc = time.Local
	}
	format := func(layout string) func(time.Time) string {
		return func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.In(loc).Format(layout)
		}
	}
	return template.FuncMap{
		"scapHref": ScapHref,
		"logo":     func() template.URL { return template.URL(brand.LogoDataURI()) },
		"css":      func() template.CSS { return template.CSS(styleCSS) },
		"js":       func() template.JS { return template.JS(appJS) },
		"icon":     icon,
		"lower":    strings.ToLower,
		"minus":    func(a, b int) int { return a - b },
		"gridCols": gridCols,
		"css2":     func(s string) template.CSS { return template.CSS(s) },
		// avOK counts the antivirus rows that are current, folded under a
		// button when others need attention.
		"sub": func(a, b int) int { return a - b },
		"avOK": func(rows []AVRow) int {
			n := 0
			for _, a := range rows {
				if a.Level == "ok" {
					n++
				}
			}
			return n
		},
		"plural": func(n int, unit string) string {
			if n == 1 {
				return unit
			}
			return unit + "s"
		},
		"overviewTitle": overviewTitleOf,
		"dayBefore":     func(ds []DetectionCard, i int) string { return ds[i-1].Day },
		"healthCrumb": func(p pageData) string {
			return p.Kind() + " · audit settings compared with the STIG for each system's OS · Blackbox only reports, it never changes settings"
		},
		"searchCrumb": func(p pageData) string {
			return fmt.Sprintf("%s · %s events from %s · searched in your browser, nothing leaves this report", p.Kind(), commas(len(p.Events)), plural(len(p.Hosts), "system"))
		},
		"searchCols": func() template.CSS { return gridCols(searchCols) },
		"periodDays": func(p pageData) []string { return p.periodDays() },
		"periodWord": func(p pageData) string {
			if p.periodNoun() == "week" {
				return "Week"
			}
			return "Period"
		},
		"dayName": func(d string) string {
			t, _ := time.Parse("20060102", d)
			return t.Format("Mon 2 Jan")
		},
		"peopleCrumb": func(p pageData) string {
			n := 0
			if p.PeoplePage != nil {
				n = p.PeoplePage.Count
			}
			return fmt.Sprintf("%s · %s active on %s", p.Kind(), plural(n, "account"), plural(len(p.Hosts), "system"))
		},
		"detectionsCrumb": func(p pageData) string {
			high, med := 0, 0
			for _, d := range p.Detections {
				if d.Severity == "high" {
					high++
				} else {
					med++
				}
			}
			n := len(p.Detections)
			c := p.Crumb()
			c = c[:strings.LastIndex(c, " · generated")]
			s := fmt.Sprintf("%s · %s %s", c, commas(n), map[bool]string{true: "detection", false: "detections"}[n == 1])
			if n > 0 {
				s += fmt.Sprintf(" · %d high, %d medium", high, med)
			}
			return s
		},
		"sevCount": func(ds []DetectionView, sev string) int {
			n := 0
			for _, d := range ds {
				if d.Severity == sev {
					n++
				}
			}
			return n
		},
		"detDayBefore": func(ds []DetectionView, i int) string { return ds[i-1].Day },
		"eventsCrumb": func(p pageData, e *EventPage) string {
			unit := "events"
			if spec, ok := pageSpecs[e.ID]; ok {
				unit = spec.unit
			}
			if e.Total == 1 {
				unit = strings.TrimSuffix(unit, "s")
			}
			s := fmt.Sprintf("%s · Events · %s %s", p.Kind(), commas(e.Total), unit)
			if n := len(e.Hosts); n > 1 {
				s += fmt.Sprintf(" on %d systems", n)
			} else if n == 1 {
				s += " on " + e.Hosts[0]
			}
			return s
		},
		// head builds a page heading: the report period and, unless crumb
		// is given, a line describing the report.
		"head": func(p pageData, title, crumb string) headData {
			if crumb == "" {
				crumb = p.Crumb()
			}
			rng := p.PeriodStart().In(loc).Format("2 Jan") + " – " + p.WindowEnd.In(loc).Format("2 Jan 2006")
			if l := periodLabel(p.PeriodStart(), p.WindowEnd, loc); strings.Contains(l, ":") {
				rng = l // a period that starts or ends during a day: "7 Oct 00:00 – 12:30" (UI6)
			}
			h := headData{Crumb: crumb, Title: title, Range: rng, Index: p.InReportsDir}
			// After the Overview, a manual report says so in a chip by the
			// title, not the banner again (UX9).
			if title != overviewTitleOf(p) {
				switch {
				case p.Range != "":
					h.Manual = "Chosen period"
				case p.Interim:
					h.Manual = "Manual"
				}
			}
			return h
		},
		"brandName": func() string { return brand.Name },
		"fontCSS":   func() template.CSS { return template.CSS(brand.FontCSS()) },
		"stamp":     format("02 Jan 2006 15:04"),
		"stampSec":  format("02 Jan 2006 15:04:05"),
		"dateLong":  format("Mon 02 Jan 2006"),
		"dateShort": format("02 Jan 2006"),
		"clock":     format("15:04"),
		"zone": func(t time.Time) string {
			name, _ := t.In(loc).Zone()
			return name
		},
		"length": func(a, b time.Time) string {
			if a.IsZero() || b.IsZero() {
				return "—"
			}
			d := b.Sub(a).Round(time.Minute)
			days, hours, mins := int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60
			var parts []string
			if days > 0 {
				parts = append(parts, plural(days, "day"))
			}
			if hours > 0 {
				parts = append(parts, plural(hours, "hour"))
			}
			if mins > 0 && days == 0 {
				parts = append(parts, plural(mins, "minute"))
			}
			if len(parts) == 0 {
				return "under a minute"
			}
			return strings.Join(parts, " ")
		},
		"commas": func(v any) string {
			switch n := v.(type) {
			case int:
				return commas(n)
			case uint64:
				return commas(n)
			}
			return fmt.Sprint(v)
		},
		"join": strings.Join,
		"dur":  roughDuration,
		"pct":  func(p float64) string { return fmt.Sprintf("%.1f%%", p) },
		"add":  func(a, b int) int { return a + b },
		"bytes": func(b uint64) string {
			if b >= 1<<30 {
				return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
			}
			return fmt.Sprintf("%d MB", b>>20)
		},
		"sevRank":  func(s event.Severity) int { return s.Rank() },
		"catTitle": func(c event.Category) string { return c.Info().Title },
		"mediumTotal": func(gs []AttentionGroup) string {
			n := 0
			for _, g := range gs {
				n += g.Count
			}
			return commas(n)
		},
		// href links to a view of the report, or to one row in it.
		"href": func(p pageData, view any, anchor string) string {
			if anchor != "" {
				return "#" + anchor
			}
			return "#" + fmt.Sprint(view)
		},
		"withSection": func(p pageData, s *Section) pageData {
			p.Section = s
			return p
		},
	}
}

func plural(n int, unit string) string {
	switch {
	case n == 1:
		return "1 " + unit
	case n < 0:
		return fmt.Sprintf("%d %ss", n, unit)
	}
	return commas(n) + " " + unit + "s" // 95,229 events, as everywhere (UI6)
}

// Crumb is the line above each page title, e.g. "Weekly report · 24
// systems · generated 29 Sep 2026 00:05".
func (r *Report) Crumb() string {
	parts := []string{r.Kind()}
	if r.IsLAN() {
		parts = append(parts, fmt.Sprintf("%d systems", len(r.Hosts)))
	} else {
		vms := 0
		for _, s := range r.SystemRows {
			if s.VM {
				vms++
			}
		}
		desc := "standalone · 1 system"
		if vms > 0 {
			desc += fmt.Sprintf(" + %d VM", vms)
			if vms > 1 {
				desc += "s"
			}
		}
		parts = append(parts, desc)
	}
	parts = append(parts, "generated "+r.Generated.In(r.Location).Format("2 Jan 2006 15:04"))
	return strings.Join(parts, " · ")
}

// Kind is "Weekly report", "Manual report" or "Report".
func (r *Report) Kind() string {
	switch {
	case r.Interim:
		return "Manual report"
	case r.Period != "":
		return strings.ToUpper(r.Period[:1]) + r.Period[1:] + " report"
	}
	return "Report"
}

// WriteHTML renders report.html. The event pages read their events from
// the data files given (see buildData), which go in the data folder.
func (r *Report) WriteHTML(w io.Writer, pages []*EventPage) error {
	t, err := template.New("report").Funcs(funcs(r.Location)).Parse(reportTemplate)
	if err != nil {
		return err
	}
	_, zoneOff := r.Generated.In(r.Location).Zone()
	meta := map[string]any{"pages": pages, "zone": zoneName(r.Generated, r.Location), "zoneOff": zoneOff}
	// For the event panel: which detection an event is part of, each
	// system's original-log zip and what it runs.
	rowDet, dets := map[int]int{}, []string{}
	for fi, f := range r.Findings {
		dets = append(dets, f.Title)
		for _, id := range append(f.RowIDs, f.RowID) {
			if i := rowIndex(id); i >= 0 {
				if _, ok := rowDet[i]; !ok {
					rowDet[i] = fi
				}
			}
		}
	}
	archives, oses := map[string]string{}, map[string]string{}
	for _, a := range r.Archives {
		archives[a.Host] = a.Name
	}
	for _, sr := range r.SystemRows {
		oses[sr.Name] = osLabel(sr)
	}
	meta["rowdet"], meta["dets"], meta["archives"], meta["os"] = rowDet, dets, archives, oses
	icons := map[string]string{}
	for _, n := range []string{"search", "user-round", "server", "shield"} {
		icons[n] = string(icon(n, 15))
	}
	meta["icons"] = icons
	kinds := map[string]string{}
	for _, sr := range r.SystemRows {
		switch {
		case sr.VM:
			kinds[sr.Name] = "vm"
		case isServer(sr):
			kinds[sr.Name] = "server"
		default:
			kinds[sr.Name] = "workstation"
		}
	}
	meta["hostKind"] = kinds
	if w := r.WorkingHours; w.Set() {
		meta["hours"] = map[string]any{"days": w.Days, "start": w.Start, "end": w.End}
	}
	people := r.peoplePage()
	if pp := people; pp != nil && len(pp.Groups) > 0 && len(pp.Groups[0].People) > 0 {
		meta["firstPerson"] = pp.Groups[0].People[0].Key
	}
	health, overview := r.healthPage(), r.overview(pages)
	inv := r.inventoryPage()
	meta["detcsv"], meta["healthcsv"], meta["sums"] = r.detectionsCSV(), r.healthCSV(health), r.dataSums
	meta["invcsv"] = r.inventoryCSV(inv)
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return t.ExecuteTemplate(w, "layout", pageData{Report: r, Pages: pages, Overview: overview,
		Detections: r.detectionViews(), SystemsPage: r.systemsPage(), PeoplePage: people, HealthPage: health, TrendsPage: r.trendsPage(),
		LogsPage: r.logsPage(), Inventory: inv, Verify: r.verification(), Print: r.printOut(overview, health), Meta: template.JS(b)})
}

func zoneName(t time.Time, loc *time.Location) string {
	name, _ := t.In(loc).Zone()
	return name
}
