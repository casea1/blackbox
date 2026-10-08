package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// The list of reports, reportsDir/index.html (UI-R1, design 13 A): four
// cards (the latest report, the next, the reports checked by the ledger,
// what is in the folder), then one table of every report grouped by
// month, newest first, with filters and the older reports folded.

// IndexRow is one report's line on the index page.
type IndexRow struct {
	Week, Dir, Trail, TrailClass, Search string
	Systems, Events, High, Medium        int
	Interim, Incomplete                  bool
	// Missing is set for a scheduled report that is gone or changed: the
	// row says so and has nothing to open.
	Missing string
	// Accepted: gone on purpose, recorded with blackbox reports accept.
	Accepted bool
	end      time.Time

	// UI-R1: the row's label ("Wed 7 Oct"), its month ("October 2026"),
	// the systems reporting of all ("28/30"), the original logs' size,
	// notes (what Blackbox works out itself) and the ledger's check.
	Label, Month, SystemsText, Logs, Notes string
	Check, CheckText, CheckTitle           string // ok | bad | mute; "✓ OK", "Changed", "Accepted"; what the ledger found
	Latest, Older                          bool
}

// Problem says whether the row is for the Problems filter: its audit
// trail is incomplete, or the ledger found it changed or missing.
func (r IndexRow) Problem() bool { return r.Incomplete || r.Check == "bad" }

// MissingReport is a scheduled report that was deleted, moved or changed
// after it was written (from the report ledger), and not accepted.
type MissingReport struct {
	Name, Dir string
	From, To  time.Time
	Problem   string // "missing" or "changed"
	// What says which file, e.g. "logs-WS-07.zip is missing" (LEDGER1).
	What string
	// Accepted, on the index only, is who accepted it as gone, when and
	// why: the row stays, muted (LEDGER2).
	Accepted string
}

// LostLogs says whether the problem reaches the period's original logs,
// which are only in the report: the whole folder is gone, or a
// logs-*.zip in it is missing or changed (LEDGER4b). Another file
// (events.zip, report.html) can be made again from the data Blackbox
// keeps.
func (m MissingReport) LostLogs() bool {
	if m.Problem == "missing" {
		return true
	}
	f := strings.Fields(m.What)
	if len(f) == 0 {
		return false
	}
	name := path.Base(f[0])
	return strings.HasPrefix(name, "logs-") && strings.HasSuffix(name, ".zip")
}

// ReportCheck is what the report ledger says about one scheduled report
// still in the folder: State "ok", "changed" or "accepted"; What the file.
type ReportCheck struct {
	State, What string
}

// IndexOptions are what the list of reports needs besides the folder.
type IndexOptions struct {
	Site     string
	Schedule string // "daily at 00:00"
	Every    string // daily | weekly | monthly
	Loc      *time.Location
	// Missing are the scheduled reports gone or changed (and accepted as
	// gone), listed in their place.
	Missing []MissingReport
	// Checks are the ledger's state of each scheduled report in the folder,
	// by folder name; nil when there is no ledger (reports from files).
	Checks map[string]ReportCheck
	Next   time.Time // when the next scheduled report is due
}

// missingRow is a missing scheduled report's line on the index page.
func missingRow(m MissingReport, loc *time.Location) IndexRow {
	r := IndexRow{Week: periodLabel(m.From, m.To, loc), Dir: m.Name, Incomplete: true, TrailClass: "bad", end: m.To,
		Missing: "Missing: deleted or moved", Check: "bad", CheckText: "Missing"}
	if m.Problem == "changed" {
		r.Missing, r.CheckText = "Changed after it was written", "Changed"
	}
	if m.What != "" {
		r.Missing += ": " + m.What
	}
	r.Trail = r.Missing
	if m.LostLogs() {
		r.Trail += " · its original logs were only in it"
	}
	if m.Accepted != "" {
		r.Incomplete, r.TrailClass, r.Accepted = false, "mute", true
		r.Trail = m.Accepted
		r.Check, r.CheckText = "mute", "Accepted"
	}
	r.Search = r.Week + " " + m.Name + " missing"
	r.Label, r.Notes = dayLabel(m.From, m.To, loc), r.Trail
	r.Month = m.To.Add(-time.Second).In(loc).Format("January 2006")
	r.SystemsText, r.Logs = "—", "—"
	return r
}

// periodLabel is a report's period on the index (UI6): one date for one
// whole day ("5 Oct 2026"), times when it starts or ends during a day
// ("5 Oct 00:00 – 06:44", "14 Sep 13:40 – 15 Sep 00:00"), else dates
// ("28 Sep – 4 Oct 2026").
func periodLabel(start, end time.Time, loc *time.Location) string {
	a, z := start.In(loc), end.In(loc)
	b := z.Add(-time.Second)
	midnight := func(t time.Time) bool { return t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 }
	if !midnight(a) || !midnight(z) {
		if a.Year() == z.Year() && a.YearDay() == z.YearDay() {
			return a.Format("2 Jan 15:04") + " – " + z.Format("15:04")
		}
		return a.Format("2 Jan 15:04") + " – " + z.Format("2 Jan 15:04")
	}
	switch {
	case a.Year() == b.Year() && a.YearDay() == b.YearDay():
		return a.Format("2 Jan 2006")
	case a.Year() != b.Year():
		return a.Format("2 Jan 2006") + " – " + b.Format("2 Jan 2006")
	case a.Month() != b.Month():
		return a.Format("2 Jan") + " – " + b.Format("2 Jan 2006")
	}
	return a.Format("2") + " – " + b.Format("2 Jan 2006")
}

// dayLabel is a report's name in the table (UI-R1): "Wed 7 Oct" for one
// whole day, "Wed 7 Oct 00:00 – 14:40" for part of one, else its period
// without the year (the month heading has it).
func dayLabel(start, end time.Time, loc *time.Location) string {
	a, z := start.In(loc), end.In(loc)
	midnight := func(t time.Time) bool { return t.Hour() == 0 && t.Minute() == 0 }
	b := z.Add(-time.Second)
	sameDay := a.Year() == b.Year() && a.YearDay() == b.YearDay()
	switch {
	case sameDay && midnight(a) && midnight(z):
		return a.Format("Mon 2 Jan")
	case a.Year() == z.Year() && a.YearDay() == z.YearDay(), sameDay && midnight(z):
		return a.Format("Mon 2 Jan 15:04") + " – " + z.Format("15:04")
	}
	return strings.TrimSuffix(periodLabel(start, end, loc), " "+b.Format("2006"))
}

// indexRow describes one report: its week and whether its audit trail is
// complete (nothing lost, no log cleared, every system reporting).
func indexRow(e IndexEntry, loc *time.Location) IndexRow {
	start := e.WindowStart
	if start.IsZero() {
		start = e.WindowEnd.AddDate(0, 0, -7)
	}
	week := periodLabel(start, e.WindowEnd, loc)
	row := IndexRow{Week: week, Dir: e.Dir, Systems: len(e.Hosts), Events: e.Events, Interim: e.Interim, end: e.WindowEnd}
	for _, d := range e.Detections { // detections by severity, as in the chart
		if d.Severity == "high" {
			row.High++
		} else {
			row.Medium++
		}
	}
	var bad, warn []string
	if e.LogClears > 0 {
		bad = append(bad, plural(e.LogClears, "log")+" cleared")
	}
	silent := 0
	for _, s := range e.Systems {
		if s.Status == "silent" {
			silent++
		}
	}
	if silent > 0 {
		bad = append(bad, commas(silent)+" silent")
	}
	if e.Lost > 0 {
		bad = append(bad, plural(int(e.Lost), "event")+" lost")
	}
	if e.AuditOff > 0 {
		bad = append(bad, "auditing was off")
	}
	if n := e.Metrics["late_events"]; n > 0 {
		warn = append(warn, commas(n)+" late")
	}
	switch {
	case len(bad) > 0:
		row.Trail, row.TrailClass, row.Incomplete = strings.Join(append(bad, warn...), " · "), "bad", true
	case len(warn) > 0:
		row.Trail, row.TrailClass = strings.Join(warn, " · "), "warn"
	default:
		row.Trail, row.TrailClass = "Complete", "ok"
	}
	row.Search = week + " " + e.Dir + " " + strings.Join(e.Hosts, " ")

	row.Label = dayLabel(start, e.WindowEnd, loc)
	row.Month = e.WindowEnd.Add(-time.Second).In(loc).Format("January 2006")
	if row.TrailClass != "ok" {
		row.Notes = row.Trail
	}
	row.SystemsText = commas(len(e.Hosts))
	if len(e.Systems) > 0 {
		row.SystemsText = fmt.Sprintf("%d/%d", len(e.Systems)-silent, len(e.Systems))
	}
	var logs uint64
	for _, a := range e.Archives {
		logs += a.Bytes
	}
	row.Logs = "—"
	if logs > 0 {
		row.Logs = humanBytes(logs)
	}
	return row
}

// WriteIndex rebuilds reportsDir/index.html from every report's
// summary.json. schedule describes when reports are made.
// missing are the scheduled reports gone or changed, listed in their place.
func WriteIndex(reportsDir, site, schedule string, loc *time.Location, missing []MissingReport) error {
	return WriteIndexWith(reportsDir, IndexOptions{Site: site, Schedule: schedule, Loc: loc, Missing: missing})
}

// indexShown is how many reports the list shows before "Show older".
const indexShown = 20

// IndexCard is one of the four cards above the list.
type IndexCard struct {
	Label, Title, Note, Class, Href string
}

// indexMonth is the reports of one month.
type indexMonth struct {
	Label string
	Rows  []IndexRow
	Older bool // every row of it is older
}

// indexNav is a link of the sidebar, into the latest report.
type indexNav struct {
	Group, Title, Icon, Href string
	Count                    int
}

// WriteIndexWith rebuilds reportsDir/index.html.
func WriteIndexWith(reportsDir string, o IndexOptions) error {
	loc := o.Loc
	if loc == nil {
		loc = time.Local
	}
	matches, err := filepath.Glob(filepath.Join(reportsDir, "*", "summary.json"))
	if err != nil {
		return err
	}
	var entries []IndexEntry
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var s Summary
		if json.Unmarshal(b, &s) != nil {
			continue
		}
		entries = append(entries, IndexEntry{Summary: s, Dir: filepath.Base(filepath.Dir(m))})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].WindowEnd.After(entries[j].WindowEnd) })
	t, err := template.New("index").Funcs(funcs(loc)).Parse(indexTemplate)
	if err != nil {
		return err
	}

	var rows []IndexRow
	byDir := map[string]IndexEntry{}
	ok, changed, accepted, manual := 0, 0, 0, 0
	for _, e := range entries {
		byDir[e.Dir] = e
		row := indexRow(e, loc)
		if e.Interim {
			manual++
		} else if c, in := o.Checks[e.Dir]; in {
			switch c.State {
			case "ok":
				row.Check, row.CheckText = "ok", "✓ OK"
				ok++
			case "accepted":
				row.Check, row.CheckText = "mute", "Accepted"
				accepted++
			default:
				row.Check, row.CheckText, row.CheckTitle = "bad", "Changed", "Changed after it was written"
				if c.What != "" {
					row.CheckTitle += ": " + c.What
				}
				changed++
				if c.What != "" {
					row.Notes = strings.TrimSpace(strings.Join([]string{strings.Replace(c.What, " is missing", " missing", 1), row.Notes}, " · "))
					row.Notes = strings.TrimSuffix(row.Notes, " ·")
				}
			}
		}
		rows = append(rows, row)
	}
	acceptedGone := 0
	for _, m := range o.Missing {
		row := missingRow(m, loc)
		if _, in := byDir[m.Name]; in && m.Accepted == "" {
			// Still in the folder, changed: its own row says so.
			for i := range rows {
				if rows[i].Dir == m.Name && rows[i].Check != "bad" {
					if rows[i].Check == "ok" {
						ok--
					}
					rows[i].Check, rows[i].CheckText, rows[i].CheckTitle = "bad", row.CheckText, row.Trail
					changed++
					if m.What != "" {
						rows[i].Notes = strings.TrimSuffix(strings.Replace(m.What, " is missing", " missing", 1)+" · "+rows[i].Notes, " · ")
					}
				}
			}
			continue
		}
		switch {
		case row.Accepted:
			accepted++
			acceptedGone++
		default:
			changed++
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].end.After(rows[j].end) })

	p := map[string]any{"Site": o.Site, "Schedule": o.Schedule}
	latest := ""
	for i := range rows {
		if rows[i].Missing == "" {
			latest = rows[i].Dir
			rows[i].Latest = true
			break
		}
	}
	p["Latest"] = latest

	// The filters' counts.
	counts := map[string]int{"all": len(rows)}
	for i := range rows {
		r := &rows[i]
		r.Older = i >= indexShown
		if r.Interim {
			counts["manual"]++
		} else {
			counts["scheduled"]++
		}
		if r.High > 0 {
			counts["high"]++
		}
		if r.Problem() {
			counts["problems"]++
		}
	}
	p["Counts"] = counts
	p["Older"] = max(len(rows)-indexShown, 0)
	var months []indexMonth
	for _, r := range rows {
		if len(months) == 0 || months[len(months)-1].Label != r.Month {
			months = append(months, indexMonth{Label: r.Month, Older: true})
		}
		m := &months[len(months)-1]
		m.Rows = append(m.Rows, r)
		m.Older = m.Older && r.Older
	}
	p["Months"] = months
	p["Rows"] = rows

	// The four cards.
	var cards []IndexCard
	if e, found := byDir[latest]; found {
		r := indexRow(e, loc)
		note := "nothing detected"
		if r.High+r.Medium > 0 {
			note = fmt.Sprintf("%d high · %d medium", r.High, r.Medium)
		}
		cards = append(cards, IndexCard{Label: "Latest report", Title: r.Label, Note: note, Href: latest + "/report.html"})
	} else {
		cards = append(cards, IndexCard{Label: "Latest report", Title: "None yet", Note: "The first scheduled report appears here once it has been made."})
	}
	next := IndexCard{Label: "Next report", Title: "—", Note: o.Schedule}
	if !o.Next.IsZero() {
		next.Title = o.Next.In(loc).Format("Mon 2 Jan 15:04")
		next.Note = nextCovers(o.Every, o.Schedule)
	}
	cards = append(cards, next)
	chk := IndexCard{Label: "Reports checked", Title: "Not checked", Class: "mute", Note: "The report ledger starts with the first scheduled report."}
	if o.Checks != nil || len(o.Missing) > 0 {
		var parts []string
		switch {
		case changed > 0:
			chk.Title, chk.Class = fmt.Sprintf("%d changed", changed), "bad"
			parts = append(parts, fmt.Sprintf("%d OK", ok))
		default:
			chk.Title, chk.Class = fmt.Sprintf("All %d OK", ok), "ok"
		}
		if accepted > 0 {
			a := fmt.Sprintf("%d accepted", accepted)
			if acceptedGone == accepted {
				a += " as deleted"
			}
			parts = append(parts, a)
		}
		parts = append(parts, "checked daily")
		chk.Note = strings.Join(parts, " · ")
	}
	cards = append(cards, chk)
	size := folderSize(reportsDir)
	what := []string{}
	if n := len(entries) - manual; n > 0 {
		what = append(what, fmt.Sprintf("%d %s", n, scheduledWord(o.Every)))
	}
	if manual > 0 {
		what = append(what, fmt.Sprintf("%d manual", manual))
	}
	note := strings.Join(what, ", ")
	if size > 0 {
		if note != "" {
			note += " · "
		}
		note += humanBytes(size)
	}
	cards = append(cards, IndexCard{Label: "In this folder", Title: plural(len(entries), "report"), Note: note})
	p["Cards"] = cards

	// The sidebar: the latest report's pages, and its card.
	if e, found := byDir[latest]; found {
		p["Nav"] = indexSideNav(e, latest)
		kind := "Scheduled report"
		switch {
		case e.Interim:
			kind = "Manual report"
		case o.Every != "":
			kind = strings.ToUpper(o.Every[:1]) + o.Every[1:] + " report"
		}
		systems := plural(len(e.Hosts), "system")
		if len(e.Systems) > 0 {
			systems = plural(len(e.Systems), "system")
		}
		card := map[string]string{"Kind": kind, "Period": periodLabel(e.WindowStart, e.WindowEnd, loc) + " " + zoneName(e.WindowEnd, loc),
			"Systems": systems}
		if !e.Generated.IsZero() {
			card["Generated"] = "generated " + e.Generated.In(loc).Format("2 Jan 2006 15:04")
		}
		if c, in := o.Checks[latest]; in && c.State == "ok" {
			card["Check"] = "Checked · files match manifest"
		}
		p["Card"] = card
	}

	// Export list CSV.
	csvRows := [][]string{{"report", "period_start", "period_end", "kind", "notes", "systems", "events", "high", "medium", "original_logs_bytes", "check", "folder"}}
	for _, r := range rows {
		e := byDir[r.Dir]
		kind := "scheduled"
		if r.Interim {
			kind = "manual"
		}
		var logs uint64
		for _, a := range e.Archives {
			logs += a.Bytes
		}
		ps, pe := "", ""
		if r.Missing == "" {
			ps, pe = e.WindowStart.In(loc).Format("2006-01-02 15:04 -07:00"), e.WindowEnd.In(loc).Format("2006-01-02 15:04 -07:00")
		}
		csvRows = append(csvRows, csvSafe([]string{r.Label, ps, pe, kind, r.Notes, r.SystemsText, strconv.Itoa(r.Events), strconv.Itoa(r.High),
			strconv.Itoa(r.Medium), strconv.FormatUint(logs, 10), strings.TrimPrefix(r.CheckText, "✓ "), r.Dir}))
	}
	p["CSV"] = csvRows

	var buf bytes.Buffer
	if err := t.Execute(&buf, p); err != nil {
		return err
	}
	return store.WriteFileAtomic(filepath.Join(reportsDir, "index.html"), buf.Bytes(), 0o640)
}

// nextCovers says what the next scheduled report covers.
func nextCovers(every, schedule string) string {
	switch every {
	case "daily":
		return "daily · each covers the day before"
	case "weekly":
		return "weekly · each covers the week before"
	case "monthly":
		return "monthly · each covers the month before"
	}
	return schedule
}

func scheduledWord(every string) string {
	switch every {
	case "daily", "weekly", "monthly":
		return every
	}
	return "scheduled"
}

// folderSize is the size of every file in the reports folder.
func folderSize(dir string) uint64 {
	var n uint64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += uint64(fi.Size())
			}
		}
		return nil
	})
	return n
}

// indexSideNav are the sidebar's links into the latest report, as the
// report's own sidebar has them, with its counts.
func indexSideNav(e IndexEntry, dir string) []indexNav {
	h := dir + "/report.html#"
	nav := []indexNav{
		{Group: "Review", Title: "Overview", Icon: "layout-dashboard", Href: h + "overview"},
		{Group: "Review", Title: "Detections", Icon: "shield-alert", Href: h + "detections", Count: len(e.Detections)},
		{Group: "Review", Title: "Search", Icon: "search", Href: h + "search"},
		{Group: "Who and what", Title: "Systems", Icon: "server", Href: h + "systems"},
		{Group: "Who and what", Title: "People", Icon: "user-round", Href: h + "people"},
		{Group: "Evidence", Title: "Audit health", Icon: "shield-check", Href: h + "health"},
		{Group: "Evidence", Title: "Original logs", Icon: "scroll-text", Href: h + "logs"},
	}
	for _, pg := range eventPages() {
		key := string(pg.Category)
		if pg.Category == "" {
			key = pg.ID
		}
		if n := e.ByCategory[key]; n > 0 {
			nav = append(nav, indexNav{Group: "Events by kind", Title: pg.Title, Icon: pg.Icon, Href: h + pg.ID, Count: n})
		}
	}
	return append(nav, indexNav{Group: "More", Title: "Inventory", Icon: "cpu", Href: h + "inventory"},
		indexNav{Group: "More", Title: "Trends", Icon: "trending-up", Href: h + "trends"})
}
