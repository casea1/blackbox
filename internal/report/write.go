package report

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/casea1/blackbox/internal/archive"
	"html/template"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// Summary is summary.json: a small machine-readable record of the report,
// used to build the index page.
type Summary struct {
	Site        string         `json:"site,omitempty"`
	Interim     bool           `json:"interim,omitempty"`
	WindowStart time.Time      `json:"window_start,omitzero"`
	WindowEnd   time.Time      `json:"window_end"`
	Generated   time.Time      `json:"generated"`
	Hosts       []string       `json:"hosts"`
	Events      int            `json:"events"`
	High        int            `json:"high"`
	Medium      int            `json:"medium"`
	ByCategory  map[string]int `json:"by_category"`
	Lost        uint64         `json:"events_lost"`
	LogClears   int            `json:"log_clears"`
	AuditOff    int            `json:"audit_off_periods,omitempty"`
	Removed     []string       `json:"removed_reports,omitempty"` // deleted under retention_days since the last report
	Scap        []ScapSummary  `json:"scap,omitempty"`            // STIG compliance from the latest SCAP scans
	Version     string         `json:"blackbox_version"`
	Source      string         `json:"source"`
	Systems     []SystemStatus `json:"systems,omitempty"`
	Detections  []Detection    `json:"detections,omitempty"`
	Archives    []ArchiveJSON  `json:"log_archives,omitempty"`
	// Metrics are the counts the Trends page charts (see metrics.go).
	Metrics map[string]int `json:"metrics,omitempty"`
	// People are per-account counts, for each person's activity over time
	// (see peopletrends.go). Nil in reports made before they were kept.
	People []PersonSummary `json:"people"`
	// Days are the same counts day by day, so trends can add them up by
	// calendar week (see weeks.go). Nil before 0.16.
	Days []DayCounts `json:"days,omitempty"`
	// First marks the first scheduled report, which reads back through
	// the logs from before Blackbox was installed.
	First bool `json:"first,omitempty"`
}

// ArchiveJSON is one archive of original logs in summary.json.
type ArchiveJSON struct {
	Host   string    `json:"host"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	File   string    `json:"file"`
	Bytes  uint64    `json:"bytes"`
	SHA256 string    `json:"sha256"`
	// Gaps are parts a full log had overwritten before it was saved.
	Gaps []archive.Gap `json:"gaps,omitempty"`
	// Logs is what each log actually covers and what it overwrote before
	// it could be exported.
	Logs  []archive.LogCover `json:"logs,omitempty"`
	Notes []string           `json:"notes,omitempty"`
}

// Detection is one detection in summary.json.
type Detection struct {
	Severity string    `json:"severity"`
	Time     time.Time `json:"time"`
	Host     string    `json:"host"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
}

// SystemStatus is one computer's line in summary.json.
type SystemStatus struct {
	Name        string    `json:"name"`
	Status      string    `json:"status"` // ok | warn | silent
	LastRun     time.Time `json:"last_collection,omitzero"`
	Events      int       `json:"events"`
	High        int       `json:"high"`
	ChecksFail  int       `json:"audit_settings_failing"`
	Explanation string    `json:"note,omitempty"`
}

func (r *Report) summary() Summary {
	s := Summary{Site: r.Site, WindowStart: r.WindowStart, WindowEnd: r.WindowEnd,
		Generated: r.Generated, Hosts: r.Hosts, Events: len(r.Events), ByCategory: map[string]int{}, Interim: r.Interim,
		LogClears: r.Health.LogClears, Version: r.Version, Source: r.Source, Metrics: r.metrics(), People: r.peopleTotals(),
		Days: r.days(), First: r.WindowStart.IsZero() && !r.Interim}
	if s.People == nil {
		s.People = []PersonSummary{} // kept, but nobody active: not "before people were kept"
	}
	if s.WindowStart.IsZero() {
		s.WindowStart = r.FirstEvent
	}
	// High counts High detections: every High row is in one (UX6), so
	// counting the rows too counted each twice.
	for _, a := range r.Archives {
		s.Archives = append(s.Archives, ArchiveJSON{Host: a.Host, From: a.From, To: a.To, File: a.Name, Bytes: a.Bytes, SHA256: a.SHA256, Gaps: a.Gaps, Logs: a.Logs, Notes: a.Notes})
	}
	for _, f := range r.Findings {
		s.Detections = append(s.Detections, Detection{Severity: string(f.Severity), Time: f.Time, Host: f.Host, Title: f.Title, Detail: f.Detail})
		if f.Severity == event.SevHigh {
			s.High++
		}
	}
	for _, g := range r.Medium {
		s.Medium += g.Count
	}
	// Counted as the event pages list them: PowerShell has a page of its
	// own, so it has a key of its own and is not under other_security.
	for _, p := range eventPages() {
		key := string(p.Category)
		if p.Category == "" {
			key = p.ID
		}
		s.ByCategory[key] = 0
		for _, e := range r.Events {
			if p.on(e) {
				s.ByCategory[key]++
			}
		}
	}
	for _, g := range r.Health.Gaps {
		s.Lost += g.Lost
	}
	s.AuditOff = len(r.Health.AuditOff)
	s.Removed = r.Removed
	s.Scap = r.scapSummary()
	if r.ShowSystems() {
		for _, sys := range r.SystemRows {
			st := SystemStatus{Name: sys.Name, Status: sys.Status, LastRun: sys.LastRun, Events: sys.Events, High: sys.High, Explanation: sys.StatusMsg}
			if sys.Checks != nil {
				st.ChecksFail = sys.Checks.Fail
			}
			s.Systems = append(s.Systems, st)
		}
	}
	return s
}

// Write creates dir and writes the report, exports and manifest into it,
// moving the original-log zips (r.Archives) in as well.
func (r *Report) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	var manifest strings.Builder
	r.archiveState = map[string]archiveState{}
	for _, a := range r.Archives {
		dst := filepath.Join(dir, a.Name)
		st := archiveState{}
		if a.Path != "" {
			sum, err := copyIn(a.Path, dst)
			if err != nil {
				return fmt.Errorf("add the original logs %s: %w", a.Name, err)
			}
			st.Verified = a.SHA256 != "" && sum == a.SHA256
		} else if sum, err := archive.FileSHA256(dst); err == nil {
			st.Verified = a.SHA256 != "" && sum == a.SHA256
		}
		st.Contents, _ = archive.Contents(dst)
		r.archiveState[a.Name] = st
	}
	// The SCAP results shown, copied in first so the page can link them.
	scapSums, err := r.scapFiles(dir)
	if err != nil {
		return err
	}
	pages, data, err := r.buildData()
	if err != nil {
		return fmt.Errorf("event data: %w", err)
	}
	var html bytes.Buffer
	if err := r.WriteHTML(&html, pages); err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	sum, err := json.MarshalIndent(r.summary(), "", "  ")
	if err != nil {
		return err
	}
	contents := map[string][]byte{
		"report.html":  html.Bytes(),
		"summary.json": append(sum, '\n'),
	}
	if len(data) > 0 {
		if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
			return err
		}
	}
	for _, f := range data {
		contents["data/"+f.Name] = f.Body
	}
	if len(scapSums) > 0 {
		contents["scap-open-rules.csv"] = r.scapCSV()
	}
	contents["README.txt"] = r.readme(scapSums)

	sums := map[string]string{}
	for name, sum := range scapSums {
		sums[name] = sum
	}
	for _, a := range r.Archives {
		if a.Path != "" {
			sums[a.Name] = a.SHA256
		}
	}
	// Every event as a spreadsheet, zipped: CSV of a busy week is large,
	// and Windows opens a zip with a double-click.
	zsum, err := r.writeEventsZip(filepath.Join(dir, "events.zip"))
	if err != nil {
		return fmt.Errorf("events.zip: %w", err)
	}
	sums["events.zip"] = zsum
	for name, b := range contents {
		if err := store.WriteFileAtomic(filepath.Join(dir, name), b, 0o640); err != nil {
			return err
		}
		h := sha256.Sum256(b)
		sums[name] = hex.EncodeToString(h[:])
	}
	names := make([]string, 0, len(sums))
	for name := range sums {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// Same format as sha256sum, so `sha256sum -c` also works.
		fmt.Fprintf(&manifest, "%s  %s\n", sums[name], name)
	}
	return store.WriteFileAtomic(filepath.Join(dir, "manifest.sha256"), []byte(manifest.String()), 0o440)
}

// writeEventsZip writes events.zip (events.csv inside), streaming so a
// large report is not held in memory, and returns its SHA-256.
func (r *Report) writeEventsZip(path string) (string, error) {
	tmp := path + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	zw := zip.NewWriter(io.MultiWriter(f, h))
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "events.csv", Method: zip.Deflate, Modified: r.Generated})
	if err == nil {
		err = r.writeCSV(w)
	}
	if err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (r *Report) writeCSV(w io.Writer) error {
	// A UTF-8 byte order mark makes Excel read accented names correctly.
	w.Write([]byte("\xef\xbb\xbf"))
	cw := csv.NewWriter(w)
	// Times with their offset from UTC, and in UTC too (ASSESS1): the
	// archive names are in UTC.
	cw.Write([]string{"time", "host", "category", "severity", "summary", "user", "target", "source_ip",
		"process", "command", "outcome", "action", "log", "event_id", "record_type", "record_id", "late", "time_utc"})
	for _, e := range r.Events {
		rec, eventID := strconv.FormatUint(e.RecordID, 10), strconv.Itoa(e.EventID)
		if e.RecordID == 0 {
			rec = ""
		}
		if e.EventID == 0 {
			eventID = ""
		}
		cw.Write(csvSafe([]string{e.Time.In(r.Location).Format("2006-01-02 15:04:05 -07:00"), e.Host, e.Category.Info().Title,
			string(e.Severity), e.Summary, e.User, e.Target, e.SourceIP, e.Process, e.Command, e.Outcome,
			e.Action, e.Source, eventID, e.RecordType, rec, map[bool]string{true: "yes", false: ""}[e.Late],
			e.Time.UTC().Format("2006-01-02 15:04:05Z")}))
	}
	cw.Flush()
	return cw.Error()
}

// DirName returns a folder name for a report ending at end: the date and
// time, then the site (network) name when one is set, else the computer
// reported on, or for several the computer that made the report (self),
// e.g. 2026-10-05_0000_Lab-3-LAN.
func DirName(end time.Time, site string, hosts []string, self string, loc *time.Location) string {
	name := end.In(loc).Format("2006-01-02_1504")
	label := cleanName(site)
	switch {
	case label != "":
	case len(hosts) == 1:
		label = cleanName(hosts[0])
	case len(hosts) > 1 && cleanName(self) != "":
		label = cleanName(self)
	case len(hosts) > 1:
		label = fmt.Sprintf("%d-systems", len(hosts))
	}
	if label != "" {
		name += "_" + label
	}
	return name
}

// cleanName is safeName without runs of dashes or dashes at either end:
// "Lab 3 / LAN" → "Lab-3-LAN".
func cleanName(s string) string {
	s = safeName(strings.TrimSpace(s))
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-_")
	if len(s) > 60 {
		s = strings.TrimRight(s[:60], "-_")
	}
	return s
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, s)
}

// UniqueDir returns parent/name, adding -2, -3… if it already exists.
func UniqueDir(parent, name string) string {
	p := filepath.Join(parent, name)
	for i := 2; ; i++ {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p
		}
		p = filepath.Join(parent, fmt.Sprintf("%s-%d", name, i))
	}
}

// Verify re-hashes the files listed in dir/manifest.sha256, and reports
// files missing from it or added since. The manifest is not signed: this
// finds accidental damage and careless edits, not someone who changes a
// file and re-writes its hash (see docs/reports.md). It returns a list of
// problems (empty if everything matches).
func Verify(dir string) ([]string, error) {
	f, err := os.Open(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var problems []string
	n := 0
	listed := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		want, name, ok := strings.Cut(strings.TrimSpace(sc.Text()), "  ")
		if !ok {
			continue
		}
		n++
		listed[name] = true
		// Files are in the report folder, or in its data (event data) or
		// scap (scan results) folder.
		base := strings.TrimPrefix(strings.TrimPrefix(name, "data/"), "scap/")
		if strings.ContainsAny(base, `/\`) || base == ".." || base == "." || base == "" {
			problems = append(problems, fmt.Sprintf("%s: unexpected path in manifest", name))
			continue
		}
		got, err := fileSHA256(filepath.Join(dir, name))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: missing (%v)", name, err))
			continue
		}
		if got != strings.ToLower(want) {
			problems = append(problems, fmt.Sprintf("%s: CHANGED since the report was produced", name))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("manifest.sha256 lists no files")
	}
	// Every file the report needs must be listed: its page, its summary,
	// and (V1) the event data the page loads and events.zip. A manifest
	// without them was cut down or replaced.
	reported := map[string]bool{}
	for _, name := range neededFiles(dir) {
		if listed[name] {
			continue
		}
		reported[name] = true
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			// One line for it, not also "added after the report" (V2).
			problems = append(problems, fmt.Sprintf("%s: not in the manifest, though the report needs it (the manifest was cut down or replaced)", name))
		} else {
			problems = append(problems, fmt.Sprintf("%s: missing, and not in the manifest (the report needs it)", name))
		}
	}
	// A file the manifest doesn't list was added (or renamed) afterwards.
	for _, sub := range []string{"", "data", "scap"} {
		entries, _ := os.ReadDir(filepath.Join(dir, sub))
		for _, e := range entries {
			name := path.Join(sub, e.Name())
			if e.IsDir() || listed[name] || reported[name] || name == "manifest.sha256" || ignoredFile[strings.ToLower(e.Name())] {
				continue
			}
			problems = append(problems, fmt.Sprintf("%s: not in the manifest (added after the report was produced)", name))
		}
	}
	return problems, nil
}

// neededFiles are the files a report can't do without: report.html,
// summary.json, and, for a report that loads its events from data files,
// every one of them and events.zip.
func neededFiles(dir string) []string {
	need := []string{"report.html", "summary.json"}
	b, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		return need
	}
	const open = `<script type="application/json" id="bb-meta">`
	i := bytes.Index(b, []byte(open))
	if i < 0 {
		return need // a report from before data files
	}
	rest := b[i+len(open):]
	j := bytes.Index(rest, []byte("</script>"))
	if j < 0 {
		return need
	}
	var meta struct {
		Sums map[string]string `json:"sums"`
	}
	if json.Unmarshal(rest[:j], &meta) != nil {
		return need
	}
	need = append(need, "events.zip")
	var data []string
	for name := range meta.Sums {
		data = append(data, "data/"+name)
	}
	sort.Strings(data)
	return append(need, data...)
}

// ignoredFile are files Windows and macOS add to folders by themselves.
var ignoredFile = map[string]bool{"desktop.ini": true, "thumbs.db": true, ".ds_store": true}

// IndexEntry is one row on the index page.
type IndexEntry struct {
	Summary
	Dir string
}

// History reads the summaries of the scheduled reports in reportsDir that
// ended before end, oldest first, keeping the last n.
//
// Reports from before day counts were kept (0.16) do not say which was the
// first; the oldest one in the folder is taken to be it.
func History(reportsDir string, end time.Time, n int) []Summary {
	matches, _ := filepath.Glob(filepath.Join(reportsDir, "*", "summary.json"))
	var out []Summary
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var s Summary
		if json.Unmarshal(b, &s) != nil || s.Interim || !s.WindowEnd.Before(end) {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WindowEnd.Before(out[j].WindowEnd) })
	if len(out) > 0 && out[0].Days == nil {
		out[0].First = true
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// HistoryWeeks is how many earlier reports trends read: enough daily
// reports for the weeks the charts show.
const HistoryWeeks = 7 * shownWeeks

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
}

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

// missingRow is a missing scheduled report's line on the index page.
func missingRow(m MissingReport, loc *time.Location) IndexRow {
	r := IndexRow{Week: periodLabel(m.From, m.To, loc), Dir: m.Name, Incomplete: true, TrailClass: "bad", end: m.To,
		Missing: "Missing: deleted or moved"}
	if m.Problem == "changed" {
		r.Missing = "Changed after it was written"
	}
	if m.What != "" {
		r.Missing += ": " + m.What
	}
	r.Trail = r.Missing + " · its original logs were only in it"
	if m.Accepted != "" {
		r.Incomplete, r.TrailClass, r.Accepted = false, "mute", true
		r.Trail = m.Accepted
	}
	r.Search = r.Week + " " + m.Name + " missing"
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
	if e.Lost > 0 {
		bad = append(bad, plural(int(e.Lost), "event")+" lost")
	}
	if e.LogClears > 0 {
		bad = append(bad, plural(e.LogClears, "log")+" cleared")
	}
	if e.AuditOff > 0 {
		bad = append(bad, "auditing was off")
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
	return row
}

// WriteIndex rebuilds reportsDir/index.html from every report's
// summary.json. schedule describes when reports are made.
// missing are the scheduled reports gone or changed, listed in their place.
func WriteIndex(reportsDir, site, schedule string, loc *time.Location, missing []MissingReport) error {
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
		e := IndexEntry{Summary: s, Dir: filepath.Base(filepath.Dir(m))}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].WindowEnd.After(entries[j].WindowEnd) })
	t, err := template.New("index").Funcs(funcs(loc)).Parse(indexTemplate)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	var rows []IndexRow
	incomplete := 0
	for _, e := range entries {
		row := indexRow(e, loc)
		if row.Incomplete {
			incomplete++
		}
		rows = append(rows, row)
	}
	for _, m := range missing {
		row := missingRow(m, loc)
		if row.Incomplete {
			incomplete++
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].end.After(rows[j].end) })
	// Detections per week (UI8): by calendar week, from the scheduled
	// reports only, once there are minWeeks complete weeks.
	chart, weeks := indexChart(entries, loc)
	latest := ""
	for _, r := range rows {
		if r.Missing == "" {
			latest = r.Dir
			break
		}
	}
	err = t.Execute(&buf, map[string]any{"Site": site, "Entries": entries, "Rows": rows, "Incomplete": incomplete, "Latest": latest,
		"Chart": chart, "Weeks": weeks, "Schedule": schedule})
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(filepath.Join(reportsDir, "index.html"), buf.Bytes(), 0o640)
}

// indexChart is the list of reports' "Detections per week": High and
// Medium detections by calendar week, the current week "so far". Manual
// reports never add a bar. Nothing is drawn before minWeeks complete
// weeks. It returns the chart and how many weeks it shows.
func indexChart(entries []IndexEntry, loc *time.Location) (template.HTML, int) {
	var sums []Summary
	for _, e := range entries {
		if !e.Interim {
			sums = append(sums, e.Summary)
		}
	}
	if len(sums) == 0 {
		return "", 0
	}
	sort.Slice(sums, func(i, j int) bool { return sums[i].WindowEnd.Before(sums[j].WindowEnd) })
	if sums[0].Days == nil {
		sums[0].First = true
	}
	ws := buildWeeks(sums[:len(sums)-1], sums[len(sums)-1], loc)
	complete := 0
	for _, w := range ws[:len(ws)-1] {
		if w.Complete {
			complete++
		}
	}
	if complete < minWeeks {
		return "", 0
	}
	var labels []string
	hi, md := Series{Name: "High", Color: colBad}, Series{Name: "Medium", Color: colWarn}
	for _, w := range ws {
		l := WeekLabel(w.Start, loc)
		if w.Current {
			l = "This week (so far)"
		}
		labels = append(labels, l)
		hi.Values, md.Values = append(hi.Values, w.High), append(md.Values, w.Med)
	}
	return stackedBars(labels, []Series{hi, md}, nil, true, 820, 100), len(ws)
}

// fileSHA256 hashes a file in pieces, so large log zips are not read into
// memory.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyIn copies src to dst as a new file, then removes src. It does not
// rename: on Windows a renamed file keeps the permissions of the folder it
// came from (the data folder, Administrators and SYSTEM only), while a new
// file takes the report folder's, like the rest of the report.
func copyIn(src, dst string) (string, error) {
	sum, err := copyFile(src, dst)
	if err != nil {
		return "", err
	}
	return sum, os.Remove(src)
}

// copyFile copies src to dst, leaving src as it is, and returns the
// copy's SHA-256.
func copyFile(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	part := dst + ".partial"
	out, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		os.Remove(part)
		return "", err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(part)
		return "", err
	}
	if err := out.Close(); err != nil {
		os.Remove(part)
		return "", err
	}
	if err := os.Rename(part, dst); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// archiveState is what Write found about one original-log zip.
type archiveState struct {
	Verified bool // its SHA-256 matches the one recorded when it was made
	Contents []archive.Info
}

// Latest is the newest report in reportsDir (scheduled or manual).
func Latest(reportsDir string) (IndexEntry, bool) {
	matches, _ := filepath.Glob(filepath.Join(reportsDir, "*", "summary.json"))
	var best IndexEntry
	found := false
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var s Summary
		if json.Unmarshal(b, &s) != nil {
			continue
		}
		if !found || s.Generated.After(best.Generated) {
			best, found = IndexEntry{Summary: s, Dir: filepath.Dir(m)}, true
		}
	}
	return best, found
}

// readme is README.txt (ASSESS1): for someone who receives only the
// folder, what each file is, how to check it without Blackbox, how to
// open the original logs, and the time zone.
func (r *Report) readme(scap map[string]string) []byte {
	var b strings.Builder
	nl := "\r\n" // read on Windows too
	line := func(format string, args ...any) { b.WriteString(fmt.Sprintf(format, args...) + nl) }
	kind := "Scheduled report"
	if r.Interim {
		kind = "Manual report"
	}
	_, off := r.Generated.In(r.Location).Zone()
	zone := fmt.Sprintf("%s (UTC%s)", r.Location.String(), time.Unix(0, 0).In(time.FixedZone("", off)).Format("-07:00"))
	line("Blackbox %s: %s", r.Version, kind)
	if r.Site != "" {
		line("Site: %s", r.Site)
	}
	line("Period: %s to %s", r.WindowStart.In(r.Location).Format("2006-01-02 15:04"), r.WindowEnd.In(r.Location).Format("2006-01-02 15:04"))
	line("Made: %s", r.Generated.In(r.Location).Format("2006-01-02 15:04"))
	line("Time zone: times in the report and in events.csv are %s; events.csv also has time_utc.", zone)
	line("The original-log archives are named, and their archive.json written, in UTC.")
	line("")
	line("FILES")
	line("  report.html        the report: open it in a web browser (it needs no network)")
	line("  data/              the report's event data, read by report.html")
	line("  summary.json       the counts, for scripts")
	line("  events.zip         events.csv: every event in the report, for a spreadsheet")
	for _, a := range r.Archives {
		line("  %-18s the original logs of %s, unaltered (see below)", a.Name, a.Host)
	}
	if len(scap) > 0 {
		line("  scap-open-rules.csv  the STIG rules SCAP scans found open, and the scan result files")
	}
	line("  manifest.sha256    the SHA-256 of every other file")
	line("")
	line("CHECK THAT NOTHING WAS CHANGED (no Blackbox needed)")
	line("  Linux:    sha256sum -c manifest.sha256")
	line("  Windows:  Get-Content manifest.sha256 | ForEach-Object { $h, $f = $_ -split '  ', 2;")
	line("              if ((Get-FileHash -Algorithm SHA256 $f).Hash -ne $h) { \"CHANGED: $f\" } }")
	line("  Blackbox: blackbox verify <this folder>")
	line("")
	line("OPEN THE ORIGINAL LOGS")
	line("  Unzip logs-<computer>.zip. Each day's logs are in a folder named for its period (UTC),")
	line("  with archive.json listing each file, its SHA-256 and anything missing.")
	line("  Windows .evtx: double-click to open in Event Viewer, or in PowerShell:")
	line("    Get-WinEvent -Path (Get-ChildItem -Recurse *.evtx).FullName")
	line("    (the LocaleMetaData folders let other computers show the messages)")
	line("  Linux audit.log: ausearch -if audit.log   (syslog, auth.log: plain text)")
	return []byte(b.String())
}
