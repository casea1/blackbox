package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// The Verified popover, the Export menu's CSV files and the printed
// summary (designs 11–13, 15).

// VerifyLine is one check of the Verified pop-up. State is ok, bad (the
// check failed; File names the file to blame) or na (nothing to check,
// e.g. a report with no original logs). File is the line under it.
type VerifyLine struct {
	Text  string
	File  string
	State string
	Bad   bool
}

// Verification is what the Verified pop-up (design 14) and the sidebar's
// report card say: three checks, the failing ones first.
type Verification struct {
	OK    bool
	Title string // "This report has not been changed", or what failed
	Short string // the report card's line: "files match manifest"
	Lines []VerifyLine
	// Written is who wrote the report, where and when.
	Written string
}

// verifiedTitle is the pop-up's title while every check passes.
const verifiedTitle = "This report has not been changed"

func (r *Report) verification() Verification {
	v := Verification{OK: true, Title: verifiedTitle, Short: "files match manifest"}
	// 1. The report's own files. They match when written; the page checks
	// its data files again as it reads them (app.js marks this line).
	files := "report.html, summary.json and events.zip"
	if n := len(r.dataSums); n > 0 {
		files = "report.html, summary.json, events.zip and " + plural(n, "event data file")
	}
	v.Lines = append(v.Lines, VerifyLine{Text: "Report files match the manifest", File: files + ", against manifest.sha256", State: "ok"})
	// 2. The original-log zips, against the SHA-256 recorded when each was made.
	zips := VerifyLine{Text: "No original-log zips in this report", State: "na"}
	if n := len(r.Archives); n > 0 {
		var size uint64
		var bad []string
		for _, a := range r.Archives {
			size += a.Bytes
			if st, ok := r.archiveState[a.Name]; ok && !st.Verified {
				bad = append(bad, a.Name)
			}
		}
		zips = VerifyLine{Text: plural(n, "original-log zip") + " checked", File: humanBytes(size) + ", each against the SHA-256 recorded when it was made", State: "ok"}
		if len(bad) > 0 {
			zips = VerifyLine{Text: fmt.Sprintf("%d of %d original-log zips do not match", len(bad), n),
				File: strings.Join(bad, ", ") + ": not the SHA-256 recorded when made", State: "bad", Bad: true}
			v.OK, v.Title, v.Short = false, "This report's original logs do not match", "a log zip does not match"
		}
	}
	v.Lines = append(v.Lines, zips)
	// 3. The chain of scheduled reports: no gap, none missing (the ledger).
	chain := VerifyLine{State: "ok"}
	switch {
	case r.Interim:
		chain = VerifyLine{Text: "A manual report: not part of the scheduled chain", State: "na"}
	case len(r.History) == 0:
		chain.Text = "The first scheduled report in this folder"
	default:
		prev := r.History[len(r.History)-1].WindowEnd
		if prev.Equal(r.WindowStart) || r.WindowStart.IsZero() {
			chain.Text, chain.File = "No gap since the previous report", "it ended "+prev.In(r.Location).Format("2 Jan 15:04")
		} else {
			chain = VerifyLine{Text: "A gap since the previous report", File: "it ended " + prev.In(r.Location).Format("2 Jan 15:04") +
				"; this one starts " + r.WindowStart.In(r.Location).Format("2 Jan 15:04"), State: "bad", Bad: true}
		}
	}
	if !r.Interim && len(r.MissingReports) > 0 {
		var what []string
		for _, m := range r.MissingReports {
			w := m.What
			if w == "" {
				w = m.Name + " is " + m.Problem
			}
			what = append(what, w)
		}
		chain = VerifyLine{Text: plural(len(r.MissingReports), "earlier report") + " missing or changed", File: strings.Join(what, "; "), State: "bad", Bad: true}
	}
	if chain.Bad {
		if v.OK {
			v.Title, v.Short = "Reports are missing or have a gap", "gap since the previous report"
			if len(r.MissingReports) > 0 {
				v.Short = "earlier reports missing"
			}
		}
		v.OK = false
	}
	v.Lines = append(v.Lines, chain)
	// The failing checks first.
	sort.SliceStable(v.Lines, func(i, j int) bool { return v.Lines[i].Bad && !v.Lines[j].Bad })
	host, _ := os.Hostname()
	v.Written = "Written by Blackbox " + orDash(r.Version)
	if host != "" {
		v.Written += " on " + host
	}
	v.Written += ", " + r.Generated.In(r.Location).Format("2 Jan 2006 15:04") + " " + zoneName(r.Generated, r.Location)
	return v
}

func csvText(rows [][]string) string {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	for _, row := range rows {
		w.Write(csvSafe(row))
	}
	w.Flush()
	return b.String()
}

// csvSafe keeps every field text in a spreadsheet: one starting with
// = + - @, a tab or a return is a formula to Excel, so a logon attempt
// with the user name =HYPERLINK(…) must not become a working link.
func csvSafe(row []string) []string {
	out := make([]string, len(row))
	for i, f := range row {
		if f != "" && strings.ContainsRune("=+-@\t\r", rune(f[0])) {
			f = "'" + f
		}
		out[i] = f
	}
	return out
}

// csvTime is a time in a CSV file: local, with its offset from UTC, so it
// means the same wherever the file is opened (ASSESS1). Empty when unknown.
func (r *Report) csvTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(r.Location).Format("2006-01-02 15:04:05 -07:00")
}

// CSVFile is one CSV the Export menu offers: rows with the header first,
// each field already safe for a spreadsheet (csvSafe). app.js writes it
// with save(); Label and File name it in the menu and on disk.
type CSVFile struct {
	Label string     `json:"label"`
	File  string     `json:"file"`
	Rows  [][]string `json:"rows"`
}

func csvFile(label, file string, rows [][]string) CSVFile {
	out := make([][]string, len(rows))
	for i, row := range rows {
		out[i] = csvSafe(row)
	}
	return CSVFile{Label: label, File: file, Rows: out}
}

// pageCSVs are the Export menu's "This page" files, by view: what each
// page shows, as CSV. The event pages and Search export their tables'
// rows from app.js instead (Table.rows).
func (r *Report) pageCSVs(hp *HealthPage, ip *InventoryPage) map[string]CSVFile {
	m := map[string]CSVFile{
		"detections": csvFile("Detections shown", "detections", r.detectionsRows()),
		"systems":    csvFile("Systems", "systems", r.systemsRows()),
		"trends":     csvFile("Weekly counts", "trends-by-week", r.trendsRows()),
	}
	if hp != nil {
		m["health"] = csvFile("Audit settings, every system", "audit-settings", r.healthRows(hp))
	}
	if ip != nil && len(ip.Rows) > 0 {
		m["inventory"] = csvFile("Systems, drives and accounts", "inventory", r.inventoryRows(ip))
	}
	if len(r.Archives)+len(r.NoArchive) > 0 {
		m["logs"] = csvFile("Original-log zips", "original-logs", r.archiveRows())
	}
	return m
}

// reportCSVs are the Export menu's "Whole report" files made in the page.
func (r *Report) reportCSVs(hp *HealthPage) map[string]CSVFile {
	return map[string]CSVFile{
		"syscsv": csvFile("Systems and drives", "systems-and-drives", r.systemsDrivesRows()),
		"fixcsv": csvFile("Audit settings to fix", "audit-settings-to-fix", r.settingsToFixRows(hp)),
	}
}

// detectionsCSV is the detections file, for a POA&M or a ticket.
func (r *Report) detectionsCSV() string { return csvText(r.detectionsRows()) }

func (r *Report) detectionsRows() [][]string {
	rows := [][]string{{"severity", "detection", "system", "time", "category", "detail"}}
	for _, c := range r.detectionCards() {
		f := r.Findings[c.Index]
		rows = append(rows, []string{string(f.Severity), f.Title, f.Host, r.csvTime(f.Time), string(f.Category), f.Detail})
	}
	return rows
}

// healthCSV is every system against every audit settings check.
func (r *Report) healthCSV(hp *HealthPage) string { return csvText(r.healthRows(hp)) }

func (r *Report) healthRows(hp *HealthPage) [][]string {
	rows := [][]string{{"system", "check", "stig id", "required", "on this system", "result"}}
	if hp != nil {
		for _, g := range hp.Groups {
			for _, row := range g.Rows {
				for _, l := range row.Table {
					rows = append(rows, []string{row.Name, l.Check, strings.Trim(l.STIG, "—"), l.Want, l.Have, l.Result})
				}
			}
		}
	}
	return rows
}

// kindWord is a system kind as a word in a CSV: Server, Workstation,
// Virtual machine.
func kindWord(k string) string {
	for _, t := range kindTitles {
		if t.Kind == k {
			return strings.TrimSuffix(t.Title, "s")
		}
	}
	return k
}

// settingsToFixRows are the audit settings that do not match, every
// system's: what an ISSO hands to whoever fixes them.
func (r *Report) settingsToFixRows(hp *HealthPage) [][]string {
	rows := [][]string{{"system", "role", "check", "stig id", "required", "on this system", "result", "how to fix", "checked"}}
	if hp == nil {
		return rows
	}
	checked := map[string]time.Time{}
	for _, s := range r.SystemRows {
		if s.Checks != nil {
			checked[strings.ToLower(s.Name)] = s.Checks.Time
		}
	}
	for _, g := range hp.Groups {
		for _, row := range g.Rows {
			for _, l := range row.Table {
				if l.Class != "bad" && l.Class != "warn" {
					continue
				}
				rows = append(rows, []string{row.Name, kindWord(r.hostKind(row.Name)), l.Check, strings.Trim(l.STIG, "—"), l.Want, l.Have, l.Result, l.Fix,
					r.csvTime(checked[strings.ToLower(row.Name)])})
			}
		}
	}
	return rows
}

// systemsDrivesRows are every system and its drives, with serial numbers:
// one row per drive (a system with none read has one row).
func (r *Report) systemsDrivesRows() [][]string {
	rows := [][]string{{"system", "role", "operating system", "make and model", "system serial", "drive model", "drive serial", "drive size", "drive type", "inventoried"}}
	for _, s := range r.systemsByKind() {
		base := []string{s.Name, kindWord(systemKind(s)), osLabel(s), "", "", "", "", "", "", ""}
		if s.Checks == nil || s.Checks.Inventory == nil {
			rows = append(rows, base)
			continue
		}
		inv := s.Checks.Inventory
		if inv.OS != "" {
			base[2] = inv.OS
		}
		base[3], base[4], base[9] = strings.TrimSpace(inv.Manufacturer+" "+inv.Model), inv.Serial, r.csvTime(s.Checks.Time)
		if len(inv.Drives) == 0 {
			rows = append(rows, base)
		}
		for _, d := range inv.Drives {
			row := append([]string(nil), base...)
			row[5], row[6], row[7], row[8] = d.Model, d.Serial, driveSize(d.Size), strings.Join(nonEmpty(d.Interface, d.Media), " ")
			rows = append(rows, row)
		}
	}
	return rows
}

// systemsRows are the Systems page's list.
func (r *Report) systemsRows() [][]string {
	rows := [][]string{{"system", "role", "operating system", "status", "note", "events", "high", "last collection", "data via"}}
	for _, s := range r.systemsByKind() {
		rows = append(rows, []string{s.Name, kindWord(systemKind(s)), osLabel(s), s.Status, s.StatusMsg, fmt.Sprint(s.Events), fmt.Sprint(s.High),
			r.csvTime(s.LastRun), s.Via})
	}
	return rows
}

// archiveRows are the Original logs page's zips, and the systems with none.
func (r *Report) archiveRows() [][]string {
	rows := [][]string{{"system", "file", "from", "to", "size bytes", "sha256", "check"}}
	for _, a := range r.Archives {
		check := "not checked"
		if st, ok := r.archiveState[a.Name]; ok {
			check = map[bool]string{true: "matches the SHA-256 recorded when made", false: "does not match"}[st.Verified]
		}
		rows = append(rows, []string{a.Host, a.Name, r.csvTime(a.From), r.csvTime(a.To), fmt.Sprint(a.Bytes), a.SHA256, check})
	}
	for _, h := range r.NoArchive {
		rows = append(rows, []string{h, "", "", "", "", "", "missing"})
	}
	return rows
}

// PrintOut is the printed summary.
type PrintOut struct {
	Kicker, Title, Sub string
	Totals             []Fact
	Detections         []DetectionCard
	Trail              []KV
}

func (r *Report) printOut(o *Overview, hp *HealthPage) PrintOut {
	p := PrintOut{Kicker: "Blackbox · " + strings.Replace(r.Kind(), "report", "audit report", 1)}
	name := r.Site
	if name == "" {
		name = r.MainSystem()
	}
	p.Title = name + " · " + r.PeriodStart().In(r.Location).Format("2 Jan") + " – " + r.WindowEnd.Add(-1).In(r.Location).Format("2 Jan 2006")
	c := r.Crumb()
	if i := strings.Index(c, " · "); i > 0 {
		c = c[i+3:]
	}
	p.Sub = c
	rep := 0
	for _, s := range r.SystemRows {
		if s.reporting() {
			rep++
		}
	}
	total := len(r.SystemRows)
	if total == 0 {
		total, rep = len(r.Hosts), len(r.Hosts)
	}
	settings := "—"
	if hp != nil && len(hp.Stats) > 0 {
		settings = strings.ReplaceAll(hp.Stats[0].Value, " ", "") + " match"
		settings = strings.Replace(settings, "/", " / ", 1)
	}
	p.Totals = []Fact{{Label: "Systems reporting", Value: fmt.Sprintf("%d / %d", rep, total)}, {Label: "Detections", Value: commas(len(r.Findings))},
		{Label: "Events", Value: commas(len(r.Events))}, {Label: "Audit settings", Value: settings}}
	p.Detections = r.detectionCards()
	for _, l := range o.Checks {
		v := l.What
		if l.Who != "" {
			v = l.Who + " " + l.What
		}
		if l.Count != "" {
			v = strings.Replace(l.Count, "/", " of ", 1) + " · " + v
		}
		p.Trail = append(p.Trail, KV{Label: l.Title, Value: v})
	}
	return p
}
