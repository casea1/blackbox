package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

// The Verified popover, the Export menu's CSV files and the printed
// summary (designs 11–13, 15).

// VerifyLine is one line of the Verified popover.
type VerifyLine struct {
	Text string
	Bad  bool
}

// Verification is what the Verified popover says.
type Verification struct {
	OK    bool
	Lines []VerifyLine
}

func (r *Report) verification() Verification {
	v := Verification{OK: true}
	files := "report.html, summary.json and events.zip"
	if n := len(r.dataSums); n > 0 {
		files += fmt.Sprintf(" (and %d event data files)", n)
	}
	v.Lines = append(v.Lines, VerifyLine{Text: files + " are listed in manifest.sha256"})
	if n := len(r.Archives); n > 0 {
		var size uint64
		bad := 0
		for _, a := range r.Archives {
			size += a.Bytes
			if st, ok := r.archiveState[a.Name]; ok && !st.Verified {
				bad++
			}
		}
		l := VerifyLine{Text: fmt.Sprintf("%s (%s), each checked against the SHA-256 recorded when it was made", plural(n, "original-log zip"), humanBytes(size))}
		if bad > 0 {
			l = VerifyLine{Text: fmt.Sprintf("%d of %d original-log zips do not match the SHA-256 recorded when they were made", bad, n), Bad: true}
			v.OK = false
		}
		v.Lines = append(v.Lines, l)
	}
	switch {
	case r.Interim:
		v.Lines = append(v.Lines, VerifyLine{Text: "A manual report, run by hand; it is not part of the scheduled chain"})
	case len(r.History) == 0:
		v.Lines = append(v.Lines, VerifyLine{Text: "The first scheduled report in this folder"})
	default:
		prev := r.History[len(r.History)-1].WindowEnd
		if prev.Equal(r.WindowStart) || r.WindowStart.IsZero() {
			v.Lines = append(v.Lines, VerifyLine{Text: "Continues from the previous report with no gap (ended " + prev.In(r.Location).Format("2 Jan 15:04") + ")"})
		} else {
			v.Lines = append(v.Lines, VerifyLine{Text: "Does not start where the previous report ended (" + prev.In(r.Location).Format("2 Jan 15:04") + ")", Bad: true})
			v.OK = false
		}
	}
	host, _ := os.Hostname()
	w := "Written by Blackbox " + orDash(r.Version)
	if host != "" {
		w += " on " + host
	}
	v.Lines = append(v.Lines, VerifyLine{Text: w + ", " + r.Generated.In(r.Location).Format("2 Jan 2006 15:04")})
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

// detectionsCSV is the Export menu's detections file, for a POA&M or a
// ticket.
func (r *Report) detectionsCSV() string {
	rows := [][]string{{"severity", "detection", "system", "time", "category", "detail"}}
	for _, c := range r.detectionCards() {
		f := r.Findings[c.Index]
		rows = append(rows, []string{string(f.Severity), f.Title, f.Host, f.Time.In(r.Location).Format("2006-01-02 15:04:05"), string(f.Category), f.Detail})
	}
	return csvText(rows)
}

// healthCSV is every system against every audit settings check.
func (r *Report) healthCSV(hp *HealthPage) string {
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
	return csvText(rows)
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
		if s.Status != "silent" {
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
