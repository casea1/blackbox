package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/scap"
	"github.com/casea1/blackbox/internal/store"
)

// STIG compliance from SCAP scans (docs/design.md, section 13a): the
// latest scan of each computer in the report, next to its audit review.

// ScapRow is one computer and benchmark on the STIG compliance table.
type ScapRow struct {
	Host       string
	Benchmark  string // title, version
	Profile    string
	When       string // scan time
	Age        string // "4 days old"
	Score      string // "94%"
	Pass, Fail int
	Cat        [4]int // open findings by CAT (1-3)
	Change     string // since the previous scan
	Stale      bool   // older than scap_max_age_days
	Missing    bool   // no scan of this computer
	File       string // the result, in the report folder (scap/…)
	Level      string // bad (open CAT I), warn (no scan, stale, or CAT II), ok

	scan *scap.Scan
}

// scapRows builds the STIG compliance table for the computers in the
// report. With no SCAP folder set, there is none.
func (r *Report) scapRows() []ScapRow {
	if !r.ScapEnabled {
		return nil
	}
	hosts := r.Hosts
	if len(r.SystemRows) > 0 {
		hosts = nil
		for _, s := range r.SystemRows {
			hosts = append(hosts, s.Name)
		}
	}
	byHost := map[string][]*scap.Scan{}
	for _, s := range r.Scap {
		k := store.SystemKey(s.Latest.Host)
		byHost[k] = append(byHost[k], s)
	}
	maxAge := time.Duration(r.ScapMaxAgeDays) * 24 * time.Hour
	if maxAge <= 0 {
		maxAge = 30 * 24 * time.Hour
	}
	now := r.WindowEnd
	var rows []ScapRow
	for _, h := range hosts {
		scans := byHost[store.SystemKey(h)]
		if len(scans) == 0 {
			rows = append(rows, ScapRow{Host: h, Missing: true, Level: "warn"})
			continue
		}
		sort.Slice(scans, func(i, j int) bool { return scans[i].Latest.Benchmark < scans[j].Latest.Benchmark })
		for _, s := range scans {
			l := s.Latest
			row := ScapRow{Host: h, Benchmark: strings.TrimSpace(l.Benchmark + " " + l.Version), Profile: l.Profile,
				When: l.When().In(r.Location).Format("2 Jan 2006 15:04"), Pass: l.Counts["pass"],
				Fail: l.Counts["fail"] + l.Counts["error"], Cat: l.OpenByCat(), scan: s, Level: "ok"}
			if l.HasScore {
				row.Score = fmt.Sprintf("%.0f%%", l.Score)
			}
			age := now.Sub(l.When())
			row.Age = roughDuration(age) + " old"
			row.Stale = age > maxAge
			if d, ok := s.Delta(); ok {
				var parts []string
				if n := len(d.NewlyOpen); n > 0 {
					parts = append(parts, fmt.Sprintf("%d newly open", n))
				}
				if n := len(d.NewlyFixed); n > 0 {
					parts = append(parts, fmt.Sprintf("%d fixed", n))
				}
				if d.Score >= 0.5 || d.Score <= -0.5 {
					parts = append(parts, fmt.Sprintf("score %+.0f", d.Score))
				}
				if len(parts) == 0 {
					parts = append(parts, "no change")
				}
				row.Change = strings.Join(parts, ", ") + " since " + s.Previous.When().In(r.Location).Format("2 Jan")
			} else {
				row.Change = "first scan"
			}
			switch {
			case row.Cat[1] > 0:
				row.Level = "bad"
			case row.Stale || row.Cat[2] > 0:
				row.Level = "warn"
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// scapFiles copies the results the table shows into the report folder
// (scap/…), returning their manifest names and hashes.
func (r *Report) scapFiles(dir string) (map[string]string, error) {
	sums := map[string]string{}
	for i := range r.scapTable {
		row := &r.scapTable[i]
		if row.scan == nil {
			continue
		}
		src := row.scan.Latest.File
		name := "scap/" + archiveName(row.Host) + "_" + filepath.Base(src)
		if _, done := sums[name]; done {
			row.File = name
			continue
		}
		if err := os.MkdirAll(filepath.Join(dir, "scap"), 0o750); err != nil {
			return nil, err
		}
		// A copy: the scan results are the site's, and stay where they are.
		sum, err := copyFile(src, filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return nil, fmt.Errorf("add the SCAP result %s: %w", src, err)
		}
		sums[name], row.File = sum, name
	}
	return sums, nil
}

// scapCSV lists every open rule: what an ISSO tracks in a POA&M.
func (r *Report) scapCSV() []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.Write([]string{"system", "benchmark", "cat", "vuln_id", "stig_id", "rule_id", "title", "scan_time"})
	for _, row := range r.scapTable {
		if row.scan == nil {
			continue
		}
		l := row.scan.Latest
		open := append([]scap.Rule(nil), l.Open...)
		sort.SliceStable(open, func(i, j int) bool { return open[i].Cat() < open[j].Cat() })
		for _, o := range open {
			w.Write(csvSafe([]string{row.Host, row.Benchmark, fmt.Sprintf("CAT %s", strings.Repeat("I", o.Cat())), o.VulnID, o.STIGID, o.ID, o.Title,
				l.When().In(r.Location).Format(time.RFC3339)}))
		}
	}
	w.Flush()
	return b.Bytes()
}

// scapCheckLine is the Overview's line: open CAT I findings, stale scans
// and computers never scanned.
func (r *Report) scapCheckLine() (CheckLine, bool) {
	if len(r.scapTable) == 0 {
		return CheckLine{}, false
	}
	var cat1, missing, stale []string
	n1 := 0
	for _, row := range r.scapTable {
		switch {
		case row.Missing:
			missing = append(missing, row.Host)
		case row.Cat[1] > 0:
			n1 += row.Cat[1]
			cat1 = append(cat1, row.Host)
		}
		if row.Stale {
			stale = append(stale, row.Host)
		}
	}
	l := CheckLine{Icon: "shield-check", Title: "STIG compliance (SCAP)", Href: "#health"}
	switch {
	case n1 > 0:
		l.Level, l.Title = "bad", "Open CAT I findings"
		l.What = fmt.Sprintf("%s on %s", plural(n1, "CAT I finding"), strings.Join(uniq(cat1), ", "))
	case len(missing) > 0:
		l.Level, l.What = "warn", "no scan found for "+strings.Join(missing, ", ")
	case len(stale) > 0:
		l.Level, l.What = "warn", "scan older than allowed on "+strings.Join(uniq(stale), ", ")
	default:
		l.Level, l.What = "ok", "no open CAT I findings in the latest scans"
	}
	return l, true
}

func uniq(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// scapLine is a computer's compliance in one line, for its Systems page.
func (r *Report) scapLine(host string) string {
	var parts []string
	for _, row := range r.scapTable {
		if !strings.EqualFold(row.Host, host) {
			continue
		}
		if row.Missing {
			return "SCAP: no scan found"
		}
		p := "SCAP " + row.Score
		if row.Cat[1] > 0 {
			p += fmt.Sprintf(" · %d CAT I", row.Cat[1])
		}
		if row.Stale {
			p += " (stale)"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

// ScapOpenRules counts the open rules in scap-open-rules.csv (the Export
// menu shows the file when there are any scans).
func (r *Report) ScapOpenRules() int {
	n := 0
	for _, row := range r.scapTable {
		if row.scan != nil {
			n += len(row.scan.Latest.Open)
		}
	}
	return n
}

// HasScapScans says whether any computer in the report has a scan.
func (r *Report) HasScapScans() bool {
	for _, row := range r.scapTable {
		if row.scan != nil {
			return true
		}
	}
	return false
}

// ScapSummary is one computer and benchmark in summary.json.
type ScapSummary struct {
	System    string    `json:"system"`
	Benchmark string    `json:"benchmark,omitempty"`
	ScanTime  time.Time `json:"scan_time,omitzero"`
	Score     string    `json:"score,omitempty"`
	OpenCAT1  int       `json:"open_cat_i"`
	OpenCAT2  int       `json:"open_cat_ii"`
	OpenCAT3  int       `json:"open_cat_iii"`
	Stale     bool      `json:"stale,omitempty"`
	NoScan    bool      `json:"no_scan,omitempty"`
}

func (r *Report) scapSummary() []ScapSummary {
	var out []ScapSummary
	for _, row := range r.scapTable {
		s := ScapSummary{System: row.Host, Benchmark: row.Benchmark, Score: row.Score, OpenCAT1: row.Cat[1], OpenCAT2: row.Cat[2],
			OpenCAT3: row.Cat[3], Stale: row.Stale, NoScan: row.Missing}
		if row.scan != nil {
			s.ScanTime = row.scan.Latest.When()
		}
		out = append(out, s)
	}
	return out
}

// ScapOpen is one benchmark's open rules on one system, for its Audit
// health pane (SC3): CAT I first, then by STIG ID.
type ScapOpen struct {
	Benchmark, When string
	Rules           []OpenRule
}

// OpenRule is one open STIG rule.
type OpenRule struct {
	Cat, STIG, Title, RuleID, VulnID string
	Level                            string // bad for CAT I, warn for CAT II, na for CAT III
}

// ScapHref is where a system's open STIG rules are listed.
func ScapHref(host string) string { return "#health/" + host + "/scap" }

func (r *Report) scapOpen(host string) []ScapOpen {
	var out []ScapOpen
	for _, row := range r.scapTable {
		if row.scan == nil || !strings.EqualFold(row.Host, host) {
			continue
		}
		open := append([]scap.Rule(nil), row.scan.Latest.Open...)
		sort.SliceStable(open, func(i, j int) bool {
			if open[i].Cat() != open[j].Cat() {
				return open[i].Cat() < open[j].Cat()
			}
			return open[i].STIGID < open[j].STIGID
		})
		so := ScapOpen{Benchmark: row.Benchmark, When: row.When}
		for _, o := range open {
			so.Rules = append(so.Rules, OpenRule{Cat: "CAT " + strings.Repeat("I", o.Cat()), STIG: o.STIGID, Title: o.Title, RuleID: o.ID, VulnID: o.VulnID,
				Level: [4]string{"", "bad", "warn", "na"}[o.Cat()]})
		}
		out = append(out, so)
	}
	return out
}

// scapSetting is the "STIG compliance (SCAP)" line of a system's settings
// table, linking to its open rules (SC3). ok is false when SCAP results
// are not read.
func (r *Report) scapSetting(host string) (SettingLine, bool) {
	l := SettingLine{Check: "STIG compliance (SCAP)", STIG: "—", Want: "No open CAT I findings, scan current"}
	found := false
	var cat [4]int
	var scores []string
	stale := false
	for _, row := range r.scapTable {
		if !strings.EqualFold(row.Host, host) {
			continue
		}
		found, host = true, row.Host // as the report names it
		if row.Missing {
			l.Have, l.Result, l.Class = "No scan found", "Warning", "warn"
			return l, true
		}
		for c := 1; c <= 3; c++ {
			cat[c] += row.Cat[c]
		}
		if row.Score != "" {
			scores = append(scores, row.Score)
		}
		stale = stale || row.Stale
	}
	if !found {
		return l, false
	}
	l.Have = fmt.Sprintf("%d CAT I, %d CAT II, %d CAT III open", cat[1], cat[2], cat[3])
	if len(scores) > 0 {
		l.Have = "Score " + strings.Join(scores, ", ") + " · " + l.Have
	}
	if stale {
		l.Have += " · stale scan"
	}
	l.Href = ScapHref(host)
	switch {
	case cat[1] > 0:
		l.Result, l.Class = fmt.Sprintf("%d CAT I open", cat[1]), "bad"
	case stale || cat[2] > 0:
		l.Result, l.Class = "Warning", "warn"
	default:
		l.Result, l.Class = "Matches", "ok"
	}
	return l, true
}
