// Package scap reads SCAP scan results (XCCDF 1.1 and 1.2 TestResults,
// on their own or inside an ARF report) so a report can show each
// computer's STIG compliance next to its audit review. It only reads
// results that already exist: it never runs a scanner and never changes
// anything (docs/design.md, section 13a).
package scap

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// refXML is a rule's <reference> or <ident>.
type refXML struct {
	Href   string `xml:"href,attr"`
	System string `xml:"system,attr"`
	Text   string `xml:",chardata"`
}

// disa reports whether the reference points at a DISA STIG (cyber.mil,
// formerly iase.disa.mil).
func (r refXML) disa() bool {
	src := strings.ToLower(r.Href + " " + r.System)
	return strings.Contains(src, "cyber.mil") || strings.Contains(src, "disa.mil")
}

var (
	// stigIDRE is a STIG ID: UBTU-24-300028, WN11-CC-000005, RHEL-08-010010,
	// APSC-DV-000010 (not an SRG ID, SRG-OS-000004-GPOS-00004).
	stigIDRE = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[A-Z0-9]{2,3}-\d{6}$`)
	// vulnOnlyRE is a vulnerability ID on its own: V-253254.
	vulnOnlyRE = regexp.MustCompile(`^V-\d+$`)
)

// Rule is one rule of the benchmark.
type Rule struct {
	ID       string // e.g. xccdf_mil.disa.stig_rule_SV-253254r991589_rule
	VulnID   string // V-253254, from the rule's group
	STIGID   string // WN11-00-000005 (the rule's version)
	Title    string
	Severity string // high, medium, low
	// FixText is the benchmark's fix for the rule, in words, and Script
	// a shell or PowerShell fix script it gives (OpenSCAP content), when
	// it is complete as written; ScriptLang is "sh" or "powershell".
	FixText, Script, ScriptLang string
}

// Cat is a rule's STIG category: 1 for high, 2 for medium, 3 for low.
func (r Rule) Cat() int {
	switch strings.ToLower(r.Severity) {
	case "high":
		return 1
	case "low":
		return 3
	}
	return 2
}

// Result is one scan of one computer against one benchmark.
type Result struct {
	File   string // where it was read from
	SHA256 string

	Host        string // the scanned computer, short name
	Benchmark   string // title
	BenchmarkID string
	Version     string // version and release, e.g. "V2R8"
	Profile     string // profile title (or ID)
	Start, End  time.Time
	Score       float64 // percent
	HasScore    bool

	// Counts are rule results by outcome: pass, fail, error,
	// notapplicable, notchecked, notselected, informational, fixed, unknown.
	Counts map[string]int
	Open   []Rule // fail or error, the findings still open
}

// When is the scan's time.
func (r *Result) When() time.Time {
	if !r.End.IsZero() {
		return r.End
	}
	return r.Start
}

// OpenByCat counts open findings by CAT (index 1-3).
func (r *Result) OpenByCat() [4]int {
	var n [4]int
	for _, o := range r.Open {
		n[o.Cat()]++
	}
	return n
}

// open says whether a rule result is a finding still open, as STIG Viewer
// and SCC count them.
func open(result string) bool { return result == "fail" || result == "error" }

type inner struct {
	Body string `xml:",innerxml"`
}

var tagRE = regexp.MustCompile(`<[^>]*>`)

// plain is an XCCDF text (which may hold XHTML) as plain text.
func plain(s string) string {
	s = strings.ReplaceAll(s, "<![CDATA[", "")
	s = strings.ReplaceAll(s, "]]>", "")
	s = tagRE.ReplaceAllString(s, "")
	return strings.TrimSpace(html.UnescapeString(s))
}

type text struct {
	Text string `xml:",chardata"`
}

var (
	vulnRE    = regexp.MustCompile(`V-\d+`)
	ruleVulRE = regexp.MustCompile(`SV-(\d+)`)
	releaseRE = regexp.MustCompile(`Release:\s*(\d+)`)
)

// Parse reads the TestResults in an XCCDF or ARF document. A file with
// several (one per profile, or an ARF with several reports) gives several
// results.
func Parse(r io.Reader) ([]*Result, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	rules := map[string]Rule{}
	profiles := map[string]string{}
	var bench struct{ id, title, version, release string }
	var results []*Result
	var groups []string // enclosing Group ids
	depth := 0
	benchDepth := -1
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			attr := func(name string) string {
				for _, a := range t.Attr {
					if a.Name.Local == name {
						return a.Value
					}
				}
				return ""
			}
			switch t.Name.Local {
			case "Benchmark":
				benchDepth = depth
				bench.id = attr("id")
			case "title":
				if depth == benchDepth+1 && bench.title == "" {
					var x text
					dec.DecodeElement(&x, &t)
					depth--
					bench.title = strings.TrimSpace(x.Text)
				}
			case "version":
				if depth == benchDepth+1 && bench.version == "" {
					var x text
					dec.DecodeElement(&x, &t)
					depth--
					bench.version = strings.TrimSpace(x.Text)
				}
			case "plain-text":
				if attr("id") == "release-info" {
					var x text
					dec.DecodeElement(&x, &t)
					depth--
					if m := releaseRE.FindStringSubmatch(x.Text); m != nil {
						bench.release = m[1]
					}
				}
			case "Profile":
				var p struct {
					Title text `xml:"title"`
				}
				dec.DecodeElement(&p, &t)
				depth--
				profiles[attr("id")] = strings.TrimSpace(p.Title.Text)
			case "Group":
				groups = append(groups, attr("id"))
			case "Rule":
				var x struct {
					Title   text     `xml:"title"`
					Version text     `xml:"version"`
					Refs    []refXML `xml:"reference"`
					Idents  []refXML `xml:"ident"`
					FixText []inner  `xml:"fixtext"`
					Fix     []struct {
						System string `xml:"system,attr"`
						Body   string `xml:",innerxml"`
					} `xml:"fix"`
				}
				id, sev := attr("id"), attr("severity")
				dec.DecodeElement(&x, &t)
				depth--
				rule := Rule{ID: id, Severity: sev, Title: strings.TrimSpace(x.Title.Text), STIGID: strings.TrimSpace(x.Version.Text)}
				if len(x.FixText) > 0 {
					rule.FixText = plain(x.FixText[0].Body)
				}
				for _, f := range x.Fix {
					// A script with <sub> parts needs the profile's values
					// filled in: it is not copied as it stands.
					lang := ""
					switch {
					case strings.HasSuffix(f.System, ":script:sh"):
						lang = "sh"
					case strings.HasSuffix(f.System, ":script:powershell"):
						lang = "powershell"
					}
					if lang != "" && rule.Script == "" && !strings.Contains(f.Body, "<") {
						rule.Script, rule.ScriptLang = strings.TrimSpace(html.UnescapeString(f.Body)), lang
					}
				}
				// SCC puts the STIG ID in the rule's version; SCAP Security
				// Guide content (OpenSCAP) names it in a reference to the DISA
				// STIG instead, next to the SRG ID (SC1).
				if !stigIDRE.MatchString(rule.STIGID) {
					rule.STIGID = ""
				}
				for _, r := range append(x.Refs, x.Idents...) {
					v := strings.TrimSpace(r.Text)
					switch {
					case rule.STIGID == "" && stigIDRE.MatchString(v) && r.disa():
						rule.STIGID = v
					case rule.VulnID == "" && vulnOnlyRE.MatchString(v):
						rule.VulnID = v
					}
				}
				for i := len(groups) - 1; i >= 0 && rule.VulnID == ""; i-- {
					rule.VulnID = vulnRE.FindString(groups[i])
				}
				if rule.VulnID == "" {
					if m := ruleVulRE.FindStringSubmatch(id); m != nil {
						rule.VulnID = "V-" + m[1]
					}
				}
				rules[id] = rule
			case "TestResult":
				res, err := testResult(dec, t)
				depth--
				if err != nil {
					return nil, err
				}
				results = append(results, res)
			}
		case xml.EndElement:
			if t.Name.Local == "Group" && len(groups) > 0 {
				groups = groups[:len(groups)-1]
			}
			if depth == benchDepth {
				benchDepth = -1
			}
			depth--
		}
	}
	if len(results) == 0 {
		return nil, errors.New("no XCCDF TestResult in it")
	}
	for _, res := range results {
		res.Benchmark, res.BenchmarkID = bench.title, firstNonEmpty(res.BenchmarkID, bench.id)
		if res.Benchmark == "" {
			res.Benchmark = benchmarkName(res.BenchmarkID)
		}
		switch {
		case bench.version != "" && bench.release != "":
			res.Version = "V" + bench.version + "R" + bench.release
		case bench.version != "":
			res.Version = bench.version
		}
		if p, ok := profiles[res.Profile]; ok && p != "" {
			res.Profile = p
		}
		for i, o := range res.Open {
			if r, ok := rules[o.ID]; ok {
				if o.Severity != "" {
					r.Severity = o.Severity
				}
				if r.STIGID == "" {
					r.STIGID = o.STIGID
				}
				res.Open[i] = r
			} else if m := ruleVulRE.FindStringSubmatch(o.ID); m != nil {
				res.Open[i].VulnID = "V-" + m[1]
			}
		}
	}
	return results, nil
}

// benchmarkName makes a readable name from a benchmark ID when the file
// doesn't carry the benchmark (an ARF report without its content).
func benchmarkName(id string) string {
	id = id[strings.LastIndex(id, "_benchmark_")+1:]
	id = strings.TrimPrefix(id, "benchmark_")
	return strings.ReplaceAll(id, "_", " ")
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// xccdf times have no zone when the scanner writes local time; they are
// read as UTC, which is close enough for "how old is this scan".
func parseTime(s string) time.Time {
	for _, f := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(f, strings.TrimSpace(s)); err == nil {
			return t
		}
	}
	return time.Time{}
}

func testResult(dec *xml.Decoder, start xml.StartElement) (*Result, error) {
	var tr struct {
		Start string `xml:"start-time,attr"`
		End   string `xml:"end-time,attr"`
		Bench struct {
			ID   string `xml:"id,attr"`
			Href string `xml:"href,attr"`
		} `xml:"benchmark"`
		Profile struct {
			IDRef string `xml:"idref,attr"`
		} `xml:"profile"`
		Target []string `xml:"target"`
		Facts  []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:",chardata"`
		} `xml:"target-facts>fact"`
		Rules []struct {
			IDRef    string `xml:"idref,attr"`
			Severity string `xml:"severity,attr"`
			Version  string `xml:"version,attr"`
			Result   string `xml:"result"`
		} `xml:"rule-result"`
		Scores []struct {
			System  string `xml:"system,attr"`
			Maximum string `xml:"maximum,attr"`
			Value   string `xml:",chardata"`
		} `xml:"score"`
	}
	if err := dec.DecodeElement(&tr, &start); err != nil {
		return nil, err
	}
	res := &Result{Start: parseTime(tr.Start), End: parseTime(tr.End), Profile: tr.Profile.IDRef, Counts: map[string]int{},
		BenchmarkID: firstNonEmpty(tr.Bench.ID, strings.TrimPrefix(tr.Bench.Href, "#"))}
	var fqdn, hostName string
	for _, f := range tr.Facts {
		switch {
		case strings.HasSuffix(f.Name, ":host_name"):
			hostName = strings.TrimSpace(f.Value)
		case strings.HasSuffix(f.Name, ":fqdn"):
			fqdn = strings.TrimSpace(f.Value)
		}
	}
	target := ""
	if len(tr.Target) > 0 {
		target = strings.TrimSpace(tr.Target[0])
	}
	res.Host = ShortHost(firstNonEmpty(target, hostName, fqdn))
	for _, rr := range tr.Rules {
		result := strings.ToLower(strings.TrimSpace(rr.Result))
		res.Counts[result]++
		if open(result) {
			res.Open = append(res.Open, Rule{ID: rr.IDRef, Severity: rr.Severity, STIGID: rr.Version})
		}
	}
	// Prefer the default (or SCC's spp) score; scale to a percentage.
	for _, s := range tr.Scores {
		v, err := strconv.ParseFloat(strings.TrimSpace(s.Value), 64)
		if err != nil {
			continue
		}
		max, _ := strconv.ParseFloat(s.Maximum, 64)
		if max > 0 && max != 100 {
			v = v * 100 / max
		}
		if !res.HasScore || strings.HasSuffix(s.System, ":default") || strings.HasSuffix(s.System, ":spp") {
			res.Score, res.HasScore = v, true
		}
	}
	if !res.HasScore {
		// Pass rate among the rules that were checked, as STIG Viewer does.
		checked := res.Counts["pass"] + res.Counts["fail"] + res.Counts["error"]
		if checked > 0 {
			res.Score, res.HasScore = float64(res.Counts["pass"])*100/float64(checked), true
		}
	}
	return res, nil
}

// ShortHost is a host name without its domain, upper-cased the way
// computers are matched elsewhere.
func ShortHost(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.IndexByte(h, '.'); i > 0 && !isIP(h) {
		h = h[:i]
	}
	return h
}

func isIP(s string) bool {
	return strings.Count(s, ".") == 3 && strings.Trim(s, "0123456789.") == ""
}

// ReadFile parses one results file (plain or .gz).
func ReadFile(path string) ([]*Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ReadBytes(path, b)
}

// ReadBytes is ReadFile for the contents b of the file at path, already
// read.
func ReadBytes(path string, b []byte) ([]*Result, error) {
	sum := sha256.Sum256(b)
	var r io.Reader = bytes.NewReader(b)
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		z, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		r = z
	}
	res, err := Parse(r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, x := range res {
		x.File, x.SHA256 = path, hex.EncodeToString(sum[:])
	}
	return res, nil
}

// Scan is a computer's latest result for one benchmark, and the one
// before it.
type Scan struct {
	Latest, Previous *Result
}

// Delta is what changed since the previous scan.
type Delta struct {
	NewlyOpen, NewlyFixed []Rule
	Score                 float64 // change in score, percentage points
}

// Delta compares the latest scan with the previous one.
func (s Scan) Delta() (Delta, bool) {
	if s.Latest == nil || s.Previous == nil {
		return Delta{}, false
	}
	was := map[string]bool{}
	for _, o := range s.Previous.Open {
		was[o.ID] = true
	}
	now := map[string]bool{}
	var d Delta
	for _, o := range s.Latest.Open {
		now[o.ID] = true
		if !was[o.ID] {
			d.NewlyOpen = append(d.NewlyOpen, o)
		}
	}
	for _, o := range s.Previous.Open {
		if !now[o.ID] {
			d.NewlyFixed = append(d.NewlyFixed, o)
		}
	}
	d.Score = s.Latest.Score - s.Previous.Score
	return d, true
}

// candidate reports whether a file may hold SCAP results.
func candidate(name string) bool {
	n := strings.ToLower(name)
	n = strings.TrimSuffix(n, ".gz")
	return strings.HasSuffix(n, ".xml") || strings.HasSuffix(n, ".arf")
}

// Find reads every results file under the folders (and their
// subfolders) and returns, for each computer and benchmark, the latest
// scan and the one before. The key is "HOST|benchmark ID". Files that
// aren't SCAP results are skipped; problems reading real ones are
// returned as notes.
func Find(dirs ...string) (map[string]*Scan, []string) { return find("", dirs) }

// FindWithReceived is Find plus received, the folder where a collector
// files the results its senders delivered, one folder per computer
// (received/HOST). A result there counts only if it is for the computer
// whose folder holds it, so a file a sender slipped in for another
// computer, kept by a version before 0.27, is ignored.
func FindWithReceived(received string, dirs ...string) (map[string]*Scan, []string) {
	return find(received, append(dirs, received))
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// folderFor is the folder name a collector files host's results under
// (the same as lan's safeName of the upper-cased name).
func folderFor(host string) string {
	s := unsafeChars.ReplaceAllString(strings.ToUpper(strings.TrimSpace(host)), "-")
	if s == "" {
		s = "UNKNOWN"
	}
	return s
}

func find(received string, dirs []string) (map[string]*Scan, []string) {
	var all []*Result
	var notes []string
	seen := map[string]bool{}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		walk(dir, 0, func(path string) {
			res, err := ReadFile(path)
			if err != nil {
				if !strings.Contains(err.Error(), "no XCCDF TestResult") {
					notes = append(notes, err.Error())
				}
				return
			}
			var folder string
			if received != "" {
				if rel, err := filepath.Rel(received, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
					folder, _, _ = strings.Cut(filepath.ToSlash(rel), "/")
					if folder == filepath.ToSlash(rel) {
						folder = "-" // a file not in a computer's folder
					}
				}
			}
			for _, r := range res {
				if folder != "" && !strings.EqualFold(folder, folderFor(r.Host)) {
					notes = append(notes, fmt.Sprintf("%s: ignored the result for %s, which is not the computer it was received for (%s)", path, r.Host, folder))
					continue
				}
				k := r.SHA256 + "|" + r.Host + "|" + r.BenchmarkID + "|" + r.When().String()
				if !seen[k] {
					seen[k] = true
					all = append(all, r)
				}
			}
		})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].When().After(all[j].When()) })
	out := map[string]*Scan{}
	for _, r := range all {
		k := strings.ToUpper(r.Host) + "|" + r.BenchmarkID
		s := out[k]
		switch {
		case s == nil:
			out[k] = &Scan{Latest: r}
		case s.Previous == nil && r.When().Before(s.Latest.When()):
			s.Previous = r
		}
	}
	return out, notes
}

// walk calls fn for each candidate file under dir, at most a few folders
// deep (SCC's Sessions\<date>\Results\SCAP\XML is four).
func walk(dir string, depth int, fn func(string)) {
	if depth > 6 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := dir + string(os.PathSeparator) + e.Name()
		switch {
		case e.IsDir():
			walk(p, depth+1, fn)
		case candidate(e.Name()):
			if info, err := e.Info(); err == nil && info.Size() < 512<<20 {
				fn(p)
			}
		}
	}
}
