package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/scap"
)

func scapScans(t *testing.T) []*scap.Scan {
	t.Helper()
	found, notes := scap.Find("../../testdata/scap")
	if len(notes) > 0 {
		t.Fatal(notes)
	}
	var out []*scap.Scan
	for _, s := range found {
		out = append(out, s)
	}
	return out
}

// §6: each computer's latest SCAP scan is in the report, the result files
// are copied in and listed in the manifest, and open rules are a CSV.
func TestScapInReport(t *testing.T) {
	end := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	evs := []*event.Event{
		{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
		{Time: end.Add(-time.Hour), Host: "ubu-01", OS: "linux", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
		{Time: end.Add(-time.Hour), Host: "DSK9", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
	}
	r := Build(evs, nil, Options{WindowEnd: end, Location: time.UTC, Scap: scapScans(t), ScapEnabled: true, ScapMaxAgeDays: 30})
	rows := map[string]ScapRow{}
	for _, row := range r.scapTable {
		rows[row.Host] = row
	}
	ws := rows["WS-07"]
	if ws.Cat != [4]int{0, 1, 1, 1} || ws.Score != "40%" || ws.Level != "bad" || !strings.Contains(ws.Benchmark, "V2R8") ||
		ws.Change != "1 newly open, 1 fixed since 1 Sep" || ws.Stale {
		t.Errorf("WS-07: %+v", ws)
	}
	if u := rows["ubu-01"]; u.Cat != [4]int{0, 0, 0, 1} || u.Change != "first scan" || u.Level != "ok" {
		t.Errorf("ubu-01: %+v", u)
	}
	if d := rows["DSK9"]; !d.Missing {
		t.Errorf("DSK9: %+v", d)
	}
	l, ok := r.scapCheckLine()
	if !ok || l.Level != "bad" || l.What != "1 CAT I finding on WS-07" {
		t.Errorf("overview: %+v", l)
	}
	if !strings.Contains(r.scapLine("WS-07"), "SCAP 40% · 1 CAT I") {
		t.Errorf("systems line: %q", r.scapLine("WS-07"))
	}
	// Stale after scap_max_age_days.
	old := Build(evs, nil, Options{WindowEnd: end.AddDate(0, 2, 0), Location: time.UTC, Scap: scapScans(t), ScapEnabled: true, ScapMaxAgeDays: 30})
	for _, row := range old.scapTable {
		if !row.Missing && !row.Stale {
			t.Errorf("two months later, %s is not stale", row.Host)
		}
	}

	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	if p, err := Verify(dir); err != nil || len(p) != 0 {
		t.Fatalf("verify: %v %v", p, err)
	}
	// The site's scan results are copied, never moved.
	if found, _ := scap.Find("../../testdata/scap"); len(found) != 2 || found["WS-07|xccdf_mil.disa.stig_benchmark_MS_Windows_11_STIG"].Previous == nil {
		t.Fatal("writing the report moved the scan results")
	}
	m, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if !strings.Contains(string(m), "  scap/WS-07_WS-07_SCC-5.10_2026-09-29_100000_XCCDF-Results_MS_Windows_11_STIG.xml") ||
		!strings.Contains(string(m), "  scap/ubu-01_ubu-01-arf.xml") || !strings.Contains(string(m), "  scap-open-rules.csv") {
		t.Errorf("manifest:\n%s", m)
	}
	csv, _ := os.ReadFile(filepath.Join(dir, "scap-open-rules.csv"))
	if !strings.Contains(string(csv), "WS-07,Microsoft Windows 11 Security Technical Implementation Guide V2R8,CAT I,V-253254,WN11-00-000005") {
		t.Errorf("csv:\n%s", csv)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, want := range []string{"STIG compliance (SCAP)", "No scan found", "Open SCAP findings as CSV"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report.html lacks %q", want)
		}
	}
	// SC3: each count opens the system's open rules, CAT I first; each
	// system's settings list has a STIG compliance line linking there.
	page := string(html)
	for _, want := range []string{`href="#health/WS-07/scap"`, "Open STIG rules on WS-07 · 3", "data-scapopen",
		`<a class="link" href="#health/WS-07/scap">STIG compliance (SCAP) →</a>`, "1 CAT I open", "Score 40% · 1 CAT I, 1 CAT II, 1 CAT III open"} {
		if !strings.Contains(page, want) {
			t.Errorf("report.html lacks %q", want)
		}
	}
	open := r.scapOpen("WS-07")
	if len(open) != 1 || len(open[0].Rules) != 3 || open[0].Rules[0].Cat != "CAT I" || open[0].Rules[0].STIG != "WN11-00-000005" ||
		open[0].Rules[1].Cat != "CAT II" || open[0].Rules[2].Cat != "CAT III" || open[0].Rules[0].RuleID == "" || open[0].Rules[0].Title == "" {
		t.Errorf("open rules: %+v", open)
	}
	if l, ok := r.scapSetting("DSK9"); !ok || l.Have != "No scan found" || l.Href != "" {
		t.Errorf("DSK9 setting: %+v", l)
	}
	if l, ok := r.scapSetting("ubu-01"); !ok || l.Class != "ok" || l.Href != "#health/ubu-01/scap" {
		t.Errorf("ubu-01 setting: %+v", l)
	}
	// A changed scan result is caught by verify.
	f := filepath.Join(dir, "scap", "ubu-01_ubu-01-arf.xml")
	os.Chmod(f, 0o644)
	os.WriteFile(f, []byte("changed"), 0o644)
	if p, _ := Verify(dir); len(p) != 1 || !strings.Contains(p[0], "CHANGED") {
		t.Errorf("verify after change: %v", p)
	}
}

// Without SCAP in use there is no table.
func TestNoScapNoTable(t *testing.T) {
	r := buildFrom([]*event.Event{{Time: fx0, Host: "WS-07", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"}}, Options{})
	if len(r.scapTable) != 0 {
		t.Errorf("table: %+v", r.scapTable)
	}
	if _, ok := r.scapCheckLine(); ok {
		t.Error("overview line without SCAP")
	}
}

// The SCAP score is at hand: a system's Audit health facts (all a
// one-computer report's Audit health shows), its Systems page health list,
// and the jump bar.
func TestScapScoreShown(t *testing.T) {
	end := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	evs := []*event.Event{
		{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
		{Time: end.Add(-time.Hour), Host: "ubu-01", OS: "linux", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
	}
	r := Build(evs, nil, Options{WindowEnd: end, Location: time.UTC, Scap: scapScans(t), ScapEnabled: true, ScapMaxAgeDays: 30, Collector: true,
		Systems: []SystemInfo{{Name: "WS-07", OS: "windows"}, {Name: "ubu-01", OS: "linux"}}})
	hp := r.healthPage()
	facts := map[string]Fact{}
	for _, g := range hp.Groups {
		for _, row := range g.Rows {
			for _, f := range row.Facts {
				if f.Label == "SCAP score" {
					facts[row.Name] = f
				}
			}
		}
	}
	if f := facts["WS-07"]; f.Value != "40% · 1 CAT I" || !f.Bad || f.Href != ScapHref("WS-07") {
		t.Errorf("WS-07 fact: %+v", f)
	}
	if f := facts["ubu-01"]; f.Value != "67%" || f.Bad {
		t.Errorf("ubu-01 fact: %+v", f)
	}
	var jump string
	for _, j := range hp.Jump {
		if j.Target == "h-scap" {
			jump = j.Note
		}
	}
	if jump != "lowest score 40% · 1 open CAT I" {
		t.Errorf("jump: %q", jump)
	}
	lines := map[string]CheckLine{}
	for _, g := range r.systemsPage().Groups {
		for _, v := range g.Systems {
			for _, l := range v.Health {
				if strings.Contains(l.Title, "SCAP") {
					lines[v.Name] = l
				}
			}
		}
	}
	if l := lines["WS-07"]; l.Title != "Open CAT I findings (SCAP)" || l.Level != "bad" || !strings.HasPrefix(l.What, "Score 40% · 1 CAT I, 1 CAT II, 1 CAT III open") || l.Href != ScapHref("WS-07") {
		t.Errorf("WS-07 health: %+v", l)
	}
	if l := lines["ubu-01"]; l.Title != "STIG compliance (SCAP)" || l.Level != "ok" || !strings.HasPrefix(l.What, "Score 67%") {
		t.Errorf("ubu-01 health: %+v", l)
	}

	// A one-computer report: Audit health opens on the system's own view,
	// which now has the score at the top.
	r = Build(evs[:1], nil, Options{WindowEnd: end, Location: time.UTC, Scap: scapScans(t), ScapEnabled: true, ScapMaxAgeDays: 30})
	var b bytes.Buffer
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	i := strings.Index(h, `data-pane="WS-07"`)
	if !strings.Contains(h, `data-single="WS-07"`) || i < 0 || !strings.Contains(h[i:], "SCAP score<b class=\"bad\">40% · 1 CAT I</b>") {
		t.Error("the one-computer report's Audit health lacks the SCAP score")
	}
}
