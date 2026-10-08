package report

import (
	"bytes"
	"encoding/json"
	"html/template"
	"regexp"
	"strings"
	"testing"
	"time"
)

// renderHTML renders report.html of r (without writing the folder) and
// returns it with its meta (the settings app.js reads).
func renderHTML(t *testing.T, r *Report) (string, map[string]json.RawMessage) {
	t.Helper()
	pages, _, err := r.buildData()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.WriteHTML(&b, pages); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	m := regexp.MustCompile(`(?s)<script type="application/json" id="bb-meta">(.*?)</script>`).FindStringSubmatch(h)
	if m == nil {
		t.Fatal("no meta")
	}
	meta := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(m[1]), &meta); err != nil {
		t.Fatal(err)
	}
	return h, meta
}

// between returns the part of s from the first a to the next b after it.
func between2(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i:], b)
	if j < 0 {
		return s[i:]
	}
	return s[i : i+j]
}

// UI-R1: the sidebar's groups, always open, with counts on Events by kind;
// the brand line with the network's name; the report card; no search box
// and no review progress.
func TestSidebarUIR1(t *testing.T) {
	r, _ := demo30(t)
	h, _ := renderHTML(t, r)
	aside := between2(h, "<aside", "</aside>")
	if aside == "" {
		t.Fatal("no sidebar")
	}
	var groups []string
	for _, m := range regexp.MustCompile(`<nav aria-label="([^"]+)">`).FindAllStringSubmatch(aside, -1) {
		groups = append(groups, m[1])
	}
	if strings.Join(groups, "|") != "Review|Who and what|Evidence|Events by kind|More" {
		t.Errorf("groups: %v", groups)
	}
	order := []string{`data-nav="overview"`, `data-nav="detections"`, `data-nav="search"`, `data-nav="systems"`, `data-nav="people"`,
		`data-nav="health"`, `data-nav="logs"`, `data-nav="privileged"`, `data-nav="inventory"`, `data-nav="trends"`}
	last := -1
	for _, o := range order {
		i := strings.Index(aside, o)
		if i < last {
			t.Errorf("%s out of order", o)
		}
		last = i
	}
	for _, bad := range []string{"data-tog", "data-fold", `type="search"`, "progress", `class="site"`} {
		if strings.Contains(aside, bad) {
			t.Errorf("sidebar has %s", bad)
		}
	}
	if !strings.Contains(aside, "<b>Blackbox</b><span>ENG-NET</span>") {
		t.Error("no brand line with the network's name")
	}
	// Events by kind, with counts.
	for _, p := range []string{"privileged", "logons", "integrity"} {
		if !regexp.MustCompile(`data-nav="` + p + `">.*?<small>[\d,]+</small>`).MatchString(aside) {
			t.Errorf("no count for %s", p)
		}
	}
	if !strings.Contains(aside, `<span>Detections</span><em>`+commas(len(r.Findings))+`</em>`) {
		t.Error("no detection count")
	}
	// The report card.
	card := between2(aside, `<div class="rcard">`, "</div>")
	for _, want := range []string{"<b>Daily report</b>", "<span>7 Oct 00:00 – 8 Oct 00:00 EDT</span>", "<span>30 systems · generated 8 Oct 2026 00:02</span>",
		`class="vline ok" data-open="verified"`, "Verified · files match manifest", `<a class="allrep" href="../index.html"`, "All reports →"} {
		if !strings.Contains(card, want) {
			t.Errorf("report card lacks %q:\n%s", want, card)
		}
	}
}

// UI-R1: one page header: the breadcrumb (the report, its period with the
// zone, then the page's own part), the title, and only the page's own
// buttons. The period, Verified and All reports are not in it.
func TestPageHeaderUIR1(t *testing.T) {
	r, _ := demo30(t)
	h, _ := renderHTML(t, r)
	heads := regexp.MustCompile(`(?s)<div class="head">.*?</div></div>`).FindAllString(h, -1)
	if len(heads) < 10 {
		t.Fatalf("%d page headers", len(heads))
	}
	for _, hd := range heads {
		if !strings.Contains(hd, `<div class="crumb">Daily report · 7 Oct 00:00 – 8 Oct 00:00 EDT`) || !strings.Contains(hd, `data-open="export"`) {
			t.Errorf("header: %s", hd)
		}
		for _, bad := range []string{"verified", "../index.html", "calendar-range", "generated"} {
			if strings.Contains(hd, bad) {
				t.Errorf("header has %s: %s", bad, hd)
			}
		}
	}
	det := between2(h, `<section class="view" data-view="detections">`, "</h1>")
	if !strings.Contains(det, " · "+commas(len(r.Findings))+" detections</div>") {
		t.Errorf("detections crumb: %s", det)
	}
	if !strings.Contains(between2(h, `<section class="view" data-view="detections">`, `</div></div>`), `data-act="pagecsv">Export CSV`) {
		t.Error("Detections has no Export CSV")
	}
}

// UI-R1: the Verified pop-up (design 14): three checks; when one fails the
// title says so in red and the failing check is first, with its file.
func TestVerifiedUIR1(t *testing.T) {
	r, _ := demo30(t)
	v := r.verification()
	if !v.OK || v.Title != "This report has not been changed" || len(v.Lines) != 3 ||
		v.Lines[0].Text != "Report files match the manifest" || v.Lines[1].Text != "28 original-log zips checked" || v.Lines[2].Text != "No gap since the previous report" {
		t.Fatalf("verified: %+v", v)
	}
	h, _ := renderHTML(t, r)
	pop := between2(h, `data-pop="verified"`, "</div>")
	for _, want := range []string{`class="vh ok"`, "This report has not been changed", "Check it yourself: <code>blackbox verify</code>"} {
		if !strings.Contains(pop, want) && !strings.Contains(between2(h, `data-pop="verified"`, "vfoot"), want) {
			t.Errorf("pop-up lacks %q", want)
		}
	}

	// A zip that does not match its recorded SHA-256.
	r.archiveState = map[string]archiveState{}
	for _, a := range r.Archives {
		r.archiveState[a.Name] = archiveState{Verified: a.Host != "ubu-db01"}
	}
	v = r.verification()
	if v.OK || v.Title != "This report's original logs do not match" || !v.Lines[0].Bad || !strings.Contains(v.Lines[0].File, "logs-ubu-db01.zip") ||
		v.Lines[1].Text != "Report files match the manifest" || v.Short != "a log zip does not match" {
		t.Errorf("a changed zip: %+v", v)
	}
	h, _ = renderHTML(t, r)
	if !strings.Contains(h, `class="vline bad" data-open="verified"`) || !strings.Contains(h, "Not verified · a log zip does not match") ||
		!strings.Contains(h, `<div class="vh bad" data-vhead><i aria-hidden="true">✕</i><b id="vtitle">This report&#39;s original logs do not match</b>`) {
		t.Error("the card or the pop-up is not red")
	}
	first := between2(h, "<ul data-vlist>", "</li>")
	if !strings.Contains(first, `class="bad"`) || !strings.Contains(first, "logs-ubu-db01.zip") {
		t.Errorf("first check: %s", first)
	}

	// A gap since the previous report, and earlier reports missing.
	r.archiveState = nil
	r.History[len(r.History)-1].WindowEnd = r.WindowStart.Add(-time.Hour)
	v = r.verification()
	if v.OK || v.Title != "Reports are missing or have a gap" || v.Lines[0].Text != "A gap since the previous report" || !strings.Contains(v.Lines[0].File, "this one starts 7 Oct 00:00") {
		t.Errorf("a gap: %+v", v)
	}
	r.MissingReports = []MissingReport{{Name: "2026-10-05_0000_ENG-NET", Problem: "missing", What: "2026-10-05_0000_ENG-NET is missing"}}
	v = r.verification()
	if v.OK || v.Lines[0].Text != "1 earlier report missing or changed" || !strings.Contains(v.Lines[0].File, "2026-10-05_0000_ENG-NET") || v.Short != "earlier reports missing" {
		t.Errorf("missing reports: %+v", v)
	}
}

// UI-R1: the Export menu (design 15): "This page" (filled in by app.js
// for the page shown) and the whole report's files; every CSV time with
// its zone; drive serials in Systems and drives.
func TestExportMenuUIR1(t *testing.T) {
	r, _ := demo30(t)
	h, meta := renderHTML(t, r)
	menu := between2(h, `data-pop="export"`, `data-pop="verified"`)
	want := []string{`data-xpage hidden`, `<div class="xh">This page</div>`, `data-act="pagecsv"`, `<div class="xh">Whole report</div>`,
		`data-act="print"`, "<b>Summary</b><small>PDF</small>", `href="events.zip"`, "<b>All events (" + commas(len(r.Events)) + ")</b><small>CSV</small>",
		`data-act="syscsv"`, "<b>Systems and drives</b>", `data-act="fixcsv"`, "<b>Audit settings to fix</b>",
		`href="scap-open-rules.csv"`, "<b>Open SCAP findings</b>", `href="./"`, "<b>Open the report folder</b>"}
	last := -1
	for _, w := range want {
		i := strings.Index(menu, w)
		if i < 0 {
			t.Errorf("menu lacks %q", w)
			continue
		}
		if i < last {
			t.Errorf("%q out of order", w)
		}
		last = i
	}
	var pages map[string]CSVFile
	if err := json.Unmarshal(meta["pagecsv"], &pages); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"detections", "systems", "health", "inventory", "logs"} {
		if f, ok := pages[k]; !ok || f.Label == "" || f.File == "" || len(f.Rows) < 2 {
			t.Errorf("no This page CSV for %s: %+v", k, f)
		}
	}
	if d := pages["detections"]; d.Label != "Detections shown" || len(d.Rows) != len(r.Findings)+1 || d.Rows[0][0] != "severity" {
		t.Errorf("detections: %+v", d.Rows[0])
	}
	var whole map[string]CSVFile
	if err := json.Unmarshal(meta["reportcsv"], &whole); err != nil {
		t.Fatal(err)
	}
	sys := whole["syscsv"]
	serials := 0
	for _, row := range sys.Rows[1:] {
		if strings.HasPrefix(row[6], "S5GXNX0T") {
			serials++
		}
		if !strings.HasSuffix(row[9], " -04:00") {
			t.Errorf("a time without its zone: %v", row)
		}
	}
	if serials != 30 || sys.Rows[0][6] != "drive serial" {
		t.Errorf("systems and drives: %d drive serials; %v", serials, sys.Rows[0])
	}
	fix := whole["fixcsv"]
	if len(fix.Rows) < 100 {
		t.Errorf("%d settings to fix", len(fix.Rows)-1)
	}
	for _, row := range fix.Rows[1:] {
		if row[6] == "OK" || row[6] == "Matches" || !strings.HasSuffix(row[8], " -04:00") {
			t.Errorf("settings to fix: %v", row)
			break
		}
	}
	// The detections file's times carry the zone too.
	for _, row := range pages["detections"].Rows[1:] {
		if !strings.HasSuffix(row[3], " -04:00") {
			t.Errorf("detection time %q", row[3])
		}
	}
	// A spreadsheet formula stays text.
	if got := csvFile("x", "x", [][]string{{"=HYPERLINK(1)"}}).Rows[0][0]; got != "'=HYPERLINK(1)" {
		t.Errorf("csvFile: %q", got)
	}
}

// UI-R1 shared components: grouping by servers and workstations, problems
// first, the check square, the fold row and the one-line item.
func TestComponentsUIR1(t *testing.T) {
	r, _ := demo30(t)
	groups := groupByKind(r.SystemRows, systemKind)
	if len(groups) != 2 || groups[0].Label() != "Servers · 11" || groups[1].Label() != "Workstations · 19" {
		t.Fatalf("groups: %v %v", groups[0].Label(), groups[len(groups)-1].Label())
	}
	level := func(s SystemRow) string {
		switch s.Status {
		case "silent":
			return "bad"
		case "warn":
			return "warn"
		}
		return "ok"
	}
	CountProblems(groups, level)
	if groups[1].Label() != "Workstations · 2 with problems" {
		t.Errorf("label: %s", groups[1].Label())
	}
	ws := groups[1].Items
	problemsFirst(ws, level, func(s SystemRow) string { return s.Name })
	if ws[0].Name != "ubu-ws-07" || ws[1].Name != "WS-ENG-06" {
		t.Errorf("problems first: %s, %s", ws[0].Name, ws[1].Name)
	}
	if r.hostKind("srv-dc01") != "server" || r.hostKind("WS-LAB-01") != "workstation" || r.hostKind("ubu-web01") != "server" {
		t.Error("hostKind")
	}
	if s := foldText(22, "systems", "with no problems", "14 with warnings, 8 all OK"); s != "22 more systems with no problems (14 with warnings, 8 all OK)" {
		t.Errorf("fold text: %s", s)
	}
	if s := foldText(1, "users", "with no privileged actions", ""); s != "1 more user with no privileged actions" {
		t.Errorf("fold text: %s", s)
	}

	tp, err := template.New("report").Funcs(funcs(time.UTC)).Parse(reportTemplate)
	if err != nil {
		t.Fatal(err)
	}
	run := func(name string, data any) string {
		var b bytes.Buffer
		if err := tp.ExecuteTemplate(&b, name, data); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	if got := run("cell", CheckCell{Level: "bad", Label: "Reporting", Title: "nothing since 6 Oct", Href: "#systems/WS-ENG-06"}); got !=
		`<a class="cell bad" href="#systems/WS-ENG-06" title="Reporting: nothing since 6 Oct"><span class="sr">Reporting: problem</span></a>` {
		t.Errorf("cell: %s", got)
	}
	if got := run("cell", CheckCell{Label: "SCAP"}); !strings.Contains(got, `class="cell na"`) || !strings.Contains(got, "SCAP: no data") {
		t.Errorf("no-data cell: %s", got)
	}
	if got := run("cellkey", nil); !strings.Contains(got, `<i class="cell warn"></i>warning`) || !strings.Contains(got, `<i class="cell na"></i>no data`) {
		t.Errorf("cell key: %s", got)
	}
	if got := run("foldrow", FoldRow{ID: "ov-ok", Text: "22 more systems with no problems"}); !strings.Contains(got, `data-foldbtn="ov-ok" aria-expanded="false"`) ||
		!strings.Contains(got, "<span>22 more systems with no problems</span>") {
		t.Errorf("fold row: %s", got)
	}
	if got := run("li1", ListItem{Title: "Security log cleared", Reason: "by adm-jlee, with wevtutil", System: "SRV-DC02", Time: "14:22", Href: "#detections/3", Level: "bad"}); got !=
		`<a class="li1 bad" href="#detections/3"><i aria-hidden="true"></i><span class="t"><b>Security log cleared</b><small>by adm-jlee, with wevtutil</small></span><span class="s">SRV-DC02</span><span class="w">14:22</span></a>` {
		t.Errorf("li1: %s", got)
	}
	if got := run("grouphead", groups[0]); got != `<div class="grph">Servers · 11</div>` {
		t.Errorf("grouphead: %s", got)
	}
}
