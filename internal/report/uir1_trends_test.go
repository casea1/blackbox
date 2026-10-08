package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// UI-R1 Trends: "New this week" from twelve weeks of the 30-system
// network's earlier summaries: the story's new administrators, account,
// logon path, address, service and USB device, and nothing of the routine.
func TestTrendsNewThisWeek(t *testing.T) {
	r, _ := demo30(t)
	tp := r.trendsPage()
	if tp.NotEnough || len(tp.Ranges) != 3 || !tp.Ranges[1].On || tp.Ranges[1].Weeks != 8 || tp.Ranges[2].Weeks != 12 {
		t.Fatalf("ranges: %v %+v", tp.NotEnough, tp.Ranges)
	}
	tr := tp.Ranges[1]
	var got []string
	for _, it := range append(tr.New, tr.NewFold...) {
		got = append(got, it.Label+": "+it.Text)
	}
	want := []string{
		"Admin: svc-backup on SRV-DC01", "Admin: labadmin on WS-LAB-01",
		"Account: labadmin on WS-LAB-01",
		"Logon path: administrator → WS-LAB-01 (Console)",
		"Logon path: jlee → SRV-DC02 (Remote Desktop)",
		"Source address: 203.0.113.50 (412 SSH failures on ubu-web01)",
		"Service: UpdaterSvc on SRV-APP01",
		"USB device: SanDisk Cruzer Blade on SRV-APP01",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("new this week:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if tr.NewSpan != "never seen in 7 weeks" || tp.Ranges[0].NewSpan != "never seen in 3 weeks" {
		t.Errorf("span: %q %q", tr.NewSpan, tp.Ranges[0].NewSpan)
	}

	// Kept in summary.json for the next report.
	s := r.summary()
	b, _ := json.Marshal(s)
	var back Summary
	if err := json.Unmarshal(b, &back); err != nil || back.Seen == nil {
		t.Fatal(err)
	}
	set := back.Seen.set()
	for kind, key := range map[string]string{SeenAdmin: `SRV-DC01\svc-backup`, SeenAccount: `WS-LAB-01\labadmin`, SeenPath: "jlee|SRV-DC02|Remote Desktop",
		SeenSource: "203.0.113.50", SeenService: `SRV-APP01\updatersvc`, SeenUSB: "SRV-APP01|sandisk cruzer blade", SeenActive: "jlee|SRV-DC02"} {
		if !set[kind][key] {
			t.Errorf("summary.json seen lacks %s %s", kind, key)
		}
	}
	if s.Metrics[MSTIGChecked] != 30 || s.Metrics[MSTIGMatching] != 8 || len(s.Matching) != 8 {
		t.Errorf("STIG: %v %v", s.Metrics, s.Matching)
	}

	// A report with no earlier report keeping the sets says when it starts.
	r.History = nil
	r.weeksCache, r.seenHist = nil, nil
	if items, _, note := r.newThisWeek(r.weeks()); items != nil || !strings.HasPrefix(note, "Starts next week") {
		t.Errorf("no history: %v %q", items, note)
	}
}

// UI-R1: the Event-detail panel's "Seen before": the event's person on its
// system in the earlier reports that kept what they saw.
func TestSeenBefore(t *testing.T) {
	r, _ := demo30(t)
	var dc2, routine *event.Event
	for _, e := range r.Events {
		if e.Host == "SRV-DC02" && personKey(e.User) == "jlee" && dc2 == nil {
			dc2 = e
		}
		if e.Host == "SRV-DC01" && e.User == "jdoe" && routine == nil {
			routine = e
		}
	}
	if dc2 == nil || routine == nil {
		t.Fatal("no events")
	}
	if got := r.seenBefore(dc2).Text(); got != "never on SRV-DC02 in 84 reports" {
		t.Errorf("jlee on SRV-DC02: %q", got)
	}
	if got := r.seenBefore(routine).Text(); got != "on SRV-DC01 in all 84 earlier reports" {
		t.Errorf("jdoe on SRV-DC01: %q", got)
	}
	ip := &event.Event{Host: "ubu-web01", SourceIP: "203.0.113.50", Category: event.CatFailedLogon}
	if got := r.seenBefore(ip).Text(); got != "never from 203.0.113.50 in 84 reports" {
		t.Errorf("address: %q", got)
	}
	r.History = nil
	r.seenHist = nil
	if got := r.seenBefore(dc2).Text(); got != "" {
		t.Errorf("no history: %q", got)
	}
}

// UI-R1: "usual" is the median of the complete earlier weeks; this week's
// bar is red when worse, green when better, blue otherwise; partial weeks
// are left out.
func TestTrendsUsualMedian(t *testing.T) {
	if median([]int{5, 1, 9}) != 5 || median([]int{4, 1, 9, 6}) != 5 || median(nil) != 0 {
		t.Error("median")
	}
	mon := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	week := func(i, v int, complete bool) trendWeek {
		s := mon.AddDate(0, 0, 7*i)
		return trendWeek{Start: s, End: s.AddDate(0, 0, 7), Complete: complete, HasData: true, Metrics: map[string]int{MFailedLogons: v}}
	}
	ws := []trendWeek{week(0, 900, false), week(1, 10, true), week(2, 30, true), week(3, 20, true), week(4, 2000, true)}
	ws[4].Complete, ws[4].Current, ws[4].Days = false, true, 7
	s := seriesOf(ws, false, func(w trendWeek) int { return w.value(MFailedLogons) })
	if s.Usual != 20 || s.N != 3 || s.Vals[0] != -1 || s.Now != 2000 || s.verdict(true) != "bad" {
		t.Errorf("series: %+v", s)
	}
	ws[4].Metrics[MFailedLogons] = 2
	if s := seriesOf(ws, false, func(w trendWeek) int { return w.value(MFailedLogons) }); s.verdict(true) != "ok" || s.verdict(false) != "bad" {
		t.Errorf("down: %+v", s)
	}
	ws[4].Metrics[MFailedLogons] = 22
	if s := seriesOf(ws, false, func(w trendWeek) int { return w.value(MFailedLogons) }); s.verdict(true) != "" {
		t.Errorf("usual: %+v", s)
	}
	// Two days into the week, 20 is well above the usual 20 by now.
	ws[4].Days, ws[4].Metrics[MFailedLogons] = 2, 20
	if s := seriesOf(ws, false, func(w trendWeek) int { return w.value(MFailedLogons) }); s.Expected > 6 || s.verdict(true) != "bad" {
		t.Errorf("so far: %+v", s)
	}

	r, _ := demo30(t)
	tr := r.trendsPage().Ranges[1]
	cards := map[string]TrendCard{}
	for _, c := range tr.Cards {
		cards[c.Title] = c
	}
	if c := cards["Systems matching the STIG"]; c.Value != "8" || c.Usual != "usual 5" || c.Class != "ok" {
		t.Errorf("STIG card: %+v", c)
	}
	if c := cards["Detections"]; c.Class != "bad" || c.Last != "this week · 3 of 7 days" {
		t.Errorf("detections card: %+v", c)
	}
	if len(tr.Cards) != 6 || len(tr.Grid.Weeks) != 8 || len(tr.Grid.Rows)+len(tr.Grid.Others) != 30 || !strings.Contains(fmt.Sprint(tr.Grid.Rows), "{SRV-DC02 ") {
		t.Errorf("cards %d, grid %v %d+%d %s", len(tr.Cards), tr.Grid.Weeks, len(tr.Grid.Rows), len(tr.Grid.Others), tr.Grid.Rows[0].Name)
	}
	var lines []string
	for _, c := range tr.Changes {
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%s", c.Level, c.Name, c.Measure, c.Usual, c.Now, c.Why))
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{"ubu-web01|Failed logons|", "SSH guessing from 203.0.113.50 on 7 Oct (412)", "|All systems|Systems matching the STIG|5|8|ubu-git01, ubu-ws-01 and ubu-ws-05 fixed"} {
		if !strings.Contains(all, want) {
			t.Errorf("biggest changes lack %q:\n%s", want, all)
		}
	}
	if len(tr.Changes) != 6 {
		t.Errorf("%d changes", len(tr.Changes))
	}
}

// UI-R1 All reports: the cards and the Check column from the ledger,
// months newest first, chips, the manual reason, the filters' counts and
// the older reports folded.
func TestIndexFromLedger(t *testing.T) {
	dir := t.TempDir()
	loc := demo30Zone
	day := time.Date(2026, 10, 7, 0, 0, 0, 0, loc)
	checks := map[string]ReportCheck{}
	write := func(name string, s Summary) {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o750); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(s)
		os.WriteFile(filepath.Join(dir, name, "summary.json"), b, 0o640)
	}
	for d := 0; d < 30; d++ {
		ws := day.AddDate(0, 0, -d)
		name := ws.AddDate(0, 0, 1).Format("2006-01-02") + "_0000_ENG-NET"
		s := Summary{WindowStart: ws, WindowEnd: ws.AddDate(0, 0, 1), Generated: ws.AddDate(0, 0, 1).Add(2 * time.Minute), Hosts: []string{"a", "b"}, Events: 1000 + d,
			ByCategory: map[string]int{"privileged": 812, "failed_logon": 40, "logon_activity": 300},
			Systems:    []SystemStatus{{Name: "a", Status: "ok"}, {Name: "b", Status: "ok"}}, Archives: []ArchiveJSON{{Bytes: 3 << 30}}}
		if d == 0 {
			s.LogClears, s.Systems[1].Status = 1, "silent"
			s.Detections = []Detection{{Severity: "high"}, {Severity: "medium"}}
		}
		write(name, s)
		checks[name] = ReportCheck{State: "ok"}
		if d == 12 {
			checks[name] = ReportCheck{State: "changed", What: "logs-ubu-ws-04.zip is missing"}
		}
	}
	write("2026-10-07_1440_ENG-NET_manual", Summary{Interim: true, WindowStart: day, WindowEnd: day.Add(14*time.Hour + 40*time.Minute), Hosts: []string{"a", "b"},
		Events: 30, Reason: "jlee incident check", Detections: []Detection{{Severity: "high"}}})
	gone := MissingReport{Name: "2026-09-01_0000_ENG-NET", From: day.AddDate(0, 0, -37), To: day.AddDate(0, 0, -36), Problem: "missing",
		Accepted: "Accepted as moved by alice on 3 Sep 2026: moved to the archive drive"}
	err := WriteIndexWith(dir, IndexOptions{Site: "ENG-NET", Schedule: "daily at 00:00", Every: "daily", Loc: loc, Checks: checks,
		Missing: []MissingReport{gone}, Next: day.AddDate(0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	h := string(b)
	if out := os.Getenv("BLACKBOX_INDEX_OUT"); out != "" {
		os.WriteFile(out, b, 0o644) // to look at in a browser
	}
	for _, want := range []string{
		"<b>Wed 7 Oct</b><span class=\"d\">1 high · 1 medium · <a href=\"2026-10-08_0000_ENG-NET/report.html\">Open →</a>",
		"<b>Thu 8 Oct 00:00</b><span class=\"d\">daily · each covers the day before",
		`<b class="bad">1 changed</b><span class="d">29 OK · 1 accepted as deleted · checked daily`,
		"<b>31 reports</b><span class=\"d\">30 daily, 1 manual · ",
		">October 2026</th>", ">September 2026</th>", ">August 2026</th>",
		`Wed 7 Oct 00:00 – 14:40</a><span class="int">Manual</span>`, `<span class="why">jlee incident check</span>`,
		`Wed 7 Oct</a><span class="latest">Latest</span>`, "1 log cleared · 1 silent", ">1/2<", ">3.0 GB<",
		`<span class="rxchk ok">✓ OK</span>`, `<span class="rxchk bad" title="Changed after it was written: logs-ubu-ws-04.zip is missing">Changed</span>`,
		"logs-ubu-ws-04.zip missing", `<span class="rxchk mute">Accepted</span>`, "Accepted as moved by alice",
		"All 32</button>", "Scheduled 31</button>", "Manual 1</button>", "With high 2</button>", "Problems 2</button>",
		"12 older reports", "Show older ↓", "Export list CSV",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("index lacks %q", want)
		}
	}
	if strings.Count(h, "data-older hidden") < 12 || strings.Contains(h, "Kept for") || strings.Contains(h, "calendar") {
		t.Error("older rows, or a calendar")
	}
	// The newest month first, the manual report above the day it is in.
	if strings.Index(h, "October 2026") > strings.Index(h, "September 2026") {
		t.Error("order")
	}
}

// Trends' links to Search use only the parameters Search reads (app.js,
// docs/reports.md) and event pages that exist.
func TestTrendsSearchLinks(t *testing.T) {
	r, _ := demo30(t)
	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	view := between2(string(b), `<section class="view" data-view="trends">`, `</section>`)
	ok := map[string]bool{"page": true, "user": true, "host": true, "role": true, "sev": true, "when": true, "at": true, "span": true, "text": true,
		"event": true, "sub": true, "flag": true, "not": true, "group": true, "sort": true, "preset": true}
	pages := map[string]bool{}
	for _, p := range eventPages() {
		pages[p.ID] = true
	}
	n := 0
	for _, part := range strings.Split(view, `href="#search?`)[1:] {
		q, _, _ := strings.Cut(part, `"`)
		q = strings.ReplaceAll(q, "&amp;", "&")
		n++
		for _, kv := range strings.Split(q, "&") {
			k, v, _ := strings.Cut(kv, "=")
			if !ok[k] {
				t.Errorf("Search has no %q parameter: #search?%s", k, q)
			}
			if k == "page" && !pages[v] {
				t.Errorf("no event page %q: #search?%s", v, q)
			}
			if k == "when" && v != "%40after" && v != "@after" {
				t.Errorf("when=%s: #search?%s", v, q)
			}
		}
	}
	if n < 5 {
		t.Errorf("only %d Search links on Trends", n)
	}
}
