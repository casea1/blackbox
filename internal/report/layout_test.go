package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// UI6: the All reports Period column shows one date for a whole day, times
// for a period that starts or ends during a day, and dates otherwise.
func TestPeriodLabel(t *testing.T) {
	d := func(day, h, m int) time.Time { return time.Date(2026, 10, day, h, m, 0, 0, time.UTC) }
	for _, c := range []struct {
		from, to time.Time
		want     string
	}{
		{d(5, 0, 0), d(6, 0, 0), "5 Oct 2026"},
		{d(5, 0, 0), d(5, 6, 44), "5 Oct 00:00 – 06:44"},
		{time.Date(2026, 9, 14, 13, 40, 0, 0, time.UTC), time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC), "14 Sep 13:40 – 15 Sep 00:00"},
		{time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC), d(5, 0, 0), "28 Sep – 4 Oct 2026"},
		{d(1, 0, 0), d(8, 0, 0), "1 – 7 Oct 2026"},
		{time.Date(2025, 12, 29, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), "29 Dec 2025 – 4 Jan 2026"},
	} {
		if got := periodLabel(c.from, c.to, time.UTC); got != c.want {
			t.Errorf("%v – %v: %q, want %q", c.from, c.to, got, c.want)
		}
	}
	// The same number format everywhere: "95,229 events lost", not "95229".
	row := indexRow(IndexEntry{Summary: Summary{WindowStart: d(5, 0, 0), WindowEnd: d(6, 0, 0), Events: 3130, Lost: 95229}}, time.UTC)
	if row.Trail != "95,229 events lost" || row.Week != "5 Oct 2026" {
		t.Errorf("row: %+v", row)
	}
	if plural(1, "run") != "1 run" || plural(3841, "run") != "3,841 runs" {
		t.Error("plural")
	}
}

// UI3, UI7: the health grid is full width with short headings (full names
// on hover) and Gaps below it; the log size box says what it holds;
// Overview tiles carry the full name; the page header keeps its buttons
// beside the title.
func TestLayoutFixes(t *testing.T) {
	r := build(t, Options{Collector: true})
	var b bytes.Buffer
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	if len(r.Hosts) == 0 || !strings.Contains(h, `title="`+r.Hosts[0]+` · `) {
		t.Errorf("an Overview tile lacks its full name on hover")
	}
	for _, want := range []string{`<th title="Removable storage">USB</th>`, `<th title="Log size and space settings">Log size</th>`,
		`data-scrollcue`, `class="morecue"`, `class="dl gapgrid"`, "Log size and space settings"} {
		if !strings.Contains(h, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(h, "Logs too small") || strings.Contains(h, `grid-template-columns:1.45fr 1fr`) {
		t.Error("old health layout")
	}
	if i, j := strings.Index(h, `id="h-matrix"`), strings.Index(h, `id="h-gaps"`); i < 0 || j < i {
		t.Error("Gaps should follow the grid")
	}
}

// UI5: a manual report's Original logs page has no empty tiles; with or
// without what waits, it says the next scheduled report holds the logs.
func TestManualLogsPage(t *testing.T) {
	r := build(t, Options{Interim: true})
	lp := r.logsPage()
	if !lp.Manual || len(lp.Stats) != 0 || !strings.Contains(lp.Waiting, "they stay where Blackbox keeps them, and the next scheduled report holds them") {
		t.Errorf("no waiting info: %+v", lp)
	}
	r = build(t, Options{Interim: true, Waiting: &WaitingLogs{Dir: `D:\BlackboxLogs`, From: time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC),
		To: time.Date(2026, 9, 28, 23, 0, 0, 0, time.UTC), Bytes: 3 << 20, Systems: 1}})
	if w := r.logsPage().Waiting; !strings.Contains(w, `they wait in D:\BlackboxLogs. So far they cover 2026-09-28 00:00 to 2026-09-28 23:00, 3 MB from 1 system. The next scheduled report holds them`) {
		t.Errorf("waiting: %s", w)
	}
	// A scheduled report keeps its page.
	if lp := build(t, Options{ArchivesKept: true}).logsPage(); lp.Manual || len(lp.Stats) != 4 {
		t.Errorf("scheduled: %+v", lp)
	}
}

// A failing checklist line says what went wrong: never "No events lost to
// log rollover" above "95,229 events were overwritten", on the Overview or
// a system's health list. Passing lines keep their wording.
func TestChecklistTitlesMatchResult(t *testing.T) {
	end := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	runs := []*store.Run{{Time: end.Add(-2 * time.Hour), Host: "WS-07", OS: "windows",
		Channels: []store.ChannelRun{{Channel: "Security", Read: 10, Gap: &store.Gap{Lost: 95229, From: end.Add(-5 * time.Hour), To: end.Add(-3 * time.Hour)}}}}}
	cleared := &event.Event{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows", Category: event.CatIntegrity, Severity: event.SevHigh,
		Action: "log_cleared", User: "mallory", Summary: "mallory cleared the Security log."}
	cs := NewCheckSet("WS-07", end.Add(-3*time.Hour), []check.Result{{Area: "Audit policy", Item: "Logon", Status: check.Fail, Want: "Success and Failure", Have: "Success"}})
	r := Build([]*event.Event{cleared}, runs, Options{WindowStart: end.AddDate(0, 0, -1), WindowEnd: end, Location: time.UTC, Source: "Live collection", Collector: true,
		Systems: []SystemInfo{{Name: "WS-07", OS: "windows"}, {Name: "WS-09", OS: "windows", LastRun: end.AddDate(0, 0, -3)}}, CheckSets: []CheckSet{cs}})
	healthy := map[string]bool{"Logs intact": true, "Every system reporting": true, "Audit settings match STIG": true,
		"No events lost to log rollover": true, "Original logs archived": true, "Reports on time": true, "Antivirus definitions current": true}
	overview := r.overview(nil).Checks
	lines := overview
	for _, sp := range r.systemsPage().Groups {
		for _, v := range sp.Systems {
			lines = append(lines, v.Health...)
		}
	}
	for _, l := range lines {
		if l.Level != "ok" && healthy[l.Title] {
			t.Errorf("failing line titled as if it passed: %q — %s", l.Title, l.What)
		}
	}
	got := map[string]CheckLine{}
	for _, l := range overview {
		got[l.Title] = l
	}
	if l := got["Events lost to log rollover"]; l.Who != "WS-07" || l.What != "95,229 events overwritten before they were collected" || l.Href == "" {
		t.Errorf("rollover line: %+v", l)
	}
	for _, want := range []string{"Logs cleared", "Not every system reporting", "Audit settings to fix"} {
		if l, ok := got[want]; !ok || l.Href == "" || l.Href == "#health" && want != "Audit settings to fix" {
			t.Errorf("missing or unlinked %q: %+v", want, l)
		}
	}
}

// SCAP: each system's operating-system STIG is shown; its other
// benchmarks (browsers, Defender) are behind a click, unless the system has
// no operating-system scan.
func TestScapOSFirst(t *testing.T) {
	for title, want := range map[string]bool{
		"Microsoft Windows 11 Security Technical Implementation Guide": true, "Canonical Ubuntu 24.04 LTS STIG SCAP Benchmark": true,
		"Microsoft Windows Server 2025 STIG": true, "Red Hat Enterprise Linux 8 STIG": true, "AlmaLinux OS 9 STIG": true,
		"Microsoft Edge Security Technical Implementation Guide": false, "Mozilla Firefox STIG": false,
		"Microsoft Defender Antivirus STIG": false, "Microsoft Windows Defender Firewall with Advanced Security STIG": false,
		"Microsoft Windows Server 2022 DNS STIG": false,
	} {
		if osBenchmark(title) != want {
			t.Errorf("%s: %v", title, !want)
		}
	}
	r := &Report{scapTable: []ScapRow{
		{Host: "WS-01", Benchmark: "Microsoft Windows 11 STIG V2R5"}, {Host: "WS-01", Benchmark: "Microsoft Edge STIG V2R2"},
		{Host: "WS-01", Benchmark: "Mozilla Firefox STIG V6R6"}, {Host: "ubu-01", Benchmark: "Canonical Ubuntu 24.04 LTS STIG V1R2"},
		{Host: "kiosk", Benchmark: "Microsoft Edge STIG V2R2"}, {Host: "WS-09", Missing: true}}}
	v := r.scapView()
	var main, other []string
	for _, row := range v.Main {
		main = append(main, row.Host+" "+row.Benchmark)
	}
	for _, row := range v.Other {
		other = append(other, row.Host+" "+row.Benchmark)
	}
	if strings.Join(main, "|") != "WS-01 Microsoft Windows 11 STIG V2R5|ubu-01 Canonical Ubuntu 24.04 LTS STIG V1R2|kiosk Microsoft Edge STIG V2R2" ||
		len(v.Missing) != 1 || v.Missing[0] != "WS-09" ||
		strings.Join(other, "|") != "WS-01 Microsoft Edge STIG V2R2|WS-01 Mozilla Firefox STIG V6R6" || v.OtherNames != "Microsoft Edge, Mozilla Firefox" {
		t.Errorf("main %q\nother %q (%s)", main, other, v.OtherNames)
	}
}

// Audit health: systems that match on every check are folded under a
// button, and a bar links to each section, so Antivirus and SCAP are in
// reach without scrolling past every system.
func TestHealthFoldAndJump(t *testing.T) {
	ok, bad := Cell{Class: "ok"}, Cell{Class: "bad"}
	hp := &HealthPage{Groups: []HealthGroup{{Title: "Workstations", Rows: []*HealthRow{
		{Name: "WS-05", Cells: []Cell{ok, bad}}, {Name: "WS-01", Cells: []Cell{ok, {Class: "na"}}}, {Name: "WS-02", Cells: []Cell{ok, ok}}}}},
		Gaps: []GapCard{{}}, AV: []AVRow{{Level: "bad"}, {Level: "ok"}}, Scap: &ScapView{Main: []ScapRow{{Cat: [4]int{0, 2}}}, Missing: []string{"WS-09"}}}
	hp.fold()
	if len(hp.Attention) != 1 || len(hp.Attention[0].Rows) != 1 || hp.Attention[0].Rows[0].Name != "WS-05" || hp.PassingN != 2 {
		t.Errorf("fold: %+v %d", hp.Attention, hp.PassingN)
	}
	var jump []string
	for _, j := range hp.Jump {
		jump = append(jump, j.Label+": "+j.Note+" #"+j.Target)
	}
	if strings.Join(jump, "\n") != "Audit settings by system: 1 of 3 need attention #h-matrix\nGaps: 1 #h-gaps\nAntivirus: 1 out of date #h-av\nSTIG compliance (SCAP): 2 open CAT I · 1 not scanned #h-scap" {
		t.Errorf("jump:\n%s", strings.Join(jump, "\n"))
	}
	r := build(t, Options{Collector: true})
	var b bytes.Buffer
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	for _, want := range []string{"Audit settings by system", `class="jump"`, `data-scroll="h-matrix"`, `data-scroll="h-gaps"`} {
		if !strings.Contains(h, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(h, "Every system, every check") {
		t.Error("old heading")
	}

	// The SCAP table names unscanned systems in one line, with the count.
	r = build(t, Options{Collector: true, ScapEnabled: true})
	b.Reset()
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	if want := "No scan found</span> for " + plural(len(r.Hosts), "system") + ":"; !strings.Contains(b.String(), want) {
		t.Errorf("report lacks %q", want)
	}
}
