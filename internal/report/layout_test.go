package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
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
