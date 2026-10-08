package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// A one-day manual report with one Security log clear by a person, one
// privileged action by a person and one by a service.
func uxReport(t *testing.T) (*Report, string) {
	t.Helper()
	end := time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)
	events := []*event.Event{
		{Time: end.Add(-3 * time.Hour), Host: "WS-07", OS: "windows", EventID: 1102, Category: event.CatIntegrity, Severity: event.SevHigh,
			Action: "log_cleared", User: `WS-07\claude`, Target: "Security", Summary: `The Security log was cleared by WS-07\claude.`},
		{Time: end.Add(-2 * time.Hour), Host: "WS-07", OS: "windows", Category: event.CatPrivileged, Severity: event.SevLow,
			Action: "elevated_process", User: `WS-07\claude`, Summary: `WS-07\claude ran with administrator rights: cmd.exe`},
		{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows", Category: event.CatPrivileged, Severity: event.SevLow,
			Action: "elevated_process", User: "SYSTEM", Summary: "SYSTEM ran with administrator rights: svc.exe"},
	}
	runs := []*store.Run{{Time: end.Add(-10 * time.Minute), Host: "WS-07", OS: "windows"}}
	r := Build(events, runs, Options{Location: time.UTC, WindowStart: end.Add(-24 * time.Hour), WindowEnd: end, Generated: end, Interim: true, Period: "weekly"})
	var b bytes.Buffer
	pages, _, err := r.buildData()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteHTML(&b, pages); err != nil {
		t.Fatal(err)
	}
	return r, b.String()
}

// UX6: a High row no detection rule took is a detection of its own, so
// "High" and "Detections" agree; and the words are Detections and Health.
func TestHighRowsAreDetections(t *testing.T) {
	r, h := uxReport(t)
	if len(r.Findings) != 1 || r.Findings[0].Title != "Log cleared on WS-07" || r.Findings[0].Severity != event.SevHigh {
		t.Fatalf("findings: %+v", r.Findings)
	}
	for _, gone := range []string{"Flagged this week", "Notable actions", "something unusual", "Red = flagged"} {
		if strings.Contains(h, gone) {
			t.Errorf("report still says %q", gone)
		}
	}
}

// UX3, UX5: four headline tiles for this report (with Audit health), only
// the counters with something in them, each health problem once; people's
// privileged actions only, as Trends counts them.
func TestOverviewOnce(t *testing.T) {
	r, h := uxReport(t)
	o := r.overview(nil)
	var labels []string
	for _, k := range o.Strip {
		labels = append(labels, k.Label)
	}
	if strings.Join(labels, ",") != "Detections,Systems reporting,Events,Audit settings" {
		t.Errorf("number strip: %v", labels)
	}
	for _, p := range o.Attention {
		if p.Level == "ok" {
			t.Errorf("a fine check listed as a problem: %+v", p)
		}
	}
	if strings.Contains(h, "No new admins") || strings.Contains(h, `class="kpis"`) || strings.Contains(h, `class="hbar"`) {
		t.Error("the Overview still has the tiles, the counters or the health bar (UI-R1)")
	}
	if strings.Contains(h, `class="alertbar">`) || strings.Contains(h, `class="sys2"`) {
		t.Error("the Overview still has the alert bar or system tiles")
	}
	if n := r.metrics()[MPrivileged]; n != 1 {
		t.Errorf("privileged actions %d, want 1 (people only)", n)
	}
}

// UX4: a page with no events is one line; a period of a day is charted by
// hour, with no "Above normal" (nothing to compare with).
func TestEmptyAndShortPages(t *testing.T) {
	_, h := uxReport(t)
	if !strings.Contains(h, "Nothing on USB &amp; removable this period.") {
		t.Error("an empty page is not one line")
	}
	if strings.Contains(h, `data-events="usb"`) {
		t.Error("an empty page still has its table")
	}
	if !strings.Contains(h, "per hour</h2>") || strings.Contains(h, "Above normal") {
		t.Error("one-day chart")
	}
}

// UX9: a short sidebar; empty kinds of event are left out of it and of
// Search; after the Overview, a manual report says so in a chip.
func TestNavigation(t *testing.T) {
	_, h := uxReport(t)
	if strings.Contains(h, `href="#usb" data-nav="usb"`) {
		t.Error("an empty kind of event is in the sidebar")
	}
	if !strings.Contains(h, `data-cat="privileged"`) || strings.Contains(h, `data-cat="usb"`) {
		t.Error("Search category chips")
	}
	if strings.Count(h, "<b>Manual report.</b>") != 1 || !strings.Contains(h, `class="chip-manual"`) {
		t.Error("manual banner once, chip after it")
	}
}
