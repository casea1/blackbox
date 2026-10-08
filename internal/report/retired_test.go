package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// ROLE1b: a system retired with "blackbox systems remove" during the
// period is shown as retired, when and by whom; it is not counted in
// Systems reporting or Health, not expected to have original logs, and
// its card does not say it collected nothing next to its events.
func TestRetiredSystem(t *testing.T) {
	end := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -7)
	retiredAt := time.Date(2026, 10, 7, 9, 30, 0, 0, time.UTC)
	var events []*event.Event
	for i := 0; i < 4; i++ {
		events = append(events, &event.Event{Time: start.Add(time.Duration(i) * time.Hour), Host: "WS-07", OS: "windows", Category: event.CatLogon,
			Severity: event.SevInfo, Action: "logon", User: "claude", Summary: "claude logged on."})
	}
	events = append(events, &event.Event{Time: end.Add(-time.Hour), Host: "WIN11", OS: "windows", Category: event.CatLogon,
		Severity: event.SevInfo, Action: "logon", User: "claude", Summary: "claude logged on."})
	var runs []*store.Run
	for d := 0; d < 7; d++ {
		runs = append(runs, &store.Run{Time: start.AddDate(0, 0, d).Add(time.Hour), Host: "WIN11", OS: "windows"})
	}
	r := Build(events, runs, Options{Location: time.UTC, WindowStart: start, WindowEnd: end, Generated: end.Add(time.Minute), Collector: true,
		ArchivesKept: true, Archives: []ArchiveRef{{Host: "WIN11", From: start, To: end, Name: "logs-WIN11.zip"}},
		Systems: []SystemInfo{{Name: "WIN11", OS: "windows", LastRun: end.Add(-time.Hour)},
			{Name: "WS-07", OS: "windows", LastRun: start.Add(-time.Hour), LastReceived: start.Add(-time.Hour), Removed: retiredAt, RemovedBy: "alice"}}})

	if len(r.SystemRows) != 1 || len(r.Retired) != 1 || r.Retired[0].Status != "retired" || r.Retired[0].Events != 4 {
		t.Fatalf("rows %+v, retired %+v", r.SystemRows, r.Retired)
	}
	if n := r.SystemsNeedingAttention(); n != 0 || len(r.Silent) != 0 {
		t.Errorf("needing attention %d, silent %v", n, r.Silent)
	}
	if len(r.NoArchive) != 0 {
		t.Errorf("original logs missing: %v", r.NoArchive)
	}
	o := r.overview(nil)
	for _, k := range o.KPIs {
		if k.Label == "Systems reporting" && k.Value != "1 / 1" {
			t.Errorf("systems reporting %q", k.Value)
		}
	}
	if o.Alert != "" {
		t.Errorf("alert: %s %s", o.Alert, o.AlertDetail)
	}
	for _, c := range o.Checks {
		if strings.Contains(c.Who, "WS-07") || c.Title == "Original logs missing" {
			t.Errorf("health: %+v", c)
		}
	}
	if hp := r.healthPage(); hp != nil {
		for _, g := range hp.Groups {
			for _, row := range g.Rows {
				if row.Name == "WS-07" {
					t.Errorf("audit health lists the retired system")
				}
			}
		}
	}

	sp := r.systemsPage()
	var v *SystemView
	for _, g := range sp.Groups {
		for _, s := range g.Systems {
			if s.Name == "WS-07" {
				if g.Title != "Retired" {
					t.Errorf("in group %s", g.Title)
				}
				v = s
			}
		}
	}
	if v == nil {
		t.Fatal("no card for the retired system")
	}
	if v.Status != "Retired" || v.Level != "retired" || !strings.Contains(v.Line, "retired 7 Oct by alice") {
		t.Errorf("card: %+v", v)
	}
	for _, f := range v.Facts {
		if f.Value == "nothing" || f.Level != "" {
			t.Errorf("fact %+v", f)
		}
	}
	if len(v.Health) != 1 || !strings.HasPrefix(v.Health[0].What, "Retired 7 Oct by alice with blackbox systems remove") {
		t.Errorf("health: %+v", v.Health)
	}
	if c := r.Crumb(); !strings.Contains(c, " · 1 system + 1 retired · ") {
		t.Errorf("crumb: %s", c)
	}
	var b bytes.Buffer
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `<span class="schip retired">Retired 7 Oct</span>`) {
		t.Error("the page does not mark it retired")
	}
}

// UI21: a detection Blackbox's own check made when it bundled the
// original logs says so, has no empty panels, and is labelled "found when
// this report was made" rather than timed after the period.
func TestBundlingDetectionWording(t *testing.T) {
	end := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -7)
	r := Build([]*event.Event{{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo,
		Action: "logon", User: "claude", Summary: "claude logged on."}}, nil,
		Options{Location: time.UTC, WindowStart: start, WindowEnd: end, Generated: end.Add(2 * time.Minute), ArchivesKept: true,
			Archives: []ArchiveRef{{Host: "WS-07", From: start, To: end, Name: "logs-WS-07.zip",
				Changed: []archive.FileInfo{{Name: "Security.evtx", Source: "Security", Changed: true}}}},
			Systems: []SystemInfo{{Name: "WS-07", OS: "windows", LastRun: end.Add(-time.Hour)}}})
	var c *DetectionCard
	for _, x := range r.detectionCards() {
		if x.Title == "Saved original log changed before it was archived" {
			c = &x
		}
	}
	if c == nil || c.Day != FoundAtReport || c.Time != "" || !strings.HasPrefix(c.Detail, "Blackbox's own check, when it bundled WS-07's original logs for this report, found") {
		t.Fatalf("card: %+v", c)
	}
	var v *DetectionView
	for _, x := range r.detectionViews() {
		if x.Index == c.Index {
			v = &x
		}
	}
	if v == nil || !strings.Contains(v.Range, "found when this report was made (Thu 8 Oct 2026, 00:02)") || len(v.Steps) != 1 ||
		!strings.Contains(v.Steps[0].Text, "Blackbox's own check of the saved original logs when it bundled them") {
		t.Fatalf("view: %+v", v)
	}
	var labels []string
	for _, kv := range v.Involved {
		labels = append(labels, kv.Label+"="+kv.Value)
	}
	if strings.Join(labels, "; ") != "System=WS-07; Found by=Blackbox; Log=Security; File=Security.evtx in logs-WS-07.zip" {
		t.Errorf("involved: %v", labels)
	}
	var b bytes.Buffer
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "The events behind this detection are not in this report") || strings.Contains(b.String(), "<span>WS-07 · </span>") {
		t.Error("an empty panel or time")
	}
}
