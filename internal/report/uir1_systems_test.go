package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// UI-R1 Systems (designs 04 and 05) on the 30-system network: one table
// grouped Servers / Workstations, worst first, six check squares; and one
// system with its chip, six facts, collection strip, checks, detections,
// activity, who was active and events by kind.
func TestSystemsUIR1(t *testing.T) {
	r, _ := demo30(t)
	sp := r.systemsPage()
	if len(sp.Groups) != 2 || sp.Groups[0].Label() != "Servers · 11" || sp.Groups[1].Label() != "Workstations · 19" {
		t.Fatalf("groups: %v %v", sp.Groups[0].Label(), sp.Groups[len(sp.Groups)-1].Label())
	}
	if sp.All != 30 || sp.Bad+sp.Warn+sp.OK != 30 || sp.Bad == 0 || sp.Crumb != "30 systems · 28 reporting" {
		t.Errorf("counts: all %d, %d / %d / %d, crumb %q", sp.All, sp.Bad, sp.Warn, sp.OK, sp.Crumb)
	}
	by := map[string]*SystemView{}
	for _, g := range sp.Groups {
		last := -1
		for _, v := range g.Systems {
			by[v.Name] = v
			if levelRank(v.Level) < last {
				t.Errorf("%s: %s after a better one", g.Title, v.Name)
			}
			last = levelRank(v.Level)
			if len(v.Cells) != 6 {
				t.Errorf("%s: %d cells", v.Name, len(v.Cells))
			}
		}
	}
	dc := by["SRV-DC02"]
	if dc.Level != "bad" || dc.Chip != "Problem: Security log cleared" || dc.Group != "Servers" || dc.OS != "Server 2025" ||
		dc.Line != "Windows Server 2025 · server · Dell PowerEdge R650" {
		t.Errorf("SRV-DC02: %q %q %q", dc.Level, dc.Chip, dc.Line)
	}
	if c := dc.Cells[1]; c.Label != "Logs intact" || c.Level != "bad" || c.Title != "Security log cleared at 14:22 by adm-jlee" {
		t.Errorf("logs intact: %+v", c)
	}
	if dc.Checks[0].Level != "bad" {
		t.Error("the checks are not problems first")
	}
	// One cell per expected collection (hourly here), red at the clear.
	red := 0
	for i, c := range dc.Strip {
		if c.Class == "bad" {
			red++
			if i != 14 {
				t.Errorf("the clear is in cell %d", i)
			}
		} else if c.Class != "" {
			t.Errorf("cell %d: %+v", i, c)
		}
	}
	if len(dc.Strip) != 24 || red != 1 || dc.StripNote != "24 of 24" || dc.Every != "every hour" || !dc.StripKey.Clear {
		t.Errorf("strip: %d cells, %d red, %q, %q", len(dc.Strip), red, dc.StripNote, dc.Every)
	}
	labels := []string{}
	for _, f := range dc.Facts {
		labels = append(labels, f.Label)
	}
	if strings.Join(labels, ",") != "Events,Detections,Last collection,Audit settings,SCAP,Original logs" || dc.Facts[1].Value != "1 high" || dc.Facts[1].Level != "bad" {
		t.Errorf("facts: %+v", dc.Facts)
	}
	if len(dc.Detections) != 1 || dc.Detections[0].Level != "bad" || len(dc.Who) != 5 || dc.WhoMore == 0 || len(dc.Kinds) == 0 || dc.Hours == "" {
		t.Errorf("panels: %d detections, %d who (+%d), %d kinds", len(dc.Detections), len(dc.Who), dc.WhoMore, len(dc.Kinds))
	}
	if !strings.Contains(string(dc.Hours), `fill="#D12C2C"`) {
		t.Error("no red dot at the detection's hour")
	}
	// The silent ones: a red Reporting square, grey strip, no logs to check.
	ws := by["WS-ENG-06"]
	if ws.Level != "bad" || ws.Cells[0].Level != "bad" || ws.Cells[1].Level != "" || ws.Chip != "Problem: not reporting" || ws.StripNote != "0 of 24" {
		t.Errorf("WS-ENG-06: %+v %q %q", ws.Cells[:2], ws.Chip, ws.StripNote)
	}
	// Prev / Next follow the list.
	first, second := sp.Groups[0].Systems[0], sp.Groups[0].Systems[1]
	if first.Prev != "" || first.Next != second.Name || second.Prev != first.Name {
		t.Errorf("prev/next: %s %q %q", first.Name, first.Prev, first.Next)
	}

	h, _ := renderHTML(t, r)
	for _, want := range []string{`data-sysfind`, `data-syslv="bad"`, `Problems <b>`, `data-sysos`, `data-syskind`, `<th scope="col" class="c">Orig. logs</th>`,
		`data-sysrow="SRV-DC02"`, `<div data-sys="SRV-DC02" hidden>`, `<a class="link" href="#systems">Systems</a> › Servers › SRV-DC02`,
		`<span class="schip bad">Problem: Security log cleared</span>`, `class="strip" role="img"`, "Audit health →", "Who was active", "Events by kind", "Search this system"} {
		if !strings.Contains(h, want) {
			t.Errorf("Systems lacks %q", want)
		}
	}
	if strings.Contains(between2(h, `<div data-syslist>`, `<div data-sys=`), ">Why<") {
		t.Error("the list has a Why column")
	}
}

// The collection interval is read from the collections: every 15 minutes
// gives 96 cells a day, and a missed one is grey.
func TestCollectionStrip15Min(t *testing.T) {
	end := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -1)
	var runs []*store.Run
	for at := start.Add(10 * time.Minute); at.Before(end); at = at.Add(15 * time.Minute) {
		if at.Hour() == 3 && at.Minute() < 15 {
			continue // one missed
		}
		runs = append(runs, &store.Run{Time: at, Host: "WS-01", OS: "windows"})
	}
	runs = append(runs, &store.Run{Time: end.Add(-time.Hour), Host: "WS-02", OS: "windows"})
	r := Build(nil, runs, Options{WindowStart: start, WindowEnd: end, Generated: end, Location: time.UTC, Source: "Live collection", Collector: true,
		Systems: []SystemInfo{{Name: "WS-01", OS: "windows", FirstSeen: start.AddDate(0, -1, 0)}, {Name: "WS-02", OS: "windows", FirstSeen: start.AddDate(0, -1, 0)}}})
	var v *SystemView
	for _, g := range r.systemsPage().Groups {
		for _, s := range g.Systems {
			if s.Name == "WS-01" {
				v = s
			}
		}
	}
	if v == nil || len(v.Strip) != 96 || v.StripNote != "95 of 96" || v.Every != "every 15 min" || v.Strip[12].Class != "miss" || v.Cells[0].Level != "warn" {
		t.Fatalf("strip: %+v", v)
	}
}
