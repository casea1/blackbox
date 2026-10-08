package report

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// UI-R1 §1: the Overview of the 30-system network (design 01).
func TestOverviewUIR1(t *testing.T) {
	r, _ := demo30(t)
	h, _ := renderHTML(t, r)
	o := r.overview(eventPages())

	if o.Clean || o.Review != "Needs review: 7 high detections, 2 systems not reporting" {
		t.Errorf("review: %q", o.Review)
	}
	if !strings.Contains(o.ReviewDetail, "Security log was cleared") || !strings.Contains(o.ReviewDetail, "ubu-ws-07 and WS-ENG-06 have sent nothing since 6 Oct.") {
		t.Errorf("review detail: %q", o.ReviewDetail)
	}
	var strip []string
	for _, c := range o.Strip {
		strip = append(strip, c.Label+"="+c.Value+"|"+c.Note)
	}
	if got := strings.Join(strip, " "); !strings.HasPrefix(got, "Detections=12|7 high · 5 medium Systems reporting=28 / 30|2 silent Events=") ||
		!strings.Contains(got, "Audit settings=8 / 30|match the STIG · ") {
		t.Errorf("strip: %s", got)
	}

	// Up to 8 detections, high first; the rest counted in the link.
	if len(o.Dets) != 8 || o.Dets[0].Level != "bad" || o.Dets[7].Level != "warn" || o.DetMore != "All 12 detections (4 more medium) →" {
		t.Errorf("detections: %d %+v %q", len(o.Dets), o.Dets, o.DetMore)
	}
	for _, d := range o.Dets {
		if strings.Contains(d.Title, " on "+d.System) || !strings.HasPrefix(d.Href, "#detections/") || len(d.Reason) > 75 {
			t.Errorf("detection line: %+v", d)
		}
	}

	// Needs attention: one line per kind, problems first, systems named
	// when one or two.
	got := map[string]AttnLine{}
	for i, l := range o.Attention {
		got[l.Title] = l
		if i > 0 && levelRank(l.Level) < levelRank(o.Attention[i-1].Level) {
			t.Errorf("not problems first: %+v", o.Attention)
		}
	}
	if l := got["Not reporting"]; l.Count != "ubu-ws-07, WS-ENG-06" || l.Reason != "nothing since 6 Oct" || l.Level != "bad" {
		t.Errorf("not reporting: %+v", l)
	}
	if l := got["Logs cleared"]; l.Count != "SRV-DC02" || l.Reason != "Security log" {
		t.Errorf("logs cleared: %+v", l)
	}
	if l := got["CAT I findings"]; l.Count != "4 systems" {
		t.Errorf("CAT I: %+v", l)
	}
	if l := got["Audit settings"]; l.Count != "22 systems" || !strings.HasSuffix(l.Reason, "settings to fix") {
		t.Errorf("audit settings: %+v", l)
	}
	if !strings.HasPrefix(o.Fine, "Reports on time · No Security or audit-log events lost") || !strings.HasSuffix(o.Fine, "systems reporting normally") {
		t.Errorf("fine: %q", o.Fine)
	}

	// Activity: 24 hours, a click opens Search for that hour, a dot on
	// the hours with a detection.
	a := o.Activity
	if a == nil || len(a.Bars) != 24 || a.Unit != "hour" || a.Total != len(r.rows) {
		t.Fatalf("activity: %+v", a)
	}
	b := a.Bars[14] // 14:00–15:00: the Security log cleared at 14:22
	if !b.Det || b.Href != "#search?when=2026100714" {
		t.Errorf("14:00 bar: %+v", b)
	}
	if !strings.Contains(h, `class="ach"`) || !strings.Contains(h, "24:00</span>") {
		t.Error("no activity chart")
	}
	// Over more than eight days, a bar per day opens Search for that day.
	ws, we := r.WindowStart, r.WindowEnd
	r.WindowStart = time.Date(2026, 9, 28, 0, 0, 0, 0, demo30Zone)
	r.WindowEnd = time.Date(2026, 10, 8, 0, 0, 0, 0, demo30Zone)
	if d := r.activityChart(); d == nil || d.Unit != "day" || len(d.Bars) != 10 || d.Bars[9].Href != "#search?when=20261007" || d.Bars[0].Href != "" {
		t.Errorf("day bars: %+v", d)
	}
	r.WindowStart, r.WindowEnd = ws, we

	// Systems at a glance: only systems with a red check, grouped.
	n := 0
	for _, g := range o.Glance {
		for _, row := range g.Items {
			n++
			red := false
			for _, c := range row.Cells {
				red = red || c.Level == "bad"
			}
			if !red || len(row.Cells) != 6 {
				t.Errorf("glance row: %+v", row)
			}
		}
	}
	if len(o.Glance) != 2 || o.Glance[0].Title != "Servers" || o.Glance[1].Title != "Workstations" || n == 0 || n >= 30 {
		t.Errorf("glance: %d groups, %d rows", len(o.Glance), n)
	}
	if !strings.HasPrefix(o.GlanceMore, strconv.Itoa(30-n)+" more systems with no problems (") || !strings.Contains(h, "All 30 systems on the Systems page →") {
		t.Errorf("glance more: %q", o.GlanceMore)
	}

	// Removed from the Overview.
	ov := between2(h, `<section class="view" data-view="overview">`, `</section>`)
	for _, gone := range []string{`class="kpis"`, `class="hbar"`, "No new admins", "What changed", " of 30 systems", "reporting normally</span>"} {
		if strings.Contains(ov, gone) {
			t.Errorf("the Overview still has %q", gone)
		}
	}
}

// UI-R1 §1: a report with nothing to review says so in green.
func TestOverviewNothingToReview(t *testing.T) {
	end := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	r := Build([]*event.Event{{Time: end.Add(-2 * time.Hour), Host: "WS-01", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo,
		Action: "logon", User: "jdoe", Summary: "jdoe logged on."}}, []*store.Run{{Time: end.Add(-time.Hour), Host: "WS-01"}},
		Options{Location: time.UTC, WindowStart: end.AddDate(0, 0, -1), WindowEnd: end, Generated: end,
			Systems: []SystemInfo{{Name: "WS-01", OS: "windows", LastRun: end.Add(-time.Hour)}}})
	o := r.overview(nil)
	if !o.Clean || o.Review != "Nothing needs review" || len(o.Dets) != 0 {
		t.Errorf("review: %q %v", o.Review, o.Clean)
	}
	h, _ := renderHTML(t, r)
	if !strings.Contains(h, `class="panel ovsum clean2"`) {
		t.Error("not green")
	}
}

// UI-R1 §2: Detections (design 02): filters, the list grouped High /
// Medium, and for one detection four facts, why, what happened around it
// with its own events marked, the Search buttons and related detections.
func TestDetectionsUIR1(t *testing.T) {
	r, _ := demo30(t)
	h, _ := renderHTML(t, r)
	p := r.detectionsPage()
	if len(p.High) != 7 || len(p.Med) != 5 || len(p.Views) != 12 || !p.Kinds {
		t.Fatalf("page: %d high, %d medium", len(p.High), len(p.Med))
	}
	for i := 1; i < len(p.High); i++ {
		if r.Findings[p.High[i].Index].Time.After(r.Findings[p.High[i-1].Index].Time) {
			t.Error("high not newest first")
		}
	}
	var v *DetectionView
	for i := range p.Views {
		if p.Views[i].Title == "Log cleared on SRV-DC02" {
			v = &p.Views[i]
		}
	}
	if v == nil {
		t.Fatal("no log cleared on SRV-DC02")
	}
	var facts []string
	for _, f := range v.Facts {
		facts = append(facts, f.Label+"="+f.Value+"|"+f.Sub)
	}
	if got := strings.Join(facts, " "); got != "System=SRV-DC02|Windows Server 2025 · server Person=adm-jlee|administrator on SRV-DC02 When=7 Oct 14:22:05|EDT (UTC−4) Record=Security 1102|record "+commas(int(r.rows[rowIndex(r.Findings[v.Index].RowID)].RecordID)) {
		t.Errorf("facts: %s", got)
	}
	if !strings.HasPrefix(v.Why, "Clearing a log removes the record of everything before it. The original logs in this report (logs-SRV-DC02.zip) keep a copy up to the last collection") {
		t.Errorf("why: %s", v.Why)
	}
	keys := 0
	for _, l := range v.Timeline {
		if l.Key {
			keys++
		}
	}
	if keys != 1 || len(v.Timeline) < 2 || v.TLHead != "adm-jlee on SRV-DC02, 14:12–14:32" {
		t.Errorf("timeline: %q %+v", v.TLHead, v.Timeline)
	}
	// Open in Search (±10 min): at and span around the log cleared.
	at := strconv.FormatInt(time.Date(2026, 10, 7, 14, 22, 5, 0, demo30Zone).Unix(), 10)
	if v.SearchHref != "#search?at="+at+"&host=SRV-DC02&span=600&user=adm-jlee" ||
		v.PersonHref != "#search?user=adm-jlee" || v.Person != "adm-jlee" {
		t.Errorf("buttons: %s %s", v.SearchHref, v.PersonHref)
	}
	if len(v.Related) != 1 || v.Related[0].System != "SRV-DC01" || v.RelNote != "Same person: adm-jlee. Nothing else on SRV-DC02." {
		t.Errorf("related: %+v %q", v.Related, v.RelNote)
	}
	det := between2(h, `<section class="view" data-view="detections">`, `</section>`)
	for _, want := range []string{`data-detsev`, `data-detf="host"`, `data-detf="user"`, `data-detf="kind"`, `data-dethead="High">High · 7`,
		`data-dethead="Medium">Medium · 5`, "Open in Search (±10 min)", "Everything adm-jlee did", "Related this period"} {
		if !strings.Contains(det, want) {
			t.Errorf("Detections lacks %q", want)
		}
	}
	for _, gone := range []string{"Involved", "Showing the first", "ATT&amp;CK", "Seen before"} {
		if strings.Contains(det, gone) {
			t.Errorf("Detections still has %q", gone)
		}
	}
}
