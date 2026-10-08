package report

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The owner's answers to UI-R1's open questions: five kinds of event,
// and one rule for a system's problem on Overview and Systems.

// Events by kind: the sidebar and Search's Kind show the five kinds, each
// counting the parts it holds.
func TestFiveEventKinds(t *testing.T) {
	r, _ := demo30(t)
	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	pages, _, err := r.buildData()
	if err != nil {
		t.Fatal(err)
	}
	part := map[string]int{}
	for _, p := range pages {
		part[p.ID] = p.Total
	}
	kinds := eventKinds(pages)
	want := []struct {
		id, title string
		n         int
	}{
		{"privileged", "Privileged activity", part["privileged"] + part["accounts"]},
		{"integrity", "Audit integrity", part["integrity"]},
		{"logons", "Logon activity", part["logons"] + part["failed"]},
		{"other", "Other security", part["other"] + part["usb"]},
		{"powershell", "PowerShell", part["powershell"]},
	}
	if len(kinds) != len(want) {
		t.Fatalf("%d kinds", len(kinds))
	}
	for i, w := range want {
		if k := kinds[i]; k.ID != w.id || k.Title != w.title || k.Total != w.n {
			t.Errorf("kind %d: %s %q %d, want %s %q %d", i, k.ID, k.Title, k.Total, w.id, w.title, w.n)
		}
	}
	if part["failed"] == 0 || part["accounts"] == 0 || part["usb"] == 0 {
		t.Errorf("the demo has no failed logons, account changes or USB events: %v", part)
	}

	b, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	h := string(b)
	nav := between2(h, `<nav aria-label="Events by kind">`, `</nav>`)
	got := regexp.MustCompile(`<a href="#(\w+)" data-nav="\w+">.*?<span>([^<]+)</span><small>([\d,]+)</small></a>`).FindAllStringSubmatch(nav, -1)
	if len(got) != 5 {
		t.Fatalf("sidebar: %d kinds: %s", len(got), nav)
	}
	for i, w := range want {
		if got[i][1] != w.id || got[i][2] != w.title || got[i][3] != commas(w.n) {
			t.Errorf("sidebar %d: %v, want %s %s %s", i, got[i][1:], w.id, w.title, commas(w.n))
		}
	}
	sel := between2(h, `<select data-q="page" aria-label="Kind">`, `</select>`)
	opts := regexp.MustCompile(`<option value="(\w*)">`).FindAllStringSubmatch(sel, -1)
	var ids []string
	for _, o := range opts {
		ids = append(ids, o[1])
	}
	if strings.Join(ids, ",") != ",privileged,integrity,logons,other,powershell" {
		t.Errorf("Search's Kind: %v", ids)
	}
	for _, id := range []string{"failed", "usb", "accounts"} {
		if strings.Contains(h, `data-view="`+id+`"`) {
			t.Errorf("a page %q still", id)
		}
	}
}

// No link anywhere in the report goes to a page that is now part of a
// kind (#failed, #usb, #accounts), or searches one as a kind (page=failed);
// links to one part say part= on its kind.
func TestNoLinksToOldKindPages(t *testing.T) {
	r, _ := demo30(t)
	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	h := strings.ReplaceAll(string(b), "&amp;", "&")
	old := regexp.MustCompile(`href="#(failed|usb|accounts)\b|[?&]page=(failed|usb|accounts)\b`)
	if m := old.FindAllString(h, 5); len(m) > 0 {
		t.Errorf("links to removed pages: %v", m)
	}
	// The demo's Trends and People link to failed logons and USB events.
	for _, want := range []string{"page=logons&part=failed", "page=other&part=usb", `href="#privileged?part=accounts"`} {
		if !strings.Contains(h, want) {
			t.Errorf("no link with %s", want)
		}
	}
	for _, c := range []struct{ got, want string }{
		{partPage("failed"), "#logons?part=failed"}, {partPage("usb"), "#other?part=usb"}, {partPage("accounts"), "#privileged?part=accounts"},
		{partPage("integrity"), "#integrity"}, {partLink("failed", "host", "A"), "#search?host=A&page=logons&part=failed"},
		{partLink("powershell", "host", "A"), "#search?host=A&page=powershell"},
	} {
		if c.got != c.want {
			t.Errorf("%s, want %s", c.got, c.want)
		}
	}
	// app.js opens the old pages on their kind with part= set.
	for id, kind := range map[string]string{"failed": "logons", "usb": "other", "accounts": "privileged"} {
		if partKind(id) != kind {
			t.Errorf("%s is under %s", id, partKind(id))
		}
	}
	for _, want := range []string{"function movedTo(id)", "p.part = p.page", "'Bad password': 'Failed: bad password'", "'Created': 'Account created'", "'Blocked': 'USB blocked'"} {
		if !strings.Contains(appJS, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	// Each absorbed part's sub-kinds say what they were.
	for id, prefix := range map[string]string{"failed": "Failed: ", "usb": "USB ", "accounts": "Account "} {
		for _, e := range r.Events {
			p := &EventPage{ID: id}
			for _, q := range eventPages() {
				if q.ID == id {
					p = q
				}
			}
			if p.on(e) && !strings.HasPrefix(pageSpecs[id].kindOf(e), prefix) {
				t.Errorf("%s: %s is %q", id, e.Action, pageSpecs[id].kindOf(e))
			}
		}
	}
}

// A problem is a red check or a high detection, on Overview's Systems at
// a glance and on Systems alike (owner, UI-R1): the two pages classify
// every system the same, and their counts agree.
func TestProblemsAgreeOverviewSystems(t *testing.T) {
	r, _ := demo30(t)
	pages, _, err := r.buildData()
	if err != nil {
		t.Fatal(err)
	}
	o := r.overview(pages)
	sp := r.systemsPage()
	sys := map[string]string{}
	for _, g := range sp.Groups {
		for _, v := range g.Systems {
			if v.Level != "retired" {
				sys[v.Name] = v.Level
			}
		}
	}
	if len(sys) != 30 || len(o.levels) != 30 {
		t.Fatalf("%d systems on Systems, %d on Overview", len(sys), len(o.levels))
	}
	n := map[string]int{}
	for name, lv := range sys {
		n[lv]++
		if o.levels[name] != lv {
			t.Errorf("%s: %s on Overview, %s on Systems", name, o.levels[name], lv)
		}
	}
	glance := map[string]GlanceRow{}
	for _, g := range o.Glance {
		for _, row := range g.Items {
			glance[row.Name] = row
		}
	}
	if len(glance) != n["bad"] || sp.Bad != n["bad"] || sp.Warn != n["warn"] || sp.OK != n["ok"] {
		t.Errorf("glance %d; Systems %d / %d / %d; levels %v", len(glance), sp.Bad, sp.Warn, sp.OK, n)
	}
	more := fmt.Sprintf("%d more systems with no problems (%d with warnings, %d all OK).", n["warn"]+n["ok"], n["warn"], n["ok"])
	if o.GlanceMore != more {
		t.Errorf("GlanceMore %q, want %q", o.GlanceMore, more)
	}
	for name, lv := range sys {
		if _, ok := glance[name]; ok != (lv == "bad") {
			t.Errorf("%s (%s) on the glance: %v", name, lv, ok)
		}
	}
	// SRV-DC01: green checks, a high detection: a problem on both, the
	// detection its reason.
	dc := glance["SRV-DC01"]
	for _, c := range dc.Cells {
		if c.Level == "bad" {
			t.Errorf("SRV-DC01 has a red check: %+v", c)
		}
	}
	if sys["SRV-DC01"] != "bad" || dc.Level != "bad" || dc.Reason != "High detection: Group membership added" {
		t.Errorf("SRV-DC01: Systems %s, glance %+v", sys["SRV-DC01"], dc)
	}
	for _, g := range sp.Groups {
		for _, v := range g.Systems {
			if v.Name == "SRV-DC01" && (v.Status != "Problem" || !strings.Contains(v.Chip, "Group membership added")) {
				t.Errorf("SRV-DC01 on Systems: %s %q", v.Status, v.Chip)
			}
		}
	}
	// The rule itself.
	for _, c := range []struct {
		cells     []string
		high, med int
		want      string
	}{
		{[]string{"ok", "ok"}, 0, 0, "ok"}, {[]string{"ok", "warn"}, 0, 0, "warn"}, {[]string{"ok", "bad"}, 0, 0, "bad"},
		{[]string{"ok", "ok"}, 1, 0, "bad"}, {[]string{"ok", "ok"}, 0, 1, "warn"}, {[]string{"bad"}, 0, 1, "bad"}, {[]string{"", ""}, 0, 0, "ok"},
	} {
		var cs []CheckCell
		for _, l := range c.cells {
			cs = append(cs, CheckCell{Level: l})
		}
		if got := systemLevel(cs, c.high, c.med); got != c.want {
			t.Errorf("%v %d high %d med: %s, want %s", c.cells, c.high, c.med, got, c.want)
		}
	}
}
