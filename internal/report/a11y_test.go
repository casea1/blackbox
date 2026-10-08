package report

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/inventory"
)

// UI19: the report passes the accessibility rules axe reported: every
// select has a name; every SVG is a named image or group, or hidden; no
// table row carries aria-expanded (Inventory's toggle is a button); each
// navigation landmark has its own name; headings never skip a level; and
// Audit health names its columns in a key, not only on hover.
func TestAccessibility(t *testing.T) {
	r := build(t, Options{Collector: true})
	end := r.WindowEnd
	cs := NewCheckSet("WS-01", end.Add(-time.Hour), nil)
	cs.Inventory = &inventory.Inventory{Manufacturer: "Dell Inc.", Model: "OptiPlex 7090", Serial: "AAA",
		Drives:   []inventory.Drive{{Model: "Samsung SSD", Serial: "SN-1", Size: 512110190592}},
		Accounts: []inventory.Account{{Name: "localadmin", ID: "…1001", Enabled: true, Admin: true, Kind: "Local"}}}
	r.CheckSets = append(r.CheckSets, cs)
	pages, _, err := r.buildData()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.WriteHTML(&b, pages); err != nil {
		t.Fatal(err)
	}
	h := b.String()

	attr := func(tag, name string) string {
		if m := regexp.MustCompile(`\s` + name + `="([^"]*)"`).FindStringSubmatch(tag); m != nil {
			return m[1]
		}
		return ""
	}
	selects := regexp.MustCompile(`<select[^>]*>`).FindAllString(h, -1)
	if len(selects) < 5 {
		t.Fatalf("%d selects", len(selects))
	}
	for _, s := range selects {
		if attr(s, "aria-label") == "" {
			t.Errorf("select with no name: %s", s)
		}
	}
	svgs := regexp.MustCompile(`<svg[^>]*>`).FindAllString(h, -1)
	if len(svgs) == 0 {
		t.Fatal("no svg")
	}
	for _, s := range svgs {
		role := attr(s, "role")
		if attr(s, "aria-hidden") != "true" && !((role == "img" || role == "group") && attr(s, "aria-label") != "") {
			t.Errorf("svg neither named nor hidden: %s", s)
		}
	}
	if regexp.MustCompile(`<tr[^>]*aria-expanded`).MatchString(h) || !strings.Contains(h, `data-invbtn aria-expanded="false"`) {
		t.Error("aria-expanded on a table row, or the Inventory toggle has none")
	}
	names := map[string]bool{}
	for _, n := range regexp.MustCompile(`<nav[^>]*>`).FindAllString(h, -1) {
		l := attr(n, "aria-label")
		if l == "" || names[l] {
			t.Errorf("navigation with no name of its own: %s", n)
		}
		names[l] = true
	}
	last := 0
	for _, m := range regexp.MustCompile(`<h([1-6])[\s>]`).FindAllStringSubmatch(h, -1) {
		n, _ := strconv.Atoi(m[1])
		if last > 0 && n > last+1 {
			t.Errorf("heading h%d after h%d", n, last)
		}
		last = n
	}
	if !strings.Contains(h, `<p class="pm mxkey"><b>Columns:</b> <span>Accounts</span> Account management · `) ||
		strings.Contains(h, "hover a heading") {
		t.Error("Audit health has no key to its columns")
	}
}
