package event

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// DOC1: the control tags in design.md's event coverage (section 4) are
// the ones in Categories, and design.md uses no other.
func TestControlTagsMatchDesign(t *testing.T) {
	b, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	start, end := strings.Index(doc, "## 4. Event coverage"), strings.Index(doc, "## 5. ")
	if start < 0 || end < start {
		t.Fatal("design.md has no section 4")
	}
	sec := doc[start:end]
	known := map[string]bool{}
	for _, c := range Categories {
		tag := c.Title + " — " + strings.Join(c.Controls, ", ")
		if !strings.Contains(sec, tag) {
			t.Errorf("design.md section 4 lacks %q", tag)
		}
		for _, ctl := range c.Controls {
			known[ctl] = true
		}
	}
	for _, m := range regexp.MustCompile(`\b(?:AC|AU|MP|IA|CM|SI|SC)-\d+(?:\(\d+\))?`).FindAllString(sec, -1) {
		if !known[m] {
			t.Errorf("design.md section 4 tags %s, which no category in event.go has", m)
		}
	}
}
