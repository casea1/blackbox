package report

import (
	"html/template"
	"strings"
	"testing"
)

// UI-R1 final check: a person's "Accounts named" table wraps
// "HOST\account" after the backslash, never inside the name, so the
// Last column is not cut off at 1440 px.
func TestPeopleAccountWrapsAfterHost(t *testing.T) {
	r, _ := demo30(t)
	html, _ := renderHTML(t, r)
	if want := `<span class="an">SRV-DC01\</span><wbr><span class="an">adm-jlee</span>`; !strings.Contains(html, want) {
		t.Errorf("no %s in the Accounts named table", want)
	}
	if !strings.Contains(styleCSS, ".pacc .an{white-space:nowrap}") {
		t.Error("the account's parts can break inside a name")
	}
	f := funcs(nil)["acctBreak"].(func(string) template.HTML)
	for in, want := range map[string]template.HTML{
		`WS-01\<b>`: `<span class="an">WS-01\</span><wbr><span class="an">&lt;b&gt;</span>`,
		`root`:      `root`,
		`a&b`:       `a&amp;b`,
	} {
		if got := f(in); got != want {
			t.Errorf("acctBreak(%q) = %q, want %q", in, got, want)
		}
	}
}

// UI-R1 final check: Search's box keeps room for its placeholder; the
// "searches every field" hint is cut short instead.
func TestSearchBoxKeepsPlaceholder(t *testing.T) {
	for _, want := range []string{".sq-text input{min-width:64px}", ".sq-hint{min-width:0;overflow:hidden;text-overflow:ellipsis}"} {
		if !strings.Contains(styleCSS, want) {
			t.Errorf("style.css has no %s", want)
		}
	}
}

// UI-R1 final check: "Detections involving <person>" is a summary list,
// so each reason is one line (the whole of it on hover and on Detections).
func TestPeopleDetectionReasonOneLine(t *testing.T) {
	if !strings.Contains(styleCSS, ".dl .dc .b span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}") {
		t.Error("a person's detection reasons are not cut to one line")
	}
	r, _ := demo30(t)
	html, _ := renderHTML(t, r)
	if !strings.Contains(html, `<span title="root moved the clock on ubu-ws-03 back by 8 minutes`) {
		t.Error("the full reason is not on hover")
	}
}

// UI-R1 final check: going to another page (Back, a bookmark) closes the
// event panel; it stayed open over the new page. scripts/browsercheck.js
// checks it in a browser.
func TestEventPanelClosesOnNavigation(t *testing.T) {
	if !strings.Contains(appJS, "window.addEventListener('hashchange', function () { closeEvent(); show(); });") {
		t.Error("a page change leaves the event panel open")
	}
}
