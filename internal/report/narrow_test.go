package report

import (
	"strings"
	"testing"
	"time"
)

// UI18: a report with no detections says "this period" (a one-day manual
// report is not a week), and at phone width tables scroll inside their
// panels and the header tools wrap.
func TestNarrowAndPeriodWording(t *testing.T) {
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	r := Build(nil, nil, Options{Location: time.UTC, WindowStart: at.Add(-24 * time.Hour), WindowEnd: at, Generated: at, Interim: true})
	var b strings.Builder
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Nothing unusual this period") || strings.Contains(b.String(), "Nothing unusual this week") {
		t.Error("empty Detections wording")
	}
	if !strings.Contains(styleCSS, "@media (max-width:640px)") || !strings.Contains(styleCSS, ".panel{max-width:100%;overflow-x:auto}") {
		t.Error("no phone-width rules")
	}
}
