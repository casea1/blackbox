package event

import (
	"strings"
	"testing"
)

// Accepting a missing scheduled report is written to the system log and
// read back as the same record, a Medium row naming who, which and why.
func TestReportAcceptedRoundTrip(t *testing.T) {
	c := SelfChange{Kind: "report_accepted", Who: `LAB\jdoe`, Setting: "2026-09-30_CI", New: "missing", Old: "moved to the archive drive (E:)", Program: "blackbox reports accept"}
	got, ok := ParseSelfChange(c.Message())
	if !ok || got != c {
		t.Fatalf("round trip: %+v %v from %q", got, ok, c.Message())
	}
	e := c.Event()
	if e.Action != "blackbox_report_accepted" || e.Severity != SevMedium || !strings.Contains(e.Summary, "2026-09-30_CI is missing: moved to the archive drive (E:)") {
		t.Errorf("event: %+v", e)
	}
}
