package report

import (
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// LEDGER3: one file moved out of a report folder names that file; several
// are listed; when the folder itself went too, the row says the report
// was deleted.
func TestReportFilesRow(t *testing.T) {
	at := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	ev := func(file string, sec int) *event.Event {
		e := &event.Event{Time: at.Add(time.Duration(sec) * time.Second), Host: "SRV", Category: event.CatIntegrity, Severity: event.SevHigh,
			Action: "blackbox_files_changed", User: "claude", Target: "2026-10-06_0000_4-systems", Process: `C:\Windows\explorer.exe`,
			DedupeKey: "bbreport|deleted|claude|2026-10-06_0000_4-systems", Fields: map[string]string{event.ReportFilesFlag: file}}
		e.Summary = event.ReportFilesSummary("claude", "deleted", e.Target, "explorer.exe", []string{file})
		return e
	}
	for _, c := range []struct {
		files []string
		want  string
	}{
		{[]string{"logs-WIN11-TEST.zip"}, "claude deleted logs-WIN11-TEST.zip from the report 2026-10-06_0000_4-systems (using explorer.exe)."},
		{[]string{"logs-WIN11-TEST.zip", "logs-UBU.zip"}, "claude deleted 2 files from the report 2026-10-06_0000_4-systems: logs-WIN11-TEST.zip, logs-UBU.zip (using explorer.exe)."},
		{[]string{"report.html", "summary.json", "data/events.js", ""}, "claude deleted the report 2026-10-06_0000_4-systems, 3 files (using explorer.exe)."},
	} {
		var in []*event.Event
		for i, f := range c.files {
			in = append(in, ev(f, i))
		}
		out := (&Report{}).dedupe(in)
		if len(out) != 1 || out[0].Summary != c.want {
			t.Errorf("%v: %d rows, %q", c.files, len(out), out[0].Summary)
		}
	}
}
