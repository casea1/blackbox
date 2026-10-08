package report

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// AU3: events.csv gives every event an outcome: success or failure where
// the source recorded one, "not recorded" where it did not.
func TestCSVOutcome(t *testing.T) {
	end := time.Date(2026, 10, 7, 7, 0, 0, 0, time.UTC)
	mk := func(min int, summary, outcome string) *event.Event {
		return &event.Event{Time: end.Add(-time.Duration(min) * time.Minute), Host: "WS-07", OS: "windows", Category: event.CatOther,
			Severity: event.SevInfo, Action: "x" + summary, Summary: summary, Outcome: outcome}
	}
	evs := []*event.Event{mk(3, "a", "success"), mk(2, "b", "failure"), mk(1, "c", "")}
	r := Build(evs, nil, Options{Location: time.UTC, WindowStart: end.Add(-24 * time.Hour), WindowEnd: end, Generated: end})
	var b bytes.Buffer
	if err := r.writeCSV(&b); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(b.Bytes(), []byte("\xef\xbb\xbf")))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	col := -1
	for i, h := range rows[0] {
		if h == "outcome" {
			col = i
		}
	}
	got := map[string]string{}
	for _, row := range rows[1:] {
		got[row[4]] = row[col]
	}
	if got["a"] != "success" || got["b"] != "failure" || got["c"] != "not recorded" {
		t.Errorf("outcomes: %v", got)
	}
}
