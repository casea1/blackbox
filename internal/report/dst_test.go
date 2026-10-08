package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// DST1: on the day the clocks go back, 01:30 happens twice. Each event
// keeps its own offset and both land on 1 Nov.
func TestDSTFallBackRows(t *testing.T) {
	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Skip(err)
	}
	pdt := time.Date(2026, 11, 1, 8, 30, 0, 0, time.UTC) // 01:30 PDT
	pst := time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC) // 01:30 PST
	var evs []*event.Event
	for _, at := range []time.Time{pdt, pst} {
		evs = append(evs, &event.Event{Time: at, Collected: at, Host: "WS-01", OS: "windows", Category: event.CatLogon,
			Severity: event.SevInfo, Action: "logon", Summary: "alice logged on", User: "alice"})
	}
	r := Build(evs, nil, Options{Location: loc, Source: "test"})
	pages, files, err := r.buildData()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pages {
		if p.Total > 0 && (len(p.Days) != 1 || p.Days[0] != "20261101") {
			t.Errorf("%s: days %v, want only 20261101", p.ID, p.Days)
		}
	}
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f.Name, "-raw.js") {
			continue
		}
		var c struct {
			Base int64
			Off  int
			Cols []string
			Rows [][]any
		}
		if err := json.Unmarshal([]byte(unpackData(t, f.Body)), &c); err != nil {
			t.Fatal(err)
		}
		if c.Cols[17] != "dz" {
			t.Fatalf("cols %v", c.Cols)
		}
		for _, row := range c.Rows {
			seen++
			// As app.js loadRows: the instant and the row's own offset.
			dz := int64(row[17].(float64))
			instant := c.Base + int64(row[1].(float64)) - dz
			off := int64(c.Off) + dz
			shown := time.Unix(instant+off, 0).UTC()
			if shown.Format("2006-01-02 15:04") != "2026-11-01 01:30" {
				t.Errorf("%s: shown %s", f.Name, shown)
			}
			want := map[int64]int64{pdt.Unix(): -7 * 3600, pst.Unix(): -8 * 3600}[instant]
			if want == 0 || off != want {
				t.Errorf("%s: instant %d has offset %d, want %d", f.Name, instant, off, want)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no rows")
	}
	var csv bytes.Buffer
	if err := r.writeCSV(&csv); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2026-11-01 01:30:00 -07:00", "2026-11-01 01:30:00 -08:00"} {
		if !strings.Contains(csv.String(), want) {
			t.Errorf("events.csv has no %q:\n%s", want, csv.String())
		}
	}
}
