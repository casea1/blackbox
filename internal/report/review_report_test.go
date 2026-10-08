package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// REVIEW-5: event times on a DST-change day are shown with the offset of
// local midnight, so events after the change are an hour off in the event
// tables, search, CSV export and after-hours filter.
func TestReviewDSTDayOffset(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip(err)
	}
	// 1 Nov 2026: clocks go back at 02:00 EDT. 15:00 EST is 20:00 UTC.
	at := time.Date(2026, 11, 1, 15, 0, 0, 0, loc)
	e := &event.Event{Time: at, Collected: at, Host: "WS-01", OS: "windows", Category: event.CatLogon,
		Severity: event.SevInfo, Action: "logon", Summary: "alice logged on", User: "alice"}
	r := Build([]*event.Event{e}, nil, Options{Location: loc, Source: "test"})
	_, files, err := r.buildData()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name, "-raw.js") {
			continue
		}
		var c struct {
			Base int64
			Off  int
			Rows [][]any
		}
		if err := json.Unmarshal([]byte(unpackData(t, f.Body)), &c); err != nil {
			t.Fatal(err)
		}
		for _, row := range c.Rows {
			// app.js when(): new Date((base + t + off)*1000) read as UTC.
			shown := time.Unix(c.Base+int64(row[1].(float64))+int64(c.Off), 0).UTC()
			t.Logf("%s: shown %s, actual %s", f.Name, shown.Format("15:04"), at.Format("15:04 MST"))
			if shown.Hour() != 15 {
				t.Errorf("%s: event at 15:00 local is shown as %s", f.Name, shown.Format("15:04"))
			}
		}
	}
}

// REVIEW-6: blackbox verify does not look inside sub-folders other than
// data/ and scap/: a folder added to a report passes verification.
func TestReviewVerifyIgnoresExtraFolders(t *testing.T) {
	r := build(t, Options{Site: "Test Site", InReportsDir: true})
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "extra"), 0o755)
	os.WriteFile(filepath.Join(dir, "extra", "report.html"), []byte("<h1>forged</h1>"), 0o644)
	os.MkdirAll(filepath.Join(dir, "data", "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "data", "sub", "x.js"), []byte("alert(1)"), 0o644)
	p, err := Verify(dir)
	t.Logf("problems=%v err=%v", p, err)
	if err == nil && len(p) == 0 {
		t.Error("verify passes a report with added folders/files")
	}
}
