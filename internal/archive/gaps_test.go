package archive

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A full log that no longer reaches back to the start of a save has a gap
// there; one that is not full has lost nothing.
func TestGaps(t *testing.T) {
	saved := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	states := []LogState{
		{Source: "Security", Oldest: saved.Add(40 * time.Minute), Wraps: true}, // already past the last save
		{Source: "System", Oldest: saved.Add(-10 * time.Minute), Wraps: true},  // about to be
		{Source: "Defender", Oldest: saved.Add(-72 * time.Hour), Wraps: true},  // holds days
		{Source: "PowerShell", Oldest: saved.Add(2 * time.Hour), Wraps: false}, // not full: nothing lost
	}
	gaps := GapsIn(states, saved, saved.Add(time.Hour))
	if len(gaps) != 1 || gaps[0].Source != "Security" || !gaps[0].From.Equal(saved) || !gaps[0].To.Equal(saved.Add(40*time.Minute)) {
		t.Errorf("gaps: %+v", gaps)
	}
	// A log that overwrote the whole period: the gap is all of it.
	if g := GapsIn(states, saved, saved.Add(10*time.Minute)); len(g) != 1 || !g[0].To.Equal(saved.Add(10*time.Minute)) {
		t.Errorf("whole period: %+v", g)
	}
}

// TZ1: every time in archive.json is UTC ("Z"), the gaps and each log's
// coverage included, whatever zone the times were given in.
func TestArchiveJSONTimesUTC(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "Security.evtx")
	os.WriteFile(logFile, []byte("pretend evtx"), 0o644)
	ny := time.FixedZone("EDT", -4*3600)
	from := time.Date(2026, 10, 6, 20, 0, 0, 0, ny)
	to := from.Add(24 * time.Hour)
	p := filepath.Join(dir, FileName("WS-07", from, to))
	info := Info{Host: "WS-07", From: from, To: to, Created: to.Add(time.Minute),
		Gaps: []Gap{{Source: "Security", From: from.Add(time.Hour), To: from.Add(2 * time.Hour)}},
		Logs: []LogCover{{Source: "Security", From: from, To: to}}}
	if _, err := Write(p, info, []Source{{Name: "Security.evtx", Source: "Security", Path: logFile}}); err != nil {
		t.Fatal(err)
	}
	if info.Gaps[0].From.Location() != ny {
		t.Error("Write changed the caller's gaps")
	}
	zr, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != InfoName {
			continue
		}
		r, _ := f.Open()
		b, _ := io.ReadAll(r)
		r.Close()
		stamps := regexp.MustCompile(`"\d{4}-\d\d-\d\dT[^"]*"`).FindAllString(string(b), -1)
		if len(stamps) != 7 {
			t.Errorf("%d times in:\n%s", len(stamps), b)
		}
		for _, s := range stamps {
			if !strings.HasSuffix(s, `Z"`) {
				t.Errorf("%s is not UTC:\n%s", s, b)
			}
		}
		return
	}
	t.Fatal("no archive.json")
}
