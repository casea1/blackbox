package archive

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeExport writes one .evtx and one text log per call, unless skip
// names them; "fail" makes every log fail.
func fakeExport(fail bool) ExportFunc {
	n := 0
	return func(dir string, from, to time.Time, skip func(string) bool) ([]Source, []string) {
		n++
		if fail {
			return nil, []string{"Security: could not be exported: access denied"}
		}
		var out []Source
		for _, s := range []struct{ name, src, body string }{
			{"Security.evtx", "Security", "evtx " + from.Format("15:04")},
			{"audit.log", "/var/log/audit/audit.log", "line " + from.Format("15:04") + "\n"},
		} {
			if skip != nil && skip(s.src) {
				continue
			}
			p := filepath.Join(dir, s.name)
			os.WriteFile(p, []byte(s.body), 0o644)
			out = append(out, Source{Name: s.name, Source: s.src, Path: p})
		}
		return out, nil
	}
}

// Pieces exported at each collection are packed into one archive: .evtx
// files kept apart and named after their piece, text logs joined in order,
// coverage merged, and the pieces removed.
func TestPiecesPacked(t *testing.T) {
	dir := t.TempDir()
	pdir := filepath.Join(dir, "pieces")
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	exp := fakeExport(false)
	for i := 0; i < 3; i++ {
		from, to := t0.Add(time.Duration(i)*15*time.Minute), t0.Add(time.Duration(i+1)*15*time.Minute)
		info := Info{Host: "WIN11", From: from, To: to, Created: to,
			Logs: Coverage([]LogState{{Source: "Security", Oldest: t0.Add(-time.Hour)}}, from, to, map[string]uint64{"Security": uint64(i)})}
		var skip func(string) bool
		if i == 1 {
			skip = func(s string) bool { return s == "Security" } // nothing new
		}
		if _, err := SavePiece(pdir, info, exp, skip); err != nil {
			t.Fatal(err)
		}
	}
	// An export that did not finish is not a piece.
	os.MkdirAll(filepath.Join(pdir, "000004"), 0o750)
	pieces, err := Pieces(pdir)
	if err != nil || len(pieces) != 3 {
		t.Fatalf("pieces: %d %v", len(pieces), err)
	}
	if _, err := os.Stat(filepath.Join(pdir, "000004")); err == nil {
		t.Error("an unfinished export was left")
	}
	if PackDue(pieces, t0.Add(time.Hour)) || !PackDue(pieces, t0.Add(25*time.Hour)) {
		t.Error("packing is due once the oldest piece is a day old")
	}
	path := filepath.Join(dir, FileName("WIN11", t0, t0.Add(45*time.Minute)))
	info, err := Pack(path, "WIN11", "windows", pieces, t0.Add(46*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path); err != nil {
		t.Fatal(err)
	}
	got := readZip(t, path)
	for _, name := range []string{"Security_20261005-1200Z.evtx", "Security_20261005-1230Z.evtx"} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing %s (has %v)", name, got)
		}
	}
	if _, ok := got["Security_20261005-1215Z.evtx"]; ok {
		t.Error("a log with nothing new was exported")
	}
	if got["audit.log"] != "line 12:00\nline 12:15\nline 12:30\n" {
		t.Errorf("audit.log: %q", got["audit.log"])
	}
	if len(info.Logs) != 1 || !info.Logs[0].From.Equal(t0) || !info.Logs[0].To.Equal(t0.Add(45*time.Minute)) || info.Logs[0].Overwritten != 3 {
		t.Errorf("coverage: %+v", info.Logs)
	}
	if p, _ := Pieces(pdir); len(p) != 0 {
		t.Error("pieces left after packing")
	}
}

// A log that no longer reaches back to the start of the period covers
// from its oldest record; one export failing for every log is an error,
// so the period is tried again.
func TestCoverageAndFailedPiece(t *testing.T) {
	from := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 0, 8)
	oldest := time.Date(2026, 10, 5, 4, 8, 0, 0, time.UTC)
	c := Coverage([]LogState{{Source: "Security", Oldest: oldest, Wraps: true}, {Source: "System", Oldest: from.AddDate(0, 0, -30)}},
		from, to, map[string]uint64{"Security": 94565, "Application": 3})
	if len(c) != 3 || c[0].Source != "Application" || c[2].Source != "System" || !c[1].From.Equal(oldest) || c[1].Overwritten != 94565 || !c[2].From.Equal(from) {
		t.Errorf("coverage: %+v", c)
	}
	dir := t.TempDir()
	if _, err := SavePiece(dir, Info{From: from, To: to}, fakeExport(true), nil); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Errorf("failed export: %v", err)
	}
	if p, _ := Pieces(dir); len(p) != 0 {
		t.Error("a failed export was kept as a piece")
	}
}

func readZip(t *testing.T, path string) map[string]string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out := map[string]string{}
	for _, f := range zr.File {
		r, _ := f.Open()
		b, _ := io.ReadAll(r)
		r.Close()
		out[f.Name] = string(b)
	}
	return out
}
