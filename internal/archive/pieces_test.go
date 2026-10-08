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
	for _, name := range []string{"Security_20261005-120000Z.evtx", "Security_20261005-123000Z.evtx"} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing %s (has %v)", name, got)
		}
	}
	if _, ok := got["Security_20261005-121500Z.evtx"]; ok {
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

// AR7: two pieces started in the same minute (a run at 13:17 and the
// next at 13:17) are packed under different names, and the archive
// verifies.
func TestPiecesSameMinute(t *testing.T) {
	dir := t.TempDir()
	pdir := filepath.Join(dir, "pieces")
	t0 := time.Date(2026, 10, 7, 13, 17, 5, 0, time.UTC)
	for _, d := range []time.Duration{0, 20 * time.Second, 20 * time.Second} {
		from := t0.Add(d)
		if _, err := SavePiece(pdir, Info{Host: "WIN11", From: from, To: from.Add(30 * time.Second), Created: from}, fakeExport(false), nil); err != nil {
			t.Fatal(err)
		}
	}
	pieces, _ := Pieces(pdir)
	path := filepath.Join(dir, FileName("WIN11", t0, t0.Add(time.Minute)))
	info, err := Pack(path, "WIN11", "windows", pieces, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path); err != nil {
		t.Fatalf("archive of pieces started in the same minute: %v", err)
	}
	var names []string
	for _, f := range info.Files {
		names = append(names, f.Name)
	}
	want := "Security_20261007-131705Z.evtx,audit.log,Security_20261007-131725Z.evtx,Security_20261007-131725Z-2.evtx"
	if strings.Join(names, ",") != want {
		t.Errorf("names: %v", names)
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

// An export deleted or unreadable before packing is a gap with its reason,
// not a reason to stop archiving (AR5); one changed since it was exported
// is packed as found and marked (AR6).
func TestPackLostAndChangedPieces(t *testing.T) {
	dir := t.TempDir()
	pdir := filepath.Join(dir, "pieces")
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	exp := fakeExport(false)
	for i := 0; i < 3; i++ {
		from, to := t0.Add(time.Duration(i)*15*time.Minute), t0.Add(time.Duration(i+1)*15*time.Minute)
		if _, err := SavePiece(pdir, Info{Host: "WIN11", From: from, To: to, Created: to}, exp, nil); err != nil {
			t.Fatal(err)
		}
	}
	pieces, err := Pieces(pdir)
	if err != nil || len(pieces) != 3 {
		t.Fatalf("pieces: %d %v", len(pieces), err)
	}
	for _, p := range pieces {
		for _, f := range p.Info.Files {
			if len(f.SHA256) != 64 {
				t.Fatalf("%s/%s: no hash taken at export: %q", p.Dir, f.Name, f.SHA256)
			}
		}
	}
	// Piece 1: Security.evtx deleted. Piece 2: audit.log unreadable (a
	// folder in its place). Piece 0: Security.evtx changed.
	os.Remove(filepath.Join(pieces[1].Dir, "Security.evtx"))
	os.Remove(filepath.Join(pieces[2].Dir, "audit.log"))
	os.Mkdir(filepath.Join(pieces[2].Dir, "audit.log"), 0o750)
	os.WriteFile(filepath.Join(pieces[0].Dir, "Security.evtx"), []byte("edited"), 0o644)

	path := filepath.Join(dir, FileName("WIN11", t0, t0.Add(45*time.Minute)))
	info, err := Pack(path, "WIN11", "windows", pieces, t0.Add(46*time.Minute))
	if err != nil {
		t.Fatalf("packing stopped: %v", err)
	}
	if _, err := Verify(path); err != nil {
		t.Fatal(err)
	}
	got := readZip(t, path)
	if got["Security_20261005-120000Z.evtx"] != "edited" {
		t.Errorf("changed export not packed as found: %v", got)
	}
	if _, ok := got["Security_20261005-121500Z.evtx"]; ok {
		t.Error("deleted export in the archive")
	}
	if got["audit.log"] != "line 12:00\nline 12:15\n" {
		t.Errorf("audit.log: %q", got["audit.log"])
	}
	if len(info.Gaps) != 2 {
		t.Fatalf("gaps: %+v", info.Gaps)
	}
	g := info.Gaps[0]
	if g.Source != "Security" || !g.From.Equal(t0.Add(15*time.Minute)) || !g.To.Equal(t0.Add(30*time.Minute)) || !strings.Contains(g.Reason, "Security.evtx") || !strings.Contains(g.Reason, "was missing") {
		t.Errorf("deleted piece gap: %+v", g)
	}
	if g := info.Gaps[1]; g.Source != "/var/log/audit/audit.log" || !strings.Contains(g.Reason, "could not be read") {
		t.Errorf("unreadable piece gap: %+v", g)
	}
	var marked []string
	for _, f := range info.Files {
		if f.Changed {
			marked = append(marked, f.Name)
		}
	}
	if strings.Join(marked, ",") != "Security_20261005-120000Z.evtx" {
		t.Errorf("marked changed: %v", marked)
	}
	notes := strings.Join(info.Notes, "\n")
	if !strings.Contains(notes, "was changed after it was exported") || !strings.Contains(notes, "not in this archive") {
		t.Errorf("notes: %s", notes)
	}
	if p, _ := Pieces(pdir); len(p) != 0 {
		t.Error("pieces left after packing")
	}
	// The marks survive into the bundle the report takes.
	b, err := Bundle(filepath.Join(dir, "logs-WIN11.zip"), []Stored{{Path: path, Host: "WIN11", From: t0, To: t0.Add(45 * time.Minute)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Changed) != 1 || len(b.Gaps) != 2 {
		t.Errorf("bundle: changed %+v gaps %+v", b.Changed, b.Gaps)
	}
}

// ASSESS1: an .evtx's message text (wevtutil al, LocaleMetaData) is kept
// with it, renamed with it when pieces are packed, so Event Viewer finds
// it on another computer.
func TestLocaleMetaKeptWithEvtx(t *testing.T) {
	dir := t.TempDir()
	pdir := filepath.Join(dir, "pieces")
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	exp := func(d string, from, to time.Time, skip func(string) bool) ([]Source, []string) {
		ev := filepath.Join(d, "Security.evtx")
		os.WriteFile(ev, []byte("evtx "+from.Format("1504")), 0o644)
		os.MkdirAll(filepath.Join(d, MetaDir), 0o755)
		mta := filepath.Join(d, MetaDir, "Security_1033.MTA")
		os.WriteFile(mta, []byte("mta "+from.Format("1504")), 0o644)
		return []Source{{Name: "Security.evtx", Source: "Security", Path: ev}, {Name: MetaDir + "/Security_1033.MTA", Source: "Security", Path: mta}}, nil
	}
	for i := 0; i < 2; i++ {
		from := t0.Add(time.Duration(i) * 15 * time.Minute)
		if _, err := SavePiece(pdir, Info{Host: "WIN11", From: from, To: from.Add(15 * time.Minute), Created: from}, exp, nil); err != nil {
			t.Fatal(err)
		}
	}
	pieces, _ := Pieces(pdir)
	path := filepath.Join(dir, FileName("WIN11", t0, t0.Add(30*time.Minute)))
	if _, err := Pack(path, "WIN11", "windows", pieces, t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got := readZip(t, path)
	for name, body := range map[string]string{
		"Security_20261007-120000Z.evtx": "evtx 1200", "LocaleMetaData/Security_20261007-120000Z_1033.MTA": "mta 1200",
		"Security_20261007-121500Z.evtx": "evtx 1215", "LocaleMetaData/Security_20261007-121500Z_1033.MTA": "mta 1215",
	} {
		if got[name] != body {
			t.Errorf("%s = %q (have %v)", name, got[name], got)
		}
	}
}
