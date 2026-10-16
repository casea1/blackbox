package main

import (
	"os"
	"path/filepath"
	"testing"
)

// READ1: the copy for a home-only browser has the index and each report
// once, without the original-log zips.
func TestMirrorCopiesReportsNotZips(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "Blackbox reports")
	rep := filepath.Join(src, "Lab-2026-10-16")
	os.MkdirAll(filepath.Join(rep, "data"), 0o750)
	for p, s := range map[string]string{"index.html": "i1", "Lab-2026-10-16/summary.json": "{}", "Lab-2026-10-16/report.html": "r",
		"Lab-2026-10-16/data/d.js": "d", "Lab-2026-10-16/original-logs.zip": "z"} {
		os.WriteFile(filepath.Join(src, p), []byte(s), 0o640)
	}
	os.MkdirAll(filepath.Join(src, "not-a-report"), 0o750)
	if err := mirror(src, dst); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"index.html", "Lab-2026-10-16/report.html", "Lab-2026-10-16/data/d.js"} {
		if _, err := os.Stat(filepath.Join(dst, p)); err != nil {
			t.Errorf("%s not copied: %v", p, err)
		}
	}
	for _, p := range []string{"Lab-2026-10-16/original-logs.zip", "not-a-report"} {
		if _, err := os.Stat(filepath.Join(dst, p)); err == nil {
			t.Errorf("%s should not be copied", p)
		}
	}
	// Again: the index is refreshed, a copied report is left alone.
	os.WriteFile(filepath.Join(src, "index.html"), []byte("i2"), 0o640)
	os.WriteFile(filepath.Join(dst, "Lab-2026-10-16/report.html"), []byte("kept"), 0o600)
	if err := mirror(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "index.html")); string(b) != "i2" {
		t.Errorf("index = %q, want the new one", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "Lab-2026-10-16/report.html")); string(b) != "kept" {
		t.Errorf("a copied report was copied again")
	}
}
