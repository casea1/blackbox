package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// VER2: verify walks the whole report folder, and a listed file it
// cannot read is a problem.
func TestVerifyWholeFolder(t *testing.T) {
	r := build(t, Options{Site: "Test Site", InReportsDir: true})
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	if p, err := Verify(dir); err != nil || len(p) != 0 {
		t.Fatalf("fresh report: %v %v", p, err)
	}
	os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755)
	os.WriteFile(filepath.Join(dir, "a", "b", "deep.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "a", "desktop.ini"), []byte("x"), 0o644)
	p, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 || !strings.HasPrefix(p[0], "a/b/deep.txt: not in the manifest") {
		t.Errorf("problems = %q, want only a/b/deep.txt", p)
	}
	os.RemoveAll(filepath.Join(dir, "a"))

	// A listed file replaced by something that can't be read as a file.
	os.Remove(filepath.Join(dir, "summary.json"))
	os.Mkdir(filepath.Join(dir, "summary.json"), 0o755)
	p, err = Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 || !strings.Contains(p[0], "summary.json: could not be read, so it is not verified") {
		t.Errorf("problems = %q", p)
	}
}
