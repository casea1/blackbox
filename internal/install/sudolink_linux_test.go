package install

import (
	"os"
	"path/filepath"
	"testing"
)

// LNX2: setup links /usr/bin/blackbox to the program, so sudo finds it
// where secure_path leaves out /usr/local/bin; it never replaces a file
// that is not a link.
func TestLinkProgram(t *testing.T) {
	dir := t.TempDir()
	exe, link := filepath.Join(dir, "local", "blackbox"), filepath.Join(dir, "bin", "blackbox")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.MkdirAll(filepath.Dir(link), 0o755)
	os.WriteFile(exe, []byte("x"), 0o755)

	if err := linkProgram(exe, link); err != nil {
		t.Fatal(err)
	}
	if to, _ := os.Readlink(link); to != exe {
		t.Fatalf("link points to %q", to)
	}
	if err := linkProgram(exe, link); err != nil { // again: nothing to do
		t.Fatal(err)
	}
	os.Remove(link)
	os.Symlink("/elsewhere/blackbox", link) // an old link is replaced
	if err := linkProgram(exe, link); err != nil {
		t.Fatal(err)
	}
	if to, _ := os.Readlink(link); to != exe {
		t.Fatalf("old link not replaced: %q", to)
	}
	os.Remove(link)
	os.WriteFile(link, []byte("other"), 0o755) // someone else's program
	if err := linkProgram(exe, link); err == nil {
		t.Error("replaced a file that is not a link")
	}
	if b, _ := os.ReadFile(link); string(b) != "other" {
		t.Error("the other program was changed")
	}
}
