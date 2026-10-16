//go:build linux

package report

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

// READ1: Share gives the reports to a group, readable, not writable.
func TestShareLetsGroupRead(t *testing.T) {
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skip("no name for this group")
	}
	dir := t.TempDir()
	rep := filepath.Join(dir, "Lab-2026-10-16")
	if err := os.MkdirAll(rep, 0o700); err != nil {
		t.Fatal(err)
	}
	os.Chmod(rep, 0o700)
	for name, mode := range map[string]os.FileMode{"report.html": 0o640, "manifest.sha256": 0o440, "logs.zip": 0o600} {
		if err := os.WriteFile(filepath.Join(rep, name), nil, mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Join(rep, name), mode)
	}
	if err := Share(dir, g.Name); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{rep: 0o750, filepath.Join(rep, "report.html"): 0o640,
		filepath.Join(rep, "manifest.sha256"): 0o440, filepath.Join(rep, "logs.zip"): 0o640} {
		fi, _ := os.Stat(p)
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", filepath.Base(p), got, want)
		}
	}
	if err := Share(dir, ""); err != nil {
		t.Errorf("no group: %v", err)
	}
	if Share(dir, "no-such-group-blackbox") == nil {
		t.Error("an unknown group should be an error")
	}
}

func TestUnreachableNamesClosedFolder(t *testing.T) {
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skip("no name for this group")
	}
	top := t.TempDir()
	closed := filepath.Join(top, "closed")
	os.MkdirAll(filepath.Join(closed, "reports"), 0o700)
	os.Chmod(closed, 0o700)
	os.Chmod(top, 0o755)
	if got := Unreachable(filepath.Join(closed, "reports"), g.Name); got != closed {
		t.Errorf("Unreachable = %q, want %q", got, closed)
	}
	os.Chmod(closed, 0o750)
	if got := Unreachable(filepath.Join(closed, "reports"), g.Name); got == closed {
		t.Errorf("group may pass through %s, got %q", closed, got)
	}
}
