package install

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A local folder the person running setup can't write to (one open only
// to an auditors' group) is offered for SYSTEM access where that works
// (Windows); a share, or any system where it doesn't, is unusable.
func TestCheckFolderNoAccess(t *testing.T) {
	exists := func(string) (bool, error) { return true, nil }
	denied := func(string) error { return errors.New("Access is denied") }
	local := `C:\_AuditFiles`
	if !CanGrantSystem {
		local = "/srv/audit"
	}
	c, _ := CheckFolder(local, exists, denied)
	want := FolderBad
	if CanGrantSystem {
		want = FolderNoAccess
	}
	if c != want {
		t.Errorf("local folder: %v, want %v", c, want)
	}
	if c, _ := CheckFolder(`\\server\audit`, exists, denied); c != FolderBad {
		t.Errorf("share: %v, want FolderBad", c)
	}
	if c, _ := CheckFolder(local, exists, func(string) error { return nil }); c != FolderOK {
		t.Errorf("writable: %v", c)
	}
}

// SEC8: an existing report folder others can write to is locked on Linux:
// root's scheduled runs write in it.
func TestLockFolderTakesAwayOthersWrite(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Linux, as root")
	}
	dir := filepath.Join(t.TempDir(), "reports")
	os.Mkdir(dir, 0o777)
	os.Chmod(dir, 0o777)
	os.Chown(dir, 65534, 65534)
	what, err := lockFolder(dir)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o755 || !strings.Contains(what, "owner changed to root") || !strings.Contains(what, "write access") {
		t.Errorf("mode %o, said %q", fi.Mode().Perm(), what)
	}
	if what, _ := lockFolder(dir); what != "" {
		t.Errorf("a locked folder changed again: %q", what)
	}
}
