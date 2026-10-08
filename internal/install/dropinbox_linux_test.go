//go:build linux

package install

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/casea1/blackbox/internal/lan"
)

// DESIGN1: a Linux collector's inbox is root:blackbox-senders, mode 1730:
// group members can add files and search it (to open the marker), but
// can't list it, and (sticky) can't remove or rename anyone else's
// files. Others can't reach it. (CI checks this as a real sender account
// too: .github/workflows/ci.yml, "Drop-only inbox on a Linux collector".)
func TestDropOnlyDirMode(t *testing.T) {
	dir := t.TempDir()
	if err := lan.PrepareInbox(dir, "COL"); err != nil {
		t.Fatal(err)
	}
	if err := dropOnlyDir(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSticky == 0 || fi.Mode().Perm() != 0o730 {
		t.Errorf("mode %v, want dtrwx-wx--- (1730)", fi.Mode())
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Gid) != os.Getgid() || int(st.Uid) != os.Getuid() {
		t.Errorf("owner %d:%d", st.Uid, st.Gid)
	}
	if !lan.IsInbox(dir) {
		t.Error("the marker must still be found")
	}
	if fi, err := os.Stat(filepath.Join(dir, lan.MarkerFile)); err != nil || fi.Mode().Perm()&0o044 == 0 {
		t.Errorf("marker not readable to the group: %v %v", fi, err)
	}
}
