//go:build !windows

package lan

import (
	"os"
	"path/filepath"
	"testing"
)

// DESIGN1: what a sender writes into the inbox is readable by its owner
// only, so another sender in the same group can't read it on a Linux
// collector, even knowing its name.
func TestDeliveredFileOwnerOnly(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "HOST_id_0000000001-0123456789ab.bbx")
	if err := writeNew(dst, func(f *os.File) error { _, err := f.Write([]byte("x")); return err }); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("delivered file mode %v: readable by others", fi.Mode().Perm())
	}
}
