//go:build !windows

package lan

import (
	"fmt"
	"os"
	"syscall"
)

// restrictKey makes the key file root's (the account running Blackbox)
// alone: mode 0600.
func restrictKey(path string) error { return os.Chmod(path, 0o600) }

// KeyProblem says what is wrong with the signing key file's permissions,
// or "" (DESIGN1): it must be mode 0600, owned by the account Blackbox
// runs as (root).
func KeyProblem(dataDir string) string {
	fi, err := os.Stat(KeyPath(dataDir))
	if err != nil {
		return ""
	}
	if m := fi.Mode().Perm(); m&0o077 != 0 {
		return fmt.Sprintf("%s has mode %04o: other accounts can read it. Run: chmod 600 %s", KeyPath(dataDir), m, KeyPath(dataDir))
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Sprintf("%s belongs to user ID %d, not to the account Blackbox runs as. Run: chown root:root %s", KeyPath(dataDir), st.Uid, KeyPath(dataDir))
	}
	return ""
}
