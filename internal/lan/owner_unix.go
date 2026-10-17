//go:build !windows

package lan

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// fileOwner is the account that owns (wrote) a file, or "".
func fileOwner(path string) string {
	fi, err := os.Lstat(path)
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	id := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(id); err == nil {
		return u.Username
	}
	return "uid " + id
}

// ownDir says whether path is a folder owned by the account Blackbox runs
// as (root). A folder a sender made in the inbox is the sender's: it could
// swap it for a link to anywhere between two steps, so it is left alone.
func ownDir(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}
