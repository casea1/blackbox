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
