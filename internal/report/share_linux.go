//go:build linux

package report

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// Share lets the members of group read the reports folder and everything
// in it (READ1): the folder, report folders and files get that group,
// with read (and, for folders, open) for it. Writing stays root's, so the
// sealed reports can't be changed by a reader. It runs after every
// report and index, so a report folder made later is shared too. A blank
// group shares nothing.
func Share(dir, group string) error {
	if group == "" {
		return nil
	}
	gid, err := groupID(group)
	if err != nil {
		return err
	}
	// Only a folder no one but root can change is shared: in one others
	// can write to, a file could be swapped for a link mid-walk (READ1).
	if p := openToOthers(dir); p != "" {
		return fmt.Errorf("not sharing the reports: %s can be changed by others than root (run setup to lock it)", p)
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // a file removed mid-walk; the next run gets the rest
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil // links, devices, pipes: left alone
		}
		if err := shareOne(p, d.IsDir(), gid); err != nil {
			return fmt.Errorf("let group %s read %s: %w", group, p, err)
		}
		return nil
	})
}

// shareOne gives one file or folder to gid with group read (and open, for
// a folder), through a handle opened without following a link, so the
// change can't land anywhere else.
func shareOne(p string, dir bool, gid int) error {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	if dir {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Open(p, flags, 0)
	if err != nil {
		if err == syscall.ENOENT || err == syscall.ELOOP || err == syscall.ENOTDIR {
			return nil // gone or swapped for a link since it was listed
		}
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if t := st.Mode & syscall.S_IFMT; t != syscall.S_IFREG && t != syscall.S_IFDIR {
		return nil
	}
	if int(st.Gid) != gid {
		if err := syscall.Fchown(fd, -1, gid); err != nil {
			return err
		}
	}
	perm := st.Mode & 0o7777
	want := perm | 0o040
	if dir {
		want |= 0o010
	}
	if want != perm {
		return syscall.Fchmod(fd, want)
	}
	return nil
}

// openToOthers is dir, or the first folder in it, that someone other than
// root can write to ("" = none).
func openToOthers(dir string) string {
	bad := ""
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return nil
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if fi.Mode().Perm()&0o022 != 0 || (ok && st.Uid != 0 && os.Geteuid() == 0) {
			bad = p
			return filepath.SkipAll
		}
		return nil
	})
	return bad
}

// Unreachable is the folder above dir that members of group can't pass
// through, so they can't open the reports even when shared ("" = none).
func Unreachable(dir, group string) string {
	gid, err := groupID(group)
	if err != nil {
		return ""
	}
	for p := filepath.Dir(dir); ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err == nil {
			m := fi.Mode().Perm()
			st, _ := fi.Sys().(*syscall.Stat_t)
			if m&0o001 == 0 && (st == nil || int(st.Gid) != gid || m&0o010 == 0) {
				return p
			}
		}
		if p == filepath.Dir(p) {
			return ""
		}
	}
}

func groupID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("no group %q on this computer", name)
	}
	return strconv.Atoi(g.Gid)
}
