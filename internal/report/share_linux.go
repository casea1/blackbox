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
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // a file removed mid-walk; the next run gets the rest
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Gid) != gid {
			if err := os.Lchown(p, -1, gid); err != nil {
				return fmt.Errorf("give %s to group %s: %w", p, group, err)
			}
		}
		want := fi.Mode().Perm() | 0o040
		if d.IsDir() {
			want |= 0o010
		}
		if want != fi.Mode().Perm() {
			if err := os.Chmod(p, want); err != nil {
				return fmt.Errorf("let group %s read %s: %w", group, p, err)
			}
		}
		return nil
	})
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
