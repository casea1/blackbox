package lan

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Deliveries the collector can't use, or holds for a key decision, are
// set aside in the data folder, not in the inbox (SEC6, 0.27): a sender
// can write to the inbox, so a folder there could be made beforehand by a
// sender, with links in it that make the collector, running as root or
// SYSTEM, write its notes over other files.
const setAsideName = "inbox-set-aside"

// SetAsideDir is where the collector keeping its data in dataDir sets
// inbox files aside; held files are in its held folder.
func SetAsideDir(dataDir string) string { return filepath.Join(dataDir, setAsideName) }

// errNotRegular: an inbox file that is a link, pipe or device. Senders
// deliver only regular files; such a file is never opened.
var errNotRegular = errors.New("it is not a regular file (a link, pipe or device), and senders deliver only regular files")

// openInbox opens a file in the inbox for reading only if it is a regular
// file: a link is not followed and a pipe does not block (openFlags).
func openInbox(path string) (*os.File, os.FileInfo, error) {
	if fi, err := os.Lstat(path); err != nil {
		return nil, nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, nil, errNotRegular
	}
	f, err := os.OpenFile(path, openFlags, 0)
	if err != nil {
		if isLinkErr(err) {
			return nil, nil, errNotRegular
		}
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = errNotRegular
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// readInbox reads a regular file in the inbox whole, refusing one larger
// than max.
func readInbox(path string, max int64) ([]byte, os.FileInfo, error) {
	f, fi, err := openInbox(path)
	if err != nil {
		return nil, fi, err
	}
	defer f.Close()
	if fi.Size() > max {
		return nil, fi, fmt.Errorf("it is %d MB, larger than Blackbox accepts (%d MB)", fi.Size()>>20, max>>20)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	return b, fi, err
}

// moveFile moves src to dst, a name not in use. A file on another disk is
// copied, then removed. A link, pipe or device is moved, never opened:
// across disks it is removed.
func moveFile(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dst); err == nil {
		return fs.ErrExist
	}
	rerr := os.Rename(src, dst)
	if rerr == nil {
		return nil
	}
	if !fi.Mode().IsRegular() {
		if err := os.Remove(src); err != nil {
			return rerr
		}
		return nil
	}
	in, _, err := openInbox(src)
	if err != nil {
		return rerr
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return rerr
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		in.Close()
		err = os.Remove(src)
	}
	if err != nil {
		os.Remove(dst)
		return rerr
	}
	return nil
}

// setAside moves name, and its signature if there is one, from dir into
// to under a name not in use there, and writes note next to it. It
// returns the name it was given.
func setAside(dir, name, to, note string) (string, error) {
	if err := os.MkdirAll(to, 0o750); err != nil {
		return "", err
	}
	dest := name
	for i := 2; i < 100; i++ {
		if _, err := os.Lstat(filepath.Join(to, dest)); err != nil {
			if _, err := os.Lstat(filepath.Join(to, dest+whyExt)); err != nil {
				break
			}
		}
		dest = AgainName(name, i)
	}
	if err := moveFile(filepath.Join(dir, name), filepath.Join(to, dest)); err != nil {
		return "", err
	}
	if _, err := os.Lstat(filepath.Join(dir, name+sigExt)); err == nil {
		moveFile(filepath.Join(dir, name+sigExt), filepath.Join(to, dest+sigExt))
	}
	if note != "" {
		writeNote(filepath.Join(to, dest+whyExt), note)
	}
	return dest, nil
}

// writeNote writes a new note file: never through a link, never into a
// file already there.
func writeNote(path, note string) error {
	os.Remove(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	_, err = f.WriteString(strings.ReplaceAll(note, "\n", "\r\n"))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// migrateSetAside moves what earlier versions set aside in inbox/rejected
// (and held in inbox/rejected/held) to the data folder, then removes
// those folders. Only regular files are moved; anything else is removed.
func migrateSetAside(inbox, aside string, logf func(string, ...any)) {
	old := filepath.Join(inbox, rejectedDir)
	if fi, err := os.Lstat(old); err != nil || !fi.IsDir() {
		return
	}
	for _, sub := range []struct{ from, to string }{{filepath.Join(old, heldDir), filepath.Join(aside, heldDir)}, {old, aside}} {
		if fi, err := os.Lstat(sub.from); err != nil || !fi.IsDir() {
			continue
		}
		entries, err := os.ReadDir(sub.from)
		if err != nil {
			logf("inbox: cannot read %s to move it to %s: %v", sub.from, sub.to, err)
			continue
		}
		if err := os.MkdirAll(sub.to, 0o750); err != nil {
			logf("inbox: cannot make %s: %v", sub.to, err)
			return
		}
		for _, e := range entries {
			n, src := e.Name(), filepath.Join(sub.from, e.Name())
			if e.IsDir() {
				continue
			}
			if !e.Type().IsRegular() {
				os.Remove(src)
				continue
			}
			dest := n
			for i := 2; i < 100; i++ {
				if _, err := os.Lstat(filepath.Join(sub.to, dest)); err != nil {
					break
				}
				dest = n + fmt.Sprintf(".%d", i)
			}
			if err := moveFile(src, filepath.Join(sub.to, dest)); err != nil {
				logf("inbox: cannot move %s to %s yet: %v", src, sub.to, err)
			}
		}
		os.Remove(sub.from)
	}
	if _, err := os.Lstat(old); err != nil {
		logf("inbox: moved the files set aside in %s to %s (since 0.27 they are kept in the data folder)", old, aside)
	}
}
