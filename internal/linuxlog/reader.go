package linuxlog

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// FollowResult is what reading a log file from a bookmark found.
type FollowResult struct {
	Bookmark store.Bookmark // where to resume next time (Time is left to the caller)
	Gap      *store.Gap     // unread data that is gone
	Reset    bool           // the file was truncated or replaced
}

// Follow reads new lines of a log file since bm, including the rest of the
// file it was rotated to, and calls fn for each complete line. A final
// line without a newline is left for next time (it is still being written).
func Follow(path string, bm store.Bookmark, fn func(string) error) (FollowResult, error) {
	var res FollowResult
	fi, err := os.Stat(path)
	if err != nil {
		return res, err
	}
	ino := inode(path, fi)
	start := int64(0)
	switch {
	case bm.Inode == 0:
		// First run: read the whole file.
	case bm.Inode == ino && fi.Size() >= bm.Offset && (bm.Head == "" || headHash(path, bm.Offset) == bm.Head):
		start = bm.Offset
	case bm.Inode == ino:
		res.Reset = true // truncated or rewritten in place (copytruncate, or emptied)
	default:
		// Rotated: finish the old file, then any files rotated after it.
		olds, found := rotatedSince(path, bm.Inode)
		if !found {
			res.Gap = &store.Gap{From: bm.Time,
				Note: "the log was rotated and its unread part was compressed or removed before it could be collected"}
		}
		for i, o := range olds {
			from := int64(0)
			if i == 0 && found {
				from = bm.Offset
			}
			if _, err := readLines(o, from, true, fn); err != nil {
				return res, err
			}
		}
	}
	n, err := readLines(path, start, false, fn)
	res.Bookmark = store.Bookmark{Inode: ino, Offset: start + n, Head: headHash(path, start+n)}
	return res, err
}

// headLen is how much of the start of a file identifies it.
const headLen = 256

// headHash fingerprints the first bytes of a file (up to limit), so a file
// that was emptied and refilled in place is not mistaken for the same one.
func headHash(path string, limit int64) string {
	n := int64(headLen)
	if limit < n {
		n = limit
	}
	if n <= 0 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		return ""
	}
	sum := sha256.Sum256(buf)
	return fmt.Sprintf("%d:%x", n, sum[:8])
}

// rotatedSince returns the rotated copy of path with the given inode
// followed by any files rotated after it, oldest first.
func rotatedSince(path string, ino uint64) ([]string, bool) {
	matches, _ := filepath.Glob(path + "?*")
	type cand struct {
		p   string
		mod int64
		ino uint64
	}
	var cs []cand
	for _, m := range matches {
		if strings.HasSuffix(m, ".gz") || strings.HasSuffix(m, ".xz") || strings.HasSuffix(m, ".bz2") {
			continue
		}
		fi, err := os.Stat(m)
		if err != nil || fi.IsDir() {
			continue
		}
		cs = append(cs, cand{m, fi.ModTime().UnixNano(), inode(m, fi)})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].mod < cs[j].mod })
	for i, c := range cs {
		if c.ino == ino {
			var out []string
			for _, x := range cs[i:] {
				out = append(out, x.p)
			}
			return out, true
		}
	}
	return nil, false
}

// readLines calls fn for each line from offset. When complete is false, a
// trailing partial line is not consumed. It returns the bytes consumed.
func readLines(path string, offset int64, complete bool, fn func(string) error) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return 0, err
		}
	}
	r := bufio.NewReaderSize(f, 256*1024)
	var n int64
	for {
		s, err := r.ReadString('\n')
		if len(s) > 0 && (strings.HasSuffix(s, "\n") || complete) {
			n += int64(len(s))
			if ferr := fn(strings.TrimRight(s, "\r\n")); ferr != nil {
				return n, ferr
			}
		}
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// ReadAll calls fn for every line of an exported log file; .gz files are
// decompressed.
func ReadAll(path string, fn func(string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		defer gz.Close()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		if err := fn(sc.Text()); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ReadJournal reads systemd journal entries after cursor (all entries when
// cursor is empty) as syslog-format lines, and returns the new cursor.
func ReadJournal(cursor string, fn func(string) error) (string, error) {
	return ReadJournalSince(cursor, time.Time{}, fn)
}

// ReadJournalSince is ReadJournal; with no cursor, it starts at since
// (when set) instead of the oldest entry.
func ReadJournalSince(cursor string, since time.Time, fn func(string) error) (string, error) {
	args := []string{"--no-pager", "--quiet", "--output=short-iso-precise", "--show-cursor"}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	} else if !since.IsZero() {
		args = append(args, "--since=@"+strconv.FormatInt(since.Unix(), 10))
	}
	cmd := exec.Command("journalctl", args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return cursor, err
	}
	if err := cmd.Start(); err != nil {
		return cursor, fmt.Errorf("run journalctl: %w", err)
	}
	next := cursor
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var ferr error
	for sc.Scan() {
		line := sc.Text()
		if c, ok := strings.CutPrefix(line, "-- cursor: "); ok {
			next = c
			continue
		}
		if ferr == nil {
			ferr = fn(line)
		}
	}
	werr := cmd.Wait()
	if ferr != nil {
		return cursor, ferr
	}
	if werr != nil {
		return cursor, fmt.Errorf("journalctl: %w", werr)
	}
	return next, sc.Err()
}
