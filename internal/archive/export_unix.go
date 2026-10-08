//go:build !windows

package archive

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/linuxlog"
	"github.com/casea1/blackbox/internal/store"
)

// export copies the lines of the logs Blackbox reads that fall in
// [from, to), unchanged: the audit log (readable with ausearch -if), and
// the system and authentication logs, or the systemd journal when there
// are no log files. Logs skip says have nothing new are left out, and so
// are logs with no lines in the period.
func export(tmp string, from, to time.Time, skip func(string) bool) ([]Source, []string) {
	var sources []Source
	var notes []string
	add := func(name, source string, write func(io.Writer) error) {
		if skip != nil && skip(source) {
			return
		}
		path := filepath.Join(tmp, name)
		f, err := os.Create(path)
		if err == nil {
			w := bufio.NewWriterSize(f, 1<<16)
			err = write(w)
			if ferr := w.Flush(); err == nil {
				err = ferr
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: could not be exported: %v", source, err))
			return
		}
		if fi, err := os.Stat(path); err == nil && fi.Size() == 0 {
			os.Remove(path)
			return
		}
		sources = append(sources, Source{Name: name, Source: source, Path: path})
	}

	if files := withRotations(collect.AuditLog); len(files) > 0 {
		add("audit.log", collect.AuditLog, func(w io.Writer) error {
			return copyLines(files, w, func(line string, _ time.Time) (time.Time, bool) { return auditTime(line) }, from, to)
		})
	} else {
		notes = append(notes, collect.AuditLog+": not on this computer")
	}
	syslogFound := false
	for _, list := range [][]string{collect.SystemLogs, collect.AuthLogs} {
		for _, p := range list {
			files := withRotations(p)
			if len(files) == 0 {
				continue
			}
			if list[0] == collect.SystemLogs[0] {
				syslogFound = true
			}
			add(filepath.Base(p), p, func(w io.Writer) error { return copyLines(files, w, syslogTime, from, to) })
			break
		}
	}
	if !syslogFound {
		add("journal.log", "systemd journal", func(w io.Writer) error {
			cmd := exec.Command("journalctl", "--no-pager", "--quiet", "--output=short-iso-precise",
				"--since=@"+strconv.FormatInt(from.Unix(), 10), "--until=@"+strconv.FormatInt(to.Unix(), 10))
			cmd.Stdout = w
			return cmd.Run()
		})
	}
	return sources, notes
}

// withRotations returns a log and its rotated copies (log.1, log.2.gz …),
// oldest first.
func withRotations(path string) []string {
	matches, _ := filepath.Glob(path + ".*")
	var out []string
	for _, m := range append(matches, path) {
		if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() && !strings.HasSuffix(m, ".xz") && !strings.HasSuffix(m, ".bz2") {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return rotationAge(out[i], path) > rotationAge(out[j], path) })
	return out
}

// rotationAge is 0 for the live log and N for log.N or log.N.gz.
func rotationAge(file, base string) int {
	s := strings.TrimSuffix(strings.TrimPrefix(file, base), ".gz")
	n, err := strconv.Atoi(strings.TrimPrefix(s, "."))
	if err != nil {
		return 0
	}
	return n
}

// copyLines writes the lines of files (oldest first) whose time is in
// [from, to). A line without a time of its own (a continuation) goes with
// the line before it.
func copyLines(files []string, w io.Writer, timeOf func(string, time.Time) (time.Time, bool), from, to time.Time) error {
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		var r io.Reader = f
		if strings.HasSuffix(name, ".gz") {
			gz, err := gzip.NewReader(f)
			if err != nil {
				f.Close()
				continue // not really gzip; skip it
			}
			r = gz
		}
		ref := to
		if fi, err := f.Stat(); err == nil {
			ref = fi.ModTime()
			if ref.Before(from.Add(-time.Hour)) {
				f.Close()
				continue // last written well before the period: nothing in it
			}
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		var last time.Time
		for sc.Scan() {
			line := sc.Text()
			if t, ok := timeOf(line, ref); ok {
				last = t
			}
			if !last.IsZero() && !last.Before(from) && last.Before(to) {
				if _, err := io.WriteString(w, line+"\n"); err != nil {
					f.Close()
					return err
				}
			}
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// auditTime reads msg=audit(SECONDS.MS:SERIAL) from an audit record.
func auditTime(line string) (time.Time, bool) {
	i := strings.Index(line, "msg=audit(")
	if i < 0 {
		return time.Time{}, false
	}
	s := line[i+len("msg=audit("):]
	j := strings.IndexByte(s, '.')
	if j <= 0 {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(s[:j], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	// The milliseconds too (AR8): a record in the same second as an
	// export's end, after it, is not before the next export's start.
	ms := s[j+1:]
	if k := strings.IndexAny(ms, ":)"); k > 0 {
		ms = ms[:k]
	}
	var nsec int64
	if len(ms) > 0 && len(ms) <= 9 {
		if v, err := strconv.ParseInt(ms, 10, 64); err == nil {
			for l := len(ms); l < 9; l++ {
				v *= 10
			}
			nsec = v
		}
	}
	return time.Unix(sec, nsec), true
}

func syslogTime(line string, ref time.Time) (time.Time, bool) {
	p := linuxlog.LineParser{Loc: time.Local, Ref: ref}
	l, ok := p.Parse(line)
	return l.Time, ok
}

// LogStates reads how far back the audit log reaches, with its rotated
// copies. Once auditd has rotated it, the oldest copy is removed as new
// ones are made, so it counts as overwriting.
func LogStates() []LogState {
	files := withRotations(collect.AuditLog)
	if len(files) == 0 {
		return nil
	}
	oldest := firstTime(files[0], func(line string, _ time.Time) (time.Time, bool) { return auditTime(line) })
	if oldest.IsZero() {
		return nil
	}
	return []LogState{{Source: collect.AuditLog, Oldest: oldest, Wraps: len(files) > 1}}
}

// firstTime is the time of the first line in file that has one.
func firstTime(name string, timeOf func(string, time.Time) (time.Time, bool)) time.Time {
	f, err := os.Open(name)
	if err != nil {
		return time.Time{}
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(name, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return time.Time{}
		}
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for i := 0; sc.Scan() && i < 1000; i++ {
		if t, ok := timeOf(sc.Text(), time.Time{}); ok {
			return t
		}
	}
	return time.Time{}
}

// exportFrom is export by position (see ByPosition): each log file from
// where its last export ended (linuxlog.Follow, which also finishes a
// file rotated since), the journal from its cursor. The audit log's
// serials are checked to follow on from the last export's.
func exportFrom(tmp string, from, to time.Time, skip func(string) bool, p *Positions) ([]Source, []string, []Gap) {
	var sources []Source
	var notes []string
	var gaps []Gap
	// add writes one log's file; it says whether the export worked (an
	// empty file is removed, but the export still worked).
	add := func(name, source string, write func(io.Writer) error) bool {
		path := filepath.Join(tmp, name)
		f, err := os.Create(path)
		if err == nil {
			w := bufio.NewWriterSize(f, 1<<16)
			err = write(w)
			if ferr := w.Flush(); err == nil {
				err = ferr
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			os.Remove(path)
			notes = append(notes, fmt.Sprintf("%s: could not be exported: %v", source, err))
			return false
		}
		if fi, err := os.Stat(path); err == nil && fi.Size() == 0 {
			os.Remove(path)
			return true
		}
		sources = append(sources, Source{Name: name, Source: source, Path: path})
		return true
	}
	// file exports one log file (and its rotations) by position.
	file := func(name, source, live string, timeOf func(string, time.Time) (time.Time, bool), check func(string)) {
		if skip != nil && skip(source) {
			return
		}
		m, have := p.Marks[source]
		var res linuxlog.FollowResult
		ok := add(name, source, func(w io.Writer) error {
			write := func(line string) error {
				if check != nil {
					check(line)
				}
				_, err := io.WriteString(w, line+"\n")
				return err
			}
			if !have {
				// No mark yet: the rotated copies and the live file by
				// time, to the millisecond, then a mark at the end.
				files := withRotations(live)
				if len(files) > 1 {
					if err := copyLines(files[:len(files)-1], w, timeOf, from, farFuture); err != nil {
						return err
					}
				}
				var last time.Time
				var err error
				res, err = linuxlog.Follow(live, store.Bookmark{}, func(line string) error {
					if t, ok := timeOf(line, to); ok {
						last = t
					}
					if last.IsZero() || last.Before(from) {
						return nil
					}
					return write(line)
				})
				return err
			}
			var err error
			res, err = linuxlog.Follow(live, m.Bookmark, write)
			return err
		})
		if !ok {
			return
		}
		next := store.ExportMark{Bookmark: res.Bookmark}
		next.Time = to
		p.Next[source] = next
		if res.Gap != nil {
			gaps = append(gaps, Gap{Source: source, From: m.Time, To: to, Reason: source + ": " + res.Gap.Note})
		}
		if res.Reset {
			notes = append(notes, source+": the file was emptied or replaced since the last export; this part starts at its beginning")
		}
	}

	if _, err := os.Stat(collect.AuditLog); err == nil {
		// Serials follow on from the last export's, with none missing;
		// a jump is a gap (AR8).
		prev := p.Marks[collect.AuditLog].Serial
		seen := map[uint64]bool{}
		var order []uint64
		at := map[uint64]time.Time{}
		file("audit.log", collect.AuditLog, collect.AuditLog, func(line string, _ time.Time) (time.Time, bool) { return auditTime(line) }, func(line string) {
			if n, t, ok := auditSerial(line); ok && !seen[n] {
				seen[n], at[n] = true, t
				order = append(order, n)
			}
		})
		if next, ok := p.Next[collect.AuditLog]; ok {
			next.Serial = prev
			missing, last := serialGaps(prev, order)
			if last > 0 {
				next.Serial = last
			}
			p.Next[collect.AuditLog] = next
			for _, m := range missing {
				before := p.Marks[collect.AuditLog].Time
				if t, ok := at[m[0]-1]; ok {
					before = t
				}
				gaps = append(gaps, Gap{Source: collect.AuditLog, From: before, To: at[m[1]+1],
					Records: fmt.Sprintf("audit serials %d-%d", m[0], m[1]),
					Reason:  fmt.Sprintf("audit serials %d-%d are not in the audit log", m[0], m[1])})
			}
		}
	} else {
		notes = append(notes, collect.AuditLog+": not on this computer")
	}
	syslogFound := false
	for _, list := range [][]string{collect.SystemLogs, collect.AuthLogs} {
		for _, path := range list {
			if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			if list[0] == collect.SystemLogs[0] {
				syslogFound = true
			}
			file(filepath.Base(path), path, path, syslogTime, nil)
			break
		}
	}
	if !syslogFound {
		const source = "systemd journal"
		if skip == nil || !skip(source) {
			m, have := p.Marks[source]
			since := time.Time{}
			if !have {
				since = from
			}
			cursor := m.Cursor
			if add("journal.log", source, func(w io.Writer) error {
				var err error
				cursor, err = linuxlog.ReadJournalSince(m.Cursor, since, func(line string) error {
					_, err := io.WriteString(w, line+"\n")
					return err
				})
				return err
			}) {
				next := store.ExportMark{}
				next.Cursor, next.Time = cursor, to
				p.Next[source] = next
			}
		}
	}
	return sources, notes, gaps
}

// serialGaps finds the audit serials missing after prev (the last one
// exported) among order, the serials seen in the order written, and the
// last serial. Records of one event share a serial and can be written a
// little out of order. Serials start again when auditd or the computer
// restarts: a drop of more than restartDrop starts a new run of serials,
// checked from its own lowest.
func serialGaps(prev uint64, order []uint64) (missing [][2]uint64, last uint64) {
	const restartDrop = 1000
	type run struct {
		seen   map[uint64]bool
		lo, hi uint64
		after  uint64 // the serial it follows on from, 0 if none
	}
	var runs []*run
	cur := &run{seen: map[uint64]bool{}, after: prev}
	for _, n := range order {
		if cur.hi > 0 && n+restartDrop < cur.hi {
			runs = append(runs, cur)
			cur = &run{seen: map[uint64]bool{}}
		} else if cur.hi == 0 && cur.after > 0 && n+restartDrop < cur.after {
			cur.after = 0 // restarted since the last export
		}
		cur.seen[n] = true
		if cur.lo == 0 || n < cur.lo {
			cur.lo = n
		}
		if n > cur.hi {
			cur.hi = n
		}
		last = n
	}
	runs = append(runs, cur)
	for _, r := range runs {
		if r.hi == 0 {
			continue
		}
		start := r.lo - 1
		if r.after > 0 && r.after < r.lo {
			start = r.after
		}
		if r.hi-start > 10_000_000 {
			continue // too far apart to be one log: not checked
		}
		for n := start + 1; n <= r.hi; n++ {
			if r.seen[n] {
				continue
			}
			m := n
			for m+1 <= r.hi && !r.seen[m+1] {
				m++
			}
			missing = append(missing, [2]uint64{n, m})
			n = m
		}
	}
	return missing, last
}

// farFuture is a time no record reaches.
var farFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// auditSerial reads the serial and time of msg=audit(SECONDS.MS:SERIAL).
func auditSerial(line string) (uint64, time.Time, bool) {
	i := strings.Index(line, "msg=audit(")
	if i < 0 {
		return 0, time.Time{}, false
	}
	s := line[i+len("msg=audit("):]
	j := strings.IndexByte(s, ':')
	k := strings.IndexByte(s, ')')
	if j <= 0 || k <= j {
		return 0, time.Time{}, false
	}
	n, err := strconv.ParseUint(s[j+1:k], 10, 64)
	if err != nil {
		return 0, time.Time{}, false
	}
	t, _ := auditTime(line)
	return n, t, true
}
