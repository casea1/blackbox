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
)

// export copies the lines of the logs Blackbox reads that fall in
// [from, to), unchanged: the audit log (readable with ausearch -if), and
// the system and authentication logs, or the systemd journal when there
// are no log files.
func export(tmp string, from, to time.Time) ([]Source, []string) {
	var sources []Source
	var notes []string
	add := func(name, source string, write func(io.Writer) error) {
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
	return time.Unix(sec, 0), true
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
	if len(files) < 2 {
		return nil
	}
	oldest := firstTime(files[0], func(line string, _ time.Time) (time.Time, bool) { return auditTime(line) })
	if oldest.IsZero() {
		return nil
	}
	return []LogState{{Source: collect.AuditLog, Oldest: oldest, Wraps: true}}
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
