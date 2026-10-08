//go:build !windows

package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
)

func useLogs(t *testing.T, dir string) string {
	t.Helper()
	a, s, au := collect.AuditLog, collect.SystemLogs, collect.AuthLogs
	t.Cleanup(func() { collect.AuditLog, collect.SystemLogs, collect.AuthLogs = a, s, au })
	audit := filepath.Join(dir, "audit.log")
	syslog := filepath.Join(dir, "syslog")
	os.WriteFile(syslog, nil, 0o644)
	collect.AuditLog, collect.SystemLogs, collect.AuthLogs = audit, []string{syslog}, nil
	return audit
}

func appendAudit(t *testing.T, path string, at time.Time, serials ...int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range serials {
		fmt.Fprintf(f, "type=SYSCALL msg=audit(%d.%03d:%d): rec%d\n", at.Unix(), at.Nanosecond()/1e6, n, n)
	}
	f.Close()
}

func exported(t *testing.T, srcs []Source, name string) string {
	t.Helper()
	for _, s := range srcs {
		if s.Name == name {
			b, _ := os.ReadFile(s.Path)
			return string(b)
		}
	}
	return ""
}

// AR8: the audit log is exported by position. A record written in the
// same second as an export's end, after it, is in the next piece (by
// time it read as before the next piece's start and was lost); a log
// rotated between runs is finished, then the new one read; a jump in the
// audit serials is a gap.
func TestAuditExportByPosition(t *testing.T) {
	dir := t.TempDir()
	audit := useLogs(t, dir)
	cut := time.Date(2026, 10, 7, 12, 31, 30, 0, time.UTC)
	appendAudit(t, audit, cut.Add(-time.Minute), 41320, 41321)
	appendAudit(t, audit, cut.Add(-200*time.Millisecond), 41322)

	pos := &Positions{}
	exp := ByPosition(pos)
	out := t.TempDir()
	srcs, notes, gaps := exp(out, cut.Add(-time.Hour), cut, nil)
	if got := exported(t, srcs, "audit.log"); strings.Count(got, "\n") != 3 || len(gaps) != 0 {
		t.Fatalf("first export: %q %v %v", got, notes, gaps)
	}
	mark := pos.Next[audit]
	if mark.Serial != 41322 || mark.Offset == 0 {
		t.Fatalf("mark: %+v", mark)
	}

	// In the same second as the cut, after it.
	appendAudit(t, audit, cut.Add(400*time.Millisecond), 41323)
	appendAudit(t, audit, cut.Add(2*time.Minute), 41324)
	pos = &Positions{Marks: pos.Next}
	exp = ByPosition(pos)
	srcs, _, gaps = exp(t.TempDir(), cut, cut.Add(15*time.Minute), nil)
	if got := exported(t, srcs, "audit.log"); !strings.Contains(got, ":41323)") || strings.Count(got, "\n") != 2 || len(gaps) != 0 {
		t.Fatalf("second export: %q %v", got, gaps)
	}

	// Rotated between runs, with a serial missing.
	appendAudit(t, audit, cut.Add(16*time.Minute), 41325)
	os.Rename(audit, audit+".1")
	appendAudit(t, audit, cut.Add(17*time.Minute), 41330)
	pos = &Positions{Marks: pos.Next}
	exp = ByPosition(pos)
	srcs, _, gaps = exp(t.TempDir(), cut.Add(15*time.Minute), cut.Add(30*time.Minute), nil)
	got := exported(t, srcs, "audit.log")
	if !strings.Contains(got, ":41325)") || !strings.Contains(got, ":41330)") || strings.Count(got, "\n") != 2 {
		t.Errorf("after rotation: %q", got)
	}
	if len(gaps) != 1 || gaps[0].Records != "audit serials 41326-41329" || gaps[0].Reason == "" {
		t.Errorf("serial gap: %+v", gaps)
	}
	if pos.Next[audit].Serial != 41330 {
		t.Errorf("serial mark %d", pos.Next[audit].Serial)
	}
}

// AR8: by time, an audit record's milliseconds count.
func TestAuditTimeMilliseconds(t *testing.T) {
	at, ok := auditTime("type=SYSCALL msg=audit(1791369090.437:41323): x")
	if !ok || at.Nanosecond() != 437e6 {
		t.Errorf("%v %v", at, ok)
	}
}

// AR8: serial gaps, allowing for records written a little out of order
// and serials starting again after a restart.
func TestSerialGaps(t *testing.T) {
	for _, c := range []struct {
		prev  uint64
		order []uint64
		want  string
		last  uint64
	}{
		{100, []uint64{101, 103, 102, 104}, "", 104},
		{100, []uint64{101, 104}, "102-103", 104},
		{100, []uint64{102}, "101-101", 102},
		{5000, []uint64{1, 2, 4}, "3-3", 4},                      // restarted since the last export
		{0, []uint64{1000, 1001, 5000, 1, 2, 3}, "1002-4999", 3}, // a restart within the export
		{0, []uint64{9000, 9001, 1, 2}, "", 2},
	} {
		missing, last := serialGaps(c.prev, c.order)
		var got []string
		for _, m := range missing {
			got = append(got, fmt.Sprintf("%d-%d", m[0], m[1]))
		}
		if strings.Join(got, ",") != c.want || last != c.last {
			t.Errorf("%d %v: %v, last %d", c.prev, c.order, got, last)
		}
	}
}
