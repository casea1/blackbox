//go:build !windows

package archive

import (
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
)

func TestFileNameRoundTrip(t *testing.T) {
	from := time.Date(2026, 9, 23, 14, 5, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	name := FileName("DEV_UBUNTU 3", from, to)
	host, f, tt, ok := ParseFileName(name)
	if !ok || host != "DEV-UBUNTU-3" || !f.Equal(from) || !tt.Equal(to) {
		t.Fatalf("%s → %q %v %v %v", name, host, f, tt, ok)
	}
}

func TestDue(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if from, due := Due(time.Time{}, now); !due || !from.Equal(now.Add(-FirstSpan)) {
		t.Error("the first archive reaches back a week")
	}
	if _, due := Due(now.Add(-23*time.Hour), now); due {
		t.Error("due again within a day")
	}
	if from, due := Due(now.Add(-25*time.Hour), now); !due || !from.Equal(now.Add(-25*time.Hour)) {
		t.Error("the next archive starts where the last ended")
	}
}

func TestCreateVerifyFileAndPrune(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "log")
	os.MkdirAll(logs, 0o755)
	from := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	in, out := from.Add(time.Hour).Unix(), from.Add(-time.Hour).Unix()

	audit := filepath.Join(logs, "audit.log")
	os.WriteFile(audit+".1", []byte("type=USER_LOGIN msg=audit("+itoa(out)+".100:1): old\ntype=USER_LOGIN msg=audit("+itoa(in)+".100:2): rotated-in-range\n"), 0o644)
	os.WriteFile(audit, []byte("type=SYSCALL msg=audit("+itoa(in)+".200:3): live-in-range\ntype=PROCTITLE msg=audit("+itoa(to.Unix())+".000:4): too-late\n"), 0o644)
	syslog := filepath.Join(logs, "syslog")
	os.WriteFile(syslog, []byte("2026-09-29T01:00:00.000000+00:00 ubu sshd[1]: kept\n  continuation line\n2026-09-28T23:00:00.000000+00:00 ubu sshd[1]: before\n"), 0o644)
	var gz strings.Builder
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("2026-09-29T02:00:00.000000+00:00 ubu sudo[2]: from-gz\n"))
	zw.Close()
	os.WriteFile(syslog+".2.gz", []byte(gz.String()), 0o644)

	defer func(a string, s, au []string) { collect.AuditLog, collect.SystemLogs, collect.AuthLogs = a, s, au }(collect.AuditLog, collect.SystemLogs, collect.AuthLogs)
	collect.AuditLog, collect.SystemLogs, collect.AuthLogs = audit, []string{syslog}, []string{filepath.Join(logs, "auth.log")}

	path := filepath.Join(dir, FileName("ubu", from, to))
	info, err := Create(path, "ubu", "linux", from, to, to, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := readZip(t, path)
	if a := got["audit.log"]; !strings.Contains(a, "rotated-in-range") || !strings.Contains(a, "live-in-range") || strings.Contains(a, "old") || strings.Contains(a, "too-late") {
		t.Errorf("audit.log:\n%s", a)
	}
	if s := got["syslog"]; !strings.Contains(s, "kept\n  continuation line") || !strings.Contains(s, "from-gz") || strings.Contains(s, "before") {
		t.Errorf("syslog:\n%s", s)
	}
	if strings.Index(got["syslog"], "from-gz") > strings.Index(got["syslog"], "kept") {
		t.Error("rotated logs come first")
	}
	if len(info.Files) != 2 {
		t.Errorf("files: %+v (notes %v)", info.Files, info.Notes)
	}

	if _, err := Verify(path); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// An altered archive is caught.
	bad := filepath.Join(dir, "bad.zip")
	tamper(t, path, bad)
	if _, err := Verify(bad); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("tampered archive: %v", err)
	}

	reports := filepath.Join(dir, "archives")
	dest, err := File(path, reports, info)
	if err != nil || filepath.Base(filepath.Dir(dest)) != "ubu" {
		t.Fatalf("file: %s %v", dest, err)
	}
	list, _ := List(reports)
	if len(list) != 1 || list[0].Host != "ubu" || !list[0].To.Equal(to) {
		t.Fatalf("list: %+v", list)
	}
	Prune(reports, 30, to.AddDate(0, 0, 10))
	if list, _ := List(reports); len(list) != 1 {
		t.Error("pruned too soon")
	}
	Prune(reports, 30, to.AddDate(0, 0, 31))
	if list, _ := List(reports); len(list) != 0 {
		t.Error("not pruned")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func readZip(t *testing.T, path string) map[string]string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out := map[string]string{}
	for _, f := range zr.File {
		r, _ := f.Open()
		b, _ := io.ReadAll(r)
		r.Close()
		out[f.Name] = string(b)
	}
	return out
}

// tamper copies an archive, changing one log's content but not its hash.
func tamper(t *testing.T, src, dst string) {
	t.Helper()
	files := readZip(t, src)
	f, _ := os.Create(dst)
	zw := zip.NewWriter(f)
	for name, content := range files {
		if name == "audit.log" {
			content = strings.Replace(content, "live-in-range", "LIVE-IN-RANGE", 1)
		}
		w, _ := zw.Create(name)
		w.Write([]byte(content))
	}
	zw.Close()
	f.Close()
}

func TestBundleCombinesDays(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "Security.evtx")
	os.WriteFile(logFile, []byte("pretend evtx"), 0o644)
	day1 := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	var list []Stored
	for i := 0; i < 2; i++ {
		from, to := day1.AddDate(0, 0, i), day1.AddDate(0, 0, i+1)
		p := filepath.Join(dir, FileName("WS-07", from, to))
		if _, err := Write(p, Info{Host: "WS-07", From: from, To: to, Created: to}, []Source{{Name: "Security.evtx", Source: "Security", Path: logFile}}); err != nil {
			t.Fatal(err)
		}
		list = append(list, Stored{Host: "WS-07", From: from, To: to, Path: p})
	}
	dst := filepath.Join(dir, "logs-WS-07.zip")
	from, to, sum, _, err := Bundle(dst, list)
	if err != nil || !from.Equal(day1) || !to.Equal(day1.AddDate(0, 0, 2)) || len(sum) != 64 {
		t.Fatalf("bundle: %v %v %s %v", from, to, sum, err)
	}
	got := readZip(t, dst)
	for _, want := range []string{"20260928-0000Z_20260929-0000Z/Security.evtx", "20260929-0000Z_20260930-0000Z/archive.json"} {
		if _, ok := got[want]; !ok {
			t.Errorf("bundle is missing %s (has %v)", want, got)
		}
	}
	if got["20260928-0000Z_20260929-0000Z/Security.evtx"] != "pretend evtx" {
		t.Error("log content changed in the bundle")
	}
	// A damaged daily archive stops the bundle rather than being included.
	os.WriteFile(list[0].Path, []byte("damaged"), 0o644)
	if _, _, _, _, err := Bundle(dst, list); err == nil {
		t.Error("damaged archive bundled")
	}
}

// Linux: once auditd has rotated the audit log, it counts as overwriting,
// reaching back to the first record of the oldest copy.
func TestAuditLogStates(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.log")
	defer func(a string) { collect.AuditLog = a }(collect.AuditLog)
	collect.AuditLog = audit
	os.WriteFile(audit, []byte("type=SYSCALL msg=audit(1791158400.000:9): live\n"), 0o644)
	if s := LogStates(); s != nil {
		t.Errorf("not rotated yet: %+v", s)
	}
	os.WriteFile(audit+".2", []byte("garbage\ntype=SYSCALL msg=audit(1791150000.500:1): oldest\n"), 0o644)
	os.WriteFile(audit+".1", []byte("type=SYSCALL msg=audit(1791155000.000:5): newer\n"), 0o644)
	s := LogStates()
	if len(s) != 1 || !s[0].Wraps || s[0].Oldest.Unix() != 1791150000 {
		t.Errorf("states: %+v", s)
	}
}
