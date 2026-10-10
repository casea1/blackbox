package lan

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/scap"
	"github.com/casea1/blackbox/internal/store"
)

// scanOf is an XCCDF document with one TestResult for each host, each
// for a different benchmark.
func scanOf(hosts ...string) string {
	x := `<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark_B">
  <Rule id="xccdf_test_rule_r1" severity="high"><title>Rule one</title></Rule>
`
	for i, h := range hosts {
		x += `  <TestResult id="xccdf_test_testresult_` + string(rune('a'+i)) + `" start-time="2026-10-05T00:17:00" end-time="2026-10-05T00:17:53">
    <benchmark href="#xccdf_test_benchmark_B` + string(rune('a'+i)) + `"/>
    <target>` + h + `</target>
    <rule-result idref="xccdf_test_rule_r1" severity="high"><result>fail</result></rule-result>
  </TestResult>
`
	}
	return x + "</Benchmark>\n"
}

// deliverScan has sender (signed as host) deliver doc, then imports the
// inbox with dirs.
func deliverScan(t *testing.T, host, doc string, dirs Dirs) (ImportResult, string) {
	t.Helper()
	in := inbox(t)
	ws := system(t, host, "windows", 1, t0)
	send(t, ws, host, in, t0)
	f := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(f, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := QueueScap(ws, []string{f}, t0); err != nil || n != 1 {
		t.Fatalf("queued %d %v", n, err)
	}
	if n, err := DeliverScap(ws, in, host); err != nil || n != 1 {
		t.Fatalf("delivered %d %v", n, err)
	}
	col, _ := store.Open(t.TempDir())
	res, err := Import(col, in, dirs, t0, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	return res, in
}

// SEC5: a sender cannot file a SCAP result for another computer by
// putting it after one for itself in the same file.
func TestScapResultForAnotherComputerRefused(t *testing.T) {
	for _, req := range []bool{false, true} {
		scapDir := filepath.Join(t.TempDir(), "scap-received")
		res, _ := deliverScan(t, "WS-07", scanOf("WS-07", "DC-01"), Dirs{Scap: scapDir, RequireSigned: req})
		if res.Scap != 0 || len(res.Rejected) != 1 || !strings.Contains(res.Rejected[0], "more than one computer") {
			t.Errorf("require_signed %v: %+v", req, res)
		}
		if got, _ := filepath.Glob(filepath.Join(scapDir, "*", "*")); len(got) != 0 {
			t.Errorf("require_signed %v: filed %v", req, got)
		}
	}
}

// Several benchmarks for the same computer in one file still go through.
func TestScapSeveralBenchmarksOneComputer(t *testing.T) {
	scapDir := filepath.Join(t.TempDir(), "scap-received")
	res, _ := deliverScan(t, "WS-07", scanOf("WS-07", "ws-07.example.mil"), Dirs{Scap: scapDir})
	if res.Scap != 1 || len(res.Rejected) != 0 {
		t.Fatalf("import %+v", res)
	}
	found, _ := scap.FindWithReceived(scapDir)
	if len(found) != 2 {
		t.Errorf("found %d scans, want 2", len(found))
	}
}

// A result for another computer kept by an earlier version, in the
// folder of the computer that sent it, does not show in the report.
func TestScapStoredForAnotherComputerIgnored(t *testing.T) {
	scapDir := filepath.Join(t.TempDir(), "scap-received")
	dir := filepath.Join(scapDir, "WS-07")
	os.MkdirAll(dir, 0o750)
	f, _ := os.Create(filepath.Join(dir, "scap_x_0123456789abcdef.xml.gz"))
	z := gzip.NewWriter(f)
	z.Write([]byte(scanOf("WS-07", "DC-01")))
	z.Close()
	f.Close()
	found, notes := scap.FindWithReceived(scapDir)
	if len(found) != 1 {
		t.Fatalf("found %d scans, want 1: %v", len(found), notes)
	}
	for _, s := range found {
		if s.Latest.Host != "WS-07" {
			t.Errorf("kept the result for %s", s.Latest.Host)
		}
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "DC-01") {
		t.Errorf("notes: %v", notes)
	}
}
