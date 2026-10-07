package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/store"
)

// STIG1: a gap two systems share under different STIGs lists each one's
// IDs, by OS; the CSV gives each system its own.
func TestGapSTIGsPerSystem(t *testing.T) {
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	set := func(host, baseline, ids string) CheckSet {
		return NewCheckSet(host, at, []check.Result{
			{Area: "Baseline", Item: "STIG", Status: check.Info, Have: baseline},
			{Area: "Audit policy", Item: "Credential Validation", Status: check.Fail, Have: "No auditing", Want: "Success and Failure", STIG: ids},
		})
	}
	sets := []CheckSet{set("WIN-498EC8UMUEL", "Windows Server 2025 STIG V1R1", "WN25-AU-000070, WN25-AU-000080"),
		set("WIN11-TEST", "Windows 11 STIG V2R8", "WN11-AU-000010, WN11-AU-000005")}
	runs := []*store.Run{{Time: at, Host: "WIN-498EC8UMUEL", OS: "windows"}, {Time: at, Host: "WIN11-TEST", OS: "windows"}}
	r := Build(nil, runs, Options{Location: time.UTC, WindowStart: at.Add(-24 * time.Hour), WindowEnd: at, Generated: at, CheckSets: sets})
	hp := r.healthPage()
	var got string
	for _, g := range hp.Gaps {
		if g.Title == "Credential Validation" {
			got = g.STIG
		}
	}
	if !strings.Contains(got, "WN25-AU-000070, WN25-AU-000080 (Windows Server 2025)") || !strings.Contains(got, "WN11-AU-000010, WN11-AU-000005 (Windows 11)") {
		t.Errorf("gap STIG IDs: %q", got)
	}
	csv := r.healthCSV(hp)
	if !strings.Contains(csv, "WIN11-TEST,Credential Validation,\"WN11-AU-000010, WN11-AU-000005\"") {
		t.Errorf("CSV:\n%s", csv)
	}
}
