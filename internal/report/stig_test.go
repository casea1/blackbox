package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/store"
)

// COMP2: a check with no STIG ID is worded as Blackbox's advice, never
// "the STIG requires", and is left out of "Systems matching STIG" but
// counted on its own.
func TestAdviceNotSTIG(t *testing.T) {
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	sets := []CheckSet{NewCheckSet("ubu-01", at, []check.Result{
		{Area: "Baseline", Item: "Compared with", Status: check.Info, Have: "Ubuntu 24.04 STIG V1R5"},
		{Area: "Time", Item: "Time synchronisation", Status: check.Fail, Have: "no time service running", Want: "chrony or systemd-timesyncd active"},
		{Area: "Audit rules", Item: "Rules locked until reboot (-e 2)", Status: check.Pass, Have: "Locked", Want: "Locked (enabled 2)", STIG: "UBTU-24-909000"},
	})}
	runs := []*store.Run{{Time: at, Host: "ubu-01", OS: "linux"}}
	r := Build(nil, runs, Options{Location: time.UTC, WindowStart: at.Add(-24 * time.Hour), WindowEnd: at, Generated: at, CheckSets: sets})
	hp := r.healthPage()
	if hp.Stats[0].Label != "Systems matching STIG" || hp.Stats[0].Value != "1 / 1" || hp.Stats[0].Note != "0 gaps · 0 warnings" {
		t.Errorf("advice counted against the STIG: %+v", hp.Stats[0])
	}
	if hp.Stats[1].Label != "Blackbox's advice" || hp.Stats[1].Value != "1" || hp.Stats[1].Level != "warn" {
		t.Errorf("advice count: %+v", hp.Stats[1])
	}
	found := false
	for _, g := range hp.Gaps {
		if g.Title != "Time synchronisation" {
			continue
		}
		found = true
		if strings.Contains(g.Explain, "STIG requires") || !strings.Contains(g.Explain, "Blackbox recommends chrony or systemd-timesyncd active") || !g.Advice || g.Level != "warn" {
			t.Errorf("advice gap: %+v", g)
		}
	}
	if !found {
		t.Error("the advice is not listed")
	}
	for _, k := range r.overview(nil).KPIs {
		if k.Label == "Audit health" && k.Value != "1 / 1" {
			t.Errorf("overview Audit health %q: advice counted against the STIG", k.Value)
		}
	}
	var b bytes.Buffer
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	if html := b.String(); !strings.Contains(html, "Blackbox&#39;s advice") || !strings.Contains(html, ">Advice</span>") {
		t.Error("the page does not mark the advice")
	}
}

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
