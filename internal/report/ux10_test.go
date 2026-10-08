package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/inventory"
)

// UX10: the Health list says its counts in words; a clear on a system
// whose name differs in case from its rows is "Logs cleared", never
// "Logs intact"; and the events-lost card says what its count covers.
func TestHealthListWording(t *testing.T) {
	at := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	events := []*event.Event{{Time: at, Host: "win11-test", OS: "windows", Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_cleared",
		User: "claude", Target: "Microsoft-Windows-PowerShell/Operational", Summary: "Log cleared."}}
	r := Build(events, nil, Options{Location: time.UTC, WindowStart: at.Add(-time.Hour), WindowEnd: at.Add(time.Hour), Generated: at.Add(time.Hour),
		Systems: []SystemInfo{{Name: "WIN11-TEST", OS: "windows", LastRun: at}, {Name: "SRV", OS: "windows", LastRun: at}, {Name: "ubu", OS: "linux", LastRun: at}}})
	o := r.overview(nil)
	var cleared *CheckLine
	for i, c := range o.Checks {
		if c.Title == "Logs cleared" {
			cleared = &o.Checks[i]
		}
		if strings.Contains(c.Count, "/") {
			t.Errorf("%s: unlabelled count %q", c.Title, c.Count)
		}
	}
	if cleared == nil || cleared.Count != "1 of 3 systems" {
		t.Fatalf("checks: %+v", o.Checks)
	}
	if strings.Contains(o.Fine, "Logs intact") {
		t.Error(`"Logs intact" next to a clear`)
	}
	if got := lostNote(0, 2); got != "checked at 2 collections" {
		t.Errorf("lost note: %q", got)
	}
}

// UX10: a Linux computer with no desktop (Ubuntu Server) is listed with
// the servers.
func TestUbuntuServerIsAServer(t *testing.T) {
	s := SystemRow{SystemInfo: SystemInfo{Name: "ubuntu-server", OS: "linux"}, Checks: &CheckSet{Baseline: "Ubuntu 24.04 STIG", Inventory: &inventory.Inventory{Server: true}}}
	if !isServer(s) {
		t.Error("Ubuntu Server is not a server")
	}
	s.Checks.Inventory.Server = false
	if isServer(s) {
		t.Error("Ubuntu with a desktop is a server")
	}
}
