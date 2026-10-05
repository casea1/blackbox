package event

import "testing"

// A15: what Blackbox writes to the system log reads back the same.
func TestSelfChangeRoundTrip(t *testing.T) {
	for _, c := range []SelfChange{
		{Kind: "setting", Setting: "retention_days", Old: "365", New: "30", Who: "claude", Program: "blackbox config set"},
		{Kind: "setting", Setting: "exclude_users", Old: "", New: `svc_a, "odd" (x) to y`, Who: `SERVER\claude`, Program: "setup"},
		{Kind: "installed", Version: "0.11.0", Who: "claude", Program: "setup"},
		{Kind: "upgraded", Old: "0.10.4", Version: "0.11.0", Who: "claude", Program: "setup"},
		{Kind: "upgraded", Version: "0.11.0", Who: "claude", Program: "setup"},
		{Kind: "removed", Who: "claude", Program: "blackbox uninstall"},
		{Kind: "resent", New: "214-216,219", Old: `\\COLLECTOR\BlackboxInbox`, Who: `WS-07\claude`, Program: "blackbox send --resend"},
	} {
		got, ok := ParseSelfChange(c.Message())
		if !ok || got != c {
			t.Errorf("%q read back as %+v (ok %v)", c.Message(), got, ok)
		}
	}
	e := SelfChange{Kind: "setting", Setting: "exclude_users", Old: "", New: "bob", Who: "claude", Program: "blackbox config set"}.Event()
	if e.Severity != SevHigh || e.Summary != "claude changed Blackbox's exclude_users setting from (empty) to bob (blackbox config set)." {
		t.Errorf("event: %s %s", e.Severity, e.Summary)
	}
	if e := (SelfChange{Kind: "setting", Setting: "site_name", New: "Lab", Program: "setup"}).Event(); e.Severity != SevMedium {
		t.Errorf("site_name: %s", e.Severity)
	}
	if e := (SelfChange{Kind: "resent", New: "214-219", Old: "/mnt/inbox", Who: "claude", Program: "blackbox send --resend"}).Event(); e.Severity != SevMedium ||
		e.Action != "blackbox_batches_resent" || e.Summary != "claude sent Blackbox batches 214-219 to the collector again (/mnt/inbox)." {
		t.Errorf("resent: %s %s %s", e.Action, e.Severity, e.Summary)
	}
	if _, ok := ParseSelfChange("Blackbox did something else."); ok {
		t.Error("parsed an unknown line")
	}
}
