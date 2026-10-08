package report

import (
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// REVIEW-8: two separate SSH sign-ins of one account from different
// addresses within 2 s are joined; the second address vanishes from rows.
func TestReviewSSHPairsDifferentSources(t *testing.T) {
	at := time.Date(2026, 10, 6, 3, 0, 0, 0, time.UTC)
	mk := func(ip string, d time.Duration, id string) *event.Event {
		e := &event.Event{Time: at.Add(d), Collected: at, Host: "SRV-01", OS: "windows", Category: event.CatLogon,
			Severity: event.SevInfo, Action: "logon", User: "CORP\\admin", SourceIP: ip, Source: "Security", EventID: 4624,
			Summary: "admin logged on over SSH from " + ip}
		e.AddDetail("Logon type", "SSH (OpenSSH)")
		e.AddDetail("Logon ID", id)
		return e
	}
	r := Build([]*event.Event{mk("10.0.0.5", 0, "0x1"), mk("203.0.113.66", time.Second, "0x2")}, nil, Options{Location: time.UTC, Source: "test"})
	ips := map[string]bool{}
	for _, e := range r.Events {
		ips[e.SourceIP] = true
	}
	t.Logf("events=%d ips=%v", len(r.Events), ips)
	if !ips["203.0.113.66"] {
		t.Error("the sign-in from 203.0.113.66 is not a row (joined into the 10.0.0.5 one)")
	}
}
