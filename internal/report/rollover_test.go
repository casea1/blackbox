package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// LOG1: the 7 Oct report's "Events lost to log rollover: WIN11-TEST: 447"
// was the PowerShell log. It is named wherever the loss is shown, kept
// apart from (and below) losses from the audit record, and the advice
// fits a system that already collects every 15 minutes.
func TestPowerShellLossNamedAndApart(t *testing.T) {
	end := fx0.Add(24 * time.Hour)
	var runs []*store.Run
	for i := 1; i < 96; i++ {
		at := fx0.Add(time.Duration(i) * 15 * time.Minute)
		r := &store.Run{Time: at, Host: "WIN11-TEST", OS: "windows", Channels: []store.ChannelRun{{Channel: "Security"}}}
		if i == 50 {
			r.Channels = append(r.Channels, store.ChannelRun{Channel: "Microsoft-Windows-PowerShell/Operational", MaxSizeBytes: 15 << 20,
				OldestTime: at.Add(-9 * time.Minute), Gap: &store.Gap{Lost: 447, From: at.Add(-15 * time.Minute), To: at.Add(-9 * time.Minute)}})
		}
		runs = append(runs, r)
	}
	r := Build(nil, runs, Options{WindowStart: fx0, WindowEnd: end, Location: time.UTC, Source: "Live collection",
		Systems: []SystemInfo{{Name: "WIN11-TEST", OS: "windows", LastRun: end}}})

	var lines []string
	for _, l := range r.overview(nil).Checks {
		lines = append(lines, l.Level+"|"+l.Title+"|"+l.What)
		if l.Title == "Events lost to log rollover" {
			t.Errorf("a PowerShell log loss is shown as the audit record's: %+v", l)
		}
	}
	all := strings.Join(lines, "\n")
	if !strings.Contains(all, "warn|Other logs overwrote events|PowerShell log: 447 events overwritten") ||
		!strings.Contains(all, "ok|No events lost from the audit logs") {
		t.Errorf("overview checklist:\n%s", all)
	}

	w := strings.Join(r.Health.Warnings, "\n")
	if !strings.Contains(w, "PowerShell log on WIN11-TEST: 447 events were overwritten") || !strings.Contains(w, "too small for how fast it is written") ||
		strings.Contains(w, "collect_every") {
		t.Errorf("warnings:\n%s", w)
	}

	hp := r.healthPage()
	// UI-R1: on the Log sizes tab, a warning, not the audit record.
	if len(hp.Losses) != 1 || hp.LostCritical {
		t.Fatalf("losses: %+v", hp.Losses)
	}
	if l := hp.Losses[0]; l.Level != "warn" || l.Host != "WIN11-TEST" || l.Log != "PowerShell log" || l.Lost != "447" ||
		!strings.Contains(l.Advice, "too small for how fast it is written") || strings.Contains(l.Advice, "collect_every") || !strings.Contains(hp.LossNote, "no export has them") {
		t.Errorf("loss: %+v", l)
	}
	for _, c := range hp.Cards {
		if c.Tab == "logs" && (c.Value != "1" || c.Level != "warn" || c.Note != "system overwrote events (PowerShell log) · 0 Security/audit lost") {
			t.Errorf("logs card: %+v", c)
		}
	}
	seen := false
	for _, s := range r.systemsPage().Groups {
		for _, v := range s.Systems {
			for _, l := range v.Health {
				if l.Title == "Other logs overwrote events" {
					seen = true
					if l.Level != "warn" || !strings.Contains(l.What, "PowerShell log: 447 events overwritten") {
						t.Errorf("systems page: %+v", l)
					}
				}
				if l.Title == "Events lost to log rollover" {
					t.Errorf("systems page shows the PowerShell loss as the audit record's: %+v", l)
				}
			}
		}
	}

	if !seen {
		t.Error("the systems page does not show the PowerShell log loss")
	}

	// A Security log loss on the same system stays High.
	runs[60].Channels[0].Gap = &store.Gap{Lost: 5}
	r = Build(nil, runs, Options{WindowStart: fx0, WindowEnd: end, Location: time.UTC, Source: "Live collection",
		Systems: []SystemInfo{{Name: "WIN11-TEST", OS: "windows", LastRun: end}}})
	found := false
	for _, l := range r.overview(nil).Checks {
		if l.Title == "Events lost to log rollover" && l.Level == "bad" && strings.Contains(l.What, "Security log: 5 events") {
			found = true
		}
	}
	if !found {
		t.Errorf("Security log loss not High: %+v", r.overview(nil).Checks)
	}
}
