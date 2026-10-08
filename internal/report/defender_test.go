package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// T2b: a 5038 on a Defender platform file within minutes of a Defender
// update into that platform's folder is Medium "during a Defender
// update"; with no update, or an update to another version, it stays
// High. The update itself is not a row.
func TestDefender5038DuringUpdate(t *testing.T) {
	at := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	file := `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25080.5-0\DefenderSessionHelper.dll`
	ci := func(host string) *event.Event {
		return &event.Event{Time: at, Host: host, OS: "windows", Category: event.CatIntegrity, Severity: event.SevHigh, Action: "code_integrity_failed", Target: file,
			Summary: "Windows found a system file whose signature doesn't match: " + file + " — it may have been altered. This is a Microsoft Defender platform file: Windows often logs this while Defender is updating its platform."}
	}
	upd := func(host string, d time.Duration, versions string) *event.Event {
		return &event.Event{Time: at.Add(d), Host: host, OS: "windows", Category: event.CatOther, Severity: event.SevInfo, Action: event.DefenderUpdate,
			Summary: "Microsoft Defender updated.", Fields: map[string]string{"versions": versions}}
	}
	events := []*event.Event{
		upd("A", -2*time.Minute, "4.18.25080.5-0 4.18.25070.5-0"), ci("A"), // during the update
		ci("B"),                                           // no update
		upd("C", time.Minute, "4.18.24090.11-0"), ci("C"), // another version
		upd("D", -time.Hour, "4.18.25080.5-0"), ci("D"), // an hour earlier
	}
	r := Build(events, nil, Options{Location: time.UTC, WindowStart: at.Add(-2 * time.Hour), WindowEnd: at.Add(time.Hour), Generated: at.Add(time.Hour)})
	sev := map[string]event.Severity{}
	for _, e := range r.Events {
		if e.Action == event.DefenderUpdate {
			t.Errorf("the update is a row: %+v", e)
		}
		if e.Action == "code_integrity_failed" {
			sev[e.Host] = e.Severity
			if e.Host == "A" && (!strings.Contains(e.Summary, "during a Microsoft Defender update (it updated 2 minutes earlier, to this platform version)") || detail(e, "Defender update") == "") {
				t.Errorf("A: %s %+v", e.Summary, e.Details)
			}
		}
	}
	if sev["A"] != event.SevMedium || sev["B"] != event.SevHigh || sev["C"] != event.SevHigh || sev["D"] != event.SevHigh {
		t.Errorf("severities: %v", sev)
	}
}
