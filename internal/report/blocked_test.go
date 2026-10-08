package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// LOCK1: collection refused while a run held the lock reaches Audit
// health as a gap in collection, with when and which process.
func TestBlockedCollectionInAuditHealth(t *testing.T) {
	end := fx0.Add(24 * time.Hour)
	runs := []*store.Run{
		{Time: fx0.Add(time.Hour), Host: "ubu1", OS: "linux"},
		{Time: fx0.Add(3 * time.Hour), Host: "ubu1", OS: "linux", Blocked: &store.Blocked{
			Holder: store.Holder{PID: 31025, Since: fx0.Add(time.Hour)}, First: fx0.Add(75 * time.Minute), Last: fx0.Add(105 * time.Minute),
			Refused: 3, Until: fx0.Add(3 * time.Hour)}},
	}
	r := Build(nil, runs, Options{WindowEnd: end, Location: time.UTC, Systems: []SystemInfo{{Name: "ubu1", OS: "linux", LastRun: fx0.Add(3 * time.Hour)}}})
	if len(r.Health.Blocked) != 1 || r.Health.Blocked[0].PID != 31025 || r.Health.Blocked[0].Refused != 3 {
		t.Fatalf("health blocked = %+v", r.Health.Blocked)
	}
	warned := false
	for _, w := range r.Health.Warnings {
		if strings.Contains(w, "collection was blocked from") && strings.Contains(w, "PID 31025") && strings.Contains(w, "3 scheduled runs collected nothing") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("warnings: %q", r.Health.Warnings)
	}
	hp := r.healthPage()
	// UI-R1: not a settings gap; the system's own Reporting line tells it.
	var line *SettingLine
	for _, g := range hp.Groups {
		for _, row := range g.Rows {
			for i := range row.Table {
				if row.Name == "ubu1" && row.Table[i].Check == "Reporting" {
					line = &row.Table[i]
				}
			}
		}
	}
	if line == nil || line.Class != "bad" || !strings.Contains(line.Note, "3 runs refused because another Blackbox run held its lock (PID 31025)") {
		t.Fatalf("reporting line = %+v", line)
	}
	for _, g := range hp.Gaps {
		if g.Title == "Collection was blocked" {
			t.Error("a blocked collection listed as a setting to fix")
		}
	}
}
