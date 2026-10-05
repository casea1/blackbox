package archive

import (
	"testing"
	"time"
)

// A full log that reaches back less than the margin before the last save
// (or not even to it) is saved early; the part it no longer holds is a gap.
func TestAtRiskAndGaps(t *testing.T) {
	saved := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	states := []LogState{
		{Source: "Security", Oldest: saved.Add(40 * time.Minute), Wraps: true}, // already past the last save
		{Source: "System", Oldest: saved.Add(-10 * time.Minute), Wraps: true},  // about to be
		{Source: "Defender", Oldest: saved.Add(-72 * time.Hour), Wraps: true},  // holds days
		{Source: "PowerShell", Oldest: saved.Add(2 * time.Hour), Wraps: false}, // not full: nothing lost
	}
	risk := AtRisk(states, saved, 30*time.Minute)
	if len(risk) != 2 || risk[0] != "Security" || risk[1] != "System" {
		t.Errorf("at risk: %v", risk)
	}
	gaps := GapsIn(states, saved, saved.Add(time.Hour))
	if len(gaps) != 1 || gaps[0].Source != "Security" || !gaps[0].From.Equal(saved) || !gaps[0].To.Equal(saved.Add(40*time.Minute)) {
		t.Errorf("gaps: %+v", gaps)
	}
	// A log that overwrote the whole period: the gap is all of it.
	if g := GapsIn(states, saved, saved.Add(10*time.Minute)); len(g) != 1 || !g[0].To.Equal(saved.Add(10*time.Minute)) {
		t.Errorf("whole period: %+v", g)
	}
}
