package archive

import (
	"sort"
	"time"
)

// Gap is part of a period missing from a log when it was saved: the log
// was full and had already overwritten it.
type Gap struct {
	Source string    `json:"source"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	// Reason is set when the gap is not the log overwriting itself: an
	// exported file was missing or unreadable when the logs were packed
	// (AR5).
	Reason string `json:"reason,omitempty"`
}

// LogState is how far back a log reaches now, and whether it is full and
// overwriting its oldest events.
type LogState struct {
	Source string
	Oldest time.Time
	Wraps  bool
}

// GapsIn lists, for a save covering [from, to), the start of the period
// each full log had already overwritten.
func GapsIn(states []LogState, from, to time.Time) []Gap {
	var out []Gap
	for _, s := range states {
		if s.Wraps && s.Oldest.After(from.Add(time.Second)) {
			end := s.Oldest
			if end.After(to) {
				end = to
			}
			out = append(out, Gap{Source: s.Source, From: from, To: end})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}
