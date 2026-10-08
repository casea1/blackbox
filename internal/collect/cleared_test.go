package collect

import (
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// LC2: the records a cleared log skipped are not lost to rollover.
func TestClearedNotLost(t *testing.T) {
	at := time.Date(2026, 10, 7, 6, 17, 0, 0, time.UTC)
	run := &store.Run{Channels: []store.ChannelRun{
		{Channel: "Microsoft-Windows-PowerShell/Operational", Gap: &store.Gap{Lost: 200, From: at.Add(-time.Hour), To: at}},
		{Channel: "Security", Gap: &store.Gap{Lost: 50, From: at.Add(-time.Hour), To: at}},
		{Channel: "System"},
	}}
	clear := &event.Event{Time: at.Add(-time.Minute), User: "claude", Action: "log_cleared"}
	ClearedNotLost(run, map[string]*event.Event{"microsoft-windows-powershell/operational": clear}, nil)
	ps, sec := run.Channels[0], run.Channels[1]
	if ps.Gap != nil || !ps.Cleared || ps.ClearedBy != "claude" || !ps.ClearedAt.Equal(clear.Time) {
		t.Errorf("cleared PowerShell log: %+v", ps)
	}
	if sec.Gap == nil || sec.Cleared {
		t.Errorf("Security, not cleared, keeps its loss: %+v", sec)
	}
}
