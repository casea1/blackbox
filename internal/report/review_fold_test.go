package report

import (
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// REVIEW-7: an elevated program named conhost.exe run from any folder,
// with "0xffffffff -ForceV1" (or no command line recorded) and no parent
// row, is dropped from the report and events.zip (UX1b, new in 0.21).
func TestReviewFakeConhostDropped(t *testing.T) {
	at := time.Date(2026, 10, 6, 3, 0, 0, 0, time.UTC)
	mk := func(proc, cmd string) *event.Event {
		e := &event.Event{Time: at, Collected: at, Host: "WS-01", OS: "windows", Category: event.CatPrivileged,
			Severity: event.SevMedium, Action: "process_elevated", User: "CORP\\mallory", Process: proc, Command: cmd,
			Summary: "mallory ran " + proc + " with administrator rights", Source: "Security", EventID: 4688}
		e.AddDetail("Started by", `C:\Users\Public\dropper.exe`)
		return e
	}
	for _, c := range []struct{ proc, cmd string }{
		{`C:\Users\Public\conhost.exe`, `"C:\Users\Public\conhost.exe" 0xffffffff -ForceV1`},
		{`C:\Users\Public\conhost.exe`, ``},
		{`C:\Users\Public\Temp\OpenConsole.exe`, `OpenConsole.exe 0x1337`},
	} {
		r := Build([]*event.Event{mk(c.proc, c.cmd)}, nil, Options{Location: time.UTC, Source: "test"})
		t.Logf("%s %q: events in report=%d folded=%d", c.proc, c.cmd, len(r.Events), r.Folded)
		if len(r.Events) == 0 {
			t.Errorf("elevated %s (%q) is not in the report at all", c.proc, c.cmd)
		}
	}
}
