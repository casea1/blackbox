package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

func TestReviewXSS(t *testing.T) {
	p := "</script><img src=x onerror=alert(1)>\u2028`${x}'\"<svg/onload=alert(2)>"
	at := time.Date(2026, 10, 6, 3, 0, 0, 0, time.UTC)
	var evs []*event.Event
	for i, sev := range []event.Severity{event.SevHigh, event.SevMedium, event.SevInfo} {
		e := &event.Event{Time: at.Add(time.Duration(i) * time.Minute), Collected: at, Host: "H" + p, OS: "windows", Category: event.CatAccount,
			Severity: sev, Action: "user_created", User: "u" + p, Target: "t" + p, Command: "c" + p, Process: `C:\` + p, SourceIP: p, Summary: "s" + p, Source: "Security", EventID: 4720}
		e.AddDetail("Started by", p)
		evs = append(evs, e)
	}
	runs := []*store.Run{{Time: at, Host: "H" + p, OS: "windows", Version: p}}
	r := Build(evs, runs, Options{Location: time.UTC, Source: "test", Site: p})
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, bad := range []string{"<img src=x", "<svg/onload"} {
		if i := strings.Index(string(b), bad); i >= 0 {
			t.Errorf("raw %q in report.html: ...%s...", bad, string(b)[max(0, i-80):i+40])
		}
	}
	if err := WriteIndex(filepath.Dir(dir), p, p, time.UTC, nil); err != nil {
		t.Log(err)
	}
	b, _ = os.ReadFile(filepath.Join(filepath.Dir(dir), "index.html"))
	for _, bad := range []string{"<img src=x", "<svg/onload"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("raw %q in index.html", bad)
		}
	}
}
