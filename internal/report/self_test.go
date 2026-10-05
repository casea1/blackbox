package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/linuxlog"
	"github.com/casea1/blackbox/internal/store"
)

// journalEvents translates the sudo-rs journal recorded on Ubuntu 26.04
// (testdata/v0.10.4), plus extra journal lines.
func journalEvents(t *testing.T, extra ...string) []*event.Event {
	t.Helper()
	b, err := os.ReadFile("../../testdata/v0.10.4/o1-sudo-rs-journal.log")
	if err != nil {
		t.Fatal(err)
	}
	tr := linuxlog.NewTranslator("ubuntu-server", nil)
	tr.SudoFromSyslog = true
	p := linuxlog.LineParser{Loc: time.UTC}
	var out []*event.Event
	for _, s := range append(strings.Split(strings.TrimSpace(string(b)), "\n"), extra...) {
		if l, ok := p.Parse(s); ok {
			if e := tr.Syslog(l, "journal"); e != nil {
				out = append(out, e)
			}
		}
	}
	return out
}

// A15: "config set exclude_users none" was applied, and Blackbox recorded
// it (in its spool and the journal): one row, with before and after.
// "config set retention_days 30" was answered "n": nothing was recorded,
// so its row says it was not applied, not that the setting changed.
func TestSelfRecordedSettingChanges(t *testing.T) {
	at := time.Date(2026, 10, 4, 23, 57, 18, 500e6, time.UTC)
	c := event.SelfChange{Kind: "setting", Setting: "exclude_users", Old: "svc_backup", New: "", Who: "claude", Program: "blackbox config set"}
	spool := c.Event()
	spool.Time, spool.Host, spool.OS = at, "ubuntu-server", "linux"
	evs := append(journalEvents(t, "2026-10-04T23:57:18+00:00 ubuntu-server blackbox[11835]: "+c.Message()), spool)
	runs := []*store.Run{{Time: at.Add(-time.Hour), Host: "ubuntu-server", OS: "linux", Version: "0.11.0"}}
	r := Build(evs, runs, Options{Location: time.UTC, WindowEnd: at.Add(time.Hour)})
	var rows []string
	for _, e := range r.Events {
		if strings.HasPrefix(e.Action, "blackbox_config") {
			rows = append(rows, string(e.Severity)+" "+e.Summary)
		}
	}
	want := []string{
		"high claude changed Blackbox's exclude_users setting from svc_backup to (empty) (blackbox config set).",
		"medium claude tried to change Blackbox's retention_days setting (not applied): /usr/local/bin/blackbox config set retention_days 30",
	}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Errorf("rows:\n%s\nwant:\n%s", strings.Join(rows, "\n"), strings.Join(want, "\n"))
	}

	// Before 0.11 nothing was recorded: the command rows stay as they were.
	runs[0].Version = "0.10.4"
	r = Build(journalEvents(t), runs, Options{Location: time.UTC, WindowEnd: at.Add(time.Hour)})
	for _, e := range r.Events {
		if e.Action == "blackbox_config_not_applied" {
			t.Errorf("0.10.4: %s", e.Summary)
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	for v, want := range map[string]bool{"0.11.0": true, "v0.12.3": true, "1.0.0": true, "0.10.4": false, "dev": false, "": false, "0.11.0-rc1": true} {
		if got := versionAtLeast(v, selfRecording); got != want {
			t.Errorf("%q: %v", v, got)
		}
	}
}

// U8b: with sudo-rs the "systemctl stop auditd" is only in the journal,
// and systemd's DAEMON_END says root; the stop is still the person's.
func TestAuditdStopNamesSudoRsUser(t *testing.T) {
	evs := journalEvents(t)
	tr := linuxlog.NewTranslator("ubuntu-server", nil)
	end := `type=DAEMON_END msg=audit(1791158240.000:900): op=terminate auid=0 uid=0 ses=4294967295 pid=1 subj=unconfined res=success`
	if _, err := linuxlog.ParseAuditStream(strings.NewReader(end+"\n"), func(ev *linuxlog.Event) error {
		if e := tr.Audit(ev); e != nil {
			e.OS = "linux"
			evs = append(evs, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		e.OS = "linux"
	}
	at := time.Date(2026, 10, 4, 23, 57, 20, 0, time.UTC)
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: at.Add(time.Hour)})
	var stop *event.Event
	for _, e := range r.Events {
		if e.Action == "audit_stopped" {
			stop = e
		}
	}
	if stop == nil || stop.User != "claude" || stop.Severity != event.SevHigh || !strings.Contains(stop.Summary, "stopped by claude (/usr/bin/systemctl stop auditd)") {
		t.Fatalf("stop: %+v", stop)
	}
}
