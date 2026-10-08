package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/rollover"
	"github.com/casea1/blackbox/internal/store"
)

// C1: events lost to log rollover since the last report are in "blackbox
// status" and in the status icon's view of things, named by log.
func TestLostEventsAreReported(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	st.State.LastWindowEnd = now.Add(-24 * time.Hour)
	st.State.LastCollect = now.Add(-10 * time.Minute)
	st.Save()
	for i, lost := range []uint64{17925, 1200} {
		st.AppendRun(&store.Run{Time: now.Add(time.Duration(i-2) * time.Hour), Host: collect.LocalHost(), OS: "windows",
			Channels: []store.ChannelRun{{Channel: "Security", Gap: &store.Gap{Lost: lost}}}})
	}
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", ReportAt: config.DefaultReportAt, CollectEvery: time.Hour},
		Now: func() time.Time { return now }, Loc: time.UTC}
	var b bytes.Buffer
	// Lost events need attention: status exits 4 (C6).
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(b.String(), "Security log on "+collect.LocalHost()+": 19,125 events overwritten") || !strings.Contains(b.String(), "every 15 minutes") {
		t.Errorf("status:\n%s", b.String())
	}
	h, err := a.Health()
	if err != nil || len(h.Lost) != 1 || h.Lost[0].Count != 19125 {
		t.Errorf("health lost: %+v %v", h.Lost, err)
	}
}

// C3: a sender with no batch for more than two collection intervals is
// pointed out in status, well before it counts as silent.
func TestNoBatchSince(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	st.NoteSystem("bbtest-sender-7f3a", "linux", "0.9.2", "bbtest-sender-7f3a", now.Add(-3*time.Hour), now.Add(-3*time.Hour), now.Add(-3*time.Hour))
	st.Save()
	a := &App{Cfg: &config.Config{DataDir: st.Dir, Inbox: t.TempDir(), ReportEvery: "weekly"}, Now: func() time.Time { return now }, Loc: time.UTC}
	var b bytes.Buffer
	a.Status(&b)
	if !strings.Contains(b.String(), "no batch since 2026-10-02 12:00") {
		t.Errorf("status:\n%s", b.String())
	}
}

// C5: audit settings are checked again after a restart (auditd and the
// kernel's audit=1 take effect then), as well as daily.
func TestCheckDue(t *testing.T) {
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	last := now.Add(-4 * time.Hour)
	if checkDue(last, now.AddDate(0, 0, -3), now) {
		t.Error("checked again without a restart, 4 hours after the last")
	}
	if !checkDue(last, now.Add(-time.Hour), now) {
		t.Error("not checked again after a restart")
	}
	if !checkDue(now.Add(-21*time.Hour), time.Time{}, now) {
		t.Error("not checked daily")
	}
}

// Finding 11: a computer switched from collector to standalone shows only
// itself in the status icon, not a former sender.
func TestStandaloneShowsOnlyItself(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	st.State.LastWindowEnd = now.AddDate(0, 0, -3)
	st.NoteSystem("bbtest-sender-7f3a", "linux", "0.9.2", "bbtest-sender-7f3a", now.AddDate(0, 0, -4), now.AddDate(0, 0, -4), now.AddDate(0, 0, -4))
	st.Save()
	st.AppendChecks(&store.CheckRecord{Time: now.Add(-time.Hour), Host: "bbtest-sender-7f3a", OS: "linux",
		Results: []check.Result{{Area: "Audit service", Item: "auditd running", Status: check.Fail, STIG: "ALMA-09-054910"}}})
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly"}, Now: func() time.Time { return now }, Loc: time.UTC}
	h, err := a.Health()
	if err != nil {
		t.Fatal(err)
	}
	if len(h.AuditGaps) != 0 || len(h.Quiet) != 0 {
		t.Errorf("a former sender is still shown: gaps %v, quiet %v", h.AuditGaps, h.Quiet)
	}
	a.Cfg.Inbox = t.TempDir()
	if h, _ := a.Health(); h.AuditGaps["bbtest-sender-7f3a"] != 1 || len(h.Quiet) != 1 {
		t.Errorf("a collector should show its sender: gaps %v, quiet %v", h.AuditGaps, h.Quiet)
	}
}

// L3: the last collection found auditing off: status says so, for this
// computer and in a collector's list of systems.
func TestAuditOffInStatus(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	st.State.LastCollect = now.Add(-10 * time.Minute)
	st.NoteSystem("ubu7", "linux", "0.10.1", "ubu7", now.Add(-time.Hour), now.Add(-time.Hour), now.Add(-time.Hour))
	st.Save()
	why := "the audit service (auditd) is not running (systemctl is-active auditd: inactive)"
	st.AppendRun(&store.Run{Time: now.Add(-10 * time.Minute), Host: collect.LocalHost(), OS: "linux", AuditOff: why})
	st.AppendRun(&store.Run{Time: now.Add(-time.Hour), Host: "ubu7", OS: "linux", AuditOff: why})
	a := &App{Cfg: &config.Config{DataDir: st.Dir, Inbox: t.TempDir(), ReportEvery: "weekly", ReportAt: config.DefaultReportAt, CollectEvery: time.Hour},
		Now: func() time.Time { return now }, Loc: time.UTC}
	var b bytes.Buffer
	a.Status(&b)
	if !strings.Contains(b.String(), "AUDITING OFF:") || !strings.Contains(b.String(), "14:00   AUDITING OFF") {
		t.Errorf("status:\n%s", b.String())
	}
	h, _ := a.Health()
	if len(h.AuditOff) != 2 {
		t.Errorf("health: %v", h.AuditOff)
	}
}

// L10: data waiting more than a day to be sent is pointed out, with the
// oldest item's age, and status says it needs attention (exit code 4).
func TestWaitingTooLong(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	st.State.Send = &store.SendState{ID: "ab12", LastAttempt: now.Add(-time.Hour), LastError: "collector inbox not available: /mnt/blackbox-inbox (nothing is mounted there)"}
	st.Save()
	out := filepath.Join(st.Dir, "outbox")
	os.MkdirAll(out, 0o700)
	for i, age := range []time.Duration{50 * time.Hour, time.Hour} {
		f := filepath.Join(out, fmt.Sprintf("%08d.bbx", i+1))
		os.WriteFile(f, []byte("x"), 0o600)
		os.Chtimes(f, now.Add(-age), now.Add(-age))
	}
	a := &App{Cfg: &config.Config{DataDir: st.Dir, SendTo: "/mnt/blackbox-inbox", ReportEvery: "weekly"}, Now: func() time.Time { return now }, Loc: time.UTC}
	var b bytes.Buffer
	err := a.Status(&b)
	var na *NeedsAttention
	if !errors.As(err, &na) {
		t.Errorf("status error: %v", err)
	}
	for _, want := range []string{"2 batches; the oldest waiting since 2026-10-03 10:00", "NOT SENT:", "never deleted", "blackbox send"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("status missing %q:\n%s", want, b.String())
		}
	}
	if h, _ := a.Health(); !h.WaitingSince.Equal(now.Add(-50 * time.Hour)) {
		t.Errorf("health waiting since %v", h.WaitingSince)
	}
}

// SC2: the sender's log counts SCAP results with the batches.
func TestSentText(t *testing.T) {
	for r, want := range map[SendResult]string{
		{Delivered: 1, ScapDelivered: 2}:                       "1 batch and 2 SCAP results",
		{Delivered: 3, ArchivesDelivered: 1, ScapDelivered: 1}: "3 batches, 1 log archive and 1 SCAP result",
		{ScapDelivered: 1}:                                     "1 SCAP result",
	} {
		if got := sentText(r); got != want {
			t.Errorf("sentText(%+v) = %q, want %q", r, got, want)
		}
	}
}

// R9: --from/--to/--days apply to exported log files too.
func TestReportFromFilesRange(t *testing.T) {
	a := &App{Cfg: &config.Config{DataDir: t.TempDir()}, Now: func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) }, Loc: time.UTC}
	in := Inputs{Audit: []string{"../../testdata/linux/ubuntu-audit.log"}}
	count := func(from, to time.Time) int {
		t.Helper()
		dir, err := a.ReportFromFiles(in, filepath.Join(t.TempDir(), "r"), from, to)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "summary.json"))
		if err != nil {
			t.Fatal(err)
		}
		var s struct{ Events int }
		json.Unmarshal(b, &s)
		return s.Events
	}
	all := count(time.Time{}, time.Time{})
	if all == 0 {
		t.Fatal("no events in the sample log")
	}
	if n := count(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), time.Time{}); n != 0 {
		t.Errorf("from 2030: %d events, want 0", n)
	}
	if n := count(time.Date(2026, 9, 28, 17, 0, 0, 0, time.UTC), time.Date(2026, 9, 28, 18, 0, 0, 0, time.UTC)); n == 0 || n >= all {
		t.Errorf("one hour: %d of %d events", n, all)
	}
}

// L12: when every delivery fails, status says since when; after a day it
// needs attention (exit 4), even with nothing new waiting. A delivery that
// works clears it.
func TestSendingFailedSince(t *testing.T) {
	base := t.TempDir()
	st, _ := store.Open(filepath.Join(base, "data"))
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	inbox := filepath.Join(base, "inbox") // not prepared yet: unreachable
	a := &App{Cfg: &config.Config{DataDir: st.Dir, SendTo: inbox, ReportEvery: "weekly"}, Loc: time.UTC, QuietSend: true}
	a.Now = func() time.Time { return now.Add(-30 * time.Hour) }
	if r := a.send(st); r.Err == nil {
		t.Fatal("send to a missing inbox worked")
	}
	a.Now = func() time.Time { return now.Add(-time.Hour) }
	a.send(st) // fails again: the first failure stays
	if got := st.State.Send.FailingSince; !got.Equal(now.Add(-30 * time.Hour)) {
		t.Fatalf("failing since %v", got)
	}

	a.Now = func() time.Time { return now.Add(-29 * time.Hour) }
	var b bytes.Buffer
	if err := a.Status(&b); err != nil {
		t.Errorf("an hour of failures should not need attention yet: %v\n%s", err, b.String())
	}
	a.Now = func() time.Time { return now }
	b.Reset()
	var na *NeedsAttention
	if err := a.Status(&b); !errors.As(err, &na) {
		t.Errorf("status error after 30 hours of failures: %v", err)
	}
	for _, want := range []string{"sending has failed since 2026-10-04 06:00", "NOT SENT:"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("status missing %q:\n%s", want, b.String())
		}
	}

	if err := lan.PrepareInbox(inbox, "COLLECTOR"); err != nil {
		t.Fatal(err)
	}
	if r := a.send(st); r.Err != nil || !st.State.Send.FailingSince.IsZero() {
		t.Errorf("after a delivery that worked: %v, failing since %v", r.Err, st.State.Send.FailingSince)
	}
}

// C6 note, LOG1: an upgraded install still collecting hourly is told
// the exact command; one already at 15 minutes is told to make the log
// larger, never to collect every 15 minutes.
func TestLostAdvice(t *testing.T) {
	adv := func(host string, every time.Duration, local bool) string {
		return LostLog{Loss: rollover.Loss{Host: host, Channel: "Security", Every: every}}.Advice(local)
	}
	if got := adv("WIN11", time.Hour, true); !strings.Contains(got, "This computer collects every hour") || !strings.Contains(got, "blackbox config set collect_every 15m") {
		t.Errorf("hourly: %s", got)
	}
	if got := adv("WIN11", 15*time.Minute, true); strings.Contains(got, "collect_every") || strings.Contains(got, "every 15 minutes (") || !strings.Contains(got, "larger") {
		t.Errorf("15 minutes: %s", got)
	}
	if got := adv("ubuntu-server", time.Hour, false); !strings.Contains(got, "on ubuntu-server: blackbox config set collect_every 15m") {
		t.Errorf("another computer: %s", got)
	}
	if got := adv("ubuntu-server", 15*time.Minute, false); strings.Contains(got, "collect_every") {
		t.Errorf("another computer already at 15 minutes: %s", got)
	}
}

// LOG1: a PowerShell log that turned over in 9 minutes on a computer
// collecting every 15 minutes: named, told the log is too small (not to
// collect every 15 minutes), and shown apart from audit-record losses,
// without making status exit 4.
func TestPowerShellLogLoss(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	st.State.LastWindowEnd = now.Add(-24 * time.Hour)
	st.State.LastCollect = now.Add(-5 * time.Minute)
	st.Save()
	host := collect.LocalHost()
	for i := 0; i < 8; i++ {
		at := now.Add(time.Duration(i-8) * 15 * time.Minute)
		r := &store.Run{Time: at, Host: host, OS: "windows", Channels: []store.ChannelRun{{Channel: "Security", MaxSizeBytes: 5 << 30}}}
		if i == 5 {
			r.Channels = append(r.Channels, store.ChannelRun{Channel: "Microsoft-Windows-PowerShell/Operational", MaxSizeBytes: 15 << 20,
				OldestTime: at.Add(-9 * time.Minute), Gap: &store.Gap{Lost: 447}})
		}
		st.AppendRun(r)
	}
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", ReportAt: config.DefaultReportAt, CollectEvery: 15 * time.Minute},
		Now: func() time.Time { return now }, Loc: time.UTC}
	var b bytes.Buffer
	if err := a.Status(&b); err != nil {
		t.Errorf("status = %v; a PowerShell log loss alone should not exit 4\n%s", err, b.String())
	}
	out := b.String()
	if !strings.Contains(out, "PowerShell log on "+host+": 447 events overwritten") || !strings.Contains(out, "too small for how fast it is written") ||
		!strings.Contains(out, "at least 1 GB") || strings.Contains(out, "collect_every") || strings.Contains(out, "EVENTS LOST") {
		t.Errorf("status:\n%s", out)
	}
	h, _ := a.Health()
	if len(h.Lost) != 1 || h.Lost[0].Held != 9*time.Minute || h.Lost[0].Every != 15*time.Minute {
		t.Errorf("health lost: %+v", h.Lost)
	}
}

// TZ1: status shows every time in local time, including the UTC times in
// a stored note, with the zone named once at the top.
func TestStatusLocalTimesOnly(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	ny := time.FixedZone("EDT", -4*3600)
	now := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	st.State.LastCollect = now.Add(-10 * time.Minute)
	st.State.LogGaps = []store.LogGap{{Source: "Security", From: now.Add(-3 * time.Hour), To: now.Add(-2 * time.Hour), Noted: now,
		Reason: "Security.evtx, exported for 2026-10-07T12:00:00Z to 2026-10-07T13:00:00Z, was missing when the logs were packed"}}
	st.Save()
	a := &App{Cfg: &config.Config{DataDir: st.Dir, ReportEvery: "weekly", ReportAt: config.DefaultReportAt, CollectEvery: 15 * time.Minute},
		Now: func() time.Time { return now }, Loc: ny}
	var b bytes.Buffer
	a.Status(&b)
	out := b.String()
	if strings.Count(out, "EDT") != 1 || !strings.Contains(out, "Times:            local time, EDT (UTC-04:00)") ||
		!strings.Contains(out, "Last collection:  2026-10-07 10:50") || !strings.Contains(out, "exported for 2026-10-07 08:00 to 2026-10-07 09:00,") {
		t.Errorf("status:\n%s", out)
	}
	if utcStamp.MatchString(out) {
		t.Errorf("a UTC time is left:\n%s", out)
	}
	for loc, want := range map[*time.Location]string{time.UTC: "local time, UTC", time.FixedZone("", 5*3600+1800): "local time, UTC+05:30"} {
		if got := zoneText(now, loc); got != want {
			t.Errorf("zone %v: %q", loc, got)
		}
	}
}
