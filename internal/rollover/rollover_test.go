package rollover

import (
	"strings"
	"testing"
	"time"
)

// LOG1, as reproduced on the Windows 11 VM: the PowerShell log (15 MB,
// script block events of about 34 KB) turned over in 9 minutes on a
// system that collects every 15 minutes.
func TestPowerShellLogTooSmall(t *testing.T) {
	l := Loss{Host: "WIN11-TEST", Channel: "Microsoft-Windows-PowerShell/Operational", Lost: 447,
		Held: 9 * time.Minute, MaxSize: 15 << 20, Every: 15 * time.Minute}
	if !l.TooSmall() {
		t.Fatal("a log that turned over in 9 minutes is not too small for 15-minute collection")
	}
	got := l.Advice(true)
	for _, want := range []string{"PowerShell log held only about 9 minutes", "15 minutes between collections", "collecting more often would not help",
		"at least 1 GB", `wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1073741824`, `WINEVT\Channels\Microsoft-Windows-PowerShell/Operational`} {
		if !strings.Contains(got, want) {
			t.Errorf("advice lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "collect_every") || strings.Contains(got, "Collect every 15") {
		t.Errorf("advice to collect every 15 minutes, which it already does:\n%s", got)
	}
	if Critical(l.Channel) {
		t.Error("the PowerShell log's losses are not the audit record's")
	}
	if !strings.Contains(l.Short(), "too small") || !strings.Contains(l.Short(), "1 GB") {
		t.Errorf("short: %s", l.Short())
	}
}

func TestAdviceByRate(t *testing.T) {
	// Collecting hourly, a log that holds 3 hours: collect more often.
	l := Loss{Host: "WS-07", Channel: "Security", Held: 3 * time.Hour, MaxSize: 20 << 20, Every: time.Hour}
	if got := l.Advice(false); !strings.Contains(got, "WS-07 collects every hour") || !strings.Contains(got, "on WS-07: blackbox config set collect_every 15m") {
		t.Errorf("hourly: %s", got)
	}
	// Already every 15 minutes: only a larger log helps, with the size.
	l.Every, l.Held = 15*time.Minute, 20*time.Minute
	got := l.Advice(true)
	if strings.Contains(got, "collect_every") || !strings.Contains(got, "Make the Security log larger (blackbox check gives the size)") || !strings.Contains(got, "already collects every 15 minutes") {
		t.Errorf("15 minutes: %s", got)
	}
	// Turned over faster than collection.
	l.Held = 5 * time.Minute
	if got := l.Advice(true); !strings.Contains(got, "too small for how fast it is written") || !strings.Contains(got, "at least 240 MB") {
		t.Errorf("too small: %s", got)
	}
	if !Critical("Security") || !Critical("/var/log/audit/audit.log") {
		t.Error("the Security and audit logs are the audit record")
	}
}

func TestNames(t *testing.T) {
	for ch, want := range map[string]string{
		"Security": "Security log",
		"Microsoft-Windows-PowerShell/Operational":                           "PowerShell log",
		"Microsoft-Windows-Windows Defender/Operational":                     "Windows Defender log",
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": "Remote Desktop sessions log",
		"/var/log/audit/audit.log":                                           "audit log",
		"/var/log/auth.log":                                                  "auth log",
	} {
		if got := Name(ch); got != want {
			t.Errorf("Name(%q) = %q, want %q", ch, got, want)
		}
	}
}

func TestInterval(t *testing.T) {
	base := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	var ts []time.Time
	for i := 0; i < 10; i++ {
		ts = append(ts, base.Add(time.Duration(i)*15*time.Minute))
	}
	ts = append(ts, base.Add(10*time.Hour)) // the computer was off for a while
	if got := Interval(ts); got != 15*time.Minute {
		t.Errorf("interval %v", got)
	}
}
