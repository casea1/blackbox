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
	if got := l.Advice(true); !strings.Contains(got, "too small for how fast it is written") || !strings.Contains(got, "at least 256 MB") {
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

// LOG1b: status gives the same capped size as blackbox check, and the
// registry advice fits a REG_DWORD.
func TestNeededCapped(t *testing.T) {
	// The PowerShell log held 1 minute of a burst at 15 MB, collected
	// hourly: 4 hours at that rate is about 3.5 GB, more than check's cap.
	l := Loss{Channel: "Microsoft-Windows-PowerShell/Operational", Held: time.Minute, Every: time.Hour, MaxSize: 15 << 20}
	if n := l.Needed(); n != MaxRecommend {
		t.Errorf("needed %s, want the cap %s", Size(n), Size(MaxRecommend))
	}
	if a := l.Advice(true); !strings.Contains(a, "Make it at least 2 GB") || !strings.Contains(a, "MaxSize (REG_DWORD, bytes) = 2147483648") {
		t.Errorf("advice: %s", a)
	}
	// Over 4 GB, the registry value is split as Windows stores it.
	if f := Fix("Microsoft-Windows-PowerShell/Operational", 5468323840); !strings.Contains(f, "MaxSize (REG_DWORD) = 1173356544 and MaxSizeUpper (REG_DWORD) = 1") {
		t.Errorf("fix: %s", f)
	}
	if !Critical("/var/log/audit/audit.log") || !Critical("/srv/audit/audit.log") || Critical("Microsoft-Windows-PowerShell/Operational") {
		t.Error("critical logs")
	}
}

// STAT2: the size advised moves in steps (a power of two MB, 1 GB and 2
// GB for the PowerShell log), so it is the same from run to run while the
// measured rate moves a little.
func TestNeededSteps(t *testing.T) {
	ps := "Microsoft-Windows-PowerShell/Operational"
	for _, c := range []struct {
		channel string
		held    time.Duration
		want    string
	}{
		{ps, 3 * time.Hour, "1 GB"},                  // 400 MB: the PowerShell minimum
		{ps, 55 * time.Minute, "2 GB"},               // 1.3 GB
		{ps, 50 * time.Minute, "2 GB"},               // 1.4 GB
		{ps, time.Minute, "2 GB"},                    // capped
		{"Application", 3 * time.Hour, "128 MB"},     // 80 MB
		{"Application", 170 * time.Minute, "128 MB"}, // 85 MB
	} {
		size := uint64(300 << 20)
		if c.channel == "Application" {
			size = 60 << 20
		}
		l := Loss{Channel: c.channel, Held: c.held, Every: time.Hour, MaxSize: size}
		if got := Size(l.Needed()); got != c.want {
			t.Errorf("%s held %v: %s, want %s", c.channel, c.held, got, c.want)
		}
	}
}
