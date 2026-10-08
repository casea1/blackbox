// Package rollover says what to do about events a log overwrote before
// Blackbox collected them (LOG1): which log, how serious, and whether
// collecting more often would help or the log is simply too small for
// how fast it is written.
package rollover

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Name is how a log is named to people: "Security log", "PowerShell log".
func Name(channel string) string {
	switch channel {
	case "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational":
		return "Remote Desktop sessions log"
	case "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational":
		return "Remote Desktop connections log"
	case "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall":
		return "Windows Firewall log"
	case "Microsoft-Windows-Kernel-PnP/Configuration":
		return "Plug and Play log"
	case "Microsoft-Windows-Partition/Diagnostic":
		return "Partition log"
	case "Microsoft-Windows-DriverFrameworks-UserMode/Operational":
		return "USB driver log"
	}
	if strings.HasPrefix(channel, "/") { // a Linux log file
		return strings.TrimSuffix(path.Base(channel), ".log") + " log"
	}
	n := strings.TrimPrefix(channel, "Microsoft-Windows-")
	if i := strings.IndexByte(n, '/'); i > 0 {
		n = n[:i]
	}
	return n + " log"
}

// Critical says whether losing events from the log loses the audit
// record the STIG requires: the Windows Security log and the Linux audit
// log. That stays High; other logs' losses are shown on their own, lower.
func Critical(channel string) bool {
	// auditd's log_file can be moved; it is still the audit log.
	return channel == "Security" || channel == "/var/log/audit/audit.log" ||
		(strings.HasPrefix(channel, "/") && path.Base(channel) == "audit.log")
}

// Loss is events one log overwrote before they could be collected.
type Loss struct {
	Host, Channel string
	Lost          uint64
	// Held is how far back the full log reached when the loss was found
	// (the shortest seen), MaxSize its size then; zero when not known.
	Held    time.Duration
	MaxSize uint64
	// Every is how often that system collects (zero when not known).
	Every time.Duration
}

// TooSmall says the log turned over in less time than there is between
// collections: it is too small for how fast it is written, and collecting
// more often would not keep up.
func (l Loss) TooSmall() bool { return l.Held > 0 && l.Every > 0 && l.Held < l.Every }

// MinPowerShell is the smallest PowerShell log Blackbox recommends: with
// script block logging each event can be 30 KB or more, so Windows' 15 MB
// default holds only a few hundred.
const MinPowerShell = 1 << 30

// MaxRecommend caps a size worked out from a burst of events: a size
// scaled up from a few minutes of a burst is far more than needed, and
// would not fit the REG_DWORD MaxSize. blackbox check and status give
// the same advice (LOG1b).
const MaxRecommend = 2 << 30

// Needed is the size that holds four collection intervals at the rate
// the log was written when it turned over, rounded up to a power of two
// MB (64 MB, ..., 512 MB, 1 GB, 2 GB) so the advice does not change from
// one run to the next as the measured rate moves a little (STAT2); at
// least 1 GB for the PowerShell log, at most MaxRecommend; 0 when it
// can't be worked out.
func (l Loss) Needed() uint64 {
	var n uint64
	if l.Held > 0 && l.Every > 0 && l.MaxSize > 0 {
		need := uint64(float64(l.MaxSize) * float64(4*l.Every) / float64(l.Held))
		for n = 1 << 20; n < need && n < MaxRecommend; n <<= 1 {
		}
	}
	if l.Channel == "Microsoft-Windows-PowerShell/Operational" && n < MinPowerShell {
		n = MinPowerShell
	}
	return min(n, MaxRecommend)
}

// Size is a size in MB or GB.
func Size(b uint64) string {
	if b >= 1<<30 {
		if b%(1<<30) == 0 {
			return fmt.Sprintf("%d GB", b>>30)
		}
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	}
	return fmt.Sprintf("%d MB", b>>20)
}

// Fix is how to make a log size bytes.
func Fix(channel string, size uint64) string {
	switch channel {
	case "Security", "System", "Application", "Setup":
		return fmt.Sprintf("Group Policy: Computer Configuration > Policies > Administrative Templates > Windows Components > Event Log Service > %s > Specify the maximum log file size (KB): Enabled, %d", channel, size/1024)
	case "/var/log/audit/audit.log":
		return "raise max_log_file (MB) and num_logs in /etc/audit/auditd.conf (blackbox check gives the values)"
	}
	if strings.HasPrefix(channel, "/") {
		return "keep more of the log in its rotation settings (logrotate or journald)"
	}
	reg := fmt.Sprintf("MaxSize (REG_DWORD, bytes) = %d", size)
	if size > 0xFFFFFFFF {
		// A REG_DWORD holds up to 4,294,967,295: Windows splits larger
		// sizes over MaxSize and MaxSizeUpper.
		reg = fmt.Sprintf("MaxSize (REG_DWORD) = %d and MaxSizeUpper (REG_DWORD) = %d", size&0xFFFFFFFF, size>>32)
	}
	return fmt.Sprintf(`as administrator: wevtutil sl "%s" /ms:%d. Group Policy has no setting for this log under Event Log Service; to set it on many computers, use a Group Policy Preferences registry item: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\%s, %s`,
		channel, size, channel, reg)
}

// Advice is what to do about the loss. local says the log is this
// computer's (the command needs no "on HOST").
func (l Loss) Advice(local bool) string {
	on := ""
	if !local {
		on = " on " + l.Host
	}
	if l.TooSmall() {
		s := fmt.Sprintf("The %s%s held only about %s of events when it turned over, less than the %s between collections: it is too small for how fast it is written, and collecting more often would not help.",
			Name(l.Channel), on, Duration(l.Held), Duration(l.Every))
		if n := l.Needed(); n > 0 {
			s += fmt.Sprintf(" Make it at least %s: %s.", Size(n), Fix(l.Channel, n))
		}
		return s
	}
	if l.Every > 15*time.Minute {
		who := "This computer collects"
		if !local {
			who = l.Host + " collects"
		}
		return fmt.Sprintf("%s every %s: collect every 15 minutes (%s: blackbox config set collect_every 15m), or make the %s larger.",
			who, every(l.Every), map[bool]string{true: "on this computer", false: "on " + l.Host}[local], Name(l.Channel))
	}
	s := fmt.Sprintf("Make the %s%s larger", Name(l.Channel), on)
	// The audit record's size is the STIG's, which check gives.
	if n := l.Needed(); n > 0 && !Critical(l.Channel) {
		s += fmt.Sprintf(" (at least %s: %s)", Size(n), Fix(l.Channel, n))
	} else {
		s += " (blackbox check gives the size)"
	}
	if l.Every > 0 {
		s += fmt.Sprintf("; it already collects every %s", every(l.Every))
	}
	return s + "."
}

// NotInExports says why the original logs don't have the lost events: the
// export at each collection holds what the log had then, and these were
// written and overwritten between two collections.
const NotInExports = "The original logs exported at each collection hold everything each log had at that moment; these events were written and overwritten between two collections, so no export has them."

// Duration is a short duration: "9 minutes", "1 hour", "2 days".
func Duration(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return "1 minute"
	case d < 2*time.Hour:
		if d >= 59*time.Minute+30*time.Second {
			return "1 hour"
		}
		return fmt.Sprintf("%d minutes", int(d.Minutes()+0.5))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()+0.5))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24+0.5))
}

// Interval is how often a system collects, from the times of its runs:
// the median time between them (0 with fewer than two).
func Interval(times []time.Time) time.Duration {
	if len(times) < 2 {
		return 0
	}
	t := append([]time.Time(nil), times...)
	sort.Slice(t, func(i, j int) bool { return t[i].Before(t[j]) })
	var gaps []time.Duration
	for i := 1; i < len(t); i++ {
		if d := t[i].Sub(t[i-1]); d > 0 {
			gaps = append(gaps, d)
		}
	}
	if len(gaps) == 0 {
		return 0
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	return gaps[len(gaps)/2].Round(time.Minute)
}

// every is a collection interval after "every": "hour", "15 minutes".
func every(d time.Duration) string {
	if s := Duration(d); s != "1 hour" {
		return s
	}
	return "hour"
}

// Short is Advice in a few words, for a notification.
func (l Loss) Short() string {
	switch {
	case l.TooSmall():
		s := "the log is too small for how fast it is written"
		if n := l.Needed(); n > 0 {
			s += fmt.Sprintf("; make it at least %s", Size(n))
		}
		return s
	case l.Every > 15*time.Minute:
		return fmt.Sprintf("collect every 15 minutes (blackbox config set collect_every 15m on %s), or make the log larger", l.Host)
	}
	return "make the log larger (see Status details)"
}
