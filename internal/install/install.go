// Package install sets Blackbox up to run on a schedule.
package install

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/selfaudit"
	"github.com/casea1/blackbox/internal/store"
)

// Options for install: the chosen settings, plus the version installed.
type Options struct {
	Answers
	Version string
	Logf    func(format string, args ...any)
}

// writeConfig creates the config file, or updates these settings in an
// existing one (keeping everything else, including comments).
func writeConfig(path string, opt Options, crlf bool) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		text := config.Render(opt.Site, opt.ReportEvery, opt.ReportAt, opt.ReportDir, opt.CollectEvery)
		if crlf {
			text = strings.ReplaceAll(text, "\n", "\r\n") // friendly for Notepad
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(text), 0o640); err != nil {
			return err
		}
		// The template's "archive_dir =" and "scap_results =" lines have
		// no value, so the settings below are set in it like in an
		// existing file (a first install lost a chosen archive_dir).
	} else if changed, err := config.Refresh(path); err != nil {
		// An upgrade: this version's comments, the same settings
		// (CONF1b). Not refreshed is not a failure.
		if opt.Logf != nil {
			opt.Logf("settings file comments not updated: %v", err)
		}
	} else if changed && opt.Logf != nil {
		opt.Logf("settings file comments updated to this version (the earlier file is %s.old)", filepath.Base(path))
	}
	return config.SetValues(path, [][2]string{
		{"site_name", opt.Site},
		{"report_every", opt.ReportEvery},
		{"report_at", opt.ReportAt.String()},
		{"report_dir", opt.ReportDir},
		{"archive_dir", opt.ArchiveDir},
		{"collect_every", config.FormatDuration(opt.CollectEvery)},
		{"send_to", opt.SendTo},
		{"share_user", opt.ShareUser},
		{"inbox", opt.Inbox},
		{"scap_results", opt.ScapResults},
	})
}

// scheduleWhat is what each scheduled run does besides collecting: a
// sender sends to its collector and makes no reports (L4).
func scheduleWhat(opt Options) string {
	if opt.SendTo != "" {
		return "sends them to the collector after each collection"
	}
	return opt.ReportEvery + " reports"
}

// setupLAN prepares what the role needs: the inbox for a collector, and
// delivery (share account, mount) for a sender. What a
// previous role set up and is no longer needed is removed.
func setupLAN(opt Options, dataDir string, logf func(string, ...any)) error {
	if opt.Inbox != "" {
		if err := prepareInbox(opt, logf); err != nil {
			return err
		}
	} else {
		removeInbox(logf)
	}
	if opt.SendTo != "" {
		return prepareSendTo(opt, dataDir, logf)
	}
	removeSendTo(logf)
	return nil
}

// PrepareReportDir makes sure reports can be written to dir. A folder that
// does not exist yet is created and restricted to administrators (Windows)
// or root (Linux); an existing folder's permissions are left exactly as
// they are, so a folder you have already locked down stays that way.
func PrepareReportDir(dir string, logf func(string, ...any)) error {
	return prepareFolder(dir, "report folder", "Report folder:      ", logf)
}

// PrepareArchiveDir is PrepareReportDir for archive_dir, where the
// original logs wait for the next scheduled report.
func PrepareArchiveDir(dir string, logf func(string, ...any)) error {
	return prepareFolder(dir, "original logs folder", "Original logs:      ", logf)
}

func prepareFolder(dir, what, label string, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if !config.IsAbs(dir) {
		return fmt.Errorf("%s must be a full path (got %q)", what, dir)
	}
	fi, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s %s: %w", what, dir, err)
		}
		if err := restrictDir(dir); err != nil {
			return err
		}
		logf("%s %s (created; administrators only)", label, dir)
	case err != nil:
		return fmt.Errorf("%s %s: %w", what, dir, err)
	case !fi.IsDir():
		return fmt.Errorf("%s %s is a file, not a folder", what, dir)
	default:
		logf("%s %s (existing folder; its permissions were not changed)", label, dir)
	}
	if err := CheckWritable(dir); err != nil {
		return err
	}
	if strings.HasPrefix(dir, `\\`) {
		logf("                     Scheduled runs write to this share as the computer account (DOMAIN\\COMPUTER$);")
		logf("                     make sure it has write access to the share and folder.")
	}
	return nil
}

// CheckWritable confirms a file can be created in dir.
func CheckWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".blackbox-write-test-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return nil
}

// SetReportDir moves future reports to dir (or back to the default when
// dir is ""), after checking the folder, and updates what the scheduled
// job is allowed to write to. Existing reports are not moved.
func SetReportDir(cfgPath, dir string, logf func(string, ...any)) error {
	if dir != "" {
		if err := PrepareReportDir(dir, logf); err != nil {
			return err
		}
	}
	if err := config.SetValue(cfgPath, "report_dir", dir); err != nil {
		return err
	}
	return afterReportDirChange(logf)
}

// SetArchiveDir moves where the original logs wait for the next scheduled
// report to dir (or back to the data folder when dir is ""), after
// checking the folder, and updates what the scheduled job may write to.
// Archives already waiting are picked up from the old folder by the next
// report.
func SetArchiveDir(cfgPath, dir string, logf func(string, ...any)) error {
	if dir != "" {
		if err := PrepareArchiveDir(dir, logf); err != nil {
			return err
		}
	}
	if err := config.SetValue(cfgPath, "archive_dir", dir); err != nil {
		return err
	}
	return afterReportDirChange(logf)
}

// ApplyLAN sets up what the LAN settings in the config file need (after
// "blackbox config set send_to|inbox|share_user"): the inbox, the share
// connection or mount, and on Linux the service's writable folders. A new
// share password is read from BLACKBOX_SHARE_PASSWORD.
func ApplyLAN(cfgPath string, logf func(string, ...any)) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	opt := Options{Answers: Answers{SendTo: cfg.SendTo, ShareUser: cfg.ShareUser, Inbox: cfg.Inbox,
		SharePassword: os.Getenv("BLACKBOX_SHARE_PASSWORD"), ShareInbox: InboxShared()}}
	if err := setupLAN(opt, cfg.DataDir, logf); err != nil {
		return err
	}
	return afterReportDirChange(logf)
}

// SendersGroup is the local group allowed to deliver into the inbox.
const SendersGroup = "Blackbox Senders"

// TaskName is the Windows scheduled task name.
const TaskName = "Blackbox Audit Collection"

// TaskStart is the start of the collection task's repeating trigger: a
// fixed time in the past, so the repetitions follow the clock as it is now
// (T1). A start taken from the clock at install time stayed in the future
// when a fast clock was corrected, and collection paused until the clock
// caught up.
var TaskStart = time.Date(2000, 1, 1, 0, 5, 0, 0, time.Local)

// taskXML is a Task Scheduler definition: run as SYSTEM with highest
// privileges, every interval indefinitely, catch up after the system was
// off, and never run two copies at once.
func taskXML(exe string, every time.Duration, start time.Time) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Blackbox</Author>
    <Description>Collects security-relevant events before logs roll over and produces Blackbox audit reports.</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>%s</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>%s</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5M</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>run</Arguments>
    </Exec>
  </Actions>
</Task>
`, isoDuration(every), start.Format("2006-01-02T15:04:05"), xmlEscape(exe))
}

// isoDuration formats d as an ISO 8601 duration (PT1H, PT15M).
func isoDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("PT%dH", int(d.Hours()))
	}
	return fmt.Sprintf("PT%dM", int(d.Minutes()))
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// systemdService is the unit that runs one collection (and a report when
// one is due). It is sandboxed: no network, read-only system, and the only
// writable places are Blackbox's data folder, the report folder and, on a
// collector, its inbox. Paths starting with "-" may be missing without
// stopping the run. mount is the unit that mounts the collector's SMB
// share, if any: it is started before each run, and a failure to mount
// does not stop collection (the data waits until the share is back).
//
// A sender to a folder (an sshfs or other mount the site set up) does not
// deliver from this unit (L8): a dead mount makes systemd fail to set up
// the sandbox, which stopped collection for the whole outage. The run only
// queues the data (run --no-deliver) and starts blackbox-send.service,
// whose failure does not affect it.
func systemdService(exe, mount string, sendUnit bool, writable ...string) string {
	deps := ""
	if mount != "" {
		deps = "\nWants=" + mount + "\nAfter=" + mount
	}
	run := exe + " run"
	if sendUnit {
		deps += "\nWants=" + sendUnitName
		run += " --no-deliver"
	}
	return fmt.Sprintf(`[Unit]
Description=Blackbox audit log collection and reporting
Documentation=https://github.com/casea1/blackbox
After=auditd.service local-fs.target%s

[Service]
Type=oneshot
ExecStart=%s
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=2h
`, deps, run) + sandbox(writable)
}

// sendUnitName delivers what a run queued to a collector's folder.
const sendUnitName = "blackbox-send.service"

// systemdSendService delivers the queued data to the collector's folder
// after each run (L8). It runs separately so a delivery problem never
// stops collection. Its sandbox does not name the collector's folder
// (systemd fails to set up a sandbox naming a dead mount); it protects the
// system (ProtectSystem=full) instead. Before sending it asks for the
// folder to be mounted from /etc/fstab, so a mount that failed at boot is
// tried again at every run (L7), as Blackbox does for an SMB share.
//
// The folder is mounted by asking systemd to start its mount unit (from
// /etc/fstab), not by running mount here (L12): this unit has no network
// of its own (PrivateNetwork), which "+" does not lift, so an sshfs mount
// started from it can't reach the collector, and would end with the unit.
// PID 1 mounts it outside the sandbox, and the mount stays.
func systemdSendService(exe, sendTo string) string {
	return fmt.Sprintf(`[Unit]
Description=Deliver Blackbox audit events to the collector
Documentation=https://github.com/casea1/blackbox/blob/main/docs/lan.md
After=blackbox.service network-online.target remote-fs.target

[Service]
Type=oneshot
ExecStartPre=-+/usr/bin/systemctl start %s
ExecStart=%s send
Nice=10
TimeoutStartSec=30min
`, systemdQuote(MountUnitFor(sendTo)), exe) + sandboxFull()
}

// MountUnitFor is the name of the systemd mount unit for a folder, as
// systemd-escape --path --suffix=mount gives it: /mnt/blackbox-inbox is
// mnt-blackbox\x2dinbox.mount.
func MountUnitFor(dir string) string {
	p := strings.Trim(path.Clean("/"+dir), "/")
	if p == "" {
		return "-.mount"
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '/':
			b.WriteByte('-')
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == ':', c == '_', c == '.' && i > 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String() + ".mount"
}

// systemdQuote quotes a path for a unit file command line.
func systemdQuote(p string) string {
	if !strings.ContainsAny(p, " \t\"'\\") {
		return p
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p) + `"`
}

// systemdShutdownService sends collected events to the collector when the
// system shuts down (for example a virtual machine stopped from its host),
// so they do not wait for the next boot. Being ordered after the network,
// remote filesystems, the share mount and the VirtualBox service, it runs
// before those are stopped. Like blackbox-send.service, its sandbox does
// not name the collector's folder (L8).
func systemdShutdownService(exe, mount string) string {
	after := "network-online.target remote-fs.target vboxadd-service.service"
	if mount != "" {
		after += " " + mount
	}
	return fmt.Sprintf(`[Unit]
Description=Send Blackbox audit events to the collector before shutdown
Documentation=https://github.com/casea1/blackbox/blob/main/docs/lan.md
Wants=network-online.target
After=%s

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStop=%s send
TimeoutStopSec=90
`, after, exe) + sandboxFull() + `
[Install]
WantedBy=multi-user.target
`
}

// sandbox is the service hardening shared by Blackbox's units.
func sandbox(writable []string) string {
	return fmt.Sprintf(`PrivateNetwork=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077
`, strings.Join(uniq(writable), " "))
}

// sandboxFull is the hardening of the units that deliver to the
// collector: the system is read-only (ProtectSystem=full: /usr, /boot,
// /etc), but no path is named, so a dead mount cannot stop the unit from
// starting (L8).
func sandboxFull() string {
	return `PrivateNetwork=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077
`
}

func uniq(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// systemdTimer runs the service on a fixed schedule and catches up after
// the system was off (Persistent=true).
// SetCollectEvery changes collect_every in the config file and the
// schedule that runs collection ("blackbox config set collect_every 15m",
// C6), without running setup again.
func SetCollectEvery(cfgPath string, every time.Duration, logf func(string, ...any)) error {
	if _, err := systemdTimer(every); err != nil {
		return err
	}
	if err := config.SetValues(cfgPath, [][2]string{{"collect_every", config.FormatDuration(every)}}); err != nil {
		return err
	}
	if err := scheduleApplier(every); err != nil {
		return fmt.Errorf("collect_every is saved, but the schedule could not be updated: %w (run setup again)", err)
	}
	logf("Collection now runs %s.", EveryText(every))
	return nil
}

// scheduleApplier updates the installed schedule (tests replace it).
var scheduleApplier = applySchedule

func systemdTimer(every time.Duration) (string, error) {
	cal, err := onCalendar(every)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`[Unit]
Description=Run Blackbox audit collection every %s

[Timer]
OnCalendar=%s
OnBootSec=5min
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
`, every, cal), nil
}

// onCalendar turns an interval into a systemd calendar expression. The
// interval must divide an hour (minutes) or a day (hours) evenly.
func onCalendar(d time.Duration) (string, error) {
	switch {
	case d < time.Hour && d >= time.Minute && time.Hour%d == 0 && d%time.Minute == 0:
		return fmt.Sprintf("*-*-* *:00/%d:00", int(d.Minutes())), nil
	case d >= time.Hour && d%time.Hour == 0 && (24*time.Hour)%d == 0:
		return fmt.Sprintf("*-*-* 00/%d:05:00", int(d.Hours())), nil
	}
	return "", fmt.Errorf("collection interval %s must divide an hour or a day evenly (e.g. 15m, 30m, 1h, 2h)", d)
}

// TrayTaskName is the Windows scheduled task that starts the status icon.
const TrayTaskName = "Blackbox Status"

// TrayQuitEvent is the named event the status icons watch: setting it
// closes every running icon (on uninstall, or when the icon is turned off).
const TrayQuitEvent = `Global\BlackboxTrayQuit`

// trayTaskXML starts the status icon when any member of Administrators
// logs on, in their session, with full rights (the task was registered by
// an administrator, so there is no UAC prompt). Every administrator who is
// logged on gets their own icon, so copies run side by side.
func trayTaskXML(exe string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Blackbox</Author>
    <Description>Shows Blackbox's status in the notification area for administrators.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-32-544</GroupId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>tray</Arguments>
    </Exec>
  </Actions>
</Task>
`, xmlEscape(exe))
}

// Installed reports whether the program itself is installed (an uninstall
// keeps the settings, so their presence alone doesn't mean it is).
func Installed() bool {
	_, err := os.Stat(ProgramPath())
	return err == nil
}

// before is what setup found before it wrote anything, for recording
// what it changed (A15).
type before struct {
	existed  bool              // a settings file was there (a re-install or upgrade)
	settings map[string]string // its values
	version  string            // the version that last ran here, if known
}

func readBefore(cfgPath, dataDir string) before {
	b := before{settings: config.RawValues(cfgPath)}
	_, err := os.Stat(cfgPath)
	b.existed = err == nil
	if v := InstalledVersion(); v != "" {
		b.version = v
	} else if st, err := store.Open(dataDir); err == nil {
		if sys := st.State.Systems[store.SystemKey(collect.LocalHost())]; sys != nil {
			b.version = sys.Version
		}
	}
	return b
}

// recordSetup has Blackbox record the install or upgrade, and each
// setting setup changed, in its spool and the system log (A15).
func recordSetup(cfgPath, dataDir string, b before, version string, logf func(string, ...any)) {
	var changes []event.SelfChange
	switch {
	case !b.existed:
		changes = append(changes, event.SelfChange{Kind: "installed", Version: version, Program: "setup"})
	case version != "" && b.version != version:
		changes = append(changes, event.SelfChange{Kind: "upgraded", Old: b.version, Version: version, Program: "setup"})
	}
	if b.existed {
		changes = append(changes, selfaudit.Changes(b.settings, config.RawValues(cfgPath), "setup")...)
	}
	for _, c := range changes {
		if err := selfaudit.Record(dataDir, c, time.Now()); err != nil {
			logf("Note: recording this change in the system log failed: %v", err)
		}
	}
}

// recordRemoval has Blackbox record that it is being removed, before
// anything is removed (A15). The copy in the system log outlives it.
func recordRemoval(logf func(string, ...any)) {
	c := event.SelfChange{Kind: "removed", Program: "blackbox uninstall"}
	if err := selfaudit.Record(config.DefaultDataDir(), c, time.Now()); err != nil {
		logf("Note: recording the removal in the system log failed: %v", err)
	}
}

// versionLine is the first line of "blackbox version": later lines (the
// FIPS 140-3 state, COMP3) are not part of the version.
func versionLine(out []byte) string {
	l, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(l)
}
