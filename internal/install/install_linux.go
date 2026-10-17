//go:build linux

package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/report"
)

// ProgramPath is where install copies the executable.
func ProgramPath() string { return "/usr/local/bin/blackbox" }

const (
	serviceFile  = "/etc/systemd/system/blackbox.service"
	timerFile    = "/etc/systemd/system/blackbox.timer"
	shutdownFile = "/etc/systemd/system/blackbox-shutdown.service"
	sendFile     = "/etc/systemd/system/" + sendUnitName
	launcherFile = "/usr/share/applications/blackbox-reports.desktop"
)

// shareReports lets report_group's members read the reports folder now
// (each run keeps it so), and says if a folder above it keeps them out.
func shareReports(cfg *config.Config, logf func(string, ...any)) {
	dir := cfg.ReportsDir()
	if cfg.ReportGroup == "" {
		logf("Reports opened by:   root only (sudo)")
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		logf("Could not create %s: %v", dir, err)
		return
	}
	if err := report.Share(dir, cfg.ReportGroup); err != nil {
		logf("Could not share the reports with %s: %v", cfg.ReportGroup, err)
		return
	}
	logf("Reports opened by:   root and members of %s (read only)", cfg.ReportGroup)
	if p := report.Unreachable(dir, cfg.ReportGroup); p != "" {
		logf("   But %s is closed to %s, so they can't reach the reports yet. Choose a report folder outside it (blackbox config set report_dir FOLDER), or let them through it: sudo chmod o+x %s", p, cfg.ReportGroup, p)
	}
}

// writeLauncher adds "Blackbox reports" to the applications menu (READ1):
// a click opens the latest report as the person clicking, right-click
// offers the index and a new report (which asks for an admin password).
func writeLauncher(exe, reportsDir string) error {
	q := func(s string) string { // a quoted argument in a desktop file's Exec
		r := strings.NewReplacer(`\`, `\\\\`, `"`, `\\"`, "`", "\\\\`", "$", `\\$`, "%", "%%")
		return `"` + r.Replace(s) + `"`
	}
	open := q(exe) + " open --dir " + q(reportsDir)
	text := "[Desktop Entry]\nType=Application\nName=Blackbox reports\nComment=Open the latest Blackbox audit report\n" +
		"Exec=" + open + "\nIcon=text-html\nTerminal=false\nCategories=Utility;\nActions=index;report;\n\n" +
		"[Desktop Action index]\nName=Open the reports index\nExec=" + q(exe) + " open --index --dir " + q(reportsDir) + "\n\n" +
		"[Desktop Action report]\nName=Make a report now\nExec=sh -c " + q("pkexec "+shellQuote(exe)+" report && "+shellQuote(exe)+" open --dir "+shellQuote(reportsDir)) + "\n"
	if err := os.MkdirAll(filepath.Dir(launcherFile), 0o755); err != nil {
		return err
	}
	return os.WriteFile(launcherFile, []byte(text), 0o644)
}

// shellQuote quotes s for sh.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Install copies the program, creates the data folder and config, and
// enables the systemd timer. It is safe to run again (upgrade).
func Install(opt Options) error {
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if os.Geteuid() != 0 {
		return errors.New("install must be run as root (sudo ./blackbox install)")
	}
	was := readBefore(config.DefaultPath(), config.DefaultDataDir())
	timer, err := systemdTimer(opt.CollectEvery)
	if err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	dst := ProgramPath()
	if resolved, _ := filepath.EvalSymlinks(self); resolved != dst {
		if err := copyFile(self, dst, 0o755); err != nil {
			return fmt.Errorf("copy program to %s: %w", dst, err)
		}
	}
	logf("Installed program:   %s", dst)
	if err := linkProgram(dst, SudoLink); err != nil {
		logf("Could not link %s to %s (%v): with sudo, run %s by its full path.", SudoLink, dst, err, dst)
	}

	data := config.DefaultDataDir()
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(data, 0o700); err != nil {
		return err
	}
	// The exports folder exists from the start, so the audit rule that
	// watches it (AR6) can be loaded before the first run.
	if err := os.MkdirAll(filepath.Join(data, "archive-pieces"), 0o700); err != nil {
		return err
	}
	logf("Data folder:         %s (root only)", data)
	if opt.ReportDir != "" {
		if err := PrepareReportDir(opt.ReportDir, logf); err != nil {
			return err
		}
	}
	if opt.ArchiveDir != "" {
		if err := PrepareArchiveDir(opt.ArchiveDir, logf); err != nil {
			return err
		}
	}

	// Config: created, or updated with these settings on a re-install.
	cfgPath := config.DefaultPath()
	if err := writeConfig(cfgPath, opt, false); err != nil {
		return err
	}
	logf("Configuration:       %s", cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := setupLAN(opt, data, logf); err != nil {
		return err
	}

	if err := writeUnits(dst, cfg); err != nil {
		return err
	}
	if err := os.WriteFile(timerFile, []byte(timer), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "blackbox.timer"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	if opt.Role != RoleSender {
		shareReports(cfg, logf)
		if err := writeLauncher(dst, cfg.ReportsDir()); err != nil {
			logf("Could not add Blackbox reports to the applications menu: %v", err)
		} else {
			logf("Applications menu:   Blackbox reports (opens the latest report; right-click for the index)")
		}
	}
	logf("Scheduled:           blackbox.timer — collects %s as root; %s", EveryText(opt.CollectEvery), scheduleWhat(opt))
	recordSetup(cfgPath, data, was, opt.Version, logf)
	return nil
}

// Uninstall disables the timer and removes the unit files. Reports and
// collected data are kept.
func Uninstall(logf func(string, ...any)) error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must be run as root")
	}
	recordRemoval(logf)
	exec.Command("systemctl", "disable", "--now", "blackbox.timer").Run()
	if _, err := os.Stat(shutdownFile); err == nil {
		removeShutdownUnit(shutdownFile)
	}
	for _, f := range []string{timerFile, serviceFile, shutdownFile, sendFile, launcherFile} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	removeSendTo(logf)
	exec.Command("systemctl", "daemon-reload").Run()
	logf("Removed the blackbox.timer schedule.")
	if cfg, _ := config.Load(config.DefaultPath()); cfg != nil {
		logf("Reports were kept in %s.", cfg.ReportsDir())
	}
	logf("Collected events were kept in %s.", config.DefaultDataDir())
	logf("To remove the program: rm %s %s (and %s if no longer needed).", ProgramPath(), SudoLink, filepath.Dir(config.DefaultPath()))
	return nil
}

// afterReportDirChange lets the sandboxed service write to the new report
// folder (systemd ReadWritePaths), if Blackbox is installed.
// SudoLink makes "sudo blackbox" work where sudo's secure_path leaves
// out /usr/local/bin (AlmaLinux, Rocky, RHEL): a link to the program in
// /usr/bin, which every secure_path has.
const SudoLink = "/usr/bin/blackbox"

// linkProgram points link at exe. A link already there is replaced; any
// other file there (another program of that name) is left alone.
func linkProgram(exe, link string) error {
	if fi, err := os.Lstat(link); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s is already there and is not a link", link)
		}
		if to, _ := os.Readlink(link); to == exe {
			return nil
		}
		if err := os.Remove(link); err != nil {
			return err
		}
	}
	return os.Symlink(exe, link)
}

func afterReportDirChange(logf func(string, ...any)) error {
	if _, err := os.Stat(serviceFile); err != nil {
		return nil // not installed as a service
	}
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return err
	}
	if err := writeUnits(ProgramPath(), cfg); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	logf("Updated blackbox.service so it may write to %s.", cfg.ReportsDir())
	return nil
}

// writeUnits writes the service unit and, on a computer that sends to a
// collector, the unit that sends before shutdown (enabled so it runs at
// the next shutdown; removed on other computers) and, for a folder the
// site mounted, the unit that delivers after each run (L8).
func writeUnits(exe string, cfg *config.Config) error {
	if err := os.WriteFile(serviceFile, []byte(serviceFor(exe, cfg)), 0o644); err != nil {
		return err
	}
	if separateSend(cfg) {
		if err := os.WriteFile(sendFile, []byte(systemdSendService(exe, cfg.SendTo)), 0o644); err != nil {
			return err
		}
	} else {
		os.Remove(sendFile)
	}
	if cfg.SendTo == "" {
		if _, err := os.Stat(shutdownFile); err == nil {
			removeShutdownUnit(shutdownFile)
		}
		return nil
	}
	if err := os.WriteFile(shutdownFile, []byte(shutdownFor(exe, cfg)), 0o644); err != nil {
		return err
	}
	exec.Command("systemctl", "daemon-reload").Run()
	if out, err := exec.Command("systemctl", "enable", "--now", "blackbox-shutdown.service").CombinedOutput(); err != nil {
		return fmt.Errorf("enable blackbox-shutdown.service: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// systemctl runs systemctl, ignoring failures (tests replace it).
var systemctl = func(args ...string) { exec.Command("systemctl", args...).Run() }

// removeShutdownUnit removes the unit that sends before shutdown, when a
// sender no longer sends (S15). Stopping it runs its send, which fails
// once send_to is gone, so systemd would keep it as "not-found failed":
// its failed state is cleared once the file is removed.
func removeShutdownUnit(path string) {
	systemctl("disable", "--now", "blackbox-shutdown.service")
	os.Remove(path)
	systemctl("daemon-reload")
	systemctl("reset-failed", "blackbox-shutdown.service")
}

// separateSend reports whether delivery runs in its own unit: for a
// folder the site mounted (sshfs, NFS, a VirtualBox shared folder), not
// for an SMB share Blackbox mounts itself inside its data folder.
func separateSend(cfg *config.Config) bool {
	return cfg.SendTo != "" && !config.IsShare(cfg.SendTo)
}

// serviceFor is the service unit for these settings.
func serviceFor(exe string, cfg *config.Config) string {
	mount, writable := unitPaths(cfg)
	return systemdService(exe, mount, separateSend(cfg), writable...)
}

// shutdownFor is the send-before-shutdown unit for these settings.
func shutdownFor(exe string, cfg *config.Config) string {
	mount, _ := unitPaths(cfg)
	return systemdShutdownService(exe, mount)
}

// unitPaths are the share mount unit (if any) and the folders the run
// may write to. The collector's folder is not one of them (L8): the run
// unit does not deliver to it.
func unitPaths(cfg *config.Config) (mount string, writable []string) {
	writable = []string{cfg.DataDir, cfg.ReportsDir()}
	if cfg.ArchiveDir != "" {
		// Only when set: the default is inside the data folder. "-": a
		// folder that is missing (an unmounted volume) must not stop the
		// unit, and so collection, from starting; the run says what failed.
		writable = append(writable, "-"+cfg.ArchiveDir)
	}
	if config.IsShare(cfg.SendTo) {
		mount = mountUnitName() // mounted inside the data folder
	}
	if cfg.Inbox != "" {
		writable = append(writable, "-"+cfg.Inbox)
	}
	return mount, writable
}

// restrictDir limits a folder Blackbox created to root.
func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }

// lockFolder makes an existing report or original-logs folder root's and
// unwritable by group and others, if it isn't: the scheduled runs write in
// it as root, and in a folder others can change, a name root is about to
// write could be made a link to /etc first. Reading is left as it was.
// It says what it changed ("" = nothing).
func lockFolder(dir string) (string, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || config.IsShare(dir) {
		return "", nil
	}
	var did []string
	if st.Uid != 0 {
		if err := os.Chown(dir, 0, -1); err != nil {
			return "", fmt.Errorf("make root its owner: %w", err)
		}
		did = append(did, "owner changed to root")
	}
	if m := fi.Mode().Perm(); m&0o022 != 0 {
		if err := os.Chmod(dir, m&^0o022); err != nil {
			return "", fmt.Errorf("take away write for others: %w", err)
		}
		did = append(did, fmt.Sprintf("write access for group and others removed (was %o): only root writes here", m))
	}
	return strings.Join(did, "; "), nil
}

// CanGrantSystem is false: root can write to any local folder.
const CanGrantSystem = false

// GrantSystem is not needed here.
func GrantSystem(string) error { return errors.New("not supported on this system") }

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// RequireAdmin returns an error unless running as root.
func RequireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("run this as root (sudo)")
	}
	return nil
}

// The status icon is Windows only.

// TrayWanted is always false here.
func TrayWanted() bool { return false }

// WindowedPath is the Windows windowed program; none elsewhere.
func WindowedPath() string { return "" }

// CheckGroups is for the Windows status icon only.
func CheckGroups([]string) error { return nil }

// StartTray is Windows only.
func StartTray() error { return nil }

// QuitTrays is Windows only.
func QuitTrays() {}

// RemoveOld is Windows only.
func RemoveOld() {}

// InstalledVersion is only used by the Windows setup window.
func InstalledVersion() string { return "" }

// VirtualBoxInstalled is only asked on Windows (the collector's host).
func VirtualBoxInstalled() bool { return false }

// applySchedule rewrites blackbox.timer for a new interval, if installed.
func applySchedule(every time.Duration) error {
	if _, err := os.Stat(timerFile); err != nil {
		return nil
	}
	timer, err := systemdTimer(every)
	if err != nil {
		return err
	}
	if err := os.WriteFile(timerFile, []byte(timer), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "restart", "blackbox.timer").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart blackbox.timer: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RefreshSchedule has nothing to do here: systemd timers follow the clock
// when it changes (T1).
func RefreshSchedule(time.Duration) error { return nil }
