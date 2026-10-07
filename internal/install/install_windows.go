//go:build windows

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/casea1/blackbox/internal/brand"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/hidden"
	"github.com/casea1/blackbox/internal/share"
)

// ProgramPath is where install copies the executable.
func ProgramPath() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "Blackbox", "blackbox.exe")
}

// Install copies the program, creates the data folder and config, and
// registers the scheduled task. It is safe to run again (upgrade).
func Install(opt Options) error {
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if !isAdmin() {
		return errors.New("install must be run from an elevated (Run as administrator) prompt")
	}
	was := readBefore(config.DefaultPath(), config.DefaultDataDir())

	// 1. Program files.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dst := ProgramPath()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	ks, err := placePrograms(self)
	if err != nil {
		rollBack(ks)
		return fmt.Errorf("copy program to %s: %w", filepath.Dir(dst), err)
	}
	if opt.Version != "" {
		if err := checkPrograms(opt.Version, ks); err != nil {
			return err
		}
	}
	logf("Installed program:   %s", dst)

	// 2. Data folder, readable only by Administrators and SYSTEM (SIDs are
	// used so this works on any language version of Windows).
	data := config.DefaultDataDir()
	if err := os.MkdirAll(data, 0o750); err != nil {
		return err
	}
	if err := restrictDir(data); err != nil {
		return err
	}
	logf("Data folder:         %s (Administrators and SYSTEM only)", data)
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

	// 3. Config: created, or updated with these settings on a re-install.
	cfgPath := config.DefaultPath()
	if err := writeConfig(cfgPath, opt, true); err != nil {
		return err
	}
	logf("Configuration:       %s", cfgPath)

	// LAN: the inbox (collector) and delivery to a collector (sender).
	if err := setupLAN(opt, data, logf); err != nil {
		return err
	}

	// 4. Scheduled task.
	if err := registerTask(dst, data, opt.CollectEvery); err != nil {
		return err
	}
	logf("Scheduled task:      \"%s\" — collects %s as SYSTEM; %s", TaskName, EveryText(opt.CollectEvery), scheduleWhat(opt))
	// Collect now, as the Linux timer does when it is enabled: an upgrade
	// replaces the task without running it (CLI1). A run already going
	// (the first registration's) is left to finish.
	if out, err := hidden.Command("schtasks.exe", "/Run", "/TN", TaskName).CombinedOutput(); err != nil {
		logf("Note: could not start a collection now (%v: %s); the task runs at its next time", err, strings.TrimSpace(string(out)))
	} else {
		logf("Collection:          started now (blackbox status shows when it has run)")
	}

	// 5. The status icon, for administrators on a collector or standalone computer.
	if err := setupTray(opt.Tray && opt.SendTo == "", logf); err != nil {
		return err
	}

	// 6. Entry in Settings > Apps and Control Panel > Programs and Features.
	if err := registerUninstall(dst, opt.Version); err != nil {
		logf("Note: could not add Blackbox to Programs and Features: %v", err)
	} else {
		logf("Programs list:       \"%s\" added to Settings > Apps and Programs and Features", brand.Name)
	}
	recordSetup(cfgPath, data, was, opt.Version, logf)
	return nil
}

// uninstallKey is where Windows lists installed programs.
const uninstallKey = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Blackbox`

func registerUninstall(exe, version string) error {
	size := "5000" // KB, shown as the program's size
	if fi, err := os.Stat(exe); err == nil {
		size = fmt.Sprint(fi.Size() / 1024)
	}
	values := [][3]string{
		{"DisplayName", "REG_SZ", brand.Name},
		{"DisplayVersion", "REG_SZ", version},
		{"Publisher", "REG_SZ", "Austin Case"},
		{"InstallLocation", "REG_SZ", filepath.Dir(exe)},
		{"DisplayIcon", "REG_SZ", exe},
		{"UninstallString", "REG_SZ", `"` + exe + `" uninstall`},
		{"QuietUninstallString", "REG_SZ", `"` + exe + `" uninstall`},
		{"URLInfoAbout", "REG_SZ", "https://github.com/casea1/blackbox"},
		{"ModifyPath", "REG_SZ", `"` + WindowedPath() + `" setup`},
		{"NoModify", "REG_DWORD", "0"},
		{"NoRepair", "REG_DWORD", "1"},
		{"EstimatedSize", "REG_DWORD", size},
	}
	for _, v := range values {
		if out, err := hidden.Command("reg.exe", "add", uninstallKey, "/v", v[0], "/t", v[1], "/d", v[2], "/f").CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// afterReportDirChange has nothing to update on Windows: the scheduled task
// runs as SYSTEM and reads the report folder from the config each run.
func afterReportDirChange(func(string, ...any)) error { return nil }

// restrictDir limits a folder Blackbox created to Administrators and
// SYSTEM (by SID, so it works on any language version of Windows).
func restrictDir(dir string) error {
	if out, err := hidden.Command("icacls.exe", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput(); err != nil {
		return fmt.Errorf("restrict permissions on %s: %v: %s", dir, err, out)
	}
	return nil
}

// Uninstall removes the scheduled task, the Programs and Features entry
// and the program folder. Reports, settings and collected data are kept.
func Uninstall(logf func(string, ...any)) error {
	if !isAdmin() {
		return errors.New("uninstall must be run from an elevated (Run as administrator) prompt")
	}
	recordRemoval(logf)
	hidden.Command("schtasks.exe", "/End", "/TN", TaskName).Run() // stop a run in progress
	if out, err := hidden.Command("schtasks.exe", "/Delete", "/TN", TaskName, "/F").CombinedOutput(); err != nil {
		logf("Scheduled task: %s", strings.TrimSpace(string(out)))
	} else {
		logf("Removed scheduled task \"%s\".", TaskName)
	}
	setupTray(false, logf)
	hidden.Command("reg.exe", "delete", uninstallKey, "/f").Run()
	removeInbox(logf)
	share.SaveSecret(config.DefaultDataDir(), "") // removes the stored share password
	logf("Removed Blackbox from Programs and Features.")

	// A running program cannot delete itself, so a short-lived cmd.exe
	// removes the program folder once this process has exited.
	dir := filepath.Dir(ProgramPath())
	if _, err := os.Stat(dir); err == nil {
		if err := removeAfterExit(dir); err == nil {
			logf("Removing %s.", dir)
		}
	}
	if cfg, _ := config.Load(config.DefaultPath()); cfg != nil {
		logf("Reports were kept in %s.", cfg.ReportsDir())
	}
	logf("Settings and collected events were kept in %s.", config.DefaultDataDir())
	return nil
}

// removeAfterExit starts a hidden cmd.exe that deletes dir once this
// process has exited. It retries for about 30 seconds, in case the
// scheduled task or an antivirus scan still has the program open.
func removeAfterExit(dir string) error {
	script := `ping -n 3 127.0.0.1 >nul & for /l %i in (1,1,30) do @(rmdir /s /q "` + dir +
		`" 2>nul & if not exist "` + dir + `" (exit /b 0) & ping -n 2 127.0.0.1 >nul)`
	cmd := hidden.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	// Set the command line directly: Go's argument quoting (\") is not
	// understood by cmd.exe and breaks paths containing spaces.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       `cmd.exe /d /s /c "` + script + `"`,
		HideWindow:    true,
		CreationFlags: 0x08000000 | syscall.CREATE_NEW_PROCESS_GROUP, // CREATE_NO_WINDOW
	}
	return cmd.Start()
}

// isAdmin checks for an elevated token by opening the raw physical disk,
// which only administrators can do.
func isAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// utf16LE encodes s with a byte order mark, as schtasks expects.
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(u))
	b[0], b[1] = 0xFF, 0xFE
	for i, c := range u {
		b[2+2*i] = byte(c)
		b[3+2*i] = byte(c >> 8)
	}
	return b
}

// RequireAdmin returns an error unless running elevated.
func RequireAdmin() error {
	if !isAdmin() {
		return errors.New("run this as an administrator (right-click Command Prompt > Run as administrator, or double-click the setup file)")
	}
	return nil
}

// VirtualBoxInstalled reports whether Oracle VirtualBox is installed, so
// setup suggests the VirtualBox shared folder only where there is one (S12).
func VirtualBoxInstalled() bool {
	for _, env := range []string{"ProgramFiles", "ProgramW6432"} {
		if d := os.Getenv(env); d != "" {
			if _, err := os.Stat(filepath.Join(d, "Oracle", "VirtualBox", "VBoxSVC.exe")); err == nil {
				return true
			}
		}
	}
	return false
}

// registerTask creates (or replaces) the collection task.
func registerTask(exe, data string, every time.Duration) error {
	xml := taskXML(exe, every, TaskStart)
	tmp := filepath.Join(data, "blackbox-task.xml")
	if err := os.WriteFile(tmp, utf16LE(xml), 0o640); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if out, err := hidden.Command("schtasks.exe", "/Create", "/TN", TaskName, "/XML", tmp, "/F").CombinedOutput(); err != nil {
		return fmt.Errorf("create scheduled task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RefreshSchedule registers the collection task again, so its next run
// follows the clock as it is now (T1). A run calls it when it finds the
// clock was moved back. Nothing is done if Blackbox is not installed.
// applySchedule registers the collection task again with a new interval.
func applySchedule(every time.Duration) error { return RefreshSchedule(every) }

func RefreshSchedule(every time.Duration) error {
	if _, err := os.Stat(ProgramPath()); err != nil {
		return nil
	}
	return registerTask(ProgramPath(), config.DefaultDataDir(), every)
}
