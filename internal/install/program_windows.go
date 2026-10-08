//go:build windows

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/casea1/blackbox/internal/hidden"
	"github.com/casea1/blackbox/internal/winexe"
)

// WindowedPath is the windowed copy of the program: the setup window and
// the status icon run from it, so Windows opens no console for them.
func WindowedPath() string { return filepath.Join(filepath.Dir(ProgramPath()), "blackboxw.exe") }

// placePrograms installs blackbox.exe (console) and blackboxw.exe
// (windowed) from the running program, whatever its name.
//
// A running program can't be overwritten but can be renamed, so each file
// in place is renamed to .old first: a collection in progress or an open
// status icon never blocks an upgrade. The .old files are kept until the
// new program has been checked (see checkPrograms), and deleted at the
// next install.
func placePrograms(self string) ([]kept, error) {
	src, err := os.ReadFile(self)
	if err != nil {
		return nil, err
	}
	RemoveOld()
	// A release's setup file carries the console program, signed: it is
	// installed as it is, so its signature stays valid (A10). Otherwise
	// both are made from this program.
	console := embeddedConsole()
	var ks []kept
	for _, p := range []struct {
		path     string
		windowed bool
	}{{ProgramPath(), false}, {WindowedPath(), true}} {
		var b []byte
		var err error
		if !p.windowed && console != nil {
			b = console
		} else {
			b, err = winexe.SetSubsystem(src, p.windowed)
		}
		if err != nil {
			return ks, err
		}
		old, err := swapIn(p.path, b)
		ks = append(ks, kept{p.path, old})
		if err != nil {
			return ks, err
		}
	}
	return ks, nil
}

// RemoveOld deletes replaced programs that are no longer running.
func RemoveOld() {
	list, _ := filepath.Glob(filepath.Join(filepath.Dir(ProgramPath()), "*.exe.old*"))
	for _, f := range list {
		os.Remove(f)
	}
}

// checkPrograms runs the installed program and confirms it is the version
// just installed. If it isn't, the previous program is put back.
func checkPrograms(version string, ks []kept) error {
	out, err := hidden.Command(ProgramPath(), "version").Output()
	got := versionLine(out)
	if err == nil && got == "blackbox "+version {
		return nil
	}
	if err == nil {
		err = fmt.Errorf("it answered %q", got)
	}
	if rollBack(ks) {
		return fmt.Errorf("the new program did not start (%v); the upgrade was undone and the previous version put back", err)
	}
	return fmt.Errorf("the new program did not start: %v", err)
}

// TrayWanted says whether the status icon is on: it is when its task
// exists, and by default when upgrading from a version without it. It is
// off only when it was turned off.
func TrayWanted() bool {
	if hidden.Command("schtasks.exe", "/Query", "/TN", TrayTaskName).Run() == nil {
		return true
	}
	_, err := os.Stat(WindowedPath())
	return err != nil
}

// setupTray registers or removes the task that starts the status icon.
func setupTray(on bool, logf func(string, ...any)) error {
	if !on {
		if hidden.Command("schtasks.exe", "/Query", "/TN", TrayTaskName).Run() == nil {
			hidden.Command("schtasks.exe", "/Delete", "/TN", TrayTaskName, "/F").Run()
			logf("Status icon:         removed")
		}
		QuitTrays()
		return nil
	}
	tmp := filepath.Join(os.TempDir(), "blackbox-tray-task.xml")
	if err := os.WriteFile(tmp, utf16LE(trayTaskXML(WindowedPath())), 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if out, err := hidden.Command("schtasks.exe", "/Create", "/TN", TrayTaskName, "/XML", tmp, "/F").CombinedOutput(); err != nil {
		return fmt.Errorf("create status icon task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	logf("Status icon:         shown to administrators when they log on (task \"%s\")", TrayTaskName)
	return nil
}

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateEventW = kernel32.NewProc("CreateEventW")
	procSetEvent     = kernel32.NewProc("SetEvent")
)

// QuitTrays asks every running status icon to close, and gives them a
// moment to do so.
func QuitTrays() {
	name, _ := syscall.UTF16PtrFromString(TrayQuitEvent)
	h, _, _ := procCreateEventW.Call(0, 1, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return
	}
	procSetEvent.Call(h)
	time.Sleep(1500 * time.Millisecond)
	syscall.CloseHandle(syscall.Handle(h))
}

// StartTray starts the status icon for the person running setup.
func StartTray() error {
	cmd := hidden.Command(WindowedPath(), "tray")
	cmd.Dir = filepath.Dir(WindowedPath())
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// IsAdmin reports whether this process has full administrator rights.
func IsAdmin() bool { return isAdmin() }

// InstalledVersion is the version of the installed program, or "".
func InstalledVersion() string {
	if _, err := os.Stat(ProgramPath()); err != nil {
		return ""
	}
	out, err := hidden.Command(ProgramPath(), "version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(versionLine(out), "blackbox ")
}
