//go:build windows

package install

import (
	"fmt"
	"github.com/casea1/blackbox/internal/config"
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

// CheckGroups says whether each name is a group on this computer or its
// domain, for the status icon (TRAY4).
func CheckGroups(groups []string) error {
	for _, g := range groups {
		_, _, typ, err := syscall.LookupSID("", g)
		if err != nil {
			return fmt.Errorf("No group %q on this computer or its domain. Enter group names as DOMAIN\\Group or Group, separated by commas.", g)
		}
		if typ != 2 && typ != 4 && typ != 5 {
			return fmt.Errorf("%q is not a group (a user account?). Name the group whose members should see the icon.", g)
		}
	}
	return nil
}

// trayTaskName is the task for the i-th group (from 0): "Blackbox
// Status", then "Blackbox Status 2" and so on (TRAY4).
func trayTaskName(i int) string {
	if i == 0 {
		return TrayTaskName
	}
	return fmt.Sprintf("%s %d", TrayTaskName, i+1)
}

// trayTasks are the status icon's tasks registered now, read with one
// schtasks call (0.29.0 queried each possible name in turn, a burst of
// hidden processes Defender's behaviour rules took for an attack).
func trayTasks() []string {
	out, err := hidden.Command("schtasks.exe", "/Query", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return nil
	}
	return trayTaskNames(string(out))
}

// setupTray registers or removes the tasks that start the status icon,
// one per group whose members see it (none: Administrators).
func setupTray(on bool, groups []string, logf func(string, ...any)) error {
	// The groups' SIDs first: a name that is not a group is refused
	// before anything changes.
	type grp struct{ name, sid string }
	var list []grp
	if on {
		for _, g := range groups {
			sid, _, typ, err := syscall.LookupSID("", g)
			if err != nil {
				return fmt.Errorf("status icon: no group %q on this computer or its domain: %v", g, err)
			}
			// SidTypeGroup 2, Alias 4, WellKnownGroup 5.
			if typ != 2 && typ != 4 && typ != 5 {
				return fmt.Errorf("status icon: %q is not a group (a user account?); name a group whose members should see it", g)
			}
			s, err := sid.String()
			if err != nil {
				return err
			}
			list = append(list, grp{g, s})
		}
		if len(list) == 0 {
			list = []grp{{"Administrators", AdministratorsSID}}
		}
	}
	removed := false
	keep := map[string]bool{}
	for i := range list {
		keep[trayTaskName(i)] = true
	}
	for _, name := range trayTasks() {
		if !keep[name] {
			hidden.Command("schtasks.exe", "/Delete", "/TN", name, "/F").Run()
			removed = true
		}
	}
	if !on {
		if removed {
			logf("Status icon:         removed")
		}
		QuitTrays()
		return nil
	}
	var names []string
	for i, g := range list {
		// In the data folder, under a new random name: a fixed name in
		// %TEMP% could be made first by someone else (C:\Windows\Temp, when
		// setup runs as SYSTEM) and changed before schtasks reads it.
		tmp, err := writeTemp(config.DefaultDataDir(), "blackbox-tray-task-*.xml", utf16LE(trayTaskXML(WindowedPath(), g.sid)))
		if err != nil {
			return err
		}
		out, err := hidden.Command("schtasks.exe", "/Create", "/TN", trayTaskName(i), "/XML", tmp, "/F").CombinedOutput()
		os.Remove(tmp)
		if err != nil {
			return fmt.Errorf("create status icon task for %s: %v: %s", g.name, err, strings.TrimSpace(string(out)))
		}
		names = append(names, g.name)
	}
	logf("Status icon:         shown to members of %s when they log on", strings.Join(names, ", "))
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
