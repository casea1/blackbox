//go:build !windows && !linux

package install

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"time"
)

var errLinux = errors.New("install is supported on Windows and Linux; on this system use `blackbox report` with exported log files")

// ProgramPath is where install copies the executable.
func ProgramPath() string { return "/usr/local/bin/blackbox" }

// Install is only available on Windows and Linux.
func Install(Options) error { return errLinux }

// Uninstall is only available on Windows and Linux.
func Uninstall(func(string, ...any)) error { return errLinux }

func afterReportDirChange(func(string, ...any)) error { return nil }

func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }

// RequireAdmin is not needed where Blackbox cannot be installed.
func RequireAdmin() error { return errLinux }

const isWindows = false

// ShareName is the conventional name of a collector's inbox share.
const ShareName = "BlackboxInbox"

// DefaultInbox is the suggested inbox folder for a collector.
func DefaultInbox() string { return "/var/lib/blackbox/inbox" }

// FindInboxes lists collector inboxes this computer can already see.
func FindInboxes() []string { return nil }

// TryInbox is only available on Windows and Linux.
func TryInbox(sendTo, user, pw string) error { return errLinux }

func readPassword(r *bufio.Reader) (string, error) {
	s, err := r.ReadString('\n')
	return strings.TrimRight(s, "\r\n"), err
}

func prepareInbox(Options, func(string, ...any)) error          { return errLinux }
func removeInbox(func(string, ...any))                          {}
func prepareSendTo(Options, string, func(string, ...any)) error { return errLinux }
func removeSendTo(func(string, ...any))                         {}

// InboxShared is always false here.
func InboxShared() bool { return false }

// The status icon is Windows only.

// TrayWanted is always false here.
func TrayWanted() bool { return false }

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

// RefreshSchedule has nothing to do here: systemd timers follow the clock
// when it changes (T1).
func RefreshSchedule(time.Duration) error { return nil }
