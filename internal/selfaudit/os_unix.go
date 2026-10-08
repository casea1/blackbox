//go:build !windows

package selfaudit

import (
	"log/syslog"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Who is the person behind this command: the user who ran sudo, else the
// login user the kernel recorded (auid), else the current user.
func Who() string {
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
		return u
	}
	if b, err := os.ReadFile("/proc/self/loginuid"); err == nil {
		if id, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && id >= 0 && id != 4294967295 {
			if u, err := user.LookupId(strconv.Itoa(id)); err == nil {
				return u.Username
			}
		}
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// systemLog writes msg to syslog/the journal with the ident blackbox (a
// sender's key, too: the message says what it is).
func systemLog(msg string, warn, _ bool) error {
	prio := syslog.LOG_AUTH | syslog.LOG_NOTICE
	if warn {
		prio = syslog.LOG_AUTH | syslog.LOG_WARNING
	}
	w, err := syslog.New(prio, "blackbox")
	if err != nil {
		return err
	}
	defer w.Close()
	if warn {
		return w.Warning(msg)
	}
	return w.Notice(msg)
}

// reportLog writes a warning about a scheduled report to syslog/the
// journal, ident blackbox (LEDGER4).
func reportLog(msg string) error { return systemLog(msg, true, false) }
