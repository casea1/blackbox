//go:build windows

package selfaudit

import (
	"fmt"
	"os/user"
	"strings"

	"github.com/casea1/blackbox/internal/hidden"
)

// Who is the account running this (elevated) command: its token user.
func Who() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// EventID is the Application log event ID Blackbox writes its own changes
// under (source Blackbox).
const EventID = 100

// ReportEventID is the Application log event ID for a scheduled report
// found missing or changed (LEDGER4), a warning.
const ReportEventID = 101

// systemLog writes msg to the Application log, source Blackbox, with
// eventcreate (part of Windows), which registers the source the first time.
func systemLog(msg string, warn bool) error { return eventLog(msg, warn, EventID) }

func reportLog(msg string) error { return eventLog(msg, true, ReportEventID) }

func eventLog(msg string, warn bool, id int) error {
	typ := "INFORMATION"
	if warn {
		typ = "WARNING"
	}
	out, err := hidden.Command("eventcreate.exe", "/L", "APPLICATION", "/SO", "Blackbox", "/T", typ,
		"/ID", fmt.Sprint(id), "/D", msg).CombinedOutput()
	if err != nil {
		return fmt.Errorf("eventcreate: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
