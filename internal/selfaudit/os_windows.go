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

// SenderEventID is the Application log event ID for an administrator's
// decision about a sender's signing key: blackbox senders approve, rekey
// or forget (DESIGN1).
const SenderEventID = 102

// systemLog writes msg to the Application log, source Blackbox, with
// eventcreate (part of Windows), which registers the source the first
// time: event 100, or 102 for a sender's key.
func systemLog(msg string, warn, sender bool) error {
	if sender {
		return eventLog(msg, warn, SenderEventID)
	}
	return eventLog(msg, warn, EventID)
}

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
