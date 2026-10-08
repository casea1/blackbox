package report

import (
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// refusedRemove is a command that would have deleted Blackbox's files
// but that the operating system refused (DET1). It is Medium, it is not
// a removal (no "Blackbox's files removed" detection, no covering of
// tracks), and it is listed apart from the deletes that happened.
const refusedRemove = "blackbox_files_remove_refused"

// refusedDeletes re-reads a command that deletes Blackbox's files ("rm
// /var/lib/blackbox/…", "del C:\ProgramData\Blackbox\…") as an attempt
// when the delete itself failed: the command's own record says so
// (outcome failure), or the audit records of the same process show the
// operating system refusing it (Linux: the unlink with success=no and a
// non-zero exit, by the program or the one sudo started; Windows: 4656 or
// 4663 audit failures by the same process ID) and none of them shows a
// file of Blackbox's deleted or changed. The refusals are kept in the
// command's row as details, not as rows of their own.
func refusedDeletes(events []*event.Event) []*event.Event {
	var refusals, changes []*event.Event
	for _, e := range events {
		switch {
		case (e.Action == "file_access_denied" || e.Action == "file_change_failed") && e.Outcome == "failure" && event.BlackboxPath(e.Target):
			refusals = append(refusals, e)
		case (e.Action == "blackbox_files_changed" || e.Action == "blackbox_config_changed" || e.Action == "blackbox_stopped") &&
			e.Fields[event.SelfFlag] == "" && e.Outcome != "failure":
			changes = append(changes, e)
		}
	}
	drop := map[*event.Event]bool{}
	for _, c := range events {
		if c.Action != "blackbox_files_removed" {
			continue
		}
		var refused []*event.Event
		for _, x := range refusals {
			if sameAttempt(c, x) {
				refused = append(refused, x)
			}
		}
		if c.Outcome != "failure" && len(refused) == 0 {
			continue
		}
		did := false
		for _, x := range changes {
			if sameAttempt(c, x) {
				did = true // it deleted something: still a removal
				break
			}
		}
		if did {
			continue
		}
		markRefused(c, refused)
		for _, x := range refused {
			drop[x] = true
		}
	}
	if len(drop) == 0 {
		return events
	}
	out := events[:0]
	for _, e := range events {
		if !drop[e] {
			out = append(out, e)
		}
	}
	return out
}

// sameAttempt reports whether x, a file record, is the work of the
// command c: the same computer, within a minute after it, and the same
// process (or, on Linux, the program sudo started for it). Records with
// no process IDs are matched by person and by the file being named in
// the command.
func sameAttempt(c, x *event.Event) bool {
	if !strings.EqualFold(c.Host, x.Host) || x.Time.Before(c.Time.Add(-2*time.Second)) || x.Time.After(c.Time.Add(time.Minute)) {
		return false
	}
	cp, xp, xpp := processIDs(c, x)
	if cp != "" && xp != "" {
		return xp == cp || xpp == cp
	}
	if c.User == "" || !strings.EqualFold(c.User, x.User) {
		return false
	}
	cmd := strings.ToLower(firstNonEmpty(c.Command, detail(c, "Command"), detail(c, "Command line")))
	for _, p := range strings.Split(x.Target, ", ") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" && strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

// processIDs are the command's process ID and the file record's process
// and parent process IDs, from the original records: auditd's pid and
// ppid; Windows' NewProcessId of a 4688 and ProcessId of a 4656 or 4663.
func processIDs(c, x *event.Event) (cmd, pid, ppid string) {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	if c.OS == "windows" {
		return norm(c.Fields["NewProcessId"]), norm(x.Fields["ProcessId"]), ""
	}
	return norm(c.Fields["pid"]), norm(x.Fields["pid"]), norm(x.Fields["ppid"])
}

func markRefused(c *event.Event, refused []*event.Event) {
	what := event.FilesRemoveRefused
	denied := len(refused) == 0 // the command's own record failed
	for _, x := range refused {
		if x.Action == "file_access_denied" {
			denied = true
		}
	}
	if !denied {
		what = "tried to delete Blackbox's files (failed)"
	}
	if strings.Contains(c.Summary, " "+event.FilesRemoved+": ") {
		c.Summary = strings.Replace(c.Summary, " "+event.FilesRemoved+": ", " "+what+": ", 1)
	} else {
		c.Summary = orUnknown(c.User) + " " + what + ": " + firstNonEmpty(c.Command, detail(c, "Command line"), detail(c, "Command"))
	}
	c.Action, c.Severity, c.Outcome = refusedRemove, event.SevMedium, "failure"
	c.DedupeKey = "refused|" + c.DedupeKey
	for _, x := range refused {
		r := firstNonEmpty(detail(x, "Result"), "refused")
		c.AddDetail("Refused", x.Target+" ("+r+")")
	}
	c.AddDetail("Not a removal", "The operating system refused the delete, so Blackbox's files are still there.")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
