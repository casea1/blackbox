package collect

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// checkRemoved notes, on a command that deletes Blackbox's files, which
// of the files it names are gone and which are still there now, at the
// run that collects it (DET1b). When the audit log has only the command
// line (no record of the delete itself, such as a share mounted over
// CIFS with no watch rules), a file gone is what shows the delete worked.
// A file gone from a folder Blackbox moves files out of itself (moved:
// the inbox, the original logs waiting) shows nothing, and a pattern
// that matches nothing is not known either way.
// lstat and glob are the file system, replaced in tests.
var (
	lstat = os.Lstat
	glob  = filepath.Glob
)

func checkRemoved(e *event.Event, moved []string) {
	if e.Action != "blackbox_files_removed" {
		return
	}
	var gone, there, movedGone []string
	for _, p := range event.RemoveTargets(firstNonEmpty(e.Command, detailOf(e, "Command line"))) {
		if strings.ContainsAny(p, "*?[") {
			if m, _ := glob(p); len(m) > 0 {
				there = append(there, p)
			}
			continue
		}
		_, err := lstat(p)
		switch {
		case err == nil:
			there = append(there, p)
		case !os.IsNotExist(err):
		case under(p, moved):
			movedGone = append(movedGone, p)
		default:
			gone = append(gone, p)
		}
	}
	set := func(k string, v []string) {
		if len(v) == 0 {
			return
		}
		if e.Fields == nil {
			e.Fields = map[string]string{}
		}
		e.Fields[k] = strings.Join(v, "\n")
	}
	set(event.RemovedGone, gone)
	set(event.RemovedThere, there)
	set(event.RemovedMoved, movedGone)
}

// under reports whether p is in one of the folders dirs, or is one.
func under(p string, dirs []string) bool {
	clean := func(s string) string {
		s = filepath.Clean(s)
		if filepath.Separator == '\\' {
			s = strings.ToLower(s)
		}
		return s
	}
	p = clean(p)
	for _, d := range dirs {
		if d == "" {
			continue
		}
		d = clean(d)
		if p == d || strings.HasPrefix(p, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func detailOf(e *event.Event, label string) string {
	for _, d := range e.Details {
		if d.Label == label {
			return d.Value
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
