// Package selfaudit records the changes Blackbox makes to itself (A15):
// a setting written by "blackbox config set" or setup, and Blackbox being
// installed, upgraded or removed. Each is written to Blackbox's own spool,
// so it is in the report like any other event, and to the operating
// system's log, so a copy exists outside Blackbox's folder. The report no
// longer has to infer a change from a command line, which a refused or
// failed command also leaves, and which Windows does not record without
// command-line process auditing.
package selfaudit

import (
	"errors"
	"runtime"
	"sort"
	"time"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// Record writes c to the spool in dataDir and to the operating system's
// log. Both are tried; the first error is returned. A failure never undoes
// the change itself.
func Record(dataDir string, c event.SelfChange, now time.Time) error {
	if c.Who == "" {
		c.Who = Who()
	}
	e := c.Event()
	e.Time, e.Collected = now, now
	e.Host = collect.LocalHost()
	e.OS = runtime.GOOS
	var errs []error
	if st, err := store.Open(dataDir); err != nil {
		errs = append(errs, err)
	} else if err := st.AppendEvents(now, []*event.Event{e}); err != nil {
		errs = append(errs, err)
	}
	if err := systemLog(c.Message(), c.Kind == "setting" || c.Kind == "removed" || c.Kind == "sender_key", c.Kind == "sender_key"); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ReportProblem writes msg, a scheduled report found missing or changed,
// to the operating system's log as a warning (LEDGER4): the Application
// log, source Blackbox, event 101, on Windows; syslog/the journal, ident
// blackbox, on Linux. The report held the only copy of its period's
// original logs, so a copy of the finding outside Blackbox's folder
// survives someone removing that too.
func ReportProblem(msg string) error { return reportLog(msg) }

// Changes compares settings before and after a write and returns one
// SelfChange per setting that changed.
func Changes(before, after map[string]string, program string) []event.SelfChange {
	var out []event.SelfChange
	for _, k := range sortedKeys(before, after) {
		if before[k] != after[k] {
			out = append(out, event.SelfChange{Kind: "setting", Setting: k, Old: before[k], New: after[k], Program: program})
		}
	}
	return out
}

func sortedKeys(maps ...map[string]string) []string {
	seen := map[string]bool{}
	var keys []string
	for _, m := range maps {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}
