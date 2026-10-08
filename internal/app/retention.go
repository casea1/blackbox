package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
)

// Retention (A9, RET1): with retention_days set, each scheduled report
// removes the report folders whose period ended more than that many days
// ago. A folder's age is its period end, from the report ledger or its
// summary.json, never its modified date: a folder restored from a backup
// is not removed for the date the copy gave it, and one with no readable
// period end is kept. Original logs not yet in a report (the archives
// waiting in archive_dir, the set-aside ones, and those senders delivered)
// are never removed; once older than retention_days they are pointed out.

// reportEnd is the end of the period of the report folder dir: the
// ledger's, or its summary.json's.
func reportEnd(dir string, ledger []store.ReportRecord) (time.Time, bool) {
	for _, r := range ledger {
		if !r.To.IsZero() && sameDir(r.Dir, dir) {
			return r.To, true
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "summary.json"))
	if err != nil {
		return time.Time{}, false
	}
	var s report.Summary
	if err := json.Unmarshal(b, &s); err != nil || s.WindowEnd.IsZero() {
		return time.Time{}, false
	}
	return s.WindowEnd, true
}

// pruneReports removes the report folders in dir whose period ended
// before days ago, and says which.
func pruneReports(dir string, days int, now time.Time, ledger []store.ReportRecord) ([]string, error) {
	if days <= 0 {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var removed []string
	cut := now.AddDate(0, 0, -days)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if _, err := os.Stat(filepath.Join(path, "manifest.sha256")); err != nil {
			continue // only remove folders Blackbox created
		}
		end, ok := reportEnd(path, ledger)
		if !ok || !end.Before(cut) {
			continue // no period end to go by: kept
		}
		if err := os.RemoveAll(path); err != nil {
			return removed, err
		}
		removed = append(removed, e.Name())
	}
	return removed, nil
}

// notOverdue are the waiting archives a scheduled report is taking now:
// those in its bundle, and those it sets aside (said on their own).
func notOverdue(used []string, left []report.LeftOutLogs) map[string]bool {
	skip := map[string]bool{}
	for _, p := range used {
		skip[filepath.Clean(p)] = true
	}
	for _, l := range left {
		skip[filepath.Clean(filepath.Join(filepath.Dir(filepath.Dir(l.SetAside)), filepath.Base(l.SetAside)))] = true
	}
	return skip
}

// overdueLogs are, by computer, the archives of original logs in no
// report whose period ended more than retention_days ago: still waiting
// in archive_dir (or the older folders), or set aside (RET1). They are
// kept; the administrator decides what to do with them.
func (a *App) overdueLogs(now time.Time, skip map[string]bool) []report.OverdueLogs {
	days := a.Cfg.RetentionDays
	if days <= 0 {
		return nil
	}
	cut := now.AddDate(0, 0, -days)
	byHost := map[string]*report.OverdueLogs{}
	waiting := map[string]time.Time{} // the end of each computer's oldest
	var hosts []string
	for _, dir := range a.waitingLogsDirs() {
		for _, pattern := range []string{filepath.Join(dir, "*", "*.zip"), filepath.Join(dir, "*", "set-aside", "*.zip")} {
			matches, _ := filepath.Glob(pattern)
			for _, m := range matches {
				host, from, to, ok := archive.ParseFileName(filepath.Base(m))
				if !ok || !to.Before(cut) || skip[filepath.Clean(m)] {
					continue
				}
				k := strings.ToLower(host)
				o := byHost[k]
				if o == nil {
					o = &report.OverdueLogs{Host: host, From: from, To: to, Dir: filepath.Dir(m)}
					byHost[k], waiting[k] = o, to
					hosts = append(hosts, k)
				}
				o.Archives++
				if from.Before(o.From) {
					o.From, o.Dir, waiting[k] = from, filepath.Dir(m), to
				}
				if to.After(o.To) {
					o.To = to
				}
			}
		}
	}
	sort.Strings(hosts)
	var out []report.OverdueLogs
	for _, k := range hosts {
		o := byHost[k]
		o.Days = int(now.Sub(waiting[k]).Hours() / 24)
		o.RetentionDays = days
		out = append(out, *o)
	}
	return out
}
