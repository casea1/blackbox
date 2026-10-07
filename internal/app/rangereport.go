package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

// ReportRange produces a report for a period chosen by hand, [from, to),
// however far back: from the events Blackbox has collected (kept for
// retention_days, or for good by default) and, for any time before those
// start, from this computer's own event logs, as far back as they still
// reach. Like a manual report it does not change the schedule. It
// returns the report folder.
func (a *App) ReportRange(from, to time.Time) (string, error) {
	if !from.Before(to) {
		return "", fmt.Errorf("the period must start before it ends")
	}
	st, unlock, err := a.open()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := a.gather(st, true); err != nil {
		return "", err
	}
	return a.reportRange(st, from, to)
}

func (a *App) reportRange(st *store.Store, from, to time.Time) (string, error) {
	generated := a.now()
	all, err := st.ReadEvents(from.Add(-contextSpan))
	if err != nil {
		return "", err
	}
	var events []*event.Event
	host := collect.LocalHost()
	var earliest time.Time // this computer's earliest collected event
	for _, e := range all {
		if strings.EqualFold(e.Host, host) && (earliest.IsZero() || e.Time.Before(earliest)) {
			earliest = e.Time
		}
		if !e.Time.Before(from) && e.Time.Before(to) {
			events = append(events, e)
		}
	}
	// Before Blackbox's own copy starts, read this computer's logs.
	fromLogs := 0
	var notes []string
	if gapEnd := earliest; gapEnd.IsZero() || from.Before(gapEnd) {
		if gapEnd.IsZero() || gapEnd.After(to) {
			gapEnd = to
		}
		read := a.readLiveLogs
		if a.LiveLogs != nil {
			read = a.LiveLogs
		}
		old, n, err := read(host, from, gapEnd)
		if err != nil {
			notes = append(notes, "This computer's logs could not be read for the time before Blackbox's copy starts: "+err.Error()+".")
		}
		notes = append(notes, n...)
		for _, e := range old {
			if !e.Time.Before(from) && e.Time.Before(gapEnd) {
				events = append(events, e)
				fromLogs++
			}
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })

	runs, err := st.ReadRuns(from)
	if err != nil {
		return "", err
	}
	latest, err := st.LatestChecks(from.AddDate(0, 0, -7), generated)
	if err != nil {
		return "", err
	}
	var sets []report.CheckSet
	for _, c := range latest {
		cs := report.NewCheckSet(c.Host, c.Time, c.Results)
		cs.Inventory = c.Inventory
		sets = append(sets, cs)
	}
	sort.Slice(sets, func(i, j int) bool { return strings.ToLower(sets[i].Host) < strings.ToLower(sets[j].Host) })

	loc := a.loc()
	rng := fmt.Sprintf("It covers %s to %s.", from.In(loc).Format("2 Jan 2006 15:04"), to.In(loc).Format("2 Jan 2006 15:04"))
	switch {
	case len(events) == 0:
		rng += " No events were found for this period."
	case events[0].Time.Sub(from) > 24*time.Hour:
		rng += " The earliest event still available is from " + events[0].Time.In(loc).Format("2 Jan 2006 15:04") +
			": older events have rolled out of the logs, or were removed after retention_days."
	}
	if fromLogs > 0 {
		rng += fmt.Sprintf(" %s from before Blackbox's own copy were read from %s's event logs.", fmt.Sprintf("%d event%s", fromLogs, plural(fromLogs)), host)
	}
	if len(notes) > 0 {
		rng += " " + strings.Join(notes, " ")
	}
	r := report.Build(events, runs, report.Options{
		Site:        a.Cfg.SiteName,
		WindowStart: from, WindowEnd: to, Generated: generated, Version: a.Version,
		Source: "Live collection", Location: loc, InReportsDir: true, Interim: true, Range: rng, Period: "range",
		History:      report.History(a.ReportsDir(), to, report.HistoryWeeks),
		ExcludeUsers: a.Cfg.ExcludeUsers, ExcludeProcesses: a.Cfg.ExcludeProcesses,
		KnownDevices: st.State.KnownDevices, CheckSets: sets,
		Context: contextEvents(all, events, from), Baseline: st.State.Baseline, BaselineHosts: st.State.BaselineHosts,
		WorkingHours: a.Cfg.WorkingHours,
		Systems:      systemsFor(st, from, a.Cfg.Inbox != ""), Collector: a.Cfg.Inbox != "",
	})
	if len(r.Hosts) == 0 {
		r.Hosts = []string{host}
	}
	dir := report.UniqueDir(a.ReportsDir(), report.DirName(to, a.Cfg.SiteName, r.Hosts, collect.LocalHost(), loc)+"_range")
	if err := r.Write(dir); err != nil {
		return "", err
	}
	a.refreshIndex(st)
	return dir, nil
}

// readLiveLogs reads this computer's own logs for [from, to): it saves
// them as the daily archive does, then translates them.
func (a *App) readLiveLogs(host string, from, to time.Time) ([]*event.Event, []string, error) {
	tmp, err := os.MkdirTemp("", "blackbox-range-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmp)
	sources, notes := archive.Export(tmp, from, to)
	now := a.now()
	var out []*event.Event
	switch runtime.GOOS {
	case "windows":
		for _, s := range sources {
			ev, _, err := collect.FromRaw(func(fn func(*winevt.Raw) error) error { return winevt.ReadFile(s.Path, fn) }, s.Path, now)
			if err != nil {
				notes = append(notes, fmt.Sprintf("%s: %v", s.Source, err))
				continue
			}
			out = append(out, ev...)
		}
	default:
		var audit, syslog []string
		for _, s := range sources {
			if filepath.Base(s.Path) == "audit.log" {
				audit = append(audit, s.Path)
			} else {
				syslog = append(syslog, s.Path)
			}
		}
		if len(audit)+len(syslog) > 0 {
			ev, _, err := collect.LinuxFiles(audit, syslog, host, "/etc/passwd", now)
			if err != nil {
				return nil, notes, err
			}
			out = ev
		}
	}
	var keep []string // only notes about logs that matter here
	for _, n := range notes {
		if !strings.Contains(n, "not on this computer") {
			keep = append(keep, n+".")
		}
	}
	return out, keep, nil
}
