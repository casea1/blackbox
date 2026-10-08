package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/inventory"
	"github.com/casea1/blackbox/internal/store"
)

// SystemInfo is what the data folder knows about one computer (from
// store.System).
type SystemInfo struct {
	Name         string
	OS           string
	Version      string
	Via          string
	FirstSeen    time.Time
	LastRun      time.Time
	LastReceived time.Time
	Former       []string // names it had before (W1b)
	// VM: the system says it is a virtual machine that sends through a
	// VirtualBox shared folder, so on only while its host PC runs it (UI2).
	// Data relayed through another computer (Via) does not make a VM.
	VM bool
}

// CheckSet is the latest audit settings check of one computer.
type CheckSet struct {
	Host             string
	Time             time.Time
	Results          []check.Result
	Pass, Fail, Warn int // audit settings
	// STIGFail and STIGWarn count only the settings a STIG rule requires;
	// Advice counts the others that need a look (Blackbox's advice, with
	// no STIG ID). "Matching the STIG" uses STIGFail (COMP2).
	STIGFail, STIGWarn, Advice int
	AVFail                     int    // antivirus checks failing (counted apart from audit settings)
	Baseline                   string // the STIG compared with, e.g. "Windows 11 STIG V2R11"
	Inventory                  *inventory.Inventory
}

// SystemRow is one computer on the Systems page.
type SystemRow struct {
	SystemInfo
	Runs      int // collection runs in this period
	Events    int
	High      int
	Checks    *CheckSet
	Problems  int    // lost events, cleared logs and read errors
	Status    string // ok | warn | silent
	StatusMsg string
	// AuditOff is why auditing was not running at the last collection in
	// this period ("" when it was).
	AuditOff string
	auditAt  time.Time

	runTimes []time.Time          // collection runs in this period
	gaps     []GapItem            // events lost before they were collected
	resets   []time.Time          // runs that found a log cleared or recreated
	holds    map[string]time.Time // oldest event still in each log, at the last run
	holdsAt  time.Time
	// lastAhead is the latest collection recorded by a clock that was
	// ahead (T1b); LastRunAhead says LastRun is one.
	lastAhead    time.Time
	LastRunAhead bool
}

// OSName is a readable operating system name.
func (s SystemRow) OSName() string {
	switch s.OS {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	}
	return s.OS
}

// expectedInterval is how often computers are expected to collect: the
// default, and the longest interval setup offers.
const expectedInterval = time.Hour

// silentAfter is how long a computer can go without a collection before
// the Systems page points it out, even within a period it did report in.
const silentAfter = 36 * time.Hour

// buildSystems fills in the Systems page: every known computer, what it
// contributed, and whether anything is wrong with its collection.
func (r *Report) buildSystems(runs []*store.Run, events []*event.Event) {
	idx := map[string]*SystemRow{}
	key := store.SystemKey
	get := func(name string) *SystemRow {
		k := key(name)
		if s := idx[k]; s != nil {
			return s
		}
		s := &SystemRow{SystemInfo: SystemInfo{Name: name}}
		idx[k] = s
		return s
	}
	// A collection time ahead of when the report was made was recorded
	// by a clock that was ahead (T1b): the latest collection is the latest
	// one that is not, and only if there is none is it shown, marked.
	ahead := func(t time.Time) bool { return !r.Generated.IsZero() && t.After(r.Generated.Add(5*time.Minute)) }
	for _, info := range r.Systems {
		if !info.FirstSeen.IsZero() && info.FirstSeen.After(r.WindowEnd) && info.LastRun.After(r.WindowEnd) && !ahead(info.LastRun) {
			continue // first seen after this period
		}
		s := get(info.Name)
		s.SystemInfo = info
		if ahead(info.LastRun) {
			s.lastAhead, s.LastRun = info.LastRun, time.Time{}
		}
	}
	for _, run := range runs {
		s := get(run.Host)
		s.Runs++
		if s.OS == "" {
			s.OS = run.OS
		}
		switch {
		case ahead(run.Time):
			if run.Time.After(s.lastAhead) {
				s.lastAhead = run.Time
			}
		case run.Time.After(s.LastRun):
			s.LastRun = run.Time
		}
		if !run.Time.Before(r.WindowStart) && !run.Time.After(r.WindowEnd) {
			s.runTimes = append(s.runTimes, run.Time)
			if !run.Time.Before(s.auditAt) {
				s.auditAt, s.AuditOff = run.Time, run.AuditOff
			}
		}
		for _, c := range run.Channels {
			if c.Gap != nil || c.Reset || c.Error != "" {
				s.Problems++
			}
			if c.Gap != nil {
				s.gaps = append(s.gaps, GapItem{Host: run.Host, Channel: c.Channel, Lost: c.Gap.Lost, From: c.Gap.From, To: c.Gap.To, Note: c.Gap.Note})
			}
			if c.Reset {
				s.resets = append(s.resets, run.Time)
			}
			if !c.OldestTime.IsZero() && !run.Time.Before(s.holdsAt) {
				if s.holds == nil || run.Time.After(s.holdsAt) {
					s.holds, s.holdsAt = map[string]time.Time{}, run.Time
				}
				s.holds[c.Channel] = c.OldestTime
			}
		}
	}
	for _, s := range idx {
		if s.LastRun.IsZero() && !s.lastAhead.IsZero() {
			s.LastRun, s.LastRunAhead = s.lastAhead, true
		}
	}
	// Events and checks count towards a computer that collects. An event
	// recorded under another name (a former name of a renamed or cloned
	// computer) does not make a new system, so it cannot be reported as
	// silent; it still appears in every table under its own name.
	for _, e := range events {
		s := idx[key(e.Host)]
		if s == nil {
			continue
		}
		s.Events++
		if e.Severity == event.SevHigh {
			s.High++
		}
		if s.OS == "" {
			s.OS = e.OS
		}
	}
	for i := range r.CheckSets {
		cs := &r.CheckSets[i]
		if s := idx[key(cs.Host)]; s != nil {
			s.Checks = cs
		}
	}

	live := r.Source == "" || strings.HasPrefix(r.Source, "Live")
	for _, s := range idx {
		s.Status = "ok"
		vm := s.VM
		switch {
		case !live:
		case vm && s.Runs == 0:
			// A VM is on only part of the time, but one that sent nothing
			// all period is worth a look (UI2).
			s.Status = "warn"
			if s.LastRun.IsZero() {
				s.StatusMsg = "Worth a look: nothing received from this virtual machine yet."
			} else {
				s.StatusMsg = fmt.Sprintf("Worth a look: nothing received since %s. A virtual machine sends only while it is on.", r.since(s.LastRun))
			}
		case s.Runs == 0 && r.WindowEnd.Sub(r.PeriodStart()) <= 2*expectedInterval && !s.LastRun.IsZero():
			// A short report (an interim one run by hand) can end before a
			// computer's next collection is due; that is not silence.
			s.StatusMsg = fmt.Sprintf("No collection in this short period yet. Last collection: %s.", r.stamp(s.LastRun))
		case s.Runs == 0:
			s.Status = "silent"
			if s.LastRun.IsZero() {
				s.StatusMsg = "No collection has been received from this computer yet."
			} else {
				s.StatusMsg = fmt.Sprintf("No collection received in this period. Last collection: %s (%s before the end of this report).",
					r.stamp(s.LastRun), roughDuration(r.WindowEnd.Sub(s.LastRun)))
			}
			s.StatusMsg += " It may have been switched off, or it cannot reach the collector."
		case s.AuditOff != "":
			s.Status = "warn"
			s.StatusMsg = fmt.Sprintf("Auditing was off at the last collection (%s): %s.", r.stamp(s.auditAt), s.AuditOff)
		case !vm && r.WindowEnd.Sub(s.LastRun) > silentAfter:
			s.Status = "warn"
			s.StatusMsg = fmt.Sprintf("Last collection %s, %s before the end of this report.", r.stamp(s.LastRun), roughDuration(r.WindowEnd.Sub(s.LastRun)))
		case s.Problems > 0:
			s.Status = "warn"
			s.StatusMsg = "Collection problems in this period; see Audit health."
		case s.Checks != nil && s.Checks.AVFail > 0 && s.Checks.Fail == 0:
			s.Status = "warn"
			s.StatusMsg = "Antivirus definitions are out of date, or real-time protection is off."
		case s.Checks != nil && s.Checks.Fail > 0:
			s.Status = "warn"
			s.StatusMsg = fmt.Sprintf("%d audit settings need attention.", s.Checks.Fail)
			if s.Checks.Fail == 1 {
				s.StatusMsg = "1 audit setting needs attention."
			}
		}
		r.SystemRows = append(r.SystemRows, *s)
	}
	rank := map[string]int{"silent": 0, "warn": 1, "ok": 2}
	sort.Slice(r.SystemRows, func(i, j int) bool {
		a, b := r.SystemRows[i], r.SystemRows[j]
		if rank[a.Status] != rank[b.Status] {
			return rank[a.Status] < rank[b.Status]
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})

	// Every computer is listed in the report, including one with no events.
	have := map[string]bool{}
	for _, h := range r.Hosts {
		have[key(h)] = true
	}
	for _, s := range r.SystemRows {
		if !have[key(s.Name)] {
			r.Hosts = append(r.Hosts, s.Name)
			have[key(s.Name)] = true
		}
		if s.Status == "silent" {
			r.Silent = append(r.Silent, s)
		}
		if s.AuditOff != "" {
			r.Health.AuditOff = append(r.Health.AuditOff, fmt.Sprintf("%s: auditing was not running at the collection at %s (%s).",
				s.Name, r.stamp(s.auditAt), s.AuditOff))
			r.Health.Warnings = append(r.Health.Warnings, s.Name+": "+s.StatusMsg)
		}
	}
	sort.Slice(r.Hosts, func(i, j int) bool { return strings.ToLower(r.Hosts[i]) < strings.ToLower(r.Hosts[j]) })
}

// ShowSystems reports whether the Systems page is useful: more than one
// computer, or this is a collector.
func (r *Report) ShowSystems() bool { return len(r.SystemRows) > 1 || r.Collector }

// SystemsNeedingAttention counts computers that are silent or have
// warnings.
func (r *Report) SystemsNeedingAttention() int {
	n := 0
	for _, s := range r.SystemRows {
		if s.Status != "ok" {
			n++
		}
	}
	return n
}

// NewCheckSet summarises one computer's audit settings check.
func NewCheckSet(host string, at time.Time, rs []check.Result) CheckSet {
	cs := CheckSet{Host: host, Time: at, Results: rs}
	var audit []check.Result
	for _, r := range rs {
		if r.Area == "Antivirus" {
			if r.Status == check.Fail {
				cs.AVFail++
			}
			continue
		}
		audit = append(audit, r)
	}
	cs.Pass, cs.Fail, cs.Warn = check.Summary(audit)
	for _, r := range audit {
		if r.Area == "Baseline" || (r.Status != check.Fail && r.Status != check.Error && r.Status != check.Warn) {
			continue
		}
		switch {
		case r.IsAdvice():
			cs.Advice++
		case r.Status == check.Warn:
			cs.STIGWarn++
		default:
			cs.STIGFail++
		}
	}
	for _, r := range rs {
		if r.Area == "Baseline" {
			cs.Baseline = r.Have
		}
	}
	// Settings that need attention first.
	sort.SliceStable(cs.Results, func(i, j int) bool {
		return (cs.Results[i].Status != check.Pass) && (cs.Results[j].Status == check.Pass)
	})
	return cs
}
