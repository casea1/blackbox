package app

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/rollover"
	"github.com/casea1/blackbox/internal/store"
)

// Health is what the status icon shows: whether collection is running on
// schedule, and anything that needs looking at. It reads the same state
// as "blackbox status".
type Health struct {
	Role        string
	ReportEvery string // daily, weekly or monthly
	Every       time.Duration
	LastCollect time.Time
	LastRun     LastRun
	NextReport  time.Time // zero when one is due at the next run
	PeriodStart time.Time // start of the current report period

	ReportsDir string
	Latest     *report.IndexEntry // newest report, if any

	AuditGaps map[string]int // host → audit settings that don't match the STIG
	AVOld     []string       // hosts whose antivirus (Defender or ClamAV) definitions are out of date
	Quiet     map[string]time.Time
	Rejected  int // files set aside in the inbox
	// Unreadable are the files in the inbox that can't be read (L9).
	Unreadable []string
	// WaitingSince is when the oldest data still waiting to be sent was
	// queued, and LowSpace the data folder's disk when nearly full (L10).
	WaitingSince time.Time
	LowSpace     string

	// AuditOff lists the systems whose last collection found auditing not
	// running, and why (host → reason).
	AuditOff map[string]string

	// Lost lists the logs that overwrote events before they could be
	// collected, since the last report.
	Lost []LostLog

	// Blocked is set while scheduled runs are refused because a run has
	// held the lock past their wait (LOCK1).
	Blocked *store.Blocked

	// MissingReports are scheduled reports deleted, moved or changed since
	// they were written, and not accepted (the report ledger).
	MissingReports []report.MissingReport
}

// LostLog is one log losing events to rollover.
type LostLog struct {
	rollover.Loss
	Count uint64    // events lost since the last report
	Since time.Time // the first loss in this period
}

// LastRun is the outcome of the last scheduled run.
type LastRun struct {
	Time  time.Time `json:"time"`
	Error string    `json:"error,omitempty"`
}

func lastRunPath(dataDir string) string { return filepath.Join(dataDir, "last-run.json") }

// lostSince adds up the events each log overwrote before they could be
// collected, since start (or the last week when there is no report yet),
// with how long each log held when it turned over and how often its
// system collects (LOG1): every is this computer's collect_every.
func lostSince(st *store.Store, start, now time.Time, every time.Duration) []LostLog {
	if start.IsZero() {
		start = now.AddDate(0, 0, -7)
	}
	runs, err := st.ReadRuns(start)
	if err != nil {
		return nil
	}
	by := map[string]*LostLog{}
	var order []string
	times := map[string][]time.Time{}
	for _, r := range runs {
		hk := store.SystemKey(r.Host)
		times[hk] = append(times[hk], r.Time)
		for _, c := range r.Channels {
			if c.Gap == nil || c.Gap.Lost == 0 {
				continue
			}
			k := hk + "|" + c.Channel
			l := by[k]
			if l == nil {
				l = &LostLog{Loss: rollover.Loss{Host: r.Host, Channel: c.Channel}, Since: r.Time}
				by[k] = l
				order = append(order, k)
			}
			l.Count += c.Gap.Lost
			l.Lost = l.Count
			if r.Time.Before(l.Since) {
				l.Since = r.Time
			}
			// How far back the full log reached when it turned over: the
			// shortest is the fastest it was written.
			if !c.OldestTime.IsZero() && r.Time.After(c.OldestTime) {
				if held := r.Time.Sub(c.OldestTime); l.Held == 0 || held < l.Held {
					l.Held, l.MaxSize = held, c.MaxSizeBytes
				}
			}
		}
	}
	self := store.SystemKey(collect.LocalHost())
	out := make([]LostLog, 0, len(order))
	for _, k := range order {
		l := by[k]
		hk := store.SystemKey(l.Host)
		if hk == self && every > 0 {
			l.Every = every
		} else {
			l.Every = rollover.Interval(times[hk])
		}
		out = append(out, *l)
	}
	// The audit record first (High), then the other logs.
	sort.SliceStable(out, func(i, j int) bool { return rollover.Critical(out[i].Channel) && !rollover.Critical(out[j].Channel) })
	return out
}

// auditOffNow finds the systems whose latest collection (in the last
// eight days) found auditing not running.
func auditOffNow(st *store.Store, now time.Time) map[string]string {
	out := map[string]string{}
	runs, err := st.ReadRuns(now.AddDate(0, 0, -8))
	if err != nil {
		return out
	}
	latest := map[string]*store.Run{}
	for _, r := range runs {
		k := store.SystemKey(r.Host)
		if l := latest[k]; l == nil || !r.Time.Before(l.Time) {
			latest[k] = r
		}
	}
	for _, r := range latest {
		if r.AuditOff != "" {
			out[r.Host] = r.AuditOff
		}
	}
	return out
}

// RecordRun notes the outcome of a scheduled run, for the status icon.
func (a *App) RecordRun(err error) {
	r := LastRun{Time: a.now()}
	if err != nil {
		r.Error = err.Error()
	}
	b, _ := json.Marshal(r)
	store.WriteFileAtomic(lastRunPath(a.Cfg.DataDir), b, 0o640)
}

// Health reads the current state.
func (a *App) Health() (Health, error) {
	h := Health{Role: a.Cfg.Role(), ReportEvery: a.Cfg.ReportEvery, Every: a.Cfg.CollectEvery, AuditGaps: map[string]int{}, Quiet: map[string]time.Time{},
		AuditOff: map[string]string{}}
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return h, err
	}
	now := a.now()
	s := st.State
	h.LastCollect = s.LastCollect
	if b, err := os.ReadFile(lastRunPath(a.Cfg.DataDir)); err == nil {
		json.Unmarshal(b, &h.LastRun)
	}
	h.AuditOff = auditOffNow(st, now)
	h.WaitingSince = a.waitingSince(st)
	h.LowSpace = lowSpace(a.Cfg.DataDir)
	h.Blocked = blockedNow(a.Cfg.DataDir, st)
	if !a.Cfg.MakesReports() {
		return h, nil
	}
	h.ReportsDir = a.Cfg.ReportsDir()
	h.MissingReports = reportProblems(st)
	h.NextReport, _ = nextReport(a.Cfg.ReportEvery, a.Cfg.ReportAt, s.LastWindowEnd, now, a.loc())
	h.PeriodStart = s.LastWindowEnd
	if l, ok := report.Latest(h.ReportsDir); ok {
		h.Latest = &l
	}
	h.Lost = lostSince(st, h.PeriodStart, now, a.Cfg.CollectEvery)

	// Audit settings: the latest check of each system.
	if checks, err := st.LatestChecks(now.AddDate(0, 0, -8), now); err == nil {
		for _, c := range checks {
			for _, r := range c.Results {
				if r.Status != check.Fail {
					continue
				}
				if r.Area == "Antivirus" {
					h.AVOld = append(h.AVOld, c.Host)
				} else if r.Area != "Baseline" {
					h.AuditGaps[c.Host]++
				}
			}
		}
		sort.Strings(h.AVOld)
	}

	// A system is quiet once nothing has arrived from it in the current
	// report period for 36 hours, the same as the report's "silent": a
	// virtual machine that is off part of the week is not flagged.
	if !h.PeriodStart.IsZero() && now.Sub(h.PeriodStart) > silentAfter {
		for _, sys := range s.Systems {
			if sys.Removed.IsZero() && !sys.LastRun.IsZero() && sys.LastRun.Before(h.PeriodStart) {
				h.Quiet[sys.Name] = sys.LastRun
			}
		}
	}
	// A computer that is no longer a collector shows only itself, though
	// the data it once received is still kept.
	if a.Cfg.Inbox == "" {
		self := store.SystemKey(collect.LocalHost())
		mine := func(h string) bool { return store.SystemKey(h) == self }
		for host := range h.AuditGaps {
			if !mine(host) {
				delete(h.AuditGaps, host)
			}
		}
		h.AVOld = slices.DeleteFunc(h.AVOld, func(x string) bool { return !mine(x) })
		maps.DeleteFunc(h.AuditOff, func(x, _ string) bool { return !mine(x) })
		h.Quiet = map[string]time.Time{}
		h.Lost = slices.DeleteFunc(h.Lost, func(l LostLog) bool { return !mine(l.Host) })
	}
	if a.Cfg.Inbox != "" {
		if rej, _ := filepath.Glob(filepath.Join(a.Cfg.Inbox, "rejected", "*")); len(rej) > 0 {
			h.Rejected = len(rej)
		}
		h.Unreadable = lan.Unreadable(a.Cfg.Inbox)
	}
	return h, nil
}
