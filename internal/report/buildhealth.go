// Audit health: collection runs, logs, gaps and the busiest event IDs.

package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/linuxlog"
	"github.com/casea1/blackbox/internal/rollover"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

func (r *Report) buildHealth(runs []*store.Run, events []*event.Event) {
	h := &r.Health
	for _, cs := range r.CheckSets {
		h.ChecksPass += cs.Pass
		h.ChecksFail += cs.Fail
		h.ChecksWarn += cs.Warn
	}
	for _, e := range events {
		if e.Action == "log_cleared" {
			h.LogClears++
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].Time.Before(runs[j].Time) })
	chIdx := map[string]*ChannelHealth{}
	var chOrder []string
	vol := map[string]*VolumeRow{}
	lastRun := map[string]time.Time{} // by host, for gaps between runs
	pause := map[string]time.Duration{}
	times := map[string][]time.Time{} // by host, for how often it collects
	for _, run := range runs {
		h.Runs++
		if h.FirstRun.IsZero() {
			h.FirstRun = run.Time
		}
		h.LastRun = run.Time
		hk := store.SystemKey(run.Host)
		if prev, ok := lastRun[hk]; ok {
			if p := run.Time.Sub(prev); p > pause[hk] {
				pause[hk] = p
			}
			if p := run.Time.Sub(prev); p > h.LongestPause {
				h.LongestPause = p
			}
		}
		lastRun[hk] = run.Time
		times[hk] = append(times[hk], run.Time)
		if b := run.Blocked; b != nil {
			to := b.Until
			if to.IsZero() {
				to = run.Time
			}
			h.Blocked = append(h.Blocked, BlockedItem{Host: run.Host, From: b.First, To: to, Since: b.Holder.Since, PID: b.Holder.PID, Refused: b.Refused})
		}
		for _, c := range run.Channels {
			k := run.Host + "|" + c.Channel
			ch := chIdx[k]
			if ch == nil {
				ch = &ChannelHealth{Host: run.Host, Channel: c.Channel}
				chIdx[k] = ch
				chOrder = append(chOrder, k)
			}
			ch.Runs++
			ch.Read += c.Read
			ch.Kept += c.Kept
			h.TotalRead += c.Read
			h.TotalKept += c.Kept
			ch.Unavailable = c.Unavailable
			if c.Error != "" {
				ch.LastError = c.Error
			}
			if !c.OldestTime.IsZero() {
				ch.History = run.Time.Sub(c.OldestTime)
			}
			if c.MaxSizeBytes > 0 {
				ch.MaxSize = c.MaxSizeBytes
			}
			if c.Gap != nil {
				ch.Lost += c.Gap.Lost
				g := GapItem{Host: run.Host, Channel: c.Channel, Lost: c.Gap.Lost, From: c.Gap.From, To: c.Gap.To, Note: c.Gap.Note, MaxSize: c.MaxSizeBytes}
				if !c.OldestTime.IsZero() && run.Time.After(c.OldestTime) {
					g.Held = run.Time.Sub(c.OldestTime)
				}
				h.Gaps = append(h.Gaps, g)
			}
			if c.Reset {
				ch.Resets++
				h.Gaps = append(h.Gaps, GapItem{Host: run.Host, Channel: c.Channel, Reset: true, To: run.Time})
			}
			for id, n := range c.EventCounts {
				vk := c.Channel + "|" + strconv.Itoa(id)
				v := vol[vk]
				if v == nil {
					v = &VolumeRow{Channel: c.Channel, EventID: id}
					if c.Channel == "Security" || c.Channel == "System" {
						v.Name = winevt.EventNames[id]
					}
					vol[vk] = v
				}
				v.Count += n
			}
			for typ, n := range c.TypeCounts {
				vk := c.Channel + "|" + typ
				v := vol[vk]
				if v == nil {
					v = &VolumeRow{Channel: c.Channel, Type: typ, Name: linuxlog.RecordTypeNames[typ]}
					vol[vk] = v
				}
				v.Count += n
			}
		}
	}
	for _, k := range chOrder {
		h.Channels = append(h.Channels, *chIdx[k])
	}
	for i := range h.Gaps {
		h.Gaps[i].Every = rollover.Interval(times[store.SystemKey(h.Gaps[i].Host)])
	}
	for _, v := range vol {
		if h.TotalRead > 0 {
			v.Percent = 100 * float64(v.Count) / float64(h.TotalRead)
		}
		h.Volume = append(h.Volume, *v)
	}
	sort.Slice(h.Volume, func(i, j int) bool {
		if h.Volume[i].Count != h.Volume[j].Count {
			return h.Volume[i].Count > h.Volume[j].Count
		}
		if h.Volume[i].EventID != h.Volume[j].EventID {
			return h.Volume[i].EventID < h.Volume[j].EventID
		}
		return h.Volume[i].Type < h.Volume[j].Type
	})
	if len(h.Volume) > 12 {
		h.Volume = h.Volume[:12]
	}

	// Plain-language warnings.
	for _, m := range r.MissingReports {
		what := "is missing (deleted or moved)"
		if m.Problem == "changed" {
			what = "was changed after it was written"
			if m.What != "" {
				what += " (" + m.What + ")"
			}
		}
		text := fmt.Sprintf("The scheduled report %s (%s to %s) %s", m.Name, r.stamp(m.From), r.stamp(m.To), what)
		if m.LostLogs() {
			text += ": it held the only copy of that period's original logs"
		}
		h.Warnings = append(h.Warnings, text+".")
	}
	for _, b := range h.Blocked {
		h.Warnings = append(h.Warnings, BlockedText(b, r.stamp))
	}
	for _, g := range h.Gaps {
		if g.Note != "" {
			h.Warnings = append(h.Warnings, fmt.Sprintf("%s: %s: %s (since %s).", g.Host, g.Channel, g.Note, r.stamp(g.From)))
			continue
		}
		if g.Reset {
			h.Warnings = append(h.Warnings, fmt.Sprintf("%s: the %s log was cleared or recreated before %s; events in it that had not yet been collected are gone.", g.Host, g.Channel, r.stamp(g.To)))
			continue
		}
		h.Warnings = append(h.Warnings, fmt.Sprintf("%s on %s: %s events were overwritten before Blackbox could collect them (between %s and %s). %s",
			rollover.Name(g.Channel), g.Host, commas(g.Lost), r.stamp(g.From), r.stamp(g.To), g.Loss().Advice(false)))
	}
	for _, ch := range h.Channels {
		if ch.LastError != "" {
			h.Warnings = append(h.Warnings, fmt.Sprintf("%s: could not read the %s log: %s", ch.Host, ch.Channel, ch.LastError))
		}
		if ch.Channel == "Security" && ch.History > 0 && ch.History < 24*time.Hour {
			h.Warnings = append(h.Warnings, fmt.Sprintf("%s: the Security log only holds about %s of history. Hourly collection keeps up, but if collection stops for longer than that, events will be lost. Increasing the log size is recommended.",
				ch.Host, roughDuration(ch.History)))
		}
	}
	if r.Source == "" || strings.HasPrefix(r.Source, "Live") {
		if h.Runs == 0 && len(r.Systems) <= 1 {
			h.Warnings = append(h.Warnings, "No collection runs were recorded in this period.")
		}
		hosts := make([]string, 0, len(pause))
		for k := range pause {
			hosts = append(hosts, k)
		}
		sort.Strings(hosts)
		for _, k := range hosts {
			if p := pause[k]; p > 6*time.Hour {
				who := "The"
				if len(lastRun) > 1 {
					who = k + ": the"
				}
				h.Warnings = append(h.Warnings, fmt.Sprintf("%s longest time between collections was %s (the computer may have been off, or the scheduled task did not run).", who, roughDuration(p)))
			}
		}
	}
	h.Warnings = append(h.Warnings, r.LANWarnings...)
}

// BlockedText describes a gap in collection while a run held the lock.
func BlockedText(b BlockedItem, stamp func(time.Time) string) string {
	return fmt.Sprintf("%s: collection was blocked from %s to %s: a run (PID %d, started %s) held Blackbox's lock, so %s collected nothing. "+
		"The next run collected what the logs still held; anything they overwrote in that time is listed as lost.",
		b.Host, stamp(b.From), stamp(b.To), b.PID, stamp(b.Since), plural(b.Refused, "scheduled run"))
}
