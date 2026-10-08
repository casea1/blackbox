// Package collect reads new events from the live logs, keeps the
// security-relevant ones in the spool, and advances bookmarks.
//
// Collection is designed to run often (hourly by default) so events are
// captured before a busy log overwrites them. Only translated events are
// stored, so the spool stays small even when a log receives millions of
// routine events a day.
package collect

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

// flushEvery bounds memory use on the first run against a large log.
const flushEvery = 10000

// Options control a collection run.
type Options struct {
	Version string
	Now     func() time.Time
	Logf    func(format string, args ...any)
	// Blocked is collection refused since the last run (LOCK1), recorded
	// with this run.
	Blocked *store.Blocked
	// MovedBy are the folders Blackbox moves files out of itself (the
	// inbox, the original logs waiting): a file gone from one does not
	// show that a command deleted it (DET1b).
	MovedBy []string
}

// LocalHost is the name this system's events and runs are recorded under:
// the upper-case computer name on Windows, the short host name on Linux.
func LocalHost() string {
	host, _ := os.Hostname()
	if runtime.GOOS == "windows" {
		return strings.ToUpper(host)
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	return host
}

// OnThisComputer files an event read from this computer's own logs under
// its current name (W1). Windows records the name at the time, so events
// from before it was renamed (a new server's WIN-XXXXXXXX name from before
// setup finished) would otherwise look like another computer.
func OnThisComputer(e *event.Event, host string) {
	short := func(h string) string {
		h, _, _ = strings.Cut(strings.TrimSpace(h), ".")
		return strings.ToUpper(h)
	}
	if e.Host == "" || short(e.Host) == short(host) {
		e.Host = host
		return
	}
	e.AddDetail("Recorded under", "its former name "+e.Host)
	e.Host = host
}

// Live collects from this system's logs: the Windows event logs, or the
// Linux audit and system logs.
func Live(st *store.Store, opt Options) (*store.Run, error) {
	switch runtime.GOOS {
	case "windows":
		return Windows(st, opt)
	case "linux":
		return Linux(st, opt)
	}
	return nil, fmt.Errorf("live collection is not supported on %s", runtime.GOOS)
}

// Windows collects from the live Windows event logs.
func Windows(st *store.Store, opt Options) (*store.Run, error) {
	if !winevt.Supported {
		return nil, errors.New("live collection is only available on Windows in this version (Linux support is next); use `blackbox report --xml` to report on exported logs")
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	start := opt.Now()
	host := LocalHost()

	tr := winevt.NewTranslator()
	tr.ResolveSID = winevt.LookupSID
	tr.MapDevicePath = winevt.DevicePathMapper()

	run := &store.Run{Time: start, Host: host, OS: runtime.GOOS, Version: opt.Version}
	clears := map[string]*event.Event{}
	for _, ch := range winevt.Channels {
		cr := collectChannel(st, tr, host, ch, start, opt, clears)
		run.Channels = append(run.Channels, cr)
	}
	ClearedNotLost(run, clears, opt.Logf)
	LogOverwritten(run, opt.Logf)
	run.Duration = opt.Now().Sub(start).Seconds()
	if b := opt.Blocked; b != nil {
		b.Until = start
		run.Blocked = b
	}
	st.State.LastCollect = start
	if err := st.AppendRun(run); err != nil {
		return run, err
	}
	return run, st.Save()
}

func collectChannel(st *store.Store, tr *winevt.Translator, host, ch string, now time.Time, opt Options, clears map[string]*event.Event) store.ChannelRun {
	cr := store.ChannelRun{Channel: ch, EventCounts: map[int]int{}}
	if ls, err := winevt.GetLogSettings(ch); err == nil {
		cr.MaxSizeBytes = ls.MaxSize
	}
	key := store.BookmarkKey(host, ch)
	bm := st.State.Bookmarks[key]

	oldest, newest, err := winevt.Edges(ch)
	if errors.Is(err, winevt.ErrChannelNotFound) {
		cr.Unavailable = "log not found or not enabled"
		return cr
	}
	if err != nil {
		cr.Error = err.Error()
		opt.Logf("%s: %v", ch, err)
		return cr
	}
	if oldest == nil {
		if bm.RecordID > 0 {
			cr.Reset = true // log is now empty: it was cleared
			st.State.Bookmarks[key] = store.Bookmark{}
		}
		return cr
	}
	cr.OldestTime = oldest.Time
	after := bm.RecordID
	switch {
	case after > 0 && newest.RecordID < after:
		cr.Reset = true // record numbers went backwards: log cleared or recreated
		after = 0
	case after > 0 && oldest.RecordID > after+1:
		// Logged once it is known the log was not cleared (LC2c).
		cr.Gap = &store.Gap{Lost: oldest.RecordID - after - 1, From: bm.Time, To: oldest.Time}
	}

	var batch []*event.Event
	last := store.Bookmark{RecordID: after, Time: bm.Time}
	flush := func() error {
		if err := st.AppendEvents(now, batch); err != nil {
			return err
		}
		batch = batch[:0]
		st.State.Bookmarks[key] = last
		return st.Save()
	}
	err = winevt.ReadChannel(ch, after, func(r *winevt.Raw) error {
		cr.Read++
		cr.EventCounts[r.EventID]++
		if cr.FirstRecord == 0 {
			cr.FirstRecord = r.RecordID
		}
		if cr.FirstTime.IsZero() || r.Time.Before(cr.FirstTime) {
			cr.FirstTime = r.Time
		}
		cr.LastRecord = r.RecordID
		if e := tr.Translate(r); e != nil {
			if e.Action == "log_cleared" {
				clears[strings.ToLower(e.Target)] = e
			}
			e.Collected = now
			OnThisComputer(e, host)
			checkRemoved(e, opt.MovedBy)
			batch = append(batch, e)
			cr.Kept++
		}
		last = store.Bookmark{RecordID: r.RecordID, Time: r.Time}
		if len(batch) >= flushEvery {
			return flush()
		}
		return nil
	})
	if ferr := flush(); ferr != nil && err == nil {
		err = ferr
	}
	if err != nil {
		cr.Error = err.Error()
		opt.Logf("%s: %v", ch, err)
	}
	opt.Logf("%s: read %d events, kept %d", ch, cr.Read, cr.Kept)
	return cr
}

// ClearedNotLost: a log cleared since the last collection skips records,
// but they were cleared, not overwritten (LC2). Its gap is dropped (the
// clear is already a High row) and it is marked cleared, so no rollover
// loss is counted and no size advice given. clears are the logs a clear
// event (System 104, Security 1102) named in this collection, by log.
func ClearedNotLost(run *store.Run, clears map[string]*event.Event, logf func(string, ...any)) {
	for i := range run.Channels {
		c := &run.Channels[i]
		e := clears[strings.ToLower(c.Channel)]
		if e == nil {
			continue
		}
		c.Cleared, c.ClearedAt, c.ClearedBy = true, e.Time, e.User
		if c.Gap != nil {
			if logf != nil {
				logf("%s: was cleared; the %d records before the clear are not counted as overwritten", c.Channel, c.Gap.Lost)
			}
			c.Gap = nil
		}
	}
}

// LogOverwritten logs the records each log overwrote before they could be
// collected. It runs after ClearedNotLost, so a cleared log is not also
// said to be overwritten (LC2c).
func LogOverwritten(run *store.Run, logf func(string, ...any)) {
	for _, c := range run.Channels {
		if c.Gap != nil && !c.Cleared && logf != nil {
			logf("%s: %d events were overwritten before they could be collected", c.Channel, c.Gap.Lost)
		}
	}
}

// FromRaw translates events from an export (XML or .evtx) and returns them
// with a synthetic run summarising what was read, for one-off reports.
func FromRaw(read func(fn func(*winevt.Raw) error) error, source string, now time.Time) ([]*event.Event, *store.Run, error) {
	tr := winevt.NewTranslator()
	tr.ResolveSID = winevt.LookupSID
	byCh := map[string]*store.ChannelRun{}
	var order []string
	var events []*event.Event
	hosts := map[string]bool{}
	err := read(func(r *winevt.Raw) error {
		cr := byCh[r.Channel]
		if cr == nil {
			cr = &store.ChannelRun{Channel: r.Channel, EventCounts: map[int]int{}}
			byCh[r.Channel] = cr
			order = append(order, r.Channel)
		}
		cr.Read++
		cr.EventCounts[r.EventID]++
		if e := tr.Translate(r); e != nil {
			e.Collected = now
			events = append(events, e)
			cr.Kept++
			hosts[e.Host] = true
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", source, err)
	}
	run := &store.Run{Time: now, Host: strings.Join(keys(hosts), ", ")}
	for _, ch := range order {
		run.Channels = append(run.Channels, *byCh[ch])
	}
	return events, run, nil
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
