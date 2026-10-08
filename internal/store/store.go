// Package store keeps Blackbox's on-disk state: where each log was last
// read up to (bookmarks), the translated events collected so far (the
// spool), and a record of every collection run.
//
// Layout under the data directory:
//
//	state.json                 bookmarks and report history
//	spool/events-YYYY-MM-DD.jsonl  translated events, by collection date
//	spool/runs-YYYY-MM-DD.jsonl    one record per collection run
//	spool/checks-YYYY-MM-DD.jsonl  audit settings checks (see lan.go)
//	outbox/…                   batches waiting to be sent to a collector
//	reports/…                  generated reports
//
// Events received from other systems (see package lan) are appended to the
// same spool files as local ones, so every system's data is read, reported
// and forwarded the same way.
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// Bookmark is the last record read from one log.
type Bookmark struct {
	RecordID uint64    `json:"record_id,omitempty"` // Windows: last record number
	Time     time.Time `json:"time,omitzero"`       // time of the last event read
	Inode    uint64    `json:"inode,omitempty"`     // Linux log files: file identity…
	Offset   int64     `json:"offset,omitempty"`    // …and bytes read
	Head     string    `json:"head,omitempty"`      // hash of the file's first bytes, to spot a replaced file
	Cursor   string    `json:"cursor,omitempty"`    // systemd journal cursor
}

// State is persisted between runs.
type State struct {
	Bookmarks map[string]Bookmark `json:"bookmarks"` // key: host|channel

	// Report chain: every event is reported exactly once.
	LastWindowEnd time.Time `json:"last_window_end,omitzero"` // events before this were reported…
	LastGenerated time.Time `json:"last_generated,omitzero"`  // …if collected before this
	LastCollect   time.Time `json:"last_collect,omitzero"`
	// ReportedTo is how far each events spool file had been read when the
	// last scheduled report was made (bytes, by file name). An event past
	// that point was collected since, whatever the clock said (T3): the
	// report chain follows collection order, not wall-clock time.
	ReportedTo map[string]int64 `json:"reported_to,omitempty"`
	// ClockBack lists the times the clock was found to have been moved
	// back (a stored collection time in the future), until a scheduled
	// report has shown them.
	ClockBack []ClockJump `json:"clock_back,omitempty"`
	// LogGaps are parts of this computer's logs that were overwritten
	// before Blackbox saved the original logs (kept 14 days, for status).
	LogGaps []LogGap `json:"log_gaps,omitempty"`

	// Removable devices seen before, so new ones can be flagged.
	KnownDevices map[string]time.Time `json:"known_devices"`

	// What people normally do, so first times can be pointed out (see
	// report.UpdateBaseline), and the computers already learned.
	Baseline      map[string]time.Time `json:"baseline,omitempty"`
	BaselineHosts map[string]time.Time `json:"baseline_hosts,omitempty"`

	// LastCheck is when the audit settings were last checked.
	LastCheck time.Time `json:"last_check,omitzero"`

	// ArchivedUntil is the end of the last export of the original logs
	// (see package archive).
	ArchivedUntil time.Time `json:"archived_until,omitzero"`
	// ArchiveRestart is where the next export starts instead, after the
	// clock was moved back (AR1): the first record written since the last
	// export.
	ArchiveRestart time.Time `json:"archive_restart,omitzero"`
	// PackFailing is set while packing the exports fails: status says so
	// and exits 4, and reports show the reason (AR5).
	PackFailing *PackFailure `json:"pack_failing,omitempty"`
	// ExportMarks are where the last export of each log ended (AR8,
	// AR9): the next export takes everything after it, whatever the
	// records' times. By log (a Windows channel, a Linux log file, or
	// "systemd journal").
	ExportMarks map[string]ExportMark `json:"export_marks,omitempty"`
	// Clears are the logs cleared since they last had a record exported,
	// by log (lower case): the gap the clear leaves in the next export is
	// labelled as the clear, not an overwrite (LC2b).
	Clears map[string]LogClear `json:"clears,omitempty"`
	// LeftOut are daily archives of original logs that failed their check
	// at a scheduled report and were set aside, not put in it (AR7):
	// status says so, and exits 4, for logGapsKept.
	LeftOut []LeftOutLogs `json:"left_out,omitempty"`

	// LAN: sending to a collector, receiving from other systems, and the
	// systems seen (see lan.go).
	Send    *SendState              `json:"send,omitempty"`
	Senders map[string]*SenderState `json:"senders,omitempty"` // by sender ID
	Systems map[string]*System      `json:"systems,omitempty"` // by SystemKey(host)
	// InboxFolders are the senders' own folders in this collector's
	// inbox, by folder name in upper case, and Renames the former names
	// an administrator accepted (SEC1).
	InboxFolders map[string]*InboxFolder `json:"inbox_folders,omitempty"`
	Renames      []Rename                `json:"renames,omitempty"`
	// InboxConflicts are kept 90 days (SEC1).
	InboxConflicts []InboxConflict `json:"inbox_conflicts,omitempty"`
	Pending        *PendingImport  `json:"pending_import,omitempty"`

	// RemovedReports are report folders deleted under retention_days since
	// the last scheduled report, which lists them (A9).
	RemovedReports []string `json:"removed_reports,omitempty"`

	// Reports is every scheduled report this computer made (the report
	// ledger): one that later goes missing or is changed is pointed out
	// in status, the status icon, the next report and the index.
	Reports []ReportRecord `json:"reports,omitempty"`

	// OwnNames are the names this computer has collected under, so a
	// renamed computer's earlier data is known to be its own (W1b).
	OwnNames []string `json:"own_names,omitempty"`

	// ScapSent are the SCAP result files (by SHA-256) a sender has queued
	// for its collector, so each goes once.
	ScapSent map[string]time.Time `json:"scap_sent,omitempty"`
}

// Gap records events lost before they could be collected.
type Gap struct {
	Lost uint64    `json:"lost"`           // number of records overwritten
	From time.Time `json:"from,omitzero"`  // last event we had
	To   time.Time `json:"to,omitzero"`    // oldest event still in the log
	Note string    `json:"note,omitempty"` // explanation when the count is unknown
}

// ChannelRun is what happened reading one log in one run.
type ChannelRun struct {
	Channel      string         `json:"channel"`
	Read         int            `json:"read"` // records read
	Kept         int            `json:"kept"` // translated (security-relevant)
	FirstRecord  uint64         `json:"first_record,omitempty"`
	LastRecord   uint64         `json:"last_record,omitempty"`
	OldestTime   time.Time      `json:"oldest_time,omitzero"` // oldest event still in the log
	FirstTime    time.Time      `json:"first_time,omitzero"`  // earliest record read in this run
	MaxSizeBytes uint64         `json:"max_size_bytes,omitempty"`
	Gap          *Gap           `json:"gap,omitempty"`
	Reset        bool           `json:"reset,omitempty"` // record numbers went backwards (log cleared/recreated)
	Unavailable  string         `json:"unavailable,omitempty"`
	Error        string         `json:"error,omitempty"`
	EventCounts  map[int]int    `json:"event_counts,omitempty"`
	TypeCounts   map[string]int `json:"type_counts,omitempty"` // Linux: records by auditd type or syslog program

	// Cleared: the log was cleared since the last collection (a 104, or
	// a 1102 for Security, was read). The records it skipped are not
	// lost to rollover (LC2).
	Cleared bool `json:"cleared,omitempty"`
	// ClearedAt and ClearedBy are the clear's time and who did it.
	ClearedAt time.Time `json:"cleared_at,omitzero"`
	ClearedBy string    `json:"cleared_by,omitempty"`
}

// Run is one collection run on one host.
type Run struct {
	Time     time.Time    `json:"time"`
	Host     string       `json:"host"`
	OS       string       `json:"os,omitempty"` // windows | linux
	Version  string       `json:"version"`
	Duration float64      `json:"duration_seconds"`
	Received time.Time    `json:"received,omitzero"` // when it arrived from another system (collector only)
	Channels []ChannelRun `json:"channels"`
	// AuditOff says, in plain words, that auditing was not running when
	// this collection ran (Linux: auditd stopped, or kernel auditing off).
	AuditOff string `json:"audit_off,omitempty"`
	// Blocked is collection refused before this run because another run
	// held the lock (LOCK1): a gap in collection.
	Blocked *Blocked `json:"blocked,omitempty"`
}

// Store is an opened data directory.
type Store struct {
	Dir   string
	State *State
}

// Open loads (or initialises) the data directory.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "spool"), 0o750); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir, State: &State{}}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, s.State); err != nil {
			return nil, fmt.Errorf("state.json is damaged (%v); move it aside to start fresh", err)
		}
	}
	if s.State.Bookmarks == nil {
		s.State.Bookmarks = map[string]Bookmark{}
	}
	if s.State.KnownDevices == nil {
		s.State.KnownDevices = map[string]time.Time{}
	}
	if s.State.Baseline == nil {
		s.State.Baseline = map[string]time.Time{}
	}
	if s.State.BaselineHosts == nil {
		s.State.BaselineHosts = map[string]time.Time{}
	}
	if s.State.Senders == nil {
		s.State.Senders = map[string]*SenderState{}
	}
	if s.State.Systems == nil {
		s.State.Systems = map[string]*System{}
	}
	return s, nil
}

// Save writes state.json atomically.
func (s *Store) Save() error {
	b, err := json.MarshalIndent(s.State, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(s.Dir, "state.json"), b, 0o640)
}

// BookmarkKey identifies a log on a host.
func BookmarkKey(host, channel string) string { return strings.ToUpper(host) + "|" + channel }

// AppendEvents adds events to today's spool file and flushes to disk.
// Callers must only advance bookmarks after this returns successfully.
func (s *Store) AppendEvents(now time.Time, events []*event.Event) error {
	if len(events) == 0 {
		return nil
	}
	return s.appendJSONL("events-"+now.UTC().Format("2006-01-02")+".jsonl", func(enc *json.Encoder) error {
		for _, e := range events {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	})
}

// AppendRun records a collection run.
func (s *Store) AppendRun(r *Run) error {
	return s.appendJSONL("runs-"+r.Time.UTC().Format("2006-01-02")+".jsonl", func(enc *json.Encoder) error {
		return enc.Encode(r)
	})
}

func (s *Store) appendJSONL(name string, write func(*json.Encoder) error) error {
	f, err := os.OpenFile(filepath.Join(s.Dir, "spool", name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := write(enc); err != nil {
		f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// spoolFiles lists spool files with the prefix whose date is on or after
// since (zero = all), oldest first.
func (s *Store) spoolFiles(prefix string, since time.Time) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(s.Dir, "spool", prefix+"-*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	if since.IsZero() {
		return matches, nil
	}
	cut := since.UTC().AddDate(0, 0, -1).Format("2006-01-02")
	var out []string
	for _, m := range matches {
		d := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), prefix+"-"), ".jsonl")
		if d >= cut {
			out = append(out, m)
		}
	}
	return out, nil
}

// ClockJump is the clock found to have been moved back: when it was
// noticed (by the corrected clock), the stored time that was in the
// future, and on which computer.
type ClockJump struct {
	Host    string    `json:"host"`
	Noticed time.Time `json:"noticed"`
	Was     time.Time `json:"was"` // the stored time, now in the future
}

// EventSizes is the current size of each events spool file, by name: the
// point a report has read to.
func (s *Store) EventSizes() (map[string]int64, error) {
	files, err := s.spoolFiles("events", time.Time{})
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil {
			out[filepath.Base(f)] = fi.Size()
		}
	}
	return out, nil
}

// ReadEventsAfter is ReadEvents, also reading any file that has grown past
// reportedTo (whatever its date: a file written after the clock was moved
// back has an earlier date), and marking the events past that point
// Unreported. With reportedTo nil, nothing is marked.
func (s *Store) ReadEventsAfter(since time.Time, reportedTo map[string]int64) ([]*event.Event, error) {
	all, err := s.spoolFiles("events", time.Time{})
	if err != nil {
		return nil, err
	}
	dated, err := s.spoolFiles("events", since)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, f := range dated {
		want[f] = true
	}
	var out []*event.Event
	for _, f := range all {
		name := filepath.Base(f)
		mark, known := reportedTo[name]
		if reportedTo != nil && !want[f] {
			fi, err := os.Stat(f)
			if err != nil || (known && fi.Size() <= mark) {
				continue
			}
		} else if !want[f] {
			continue
		}
		err := readJSONLOffsets(f, func(b []byte, at int64) error {
			var e event.Event
			if err := json.Unmarshal(b, &e); err != nil {
				return err
			}
			e.Unreported = reportedTo != nil && (!known || at >= mark)
			out = append(out, &e)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ReadEvents returns spooled events collected on or after since (by file
// date, so callers still filter precisely).
func (s *Store) ReadEvents(since time.Time) ([]*event.Event, error) {
	files, err := s.spoolFiles("events", since)
	if err != nil {
		return nil, err
	}
	var out []*event.Event
	for _, f := range files {
		err := readJSONL(f, func(b []byte) error {
			var e event.Event
			if err := json.Unmarshal(b, &e); err != nil {
				return err
			}
			out = append(out, &e)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Available is when a run's record reached this data folder: when it ran,
// or when it was received from another system.
func (r *Run) Available() time.Time {
	if r.Received.After(r.Time) {
		return r.Received
	}
	return r.Time
}

// ReadRuns returns collection runs that became available on or after since
// (see Available), so a run received late still reaches the next report.
func (s *Store) ReadRuns(since time.Time) ([]*Run, error) {
	files, err := s.spoolFiles("runs", since)
	if err != nil {
		return nil, err
	}
	var out []*Run
	for _, f := range files {
		err := readJSONL(f, func(b []byte) error {
			var r Run
			if err := json.Unmarshal(b, &r); err != nil {
				return err
			}
			if !r.Available().Before(since) {
				out = append(out, &r)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readJSONL calls fn for each line. A damaged final line (e.g. from a
// power loss mid-write) is ignored rather than failing the report.
func readJSONL(path string, fn func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	var pending error
	for sc.Scan() {
		if pending != nil {
			return fmt.Errorf("%s: %w", path, pending)
		}
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		pending = fn(line)
	}
	return sc.Err()
}

// readJSONLOffsets is readJSONL, also giving each line's byte offset.
func readJSONLOffsets(path string, fn func(line []byte, at int64) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1024*1024)
	var at int64
	var pending error // a bad line is an error only if another follows (a cut-short last line is not)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if t := strings.TrimSpace(string(line)); t != "" {
				if pending != nil {
					return fmt.Errorf("%s: %w", path, pending)
				}
				pending = fn([]byte(t), at)
			}
			at += int64(len(line))
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// spoolKinds are the spool file prefixes.
var spoolKinds = []string{"events", "runs", "checks"}

// Prune deletes spool files older than days (0 = never).
func (s *Store) Prune(days int, now time.Time) error {
	if days <= 0 {
		return nil
	}
	cut := now.UTC().AddDate(0, 0, -days).Format("2006-01-02")
	// Never delete anything that has not been reported yet.
	if !s.State.LastWindowEnd.IsZero() {
		if lw := s.State.LastWindowEnd.UTC().AddDate(0, 0, -2).Format("2006-01-02"); lw < cut {
			cut = lw
		}
	}
	for _, prefix := range spoolKinds {
		files, err := s.spoolFiles(prefix, time.Time{})
		if err != nil {
			return err
		}
		for _, f := range files {
			d := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), prefix+"-"), ".jsonl")
			if d >= cut || !s.fullySent(f) {
				continue // too recent, or not yet sent to the collector
			}
			if err := os.Remove(f); err != nil {
				return err
			}
			if s.State.Send != nil {
				delete(s.State.Send.Offsets, filepath.Base(f))
			}
		}
	}
	return nil
}

// ErrBusy means another Blackbox run holds the lock.
var ErrBusy = errors.New("another Blackbox run is in progress")

// WaitLock is Lock, but waits up to timeout for a run in progress to
// finish. waiting is called once if it has to wait.
func (s *Store) WaitLock(timeout time.Duration, waiting func()) (unlock func(), err error) {
	deadline := time.Now().Add(timeout)
	for told := false; ; told = true {
		unlock, err = s.Lock()
		if !errors.Is(err, ErrBusy) || time.Now().After(deadline) {
			return unlock, err
		}
		if !told && waiting != nil {
			waiting()
		}
		time.Sleep(lockPoll)
	}
}

var lockPoll = 2 * time.Second

// WriteFileAtomic writes to a temp file and renames it into place.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	os.Chmod(name, perm)
	return os.Rename(name, path)
}

// LogGap is a part of one log missing from the saved original logs.
type LogGap struct {
	Source string    `json:"source"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Noted  time.Time `json:"noted"`
	// Reason is set when the export was lost or unreadable before it
	// was packed, rather than overwritten in the log (AR5).
	Reason string `json:"reason,omitempty"`
	// Cleared is set when the gap is the log being cleared, not
	// overwritten (LC2b): who cleared it and when.
	Cleared *LogClear `json:"cleared,omitempty"`
	// Records names the records missing, when known (AR8, AR9).
	Records string `json:"records,omitempty"`
}

// ExportMark is where the last export of a log ended: a Windows log's
// last record ID, a Linux log file's position, or the journal's cursor
// (see Bookmark), and for the audit log the last audit serial.
type ExportMark struct {
	Bookmark
	Serial uint64 `json:"serial,omitempty"`
}

// LogClear is a log being cleared: when and by whom.
type LogClear struct {
	Channel string    `json:"channel"`
	At      time.Time `json:"at"`
	By      string    `json:"by,omitempty"`
	// Gap is set once an export has recorded the clear as a gap (LC2c):
	// the clear stays open, so the cleared file, still "full" or with its
	// record numbers started again, is not then taken for an overwrite.
	Gap bool `json:"gap,omitempty"`
}

// LeftOutLogs is a daily archive of original logs left out of a
// scheduled report because it failed its check (AR7).
type LeftOutLogs struct {
	Report   string    `json:"report"` // the report's folder name
	Host     string    `json:"host"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Reason   string    `json:"reason"`
	SetAside string    `json:"set_aside"` // where the archive was moved
	Noted    time.Time `json:"noted"`
}

// PackFailure is set while the exported original logs cannot be packed
// into an archive (AR5).
type PackFailure struct {
	Since  time.Time `json:"since"`
	Reason string    `json:"reason"`
}

// ReportRecord is one scheduled report in the ledger.
type ReportRecord struct {
	Dir  string    `json:"dir"` // the report's folder, where it was written
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	Made time.Time `json:"made"`
	// Manifest is the SHA-256 of the report's manifest.sha256, which
	// lists the hash of every other file in it.
	Manifest string `json:"manifest"`
	// Files are the size of each file the manifest lists, when it was
	// written: checked at every run (LEDGER1).
	Files map[string]int64 `json:"files,omitempty"`
	// FileCount is how many files the folder held when it was written,
	// at any depth, with the manifest (VER2). A file added afterwards is
	// pointed out by name; 0 for reports recorded before 0.23.
	FileCount int `json:"file_count,omitempty"`
	// Verified is when every file was last hashed against the manifest
	// (once a day), and Bad what that found wrong ("" if nothing).
	Verified time.Time `json:"verified,omitzero"`
	Bad      string    `json:"bad,omitempty"`
	// Removed is when retention_days removed it (not a problem).
	Removed time.Time `json:"removed,omitzero"`
	// Accepted says a person recorded that it is gone or changed on
	// purpose (moved to an archive drive, for example).
	Accepted *ReportAcceptance `json:"accepted,omitempty"`
}

// ReportAcceptance is who accepted a missing or changed report, when and why.
type ReportAcceptance struct {
	Who    string    `json:"who"`
	When   time.Time `json:"when"`
	Reason string    `json:"reason"`
}
