package store

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/inventory"
)

// SendState tracks what has been sent to a collector.
type SendState struct {
	LastAttempt   time.Time `json:"last_attempt,omitzero"`
	LastDelivered time.Time `json:"last_delivered,omitzero"`
	LastError     string    `json:"last_error,omitempty"`
	// FailingSince is the first of the deliveries failing in a row, zero
	// once one succeeds (L12).
	FailingSince time.Time `json:"failing_since,omitzero"`

	// ID identifies this sender's stream of batches. It is created once and
	// never changes, so the collector can tell a re-installed or renamed
	// system from a gap in the batches.
	ID      string           `json:"id"`
	NextSeq uint64           `json:"next_seq"`
	Offsets map[string]int64 `json:"offsets"` // spool file name → bytes already batched

	// Dest is the collector folder (send_to) batches go to, and Collector
	// that collector's name (from its inbox marker). FirstSeq is the first
	// batch it got after send_to changed; earlier ones went to Earlier
	// (L13).
	Dest      string `json:"dest,omitempty"`
	Collector string `json:"collector,omitempty"`
	FirstSeq  uint64 `json:"first_seq,omitempty"`
	Earlier   string `json:"earlier,omitempty"`
	// Since is when this computer last started sending after making
	// reports itself (AR3): what it had by then went into a final report.
	Since time.Time `json:"since,omitzero"`
	// VM: send_to is a VirtualBox shared folder, so this computer is a
	// virtual machine on the collector's PC (UI2).
	VM bool `json:"vm,omitempty"`
}

// SenderState is what a collector knows about one sender.
type SenderState struct {
	Host         string    `json:"host"`
	LastSeq      uint64    `json:"last_seq"`
	FirstSeen    time.Time `json:"first_seen"`
	LastReceived time.Time `json:"last_received"`
	Version      string    `json:"version,omitempty"`
	Missing      []SeqGap  `json:"missing,omitempty"`
	ClockAhead   string    `json:"clock_ahead,omitempty"` // last clock problem noticed
	ClockNoted   time.Time `json:"clock_noted,omitzero"`
	// StartSeq is the first batch this sender sent here after sending to
	// another collector (Earlier) before (L13); earlier ones are not gaps.
	StartSeq uint64 `json:"start_seq,omitempty"`
	Earlier  string `json:"earlier,omitempty"`
	// Kept is the range of batches the sender still keeps after delivery
	// and can send again (nil: it did not say, an older version).
	Kept *SeqRange `json:"kept,omitempty"`
	// Former are names the sender's computer had before (W1b).
	Former []string `json:"former,omitempty"`
	// Accepted are gaps an administrator accepted as never arriving
	// ("blackbox gaps accept"): no longer missing, and kept with who,
	// when and why.
	Accepted []AcceptedGap `json:"accepted,omitempty"`
}

// AcceptedGap is a range of batches accepted as never arriving.
type AcceptedGap struct {
	From   uint64    `json:"from"`
	To     uint64    `json:"to"`
	Reason string    `json:"reason"`
	Who    string    `json:"who"`
	When   time.Time `json:"when"`
}

// SeqRange is a range of batch numbers; From 0 means none.
type SeqRange struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

// SeqGap is a range of batches that never arrived.
type SeqGap struct {
	From  uint64    `json:"from"`
	To    uint64    `json:"to"`
	Noted time.Time `json:"noted"`
}

// System is one computer whose events are in this data folder: this one,
// or one that sent to this collector.
type System struct {
	Name         string    `json:"name"`
	OS           string    `json:"os,omitempty"`
	Version      string    `json:"version,omitempty"`
	Via          string    `json:"via,omitempty"` // system that delivered its data, if not itself
	FirstSeen    time.Time `json:"first_seen"`
	LastRun      time.Time `json:"last_run,omitzero"`      // its latest collection (its own clock)
	LastReceived time.Time `json:"last_received,omitzero"` // when its data last arrived here
	Removed      time.Time `json:"removed,omitzero"`       // retired with "blackbox systems remove"
	// Direct is set once its data came from itself (collected here, or
	// delivered by it): Via then stays empty, even if another computer
	// also passed its data on (L14).
	Direct bool `json:"direct,omitempty"`
	// Former are names this computer had before (W1b): data recorded
	// under them is its own.
	Former []string `json:"former,omitempty"`
	// VM: it says it is a virtual machine sending through a VirtualBox
	// shared folder (UI2).
	VM bool `json:"vm,omitempty"`
}

// SystemKey is the registry key for a host name (names are compared
// without regard to case).
func SystemKey(host string) string { return strings.ToUpper(strings.TrimSpace(host)) }

// NoteSystem records that host was seen: ran a collection at lastRun (zero
// if unknown), with data arriving at received (zero for local data).
func (s *Store) NoteSystem(host, osName, version, via string, lastRun, received, now time.Time) {
	if host == "" {
		return
	}
	k := SystemKey(host)
	sys := s.State.Systems[k]
	if sys == nil {
		sys = &System{Name: host, FirstSeen: now}
		s.State.Systems[k] = sys
	}
	if !sys.Removed.IsZero() && (lastRun.After(sys.Removed) || received.After(sys.Removed)) {
		sys.Removed = time.Time{} // it came back
	}
	if osName != "" {
		sys.OS = osName
	}
	if version != "" {
		sys.Version = version
	}
	if via == "" || strings.EqualFold(via, host) {
		sys.Via, sys.Direct = "", true
	} else if !sys.Direct {
		sys.Via = via
	}
	// The latest collection, by when it happened (T1b): one recorded by a
	// clock that was ahead and since corrected is replaced by the next.
	if lastRun.After(sys.LastRun) || (!lastRun.IsZero() && sys.LastRun.After(now.Add(5*time.Minute))) {
		sys.LastRun = lastRun
	}
	if received.After(sys.LastReceived) {
		sys.LastReceived = received
	}
}

// NewID returns a random identifier for a sender stream.
func NewID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// CheckRecord is the result of checking one system's audit settings.
type CheckRecord struct {
	Time    time.Time      `json:"time"`
	Host    string         `json:"host"`
	OS      string         `json:"os,omitempty"`
	Results []check.Result `json:"results"`
	// Inventory is the computer's hardware and accounts, read with the
	// check (nil from versions before 0.13).
	Inventory *inventory.Inventory `json:"inventory,omitempty"`
}

// AppendChecks records an audit settings check.
func (s *Store) AppendChecks(c *CheckRecord) error {
	return s.appendJSONL("checks-"+c.Time.UTC().Format("2006-01-02")+".jsonl", func(enc *json.Encoder) error {
		return enc.Encode(c)
	})
}

// LatestChecks returns the most recent check for each system made before
// end, looking back from since (by file date).
func (s *Store) LatestChecks(since, end time.Time) (map[string]*CheckRecord, error) {
	files, err := s.spoolFiles("checks", since)
	if err != nil {
		return nil, err
	}
	out := map[string]*CheckRecord{}
	for _, f := range files {
		err := readJSONL(f, func(b []byte) error {
			var c CheckRecord
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			if c.Time.After(end) {
				return nil
			}
			k := SystemKey(c.Host)
			if prev := out[k]; prev == nil || c.Time.After(prev.Time) {
				out[k] = &c
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SpoolFile is one spool file and its kind (events, runs or checks).
type SpoolFile struct {
	Kind string
	Name string // base name
	Path string
	Size int64
}

// SpoolFiles lists all spool files, oldest first.
func (s *Store) SpoolFiles() ([]SpoolFile, error) {
	var out []SpoolFile
	for _, kind := range spoolKinds {
		files, err := s.spoolFiles(kind, time.Time{})
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			fi, err := os.Stat(f)
			if err != nil {
				continue
			}
			out = append(out, SpoolFile{Kind: kind, Name: filepath.Base(f), Path: f, Size: fi.Size()})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return dateOf(out[i].Name) < dateOf(out[j].Name) })
	return out, nil
}

func dateOf(name string) string {
	name = strings.TrimSuffix(name, ".jsonl")
	if i := strings.IndexByte(name, '-'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// fullySent reports whether a spool file has been completely batched for
// the collector (always true when this system does not send).
func (s *Store) fullySent(path string) bool {
	if s.State.Send == nil {
		return true
	}
	fi, err := os.Stat(path)
	if err != nil {
		return true
	}
	return s.State.Send.Offsets[filepath.Base(path)] >= fi.Size()
}

// ReadLines returns the complete lines of a spool file from offset on, and
// the offset just past the last complete line. A partly written final line
// is left for next time.
func ReadLines(path string, offset int64, maxLines int) (lines [][]byte, next int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, offset, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}
	r := bufio.NewReaderSize(f, 1<<20)
	next = offset
	for maxLines <= 0 || len(lines) < maxLines {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			break // an incomplete final line is not consumed
		}
		if err != nil {
			return lines, next, err
		}
		next += int64(len(line))
		if t := strings.TrimSpace(string(line)); t != "" {
			lines = append(lines, []byte(t))
		}
	}
	return lines, next, nil
}

// PendingImport protects the spool while a received batch is appended:
// the size of each file before the append is saved first, so a crash part
// way through is undone on the next start instead of leaving half a batch
// (or, after a retry, a batch twice).
type PendingImport struct {
	Sizes map[string]int64 `json:"sizes"` // spool file name → size before (-1: did not exist)
}

// BeginImport records the current size of the spool files an import will
// append to.
func (s *Store) BeginImport(names []string) error {
	p := &PendingImport{Sizes: map[string]int64{}}
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(s.Dir, "spool", n))
		switch {
		case os.IsNotExist(err):
			p.Sizes[n] = -1
		case err != nil:
			return err
		default:
			p.Sizes[n] = fi.Size()
		}
	}
	s.State.Pending = p
	return s.Save()
}

// EndImport marks an import complete; the caller saves state.
func (s *Store) EndImport() { s.State.Pending = nil }

// AppendRaw appends already-encoded JSON lines to a spool file.
func (s *Store) AppendRaw(name string, lines [][]byte) error {
	if len(lines) == 0 {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, "spool", name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		w.Write(l)
		w.WriteByte('\n')
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

// recoverImport undoes an import that was interrupted.
func (s *Store) recoverImport() error {
	p := s.State.Pending
	if p == nil {
		return nil
	}
	for name, size := range p.Sizes {
		path := filepath.Join(s.Dir, "spool", name)
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		switch {
		case size < 0:
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("undo interrupted import: %w", err)
			}
		case fi.Size() > size:
			if err := os.Truncate(path, size); err != nil {
				return fmt.Errorf("undo interrupted import: %w", err)
			}
		}
	}
	s.State.Pending = nil
	return s.Save()
}
