package lan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// MarkerFile identifies a folder as a Blackbox collector inbox. Senders
// only deliver to a folder that has it, so a share that is not mounted
// (an empty local folder) is never mistaken for the collector.
const MarkerFile = "BLACKBOX-INBOX.txt"

// IsInbox reports whether dir is a collector inbox that can be reached.
func IsInbox(dir string) bool {
	if dir == "" {
		return false
	}
	fi, err := os.Stat(filepath.Join(dir, MarkerFile))
	return err == nil && !fi.IsDir()
}

// PrepareInbox creates the inbox folder (if needed) and its marker file.
func PrepareInbox(dir, collector string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if IsInbox(dir) {
		return nil
	}
	text := strings.ReplaceAll(fmt.Sprintf(`Blackbox collector inbox
Collector: %s
Created:   %s

Other computers running Blackbox copy their collected audit events into this
folder. The collector (the computer named above) imports them every time it
collects, adds them to its reports, and then removes them.

Please do not delete, move or edit the files here. Removing a file loses
those events; the collector notices the gap and reports it.
`, collector, time.Now().Format("2006-01-02 15:04")), "\n", "\r\n")
	return os.WriteFile(filepath.Join(dir, MarkerFile), []byte(text), 0o644)
}

// ImportResult summarises one import.
type ImportResult struct {
	Batches  int
	Records  int
	Archives int      // log archives filed
	Scap     int      // SCAP scan results filed
	Rejected []string // files that could not be used, and why
}

// maxClockLead is how far a sender's clock may be ahead before it is noted.
const maxClockLead = 10 * time.Minute

// Dirs are where a collector files what senders deliver besides events:
// log archives, and SCAP scan results ("" leaves them in the inbox).
type Dirs struct {
	Archives, Scap string
}

// Import reads every complete batch in the inbox into the store, in order
// for each sender, and removes each file once its data is safely stored.
// A batch this system sent itself is refused, which stops a loop if two
// systems were set to send to each other.
//
// Log archives are checked against their recorded hashes and filed under
// archivesDir.
func Import(st *store.Store, inbox string, dirs Dirs, now time.Time, logf func(string, ...any)) (ImportResult, error) {
	archivesDir := dirs.Archives
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var res ImportResult
	entries, err := os.ReadDir(inbox)
	if err != nil {
		return res, err
	}
	type item struct {
		name string
		id   string
		seq  uint64
	}
	var items []item
	for _, e := range entries {
		n := e.Name()
		if archivesDir != "" && !e.IsDir() && strings.HasPrefix(n, archivePrefix) && strings.HasSuffix(n, archiveExt) {
			if err := importArchive(st, inbox, n, archivesDir); err != nil {
				res.Rejected = append(res.Rejected, reject(inbox, n, err.Error()))
			} else {
				res.Archives++
			}
			continue
		}
		if dirs.Scap != "" && !e.IsDir() && strings.HasPrefix(n, scapPrefix) && strings.HasSuffix(n, scapExt) {
			if err := importScap(st, inbox, n, dirs.Scap); err != nil {
				res.Rejected = append(res.Rejected, reject(inbox, n, err.Error()))
			} else {
				res.Scap++
			}
			continue
		}
		if e.IsDir() || strings.HasPrefix(n, ".") || !strings.HasSuffix(n, batchExt) {
			continue
		}
		id, seq, ok := parseInboxName(n)
		if !ok {
			res.Rejected = append(res.Rejected, reject(inbox, n, "file name is not a Blackbox batch name"))
			continue
		}
		items = append(items, item{n, id, seq})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].id != items[j].id {
			return items[i].id < items[j].id
		}
		return items[i].seq < items[j].seq
	})
	for _, it := range items {
		path := filepath.Join(inbox, it.name)
		data, err := os.ReadFile(path)
		if err != nil {
			// One file that can't be read must not hold up the others (L1).
			res.Rejected = append(res.Rejected, reject(inbox, it.name, "it could not be read: "+err.Error()))
			continue
		}
		b, err := Decode(bytes.NewReader(data))
		if err == nil && (b.SenderID != it.id || b.Seq != it.seq) {
			err = fmt.Errorf("its contents say sender %s batch %d", b.SenderID, b.Seq)
		}
		if err == nil && st.State.Send != nil && b.SenderID == st.State.Send.ID {
			err = fmt.Errorf("it was sent by this computer (a system cannot send to itself)")
		}
		if err != nil {
			res.Rejected = append(res.Rejected, reject(inbox, it.name, err.Error()))
			continue
		}
		n, err := importBatch(st, b, now)
		if err != nil {
			return res, fmt.Errorf("import %s: %w", it.name, err)
		}
		if err := os.Remove(path); err != nil {
			logf("imported %s but could not remove it: %v (it will be skipped as a duplicate)", it.name, err)
		}
		res.Batches++
		res.Records += n
	}
	for _, r := range res.Rejected {
		logf("inbox: %s", r)
	}
	return res, nil
}

// importArchive verifies a log archive and files it.
func importArchive(st *store.Store, inbox, name, archivesDir string) error {
	id, _, _ := strings.Cut(strings.TrimPrefix(name, archivePrefix), "_")
	if st.State.Send != nil && id == st.State.Send.ID {
		return fmt.Errorf("it was sent by this computer (a system cannot send to itself)")
	}
	path := filepath.Join(inbox, name)
	info, err := archive.Verify(path)
	if err != nil {
		return err
	}
	_, err = archive.File(path, archivesDir, info)
	return err
}

// parseInboxName reads <sender>_<id>_<seq>.bbx.
func parseInboxName(n string) (id string, seq uint64, ok bool) {
	parts := strings.Split(strings.TrimSuffix(n, batchExt), "_")
	if len(parts) < 3 {
		return "", 0, false
	}
	seq, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	if err != nil || seq == 0 {
		return "", 0, false
	}
	return parts[len(parts)-2], seq, parts[len(parts)-2] != ""
}

// reject moves an unusable file aside (so it is not retried every run) and
// describes why. It says "set aside" only if the move worked (L9): a file
// that can't be moved stays in the inbox, is tried again every run, and
// status and the report list it (Unreadable).
func reject(inbox, name, why string) string {
	dir := filepath.Join(inbox, "rejected")
	err := os.MkdirAll(dir, 0o750)
	if err == nil {
		err = os.Rename(filepath.Join(inbox, name), filepath.Join(dir, name))
	}
	if err != nil {
		return fmt.Sprintf("%s could not be used (%s) and could not be set aside (%s); it stays in the inbox and is tried again every run",
			name, why, errReason(err))
	}
	return fmt.Sprintf("%s was set aside in %s: %s", name, dir, why)
}

// errReason is an error in a few words: "access denied" for a permission
// error, otherwise the error itself.
func errReason(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "access denied"
	}
	return err.Error()
}

// Unreadable lists the files in the inbox that this collector can't read,
// as "name (reason)": they stay in the inbox and their events are not in
// the reports until someone fixes the file's permissions (L9).
func Unreadable(inbox string) []string {
	entries, err := os.ReadDir(inbox)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || n == MarkerFile {
			continue
		}
		if !strings.HasSuffix(n, batchExt) && !strings.HasSuffix(n, archiveExt) && !strings.HasSuffix(n, scapExt) {
			continue
		}
		f, err := os.Open(filepath.Join(inbox, n))
		if err != nil {
			out = append(out, fmt.Sprintf("%s (%s)", n, errReason(err)))
			continue
		}
		f.Close()
	}
	return out
}

// importBatch appends one verified batch to the spool.
func importBatch(st *store.Store, b *Batch, now time.Time) (int, error) {
	snd := st.State.Senders[b.SenderID]
	if snd == nil {
		snd = &store.SenderState{Host: b.Sender, FirstSeen: now}
		st.State.Senders[b.SenderID] = snd
	}
	// The sender went to another collector before this batch (L13): the
	// batches before it are not missing here.
	if f := b.FirstSeq; f > 1 && b.Seq >= f {
		snd.Missing = dropBelow(snd.Missing, f)
		if snd.LastSeq < f-1 {
			snd.LastSeq = f - 1
			snd.StartSeq, snd.Earlier = f, b.Earlier
		}
	}
	if b.Kept != nil {
		k := *b.Kept
		snd.Kept = &k
	}
	if b.Former != nil {
		snd.Former = b.Former
	}
	late := b.Seq <= snd.LastSeq
	if late && !inGap(snd.Missing, b.Seq) {
		return 0, nil // already imported (delivered twice)
	}

	// Received events count as collected now: that is when they became
	// available to this collector's reports, so one that arrives late goes
	// into the next report (marked Late) rather than being skipped.
	events := make([][]byte, 0, len(b.Events))
	for _, raw := range b.Events {
		var e event.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return 0, fmt.Errorf("event: %w", err)
		}
		if e.Host == "" {
			e.Host = b.Sender
		}
		e.Collected = now
		e.Late = false
		out, err := marshal(&e)
		if err != nil {
			return 0, err
		}
		events = append(events, out)
	}
	runs := make([][]byte, 0, len(b.Runs))
	var runList []store.Run
	for _, raw := range b.Runs {
		var r store.Run
		if err := json.Unmarshal(raw, &r); err != nil {
			return 0, fmt.Errorf("run: %w", err)
		}
		if r.Host == "" {
			r.Host = b.Sender
		}
		if r.Received.IsZero() || r.Received.Before(now) {
			r.Received = now
		}
		out, err := marshal(&r)
		if err != nil {
			return 0, err
		}
		runs = append(runs, out)
		runList = append(runList, r)
	}
	checks := make([][]byte, 0, len(b.Checks))
	for _, raw := range b.Checks {
		var c store.CheckRecord
		if err := json.Unmarshal(raw, &c); err != nil {
			return 0, fmt.Errorf("checks: %w", err)
		}
		checks = append(checks, raw)
	}

	day := now.UTC().Format("2006-01-02")
	files := map[string][][]byte{"events-" + day + ".jsonl": events, "runs-" + day + ".jsonl": runs, "checks-" + day + ".jsonl": checks}
	var names []string
	for n, lines := range files {
		if len(lines) > 0 {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if err := st.BeginImport(names); err != nil {
		return 0, err
	}
	for _, n := range names {
		if err := st.AppendRaw(n, files[n]); err != nil {
			return 0, err
		}
	}

	// Bookkeeping: gaps in the sequence, the sender's clock, and which
	// systems this data came from.
	if late {
		// A batch that was missing has arrived after all (out of order).
		snd.Missing = fillGap(snd.Missing, b.Seq)
	} else {
		if b.Seq > snd.LastSeq+1 {
			snd.Missing = append(snd.Missing, store.SeqGap{From: snd.LastSeq + 1, To: b.Seq - 1, Noted: now})
		}
		snd.LastSeq = b.Seq
	}
	snd.Host = b.Sender
	snd.Version = b.Version
	snd.LastReceived = now
	if lead := b.Created.Sub(now); lead > maxClockLead {
		snd.ClockAhead = roughly(lead)
		snd.ClockNoted = now
	}
	for _, r := range runList {
		st.NoteSystem(r.Host, r.OS, r.Version, b.Sender, r.Time, now, now)
	}
	if b.Former != nil {
		if sys := st.State.Systems[store.SystemKey(b.Sender)]; sys != nil {
			sys.Former = b.Former
		}
	}
	// Systems are only the computers that collect (they send runs), not
	// every host name in the events: old events can carry a computer's
	// former name (a renamed PC, or a VM cloned from an image), which is
	// not a separate computer that has gone silent.
	st.EndImport()
	if err := st.Save(); err != nil {
		return 0, err
	}
	return b.Records(), nil
}

// dropBelow removes the missing batches numbered below first.
func dropBelow(gaps []store.SeqGap, first uint64) []store.SeqGap {
	var out []store.SeqGap
	for _, g := range gaps {
		if g.To < first {
			continue
		}
		if g.From < first {
			g.From = first
		}
		out = append(out, g)
	}
	return out
}

// inGap reports whether batch seq is one of the missing ones.
func inGap(gaps []store.SeqGap, seq uint64) bool {
	for _, g := range gaps {
		if seq >= g.From && seq <= g.To {
			return true
		}
	}
	return false
}

// fillGap removes seq from the missing batches, splitting a gap if needed.
func fillGap(gaps []store.SeqGap, seq uint64) []store.SeqGap {
	var out []store.SeqGap
	for _, g := range gaps {
		if seq < g.From || seq > g.To {
			out = append(out, g)
			continue
		}
		if seq > g.From {
			out = append(out, store.SeqGap{From: g.From, To: seq - 1, Noted: g.Noted})
		}
		if seq < g.To {
			out = append(out, store.SeqGap{From: seq + 1, To: g.To, Noted: g.Noted})
		}
	}
	return out
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func roughly(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	case d >= 2*time.Hour:
		return fmt.Sprintf("%.0f hours", d.Hours())
	}
	return fmt.Sprintf("%.0f minutes", d.Minutes())
}
