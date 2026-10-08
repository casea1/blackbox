package lan

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// OutboxDir is where batches wait until they reach the collector.
func OutboxDir(st *store.Store) string { return filepath.Join(st.Dir, "outbox") }

// Export turns everything in the spool that has not been sent yet into
// numbered batches in the outbox. It returns the number of batches made.
//
// Only this computer's own data is sent (L14): events, collections and
// checks of computers that delivered to it while it was a collector stay
// in its final report (see app.handover), so the new collector neither
// gets them twice nor files them under this computer.
func Export(st *store.Store, host, version string, now time.Time) (int, error) {
	if st.State.Send == nil {
		st.State.Send = &store.SendState{ID: store.NewID(), NextSeq: 1}
	}
	s := st.State.Send
	others := OtherSystems(st, host)
	var kept *store.SeqRange
	if k := Kept(st); len(k) > 0 {
		kept = &store.SeqRange{From: k[0], To: k[len(k)-1]}
	} else {
		kept = &store.SeqRange{}
	}
	var former []string
	for _, n := range st.State.OwnNames {
		if !strings.EqualFold(n, host) {
			former = append(former, n)
		}
	}
	if s.Offsets == nil {
		s.Offsets = map[string]int64{}
	}
	if err := os.MkdirAll(OutboxDir(st), 0o750); err != nil {
		return 0, err
	}
	files, err := st.SpoolFiles()
	if err != nil {
		return 0, err
	}
	made := 0
	b := &Batch{}
	advance := map[string]int64{} // offsets reached by the batch being built
	flush := func() error {
		if b.Records() == 0 {
			return nil
		}
		b.Header = Header{Sender: host, SenderID: s.ID, Seq: s.NextSeq, Created: now, Version: version, OS: runtime.GOOS,
			FirstSeq: s.FirstSeq, Earlier: s.Earlier, Kept: kept, Former: former, VM: s.VM}
		data, err := b.Bytes()
		if err != nil {
			return err
		}
		// Written to the outbox before the offsets move: a crash in between
		// makes the same batch again next time, never loses it.
		if err := store.WriteFileAtomic(filepath.Join(OutboxDir(st), outboxName(s.NextSeq)), data, 0o640); err != nil {
			return err
		}
		for name, off := range advance {
			s.Offsets[name] = off
		}
		s.NextSeq++
		if err := st.Save(); err != nil {
			return err
		}
		made++
		b, advance = &Batch{}, map[string]int64{}
		return nil
	}
	for _, f := range files {
		off := s.Offsets[f.Name]
		if off > f.Size {
			off = 0 // the file was replaced; send it again from the start
		}
		for off < f.Size {
			room := maxBatchLines - b.Records()
			lines, next, err := store.ReadLines(f.Path, off, room)
			if err != nil {
				return made, err
			}
			if next == off {
				break // only an incomplete final line remains
			}
			lines = ownLines(lines, others)
			switch f.Kind {
			case "events":
				b.Events = append(b.Events, lines...)
			case "runs":
				b.Runs = append(b.Runs, lines...)
			case "checks":
				b.Checks = append(b.Checks, lines...)
			}
			off = next
			advance[f.Name] = next
			if b.Records() >= maxBatchLines {
				if err := flush(); err != nil {
					return made, err
				}
			}
		}
	}
	return made, flush()
}

// OtherSystems are the computers whose data reached this one from
// elsewhere: those that delivered to it as a collector, and those their
// data came through. Their keys are store.SystemKey names.
func OtherSystems(st *store.Store, host string) map[string]bool {
	out := map[string]bool{}
	for _, snd := range st.State.Senders {
		out[store.SystemKey(snd.Host)] = true
	}
	for k, sys := range st.State.Systems {
		if sys.Via != "" {
			out[k] = true
		}
	}
	delete(out, store.SystemKey(host))
	for _, n := range st.State.OwnNames {
		delete(out, store.SystemKey(n))
	}
	return out
}

// ownLines leaves out the spool lines (events, runs, checks: each has a
// "host") of the other systems.
func ownLines(lines [][]byte, others map[string]bool) [][]byte {
	if len(others) == 0 {
		return lines
	}
	out := lines[:0:0]
	for _, l := range lines {
		var h struct {
			Host string `json:"host"`
		}
		if json.Unmarshal(l, &h) == nil && others[store.SystemKey(h.Host)] {
			continue
		}
		out = append(out, l)
	}
	return out
}

func outboxName(seq uint64) string { return fmt.Sprintf("%010d%s", seq, batchExt) }

// Queued returns the number of batches waiting in the outbox.
func Queued(st *store.Store) int {
	list, _ := outbox(st)
	return len(list)
}

// outbox lists waiting batches, oldest first.
func outbox(st *store.Store) ([]string, error) { return listOutbox(st, batchExt) }

// listOutbox lists the outbox files with the extension, in name order.
func listOutbox(st *store.Store, ext string) ([]string, error) {
	entries, err := os.ReadDir(OutboxDir(st))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ext) && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// ErrNoInbox means the collector's folder is not reachable: not mounted,
// not connected, or not a Blackbox inbox.
var ErrNoInbox = errors.New("collector inbox not available")

// SentDir is where delivered batches are kept for keep_sent_days, so they
// can be sent again (L11). It is inside the data folder: root/SYSTEM only,
// and watched like the rest of it.
func SentDir(st *store.Store) string { return filepath.Join(OutboxDir(st), "sent") }

// Deliver copies waiting batches, oldest first, into the collector's inbox
// and removes each from the outbox once it is written, or moves it to
// SentDir when keep is set. It stops at the first failure; what is left is
// retried at the next run.
//
// The inbox is drop-only (DESIGN1): a sender can add files to it, but
// can't list it or read anything in it, its own files included. So a
// batch counts as delivered when it was written and closed without error;
// the collector's missing-batch list (blackbox gaps, send --resend) is
// the check that it arrived.
func Deliver(st *store.Store, inbox, host string, keep bool) (int, error) {
	if !IsInbox(inbox) {
		return 0, fmt.Errorf("%w: %s (is the shared folder connected or mounted? on the collector, the folder must be set as its inbox)", ErrNoInbox, inbox)
	}
	list, err := outbox(st)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, name := range list {
		seq, err := strconv.ParseUint(strings.TrimSuffix(name, batchExt), 10, 64)
		if err != nil {
			continue
		}
		src := filepath.Join(OutboxDir(st), name)
		if _, err := drop(src, deliveryDir(st, inbox), inboxBase(host, st.State.Send.ID, seq), batchExt); err != nil {
			return sent, fmt.Errorf("copy batch %d to %s: %w", seq, inbox, err)
		}
		if err := retire(st, src, name, keep); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// retire removes a delivered batch from the outbox, or keeps it in SentDir,
// dated now so PruneSent counts its days from delivery.
func retire(st *store.Store, src, name string, keep bool) error {
	if !keep {
		return os.Remove(src)
	}
	if err := os.MkdirAll(SentDir(st), 0o750); err != nil {
		return err
	}
	dst := filepath.Join(SentDir(st), name)
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(dst, now, now)
}

// PruneSent removes kept batches delivered more than days ago; with days
// 0, all of them. Undelivered batches are never touched.
func PruneSent(st *store.Store, days int, now time.Time) (int, error) {
	entries, err := os.ReadDir(SentDir(st))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	cutoff := now.AddDate(0, 0, -days)
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), batchExt) {
			continue
		}
		fi, err := e.Info()
		if err != nil || (days > 0 && fi.ModTime().After(cutoff)) {
			continue
		}
		if err := os.Remove(filepath.Join(SentDir(st), e.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// Kept lists the sequence numbers of the batches kept after delivery,
// lowest first.
func Kept(st *store.Store) []uint64 {
	entries, _ := os.ReadDir(SentDir(st))
	var out []uint64
	for _, e := range entries {
		if n, err := strconv.ParseUint(strings.TrimSuffix(e.Name(), batchExt), 10, 64); err == nil && strings.HasSuffix(e.Name(), batchExt) {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ParseRange reads "214-219" or "214".
func ParseRange(s string) (from, to uint64, err error) {
	a, b, found := strings.Cut(strings.TrimSpace(s), "-")
	from, err = strconv.ParseUint(strings.TrimSpace(a), 10, 64)
	to = from
	if err == nil && found {
		to, err = strconv.ParseUint(strings.TrimSpace(b), 10, 64)
	}
	if err != nil || from == 0 || to < from {
		return 0, 0, fmt.Errorf("%q is not a batch range: give the numbers the collector reports, like 214-219 or 214", s)
	}
	return from, to, nil
}

// Resend copies the kept batches from..to into the collector's inbox
// again (L11). The collector imports those that fill a gap and ignores
// the rest. It returns the batches sent and those no longer kept.
func Resend(st *store.Store, inbox, host string, from, to uint64) (sent []uint64, missing []uint64, err error) {
	if !IsInbox(inbox) {
		return nil, nil, fmt.Errorf("%w: %s", ErrNoInbox, inbox)
	}
	if st.State.Send == nil {
		return nil, nil, errors.New("this computer has not sent any batches yet")
	}
	for seq := from; seq <= to; seq++ {
		src := filepath.Join(SentDir(st), outboxName(seq))
		if _, err := os.Stat(src); err != nil {
			// Still waiting in the outbox goes with the next delivery.
			if _, werr := os.Stat(filepath.Join(OutboxDir(st), outboxName(seq))); werr != nil {
				missing = append(missing, seq)
			}
			continue
		}
		if _, err := drop(src, deliveryDir(st, inbox), inboxBase(host, st.State.Send.ID, seq), batchExt); err != nil {
			return sent, missing, fmt.Errorf("copy batch %d to %s: %w", seq, inbox, err)
		}
		sent = append(sent, seq)
	}
	return sent, missing, nil
}

// Archives are zips of the original logs (see package archive), queued in
// the outbox next to the batches and delivered after them.
const archiveExt, archivePrefix = ".zip", "archive_"

// QueuedArchives returns the number of log archives waiting in the outbox.
func QueuedArchives(st *store.Store) int {
	list, _ := listOutbox(st, archiveExt)
	return len(list)
}

// DeliverArchives copies waiting log archives into the collector's inbox,
// named with this sender's ID, and removes each from the outbox once it is
// safely there.
func DeliverArchives(st *store.Store, inbox string) (int, error) {
	if !IsInbox(inbox) {
		return 0, fmt.Errorf("%w: %s", ErrNoInbox, inbox)
	}
	list, err := listOutbox(st, archiveExt)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, name := range list {
		src := filepath.Join(OutboxDir(st), name)
		if _, err := drop(src, deliveryDir(st, inbox), archivePrefix+st.State.Send.ID+"_"+strings.TrimSuffix(name, archiveExt), archiveExt); err != nil {
			return sent, fmt.Errorf("copy log archive %s to %s: %w", name, inbox, err)
		}
		if err := os.Remove(src); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// InboxName is a batch's file name in the inbox as senders before 0.24
// named it: sender, stream ID and sequence number. A 0.24 sender adds a
// random part (see drop), since it can't see what is already there.
func InboxName(host, id string, seq uint64) string {
	return inboxBase(host, id, seq) + batchExt
}

// inboxBase is a batch's name in the inbox without its random part and
// extension: HOST_SENDERID_SEQ (delivered as HOST_SENDERID_SEQ-RANDOM.bbx).
func inboxBase(host, id string, seq uint64) string {
	return fmt.Sprintf("%s_%s_%010d", safeName(host), id, seq)
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

func safeName(s string) string {
	s = unsafeChars.ReplaceAllString(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}

// deliveryDir is the folder this sender drops its files into: the inbox
// itself, or, while the collector is still 0.23, the sender's own folder
// there (DESIGN1). A 0.23 collector refuses a file in the inbox itself
// from a computer that has a folder, so a sender upgraded before the
// collector keeps using the folder 0.23 recorded for it, for as long as
// that folder's marker is there. A 0.24 collector moves what the folder
// holds into the inbox and removes it, and from then on the sender drops
// into the inbox. Nothing is listed: the marker is looked up by name.
func deliveryDir(st *store.Store, inbox string) string {
	s := st.State.Send
	if s == nil || s.Folder == "" || s.Folder != filepath.Base(s.Folder) || s.Folder == "." || s.Folder == ".." {
		return inbox
	}
	dir := filepath.Join(inbox, s.Folder)
	if fi, err := os.Stat(filepath.Join(dir, legacyMarker)); err != nil || !fi.Mode().IsRegular() {
		return inbox
	}
	return dir
}

// dropTries is how many random names a delivery tries before giving up.
const dropTries = 8

// drop writes src into the drop-only inbox as base-RANDOM.ext, and
// returns the name used (DESIGN1). The random part follows a dash, not an
// underscore, so a 0.23 collector reads the name too (it takes the dash
// and what follows for the "-N" of a batch delivered again): senders can
// be upgraded before the collector. The file is created only if no file
// has that name (O_EXCL, CREATE_NEW), written, flushed and closed: the
// sender can't rename or delete anything in the inbox, so it writes the
// final name straight away, and the collector waits for a file that is
// not complete yet. A name already taken means someone else made that
// file; the batch then goes under a new random part. Nothing in the
// inbox is listed or read.
func drop(src, inbox, base, ext string) (string, error) {
	for i := 0; i < dropTries; i++ {
		name := base + "-" + randomPart() + ext
		err := writeNew(src, filepath.Join(inbox, name))
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return name, err
	}
	return "", fmt.Errorf("%s: %d random names were all taken; someone is filling the inbox", base+ext, dropTries)
}

// randomPart is the random part of a name in the inbox: 12 hex digits.
func randomPart() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// writeNew writes src to path, which must not exist yet.
func writeNew(src, path string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// Readable by its owner only: on a Linux collector another sender in
	// the same group must not read it, even knowing its name (DESIGN1).
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// OldestQueued is when the oldest item still waiting in the outbox (a
// batch, log archive or SCAP result) was queued, and false when nothing
// is waiting (L10).
func OldestQueued(st *store.Store) (time.Time, bool) {
	entries, err := os.ReadDir(OutboxDir(st))
	if err != nil {
		return time.Time{}, false
	}
	var oldest time.Time
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") {
			continue
		}
		if !strings.HasSuffix(n, batchExt) && !strings.HasSuffix(n, archiveExt) && !strings.HasSuffix(n, scapExt) {
			continue
		}
		if fi, err := e.Info(); err == nil && (oldest.IsZero() || fi.ModTime().Before(oldest)) {
			oldest = fi.ModTime()
		}
	}
	return oldest, !oldest.IsZero()
}

// InboxCollector is the name of the collector an inbox belongs to, from
// its marker file ("" if it can't be read).
func InboxCollector(inbox string) string {
	b, err := os.ReadFile(filepath.Join(inbox, MarkerFile))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Collector:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// NoteVM records whether this computer is a VM sending through a VirtualBox
// shared folder (UI2); its batches say so, and only that makes it a VM in
// the collector's reports.
func NoteVM(st *store.Store, vm bool) {
	if st.State.Send == nil {
		st.State.Send = &store.SendState{ID: store.NewID(), NextSeq: 1}
	}
	st.State.Send.VM = vm
}

// NoteDestination records where batches now go: dest is send_to, and
// collector the name in its inbox marker ("" if not known yet). When
// either changed since the last delivery, the first batch not yet
// delivered is marked as the first for this collector, and the earlier
// ones as gone to the previous one (L13), so the new collector does not
// count them as missing. It reports whether the destination changed.
func NoteDestination(st *store.Store, dest, collector string) (bool, error) {
	if st.State.Send == nil {
		st.State.Send = &store.SendState{ID: store.NewID(), NextSeq: 1}
	}
	s := st.State.Send
	if s.Dest == "" {
		// The first delivery, or the first since an upgrade: there is
		// nothing to tell the collector.
		s.Dest, s.Collector = dest, collector
		return false, nil
	}
	norm := func(p string) string { return strings.TrimRight(strings.ReplaceAll(p, `\`, "/"), "/") }
	sameDest := strings.EqualFold(norm(s.Dest), norm(dest))
	sameName := collector == "" || s.Collector == "" || strings.EqualFold(collector, s.Collector)
	if sameDest && sameName {
		if collector != "" {
			s.Collector = collector
		}
		return false, nil
	}
	list, err := outbox(st)
	if err != nil {
		return false, err
	}
	first := s.NextSeq
	if len(list) > 0 {
		if n, err := strconv.ParseUint(strings.TrimSuffix(list[0], batchExt), 10, 64); err == nil {
			first = n
		}
	}
	earlier := s.Collector
	if earlier == "" {
		earlier = s.Dest
	}
	s.FirstSeq, s.Earlier, s.Dest, s.Collector = first, earlier, dest, collector
	// Batches already made for the previous collector carry the news too.
	for _, name := range list {
		if err := restamp(filepath.Join(OutboxDir(st), name), s.FirstSeq, s.Earlier); err != nil {
			return true, err
		}
	}
	return true, nil
}

// restamp rewrites a waiting batch with a new FirstSeq and Earlier.
func restamp(path string, first uint64, earlier string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	b, err := Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	b.FirstSeq, b.Earlier = first, earlier
	out, err := b.Bytes()
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(path, out, 0o640)
}

// NewID gives this computer a new sender ID, for a computer cloned from
// another (SEC1). Waiting batches are rewritten under the new ID,
// numbered from 1; batches kept for resending belong to the old ID and
// are moved aside (sent-OLDID), so they are never resent under the new
// one.
func NewID(st *store.Store) (old, id string, err error) {
	if st.State.Send == nil {
		st.State.Send = &store.SendState{ID: store.NewID(), NextSeq: 1}
		return "", st.State.Send.ID, st.Save()
	}
	s := st.State.Send
	old, id = s.ID, store.NewID()
	list, err := outbox(st)
	if err != nil {
		return old, "", err
	}
	type renum struct{ from, to string }
	var moves []renum
	seq := uint64(1)
	for _, name := range list {
		path := filepath.Join(OutboxDir(st), name)
		data, err := os.ReadFile(path)
		if err != nil {
			return old, "", err
		}
		b, err := Decode(bytes.NewReader(data))
		if err != nil {
			return old, "", fmt.Errorf("%s: %w", name, err)
		}
		b.SenderID, b.Seq, b.FirstSeq, b.Earlier, b.Kept = id, seq, 0, "", &store.SeqRange{}
		out, err := b.Bytes()
		if err != nil {
			return old, "", err
		}
		tmp := path + ".new"
		if err := store.WriteFileAtomic(tmp, out, 0o640); err != nil {
			return old, "", err
		}
		moves = append(moves, renum{tmp, filepath.Join(OutboxDir(st), outboxName(seq))})
		os.Remove(path)
		seq++
	}
	for _, m := range moves {
		if err := os.Rename(m.from, m.to); err != nil {
			return old, "", err
		}
	}
	if _, err := os.Stat(SentDir(st)); err == nil {
		if err := os.Rename(SentDir(st), filepath.Join(OutboxDir(st), "sent-"+old)); err != nil {
			return old, "", err
		}
	}
	s.ID, s.NextSeq, s.FirstSeq, s.Earlier = id, seq, 0, ""
	return old, id, st.Save()
}
