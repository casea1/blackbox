package lan

import (
	"errors"
	"fmt"
	"io"
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
func Export(st *store.Store, host, version string, now time.Time) (int, error) {
	if st.State.Send == nil {
		st.State.Send = &store.SendState{ID: store.NewID(), NextSeq: 1}
	}
	s := st.State.Send
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
		b.Header = Header{Sender: host, SenderID: s.ID, Seq: s.NextSeq, Created: now, Version: version, OS: runtime.GOOS}
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
// and removes each from the outbox once it is safely there, or moves it to
// SentDir when keep is set. It stops at the first failure; what is left is
// retried at the next run.
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
		final := InboxName(host, st.State.Send.ID, seq)
		if err := copyInto(src, inbox, final); err != nil {
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
		if err := copyInto(src, inbox, InboxName(host, st.State.Send.ID, seq)); err != nil {
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
		if err := copyInto(src, inbox, archivePrefix+st.State.Send.ID+"_"+name); err != nil {
			return sent, fmt.Errorf("copy log archive %s to %s: %w", name, inbox, err)
		}
		if err := os.Remove(src); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// InboxName is a batch's file name in the inbox: sender, stream ID and
// sequence number, so batches sort in order and never collide.
func InboxName(host, id string, seq uint64) string {
	return fmt.Sprintf("%s_%s_%010d%s", safeName(host), id, seq, batchExt)
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

func safeName(s string) string {
	s = unsafeChars.ReplaceAllString(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}

// copyInto copies src into dir as name: written under a temporary name,
// flushed to disk, then renamed, so the collector never sees half a file.
func copyInto(src, dir, name string) error {
	final := filepath.Join(dir, name)
	if _, err := os.Stat(final); err == nil {
		return nil // already delivered (the outbox copy was not removed last time)
	}
	tmp := filepath.Join(dir, "."+name+".partial")
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		if _, serr := os.Stat(final); serr == nil {
			os.Remove(tmp)
			return nil
		}
		os.Remove(tmp)
		return err
	}
	return nil
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
