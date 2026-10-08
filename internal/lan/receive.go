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
	Already  int      // batches delivered again that were already imported (L11b)
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
// Senders deliver into their own folders in the inbox (SEC1), where only
// their account can write: what a folder holds must be from that folder's
// computer. Files in the inbox itself (the shared folder of earlier
// versions) are still read, unless they claim to be from a computer that
// has its own folder.
//
// Log archives are checked against their recorded hashes and filed under
// dirs.Archives, and SCAP results under dirs.Scap. A file that can't be
// used is moved to inbox/rejected with a note of why, and the rest are
// still imported (SEC2).
func Import(st *store.Store, inbox string, dirs Dirs, now time.Time, logf func(string, ...any)) (ImportResult, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var res ImportResult
	entries, err := os.ReadDir(inbox)
	if err != nil {
		return res, err
	}
	type item struct {
		dir, folder, name string
		id                string
		seq               uint64
	}
	var items []item
	rej := func(dir, folder, name, why string) {
		res.Rejected = append(res.Rejected, reject(inbox, dir, folder, name, why, now))
	}
	scan := func(dir, folder string, entries []os.DirEntry) {
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || strings.HasPrefix(n, ".") {
				continue
			}
			switch {
			case dirs.Archives != "" && strings.HasPrefix(n, archivePrefix) && strings.HasSuffix(n, archiveExt):
				switch err := importArchive(st, dir, folder, n, dirs.Archives, now); {
				case errors.Is(err, errWriting):
				case err != nil:
					rej(dir, folder, n, err.Error())
				default:
					res.Archives++
				}
				continue
			case dirs.Scap != "" && strings.HasPrefix(n, scapPrefix) && strings.HasSuffix(n, scapExt):
				switch err := importScap(st, dir, folder, n, dirs.Scap, now); {
				case errors.Is(err, errWriting):
				case err != nil:
					rej(dir, folder, n, err.Error())
				default:
					res.Scap++
				}
				continue
			case !strings.HasSuffix(n, batchExt):
				continue
			}
			id, seq, ok := parseInboxName(n)
			if !ok {
				rej(dir, folder, n, "file name is not a Blackbox batch name")
				continue
			}
			items = append(items, item{dir, folder, n, id, seq})
		}
	}
	scan(inbox, "", entries)
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && e.Name() != rejectedDir {
			sub, err := os.ReadDir(filepath.Join(inbox, e.Name()))
			if err != nil {
				logf("inbox: cannot read the folder %s: %v", e.Name(), err)
				continue
			}
			scan(filepath.Join(inbox, e.Name()), e.Name(), sub)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].id != items[j].id {
			return items[i].id < items[j].id
		}
		if items[i].seq != items[j].seq {
			return items[i].seq < items[j].seq
		}
		return items[i].name < items[j].name
	})
	for _, it := range items {
		path := filepath.Join(it.dir, it.name)
		// The size is checked before the file is read (SEC3b).
		fi, err := os.Stat(path)
		if err == nil && fi.Size() > maxBatchFile {
			rej(it.dir, it.folder, it.name, fmt.Sprintf("it is %d MB, larger than any batch Blackbox makes (%d MB)", fi.Size()>>20, maxBatchFile>>20))
			continue
		}
		var data []byte
		if err == nil {
			data, err = os.ReadFile(path)
		}
		if err != nil {
			// One file that can't be read must not hold up the others (L1).
			rej(it.dir, it.folder, it.name, "it could not be read: "+err.Error())
			continue
		}
		b, err := Decode(bytes.NewReader(data))
		if errors.Is(err, ErrIncomplete) && it.folder != "" && now.Sub(fi.ModTime()) < settle {
			continue // still being written (a sender's own folder has no temporary names)
		}
		trusted := b != nil && b.SenderID == it.id && b.Seq == it.seq
		if b != nil && !trusted {
			err = fmt.Errorf("its contents say sender %s batch %d", b.SenderID, b.Seq)
		}
		if trusted && st.State.Send != nil && b.SenderID == st.State.Send.ID {
			err, trusted = fmt.Errorf("it was sent by this computer (a system cannot send to itself)"), false
		}
		if trusted {
			if ferr := checkFolder(st, it.folder, b.Sender, b.SenderID); ferr != nil {
				err, trusted = ferr, false
			}
		}
		writer := fileOwner(path)
		var n int
		var dup bool
		if err == nil {
			n, dup, err = importBatch(st, b, it.folder, writer, now)
			var bad *badBatch
			if err != nil && !errors.As(err, &bad) {
				return res, fmt.Errorf("import %s: %w", it.name, err)
			}
		}
		if err != nil {
			rej(it.dir, it.folder, it.name, err.Error())
			// The batch's number stays missing until it is sent again (SEC2).
			if trusted {
				if err := noteRejected(st, b, it.folder, now); err != nil {
					return res, err
				}
			}
			continue
		}
		if writer != "" {
			logf("inbox: imported %s, written by %s", filepath.Join(it.folder, it.name), writer)
		}
		if err := os.Remove(path); err != nil {
			logf("imported %s but could not remove it: %v (it will be skipped as a duplicate)", it.name, err)
		}
		if dup {
			res.Already++
			continue
		}
		res.Batches++
		res.Records += n
	}
	for _, r := range res.Rejected {
		logf("inbox: %s", r)
	}
	return res, nil
}

// importArchive verifies a log archive and files it. A different archive
// for a period already filed is kept next to it and raised (SEC1).
func importArchive(st *store.Store, dir, folder, name, archivesDir string, now time.Time) error {
	id, _, _ := strings.Cut(strings.TrimPrefix(name, archivePrefix), "_")
	if st.State.Send != nil && id == st.State.Send.ID {
		return fmt.Errorf("it was sent by this computer (a system cannot send to itself)")
	}
	path := filepath.Join(dir, name)
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	info, err := archive.Verify(path)
	if err != nil {
		if folder != "" && now.Sub(fi.ModTime()) < settle {
			return errWriting
		}
		return err
	}
	if !archive.UsableHost(info.Host) {
		return fmt.Errorf("its archive.json gives the computer as %q, which is not a usable name", info.Host)
	}
	if err := checkFolder(st, folder, info.Host, id); err != nil {
		return err
	}
	writer := fileOwner(path)
	dest, clash, err := archive.File(path, archivesDir, info)
	if err != nil {
		return err
	}
	bindFolder(st, folder, info.Host, now)
	if clash != "" {
		addConflict(st, store.InboxConflict{Time: now, Host: info.Host, Summary: fmt.Sprintf("Two different original-log archives from %s for %s to %s: both are kept and go into the report. One of them is not the computer's own log.",
			info.Host, info.From.UTC().Format("2006-01-02 15:04Z"), info.To.UTC().Format("2006-01-02 15:04Z")),
			Details: []string{"First", filepath.Base(clash), "Second", filepath.Base(dest), "Written by", orUnknown(writer), "Inbox folder", folderName(folder)}})
	}
	return st.Save()
}

// parseInboxName reads <sender>_<id>_<seq>.bbx, or <sender>_<id>_<seq>-N.bbx
// for a batch a sender delivered again under a new name (SEC1).
func parseInboxName(n string) (id string, seq uint64, ok bool) {
	parts := strings.Split(strings.TrimSuffix(n, batchExt), "_")
	if len(parts) < 3 {
		return "", 0, false
	}
	last, _, _ := strings.Cut(parts[len(parts)-1], "-")
	seq, err := strconv.ParseUint(last, 10, 64)
	if err != nil || seq == 0 {
		return "", 0, false
	}
	return parts[len(parts)-2], seq, parts[len(parts)-2] != ""
}

// rejectedDir is where unusable files are set aside, in the inbox.
const rejectedDir = "rejected"

// reject moves an unusable file to inbox/rejected (so it is not retried
// every run), with NAME.why.txt next to it, and describes why. It says
// "set aside" only if the move worked (L9): a file that can't be moved
// stays where it is, is tried again every run, and status and the report
// list it (Unreadable).
func reject(inbox, dir, folder, name, why string, now time.Time) string {
	rdir := filepath.Join(inbox, rejectedDir)
	writer := fileOwner(filepath.Join(dir, name))
	err := os.MkdirAll(rdir, 0o750)
	dest := name
	if err == nil {
		for i := 2; i < 100; i++ {
			if _, serr := os.Lstat(filepath.Join(rdir, dest)); serr != nil {
				break
			}
			dest = AgainName(name, i)
		}
		err = os.Rename(filepath.Join(dir, name), filepath.Join(rdir, dest))
	}
	shown := filepath.Join(folder, name)
	if err != nil {
		return fmt.Sprintf("%s could not be used (%s) and could not be set aside (%s); it stays in the inbox and is tried again every run",
			shown, why, errReason(err))
	}
	note := fmt.Sprintf("%s was set aside by Blackbox at %s.\n\nFrom:       %s\nWritten by: %s\nWhy:        %s\n\n"+
		"Its data is not in the reports. If it came from a Blackbox sender, fix the cause and send it again from that computer\n"+
		"(blackbox send --resend NUMBER); then delete this file and its note. Until then, blackbox status says so.\n",
		name, now.Format("2006-01-02 15:04:05 -07:00"), folderName(folder), orUnknown(writer), why)
	os.WriteFile(filepath.Join(rdir, dest+whyExt), []byte(strings.ReplaceAll(note, "\n", "\r\n")), 0o640)
	return fmt.Sprintf("%s was set aside in %s: %s", shown, rdir, why)
}

// whyExt is the note next to a rejected file.
const whyExt = ".why.txt"

// Rejected lists the files set aside in inbox/rejected, with why (from
// each one's note), oldest first (SEC2).
func Rejected(inbox string) []string {
	entries, err := os.ReadDir(filepath.Join(inbox, rejectedDir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, whyExt) || strings.HasPrefix(n, ".") {
			continue
		}
		why := ""
		if b, err := os.ReadFile(filepath.Join(inbox, rejectedDir, n+whyExt)); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(l, "Why:"); ok {
					why = strings.TrimSpace(v)
				}
			}
		}
		if why != "" {
			out = append(out, n+" ("+why+")")
		} else {
			out = append(out, n)
		}
	}
	return out
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

// importBatch appends one verified batch to the spool. A batch whose
// records can't be read is a *badBatch: nothing of it is stored.
func importBatch(st *store.Store, b *Batch, folder, writer string, now time.Time) (int, bool, error) {
	snd := st.State.Senders[b.SenderID]
	fresh := snd == nil
	if fresh {
		snd = &store.SenderState{Host: b.Sender, FirstSeen: now}
	}
	// A different batch under a number already imported is kept too, and
	// raised (SEC1): two computers using one sender ID (a cloned
	// computer), or a batch that is not what the sender sent.
	clash := false
	late := b.Seq <= snd.LastSeq
	if late && !inGap(snd.Missing, b.Seq) {
		prev, known := snd.Sums[b.Seq]
		if !known || prev == b.Sum {
			// Already imported (delivered twice). One imported before its
			// content was recorded can't be compared, and is taken to be.
			return 0, true, nil
		}
		clash = true
		if !strings.EqualFold(b.Sender, snd.Host) {
			raise(st, snd, "cloned|"+strings.ToUpper(b.Sender), b.Sender, now,
				fmt.Sprintf("Two computers are using one sender ID (a cloned machine?): %s and %s both send as %s. Both are kept. Run blackbox send --new-id on one of them.", snd.Host, b.Sender, b.SenderID),
				"Sender ID", b.SenderID, "Computers", snd.Host+", "+b.Sender, "Batch", strconv.FormatUint(b.Seq, 10), "Written by", orUnknown(writer), "Inbox folder", folderName(folder))
		} else {
			raise(st, snd, "batch|"+strconv.FormatUint(b.Seq, 10), b.Sender, now,
				fmt.Sprintf("Two different batches %d from %s: both are kept. One of them is not what %s's Blackbox sent.", b.Seq, b.Sender, b.Sender),
				"Sender ID", b.SenderID, "Batch", strconv.FormatUint(b.Seq, 10), "Written by", orUnknown(writer), "Inbox folder", folderName(folder))
		}
	}
	// A former name is accepted only if this sender ID used it before, or
	// an administrator accepted it (blackbox systems rename); a name that
	// is another computer still sending here is raised, not merged (SEC1).
	var former []string
	if b.Former != nil {
		former = []string{}
		for _, f := range b.Former {
			switch {
			case strings.EqualFold(f, b.Sender):
			case hasName(snd.Names, f) || strings.EqualFold(f, snd.Host) || hasName(snd.Former, f) || renameAccepted(st, f, b.Sender):
				former = append(former, f)
			case liveElsewhere(st, f, b.SenderID, now):
				raise(st, snd, "former|"+strings.ToUpper(f), b.Sender, now,
					fmt.Sprintf("%s says it was formerly called %s, but %s is another computer that still reports here. Its data is not merged into %s's. If %s really was renamed, run blackbox systems rename %s %s on this computer.", b.Sender, f, f, b.Sender, f, f, b.Sender),
					"Sender ID", b.SenderID, "Claimed former name", f, "Written by", orUnknown(writer), "Inbox folder", folderName(folder))
			}
		}
	}
	if fresh {
		st.State.Senders[b.SenderID] = snd
	}
	if !clash {
		// The first batch for this collector after the sender sent to
		// another (L13): the ones before it are not missing here. Only a
		// number close to the next one expected is taken (SEC1); a jump
		// is a gap like any other, and a gap already recorded is never
		// erased by it.
		if f := b.FirstSeq; f > 1 && b.Seq >= f && (fresh || f <= snd.LastSeq+1+firstSeqWindow) && snd.LastSeq < f-1 {
			snd.LastSeq = f - 1
			snd.StartSeq, snd.Earlier = f, b.Earlier
		}
		if b.Kept != nil {
			k := *b.Kept
			snd.Kept = &k
		}
		if former != nil {
			snd.Former = former
		}
	}

	// Received events count as collected now: that is when they became
	// available to this collector's reports, so one that arrives late goes
	// into the next report (marked Late) rather than being skipped.
	events := make([][]byte, 0, len(b.Events))
	for _, raw := range b.Events {
		var e event.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return 0, false, &badBatch{fmt.Sprintf("event %d can't be read: %v", len(events)+1, err)}
		}
		if e.Host == "" {
			e.Host = b.Sender
		}
		e.Collected = now
		e.Late = false
		out, err := marshal(&e)
		if err != nil {
			return 0, false, err
		}
		events = append(events, out)
	}
	runs := make([][]byte, 0, len(b.Runs))
	var runList []store.Run
	for _, raw := range b.Runs {
		var r store.Run
		if err := json.Unmarshal(raw, &r); err != nil {
			return 0, false, &badBatch{fmt.Sprintf("collection record %d can't be read: %v", len(runs)+1, err)}
		}
		if r.Host == "" {
			r.Host = b.Sender
		}
		if r.Received.IsZero() || r.Received.Before(now) {
			r.Received = now
		}
		out, err := marshal(&r)
		if err != nil {
			return 0, false, err
		}
		runs = append(runs, out)
		runList = append(runList, r)
	}
	checks := make([][]byte, 0, len(b.Checks))
	for _, raw := range b.Checks {
		var c store.CheckRecord
		if err := json.Unmarshal(raw, &c); err != nil {
			return 0, false, &badBatch{fmt.Sprintf("settings check %d can't be read: %v", len(checks)+1, err)}
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
		return 0, false, err
	}
	for _, n := range names {
		if err := st.AppendRaw(n, files[n]); err != nil {
			return 0, false, err
		}
	}

	// Bookkeeping: gaps in the sequence, the sender's clock, and which
	// systems this data came from.
	switch {
	case clash:
		// Kept, but the sender's numbering is the first batch's.
	case late:
		// A batch that was missing has arrived after all (out of order).
		snd.Missing = fillGap(snd.Missing, b.Seq)
	default:
		if b.Seq > snd.LastSeq+1 {
			snd.Missing = append(snd.Missing, store.SeqGap{From: snd.LastSeq + 1, To: b.Seq - 1, Noted: now})
		}
		snd.LastSeq = b.Seq
	}
	if !clash {
		snd.Host = b.Sender
		noteSum(snd, b.Seq, b.Sum)
	}
	if !hasName(snd.Names, b.Sender) {
		snd.Names = append(snd.Names, b.Sender)
	}
	if folder != "" {
		snd.Folder = folder
	}
	snd.Writer = writer
	bindFolder(st, folder, b.Sender, now)
	snd.Version = b.Version
	snd.LastReceived = now
	if lead := b.Created.Sub(now); lead > maxClockLead {
		snd.ClockAhead = roughly(lead)
		snd.ClockNoted = now
	}
	for _, r := range runList {
		st.NoteSystem(r.Host, r.OS, r.Version, b.Sender, r.Time, now, now)
	}
	if sys := st.State.Systems[store.SystemKey(b.Sender)]; sys != nil {
		if former != nil {
			sys.Former = former
		}
		sys.VM = b.VM
	}
	// Systems are only the computers that collect (they send runs), not
	// every host name in the events: old events can carry a computer's
	// former name (a renamed PC, or a VM cloned from an image), which is
	// not a separate computer that has gone silent.
	st.EndImport()
	if err := st.Save(); err != nil {
		return 0, false, err
	}
	return b.Records(), false, nil
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
