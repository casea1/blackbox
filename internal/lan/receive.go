package lan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	Held     []string // files waiting for blackbox senders approve or rekey (DESIGN1)
}

// maxClockLead is how far a sender's clock may be ahead before it is noted.
const maxClockLead = 10 * time.Minute

// Dirs are where a collector files what senders deliver besides events:
// log archives, and SCAP scan results ("" leaves them in the inbox).
type Dirs struct {
	Archives, Scap string
	// HoldNew (new_senders = hold) holds a new computer's deliveries
	// until "blackbox senders approve"; RequireSigned (require_signed =
	// yes) refuses unsigned ones (DESIGN1).
	HoldNew, RequireSigned bool
}

// Import reads every complete batch in the inbox into the store, in order
// for each sender, and removes each file once its data is safely stored.
// A batch this system sent itself is refused, which stops a loop if two
// systems were set to send to each other.
//
// The inbox is drop-only (DESIGN1): senders write each file straight
// under its final name, so a file may still be being written. One that
// can't be read whole is left for settle (10 minutes) after it was last
// written, then refused as incomplete. The per-sender folders of 0.23
// are emptied into the inbox first (MigrateSenderFolders).
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
	aside := SetAsideDir(st.Dir)
	migrateSetAside(inbox, aside, logf)
	MigrateSenderFolders(st, inbox, logf)
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
	rej := func(name, why string) {
		res.Rejected = append(res.Rejected, reject(aside, inbox, "", name, why, now))
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() {
			continue
		}
		if !e.Type().IsRegular() {
			rej(n, errNotRegular.Error()) // never opened (SEC6)
			continue
		}
		if !isDelivery(n) {
			// Not something a sender delivers (SEC1f): set aside once it
			// has not changed for settle, so nothing fills the inbox unseen.
			// One already gone was set aside with the file it signs.
			if fi, err := os.Lstat(filepath.Join(inbox, n)); err == nil && !writing(fi, now) {
				rej(n, "it is not a Blackbox delivery (a batch, log archive, SCAP result or signature), and senders put nothing else in the inbox")
			}
			continue
		}
		switch {
		case dirs.Archives != "" && strings.HasPrefix(n, archivePrefix) && strings.HasSuffix(n, archiveExt):
			var h *heldError
			switch err := importArchive(st, inbox, n, dirs, now); {
			case errors.Is(err, errWriting):
			case errors.As(err, &h):
				res.Held = append(res.Held, holdFile(aside, inbox, n, h, now))
			case err != nil:
				rej(n, err.Error())
			default:
				res.Archives++
			}
			continue
		case dirs.Scap != "" && strings.HasPrefix(n, scapPrefix) && strings.HasSuffix(n, scapExt):
			var h *heldError
			switch err := importScap(st, inbox, n, dirs, now); {
			case errors.Is(err, errWriting):
			case errors.As(err, &h):
				res.Held = append(res.Held, holdFile(aside, inbox, n, h, now))
			case err != nil:
				rej(n, err.Error())
			default:
				res.Scap++
			}
			continue
		case !strings.HasSuffix(n, batchExt):
			continue
		}
		id, seq, ok := parseInboxName(n)
		if !ok {
			rej(n, "file name is not a Blackbox batch name")
			continue
		}
		items = append(items, item{n, id, seq})
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
		path := filepath.Join(inbox, it.name)
		// The size is checked before the file is read (SEC3b), and only a
		// regular file is read (SEC6).
		data, fi, err := readInbox(path, maxBatchFile)
		if fi != nil && fi.Size() > maxBatchFile {
			rej(it.name, fmt.Sprintf("it is %d MB, larger than any batch Blackbox makes (%d MB)", fi.Size()>>20, maxBatchFile>>20))
			continue
		}
		if err != nil {
			// One file that can't be read must not hold up the others (L1).
			rej(it.name, "it could not be read: "+err.Error())
			continue
		}
		b, err := Decode(bytes.NewReader(data))
		if err != nil && truncated(err) {
			if writing(fi, now) {
				continue // its sender may still be writing it (DESIGN1)
			}
			err = incomplete(err)
		}
		trusted := b != nil && b.SenderID == it.id && b.Seq == it.seq
		if b != nil && !trusted {
			err = fmt.Errorf("its contents say sender %s batch %d", b.SenderID, b.Seq)
		}
		if trusted && st.State.Send != nil && b.SenderID == st.State.Send.ID {
			err, trusted = fmt.Errorf("it was sent by this computer (a system cannot send to itself)"), false
		}
		// Its signature (DESIGN1); the checks below are the second line.
		// Only a delivery whose signature verified is authenticated: what
		// else it says (its number, its sender) may come from anyone who
		// can write to the inbox, so nothing about that sender is changed
		// for it when it is refused (SEC4).
		var pub []byte
		authed := false
		if err == nil {
			if pub, err = verifyBatch(b); err != nil {
				trusted = false // not shown to be its sender's: no gap is noted
			} else {
				authed = pub != nil
			}
		}
		// An unsigned copy of a batch already imported (signed) is the
		// same batch delivered again, such as a copy from the sender's
		// outbox\sent: nothing new in it (SEC1f). One that is not an
		// exact copy goes on to be judged, and refused if its sender signs.
		if err == nil && trusted && pub == nil && importedAlready(st, b) {
			logf("inbox: %s is an unsigned copy of batch %d from %s, already imported; removed", it.name, b.Seq, b.Sender)
			if err := os.Remove(path); err != nil {
				logf("inbox: could not remove %s: %v (it will be skipped as a duplicate)", it.name, err)
			}
			res.Already++
			continue
		}
		if err == nil {
			v, jerr := judge(st, delivery{host: b.Sender, id: b.SenderID, pub: pub, former: b.Former}, dirs, now)
			var h *heldError
			switch {
			case v == hold && errors.As(jerr, &h):
				res.Held = append(res.Held, holdFile(aside, inbox, it.name, h, now))
				st.Save()
				continue
			case v == refuse:
				err, trusted = jerr, false
			}
		}
		writer := fileOwner(path)
		var n int
		var dup bool
		if err == nil {
			n, dup, err = importBatch(st, b, writer, now)
			var bad *badBatch
			if err != nil && !errors.As(err, &bad) {
				return res, fmt.Errorf("import %s: %w", it.name, err)
			}
		}
		if err != nil {
			rej(it.name, err.Error())
			// The batch's number stays missing until it is sent again (SEC2),
			// if the batch was shown to be its sender's (SEC4).
			if trusted && authed {
				if err := noteRejected(st, b, now); err != nil {
					return res, err
				}
			}
			continue
		}
		noteSigned(st, b.SenderID, pub, now)
		if writer != "" {
			// A batch delivered again adds nothing: its line says so (LOG2).
			if dup {
				logf("inbox: %s was already imported (sent again), written by %s", it.name, writer)
			} else {
				logf("inbox: imported %s, written by %s", it.name, writer)
			}
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
	removeOrphanSigs(inbox, now, logf)
	for _, r := range res.Rejected {
		logf("inbox: %s", r)
	}
	for _, r := range res.Held {
		logf("inbox: %s", r)
	}
	if len(res.Held) > 0 {
		st.Save()
	}
	return res, nil
}

// importedAlready reports whether b is exactly a batch already imported
// from its sender ID: the same number, not missing, with the same content
// hash (which Decode checked against the content).
func importedAlready(st *store.Store, b *Batch) bool {
	snd := st.State.Senders[b.SenderID]
	if snd == nil || b.Sum == "" || b.Seq > snd.LastSeq || inGap(snd.Missing, b.Seq) {
		return false
	}
	return snd.Sums[b.Seq] == b.Sum
}

// isDelivery reports whether a file in the inbox is something a sender
// delivers, or the inbox's marker: a batch, log archive, SCAP result or
// the signature of one. A 0.24 sender writes each under its final name
// (DESIGN1), so a hidden or temporary name is not one either. Anything
// else is set aside (SEC1f).
func isDelivery(n string) bool {
	switch {
	case n == MarkerFile:
		return true
	case strings.HasSuffix(n, sigExt):
		return isDelivery(strings.TrimSuffix(n, sigExt))
	case strings.HasPrefix(n, "."):
		return false
	}
	return strings.HasSuffix(n, batchExt) ||
		strings.HasPrefix(n, archivePrefix) && strings.HasSuffix(n, archiveExt) ||
		strings.HasPrefix(n, scapPrefix) && strings.HasSuffix(n, scapExt)
}

// noteSigned records whether a sender ID's latest batch was signed, and
// with which key: from then on it signs with that one (DESIGN1).
func noteSigned(st *store.Store, id string, pub []byte, now time.Time) {
	snd := st.State.Senders[id]
	if snd == nil {
		return
	}
	if pub == nil {
		snd.Unsigned = now
	} else {
		snd.KeyFP = Fingerprint(pub)
	}
	st.Save()
}

// removeOrphanSigs removes a signature file whose archive or SCAP result
// is not in the inbox, once it has waited settle, and logs it. Such a file
// is left when a sender stopped between the two (it delivers the file
// again under a new name, with a new signature), and by a 0.23 collector,
// which imports the file and leaves its signature: senders are upgraded
// before the collector (DESIGN1). A signature alone holds nothing to
// import, so it is not set aside as a refused delivery.
func removeOrphanSigs(inbox string, now time.Time, logf func(string, ...any)) {
	entries, err := os.ReadDir(inbox)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, sigExt) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(inbox, strings.TrimSuffix(n, sigExt))); err == nil {
			continue
		}
		if fi, err := e.Info(); err != nil || writing(fi, now) {
			continue
		}
		if err := os.Remove(filepath.Join(inbox, n)); err == nil {
			logf("inbox: removed %s, a signature whose archive or SCAP result is not in the inbox (already imported, or delivered again under another name)", n)
		}
	}
}

// writing reports whether a file that can't be read whole may still be
// being written: it changed less than settle ago (DESIGN1). A file dated
// after now (a sender's clock ahead of the collector's) counts as one.
func writing(fi os.FileInfo, now time.Time) bool {
	return fi != nil && now.Sub(fi.ModTime()) < settle
}

// truncated reports whether err is what a file cut short gives: it ends
// before its gzip stream or its end marker do.
func truncated(err error) bool {
	return errors.Is(err, ErrIncomplete) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

// incomplete is the reason a file that stayed cut short is refused.
func incomplete(err error) error {
	return fmt.Errorf("it is incomplete (%v) and has not changed for %d minutes: its sender stopped part way through writing it, and sends it again by itself", err, int(settle.Minutes()))
}

// importArchive verifies a log archive and files it. A different archive
// for a period already filed is kept next to it and raised (SEC1).
func importArchive(st *store.Store, dir, name string, dirs Dirs, now time.Time) error {
	id, _, _ := strings.Cut(strings.TrimPrefix(name, archivePrefix), "_")
	if st.State.Send != nil && id == st.State.Send.ID {
		return fmt.Errorf("it was sent by this computer (a system cannot send to itself)")
	}
	path := filepath.Join(dir, name)
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, _, err := openInbox(path) // a regular file only (SEC6)
	if err != nil {
		return err
	}
	info, err := archive.VerifyReader(f, fi.Size())
	f.Close()
	if err != nil {
		// A zip cut short can't be told from a damaged one (DESIGN1).
		if writing(fi, now) {
			return errWriting
		}
		return err
	}
	if !archive.UsableHost(info.Host) {
		return fmt.Errorf("its archive.json gives the computer as %q, which is not a usable name", info.Host)
	}
	// Its signature, in NAME.sig, written before it (DESIGN1).
	sig, pub, err := readSig(path, "archive")
	switch {
	case errors.Is(err, errSigIncomplete) && writing(fi, now):
		return errWriting
	case err != nil:
		return err
	case sig != nil && (!strings.EqualFold(sig.Host, info.Host) || sig.SenderID != id || sig.What != archiveWhat(info.From, info.To)):
		return fmt.Errorf("its signature is for %s (sender %s) %s, but its archive.json says %s %s", sig.Host, sig.SenderID, sig.What, info.Host, archiveWhat(info.From, info.To))
	}
	if v, err := judge(st, delivery{host: info.Host, id: id, pub: pub}, dirs, now); v != accept {
		return err
	}
	writer := fileOwner(path)
	// It is moved out of the inbox before it is filed, and checked again
	// there, where no sender can change what the name points to (SEC6).
	staged, err := stage(st, path, sig)
	if err != nil {
		return err
	}
	dest, clash, err := archive.File(staged, dirs.Archives, info)
	if err != nil {
		moveFile(staged, path)
		return err
	}
	if clash != "" {
		addConflict(st, store.InboxConflict{Time: now, Host: info.Host, Summary: fmt.Sprintf("Two different original-log archives from %s for %s to %s: both are kept and go into the report. One of them is not the computer's own log.",
			info.Host, info.From.UTC().Format("2006-01-02 15:04Z"), info.To.UTC().Format("2006-01-02 15:04Z")),
			Details: []string{"First", filepath.Base(clash), "Second", filepath.Base(dest), "Written by", orUnknown(writer)}})
	}
	os.Remove(path + sigExt)
	return st.Save()
}

// stage moves an archive out of the inbox into the data folder, and
// checks it is still a regular file with the contents its signature
// gives. On error it is back in the inbox.
func stage(st *store.Store, path string, sig *sigFile) (string, error) {
	dir := filepath.Join(st.Dir, "inbox-importing")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	staged := filepath.Join(dir, filepath.Base(path))
	os.Remove(staged)
	if err := moveFile(path, staged); err != nil {
		return "", err
	}
	fi, err := os.Lstat(staged)
	switch {
	case err != nil:
	case !fi.Mode().IsRegular():
		err = errNotRegular
	case sig != nil:
		if sum, serr := fileSHA256(staged); serr != nil || !strings.EqualFold(sum, sig.SHA256) {
			err = errors.New("it changed while it was being imported")
		}
	}
	if err != nil {
		moveFile(staged, path)
		return "", err
	}
	return staged, nil
}

// parseInboxName reads HOST_ID_SEQ-RANDOM.bbx (0.24, DESIGN1), and
// HOST_ID_SEQ.bbx or HOST_ID_SEQ-N.bbx from earlier senders: what follows
// the first dash in the last part is not the sequence number.
func parseInboxName(n string) (id string, seq uint64, ok bool) {
	parts := strings.Split(strings.TrimSuffix(n, batchExt), "_")
	if len(parts) != 3 {
		return "", 0, false
	}
	last, _, _ := strings.Cut(parts[2], "-")
	seq, err := strconv.ParseUint(last, 10, 64)
	if err != nil || seq == 0 {
		return "", 0, false
	}
	return parts[1], seq, parts[1] != ""
}

// MigrateSenderFolders empties the per-sender folders 0.23 made in the
// inbox (DESIGN1): what is waiting in each is moved into the inbox itself,
// under a name of its own, and imported there like any other delivery;
// then the folder is removed. A file that can't be moved yet (still open)
// stays, with its folder, and is moved at the next run. The 0.23 record of
// the folders is dropped once they are gone (st nil: setup, which finds
// the folders by their marker alone).
func MigrateSenderFolders(st *store.Store, inbox string, logf func(string, ...any)) int {
	entries, err := os.ReadDir(inbox)
	if err != nil {
		return 0
	}
	moved, left := 0, false
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() || n == rejectedDir || strings.HasPrefix(n, ".") {
			continue
		}
		dir := filepath.Join(inbox, n)
		if _, err := os.Stat(filepath.Join(dir, legacyMarker)); err != nil && (st == nil || st.State.InboxFolders[strings.ToUpper(n)] == nil) {
			continue // not a sender folder: someone else's, left alone
		}
		files, err := os.ReadDir(dir)
		if err != nil {
			logf("inbox: cannot read the 0.23 sender folder %s: %v", n, err)
			left = true
			continue
		}
		for _, f := range files {
			fn := f.Name()
			if f.IsDir() || fn == legacyMarker {
				continue
			}
			if strings.HasSuffix(fn, sigExt) {
				if _, err := os.Lstat(filepath.Join(dir, strings.TrimSuffix(fn, sigExt))); err == nil {
					continue // moved with its file, below
				}
			}
			to := migratedName(fn)
			for i := 0; i < dropTries; i++ {
				if _, err := os.Lstat(filepath.Join(inbox, to)); err != nil {
					break
				}
				to = migratedName(fn)
			}
			if err := os.Rename(filepath.Join(dir, fn), filepath.Join(inbox, to)); err != nil {
				logf("inbox: cannot move %s out of the 0.23 sender folder %s yet: %v", fn, n, err)
				continue
			}
			// A 0.24 sender delivering into its 0.23 folder (it was upgraded
			// first) put the file's signature next to it: it goes along.
			if _, err := os.Lstat(filepath.Join(dir, fn+sigExt)); err == nil {
				if err := os.Rename(filepath.Join(dir, fn+sigExt), filepath.Join(inbox, to+sigExt)); err != nil {
					logf("inbox: cannot move %s out of the 0.23 sender folder %s yet: %v", fn+sigExt, n, err)
				}
			}
			moved++
			logf("inbox: moved %s out of the 0.23 sender folder %s, as %s", fn, n, to)
		}
		os.Remove(filepath.Join(dir, legacyMarker))
		if err := os.Remove(dir); err != nil {
			logf("inbox: the 0.23 sender folder %s is not empty yet; it is removed at a later run", n)
			left = true
			continue
		}
		logf("inbox: removed the 0.23 sender folder %s (0.24 senders deliver into the inbox itself)", n)
	}
	if st != nil && !left && len(st.State.InboxFolders) > 0 {
		st.State.InboxFolders = nil
		st.Save()
	}
	return moved
}

// migratedName is a file's name once moved out of a 0.23 sender folder: a
// random part is added (after a dash, as a 0.24 sender names its files),
// so it can't clash with a file in the inbox.
func migratedName(n string) string {
	if f, ok := strings.CutSuffix(n, sigExt); ok {
		return migratedName(f) + sigExt
	}
	for _, ext := range []string{scapExt, batchExt, archiveExt} {
		if strings.HasSuffix(n, ext) {
			return strings.TrimSuffix(n, ext) + "-" + randomPart() + ext
		}
	}
	return n + "-" + randomPart()
}

// rejectedDir is where versions before 0.27 set unusable files aside, in
// the inbox; they are moved to SetAsideDir (migrateSetAside).
const rejectedDir = "rejected"

// reject moves an unusable file to inbox/rejected (so it is not retried
// every run), with NAME.why.txt next to it, and describes why. It says
// "set aside" only if the move worked (L9): a file that can't be moved
// stays where it is, is tried again every run, and status and the report
// list it (Unreadable).
func reject(aside, dir, folder, name, why string, now time.Time) string {
	writer := fileOwner(filepath.Join(dir, name))
	note := fmt.Sprintf("%s was set aside by Blackbox at %s.\n\nWritten by: %s\nWhy:        %s\n\n"+
		"Its data is not in the reports. If it came from a Blackbox sender, fix the cause and send it again from that computer\n"+
		"(blackbox send --resend NUMBER); then delete this file and its note. Until then, blackbox status says so.\n",
		name, now.Format("2006-01-02 15:04:05 -07:00"), orUnknown(writer), why)
	_, err := setAside(dir, name, aside, note)
	shown := name
	if folder != "" {
		shown = filepath.Join(folder, name)
	}
	if err != nil {
		return fmt.Sprintf("%s could not be used (%s) and could not be set aside (%s); it stays in the inbox and is tried again every run",
			shown, why, errReason(err))
	}
	return fmt.Sprintf("%s was set aside in %s: %s", shown, aside, why)
}

// whyExt is the note next to a rejected file.
const whyExt = ".why.txt"

// Rejected lists the files set aside in inbox/rejected, with why (from
// each one's note), oldest first (SEC2).
func Rejected(aside string) []string {
	entries, err := os.ReadDir(aside)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, whyExt) {
			continue
		}
		// A signature set aside with its file is listed with it; one set
		// aside alone (SEC1f) is listed itself.
		if f, ok := strings.CutSuffix(n, sigExt); ok {
			if _, err := os.Lstat(filepath.Join(aside, f)); err == nil {
				continue
			}
		}
		why := ""
		if b, err := os.ReadFile(filepath.Join(aside, n+whyExt)); err == nil {
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
		f, _, err := openInbox(filepath.Join(inbox, n))
		if errors.Is(err, errNotRegular) {
			continue // set aside at the next import
		}
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
func importBatch(st *store.Store, b *Batch, writer string, now time.Time) (int, bool, error) {
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
				"Sender ID", b.SenderID, "Computers", snd.Host+", "+b.Sender, "Batch", strconv.FormatUint(b.Seq, 10), "Written by", orUnknown(writer))
		} else {
			raise(st, snd, "batch|"+strconv.FormatUint(b.Seq, 10), b.Sender, now,
				fmt.Sprintf("Two different batches %d from %s: both are kept. One of them is not what %s's Blackbox sent.", b.Seq, b.Sender, b.Sender),
				"Sender ID", b.SenderID, "Batch", strconv.FormatUint(b.Seq, 10), "Written by", orUnknown(writer))
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
					"Sender ID", b.SenderID, "Claimed former name", f, "Written by", orUnknown(writer))
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
	snd.Writer = writer // information only: the account is not trusted
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
