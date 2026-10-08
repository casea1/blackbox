package lan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// The inbox is a trust boundary (SEC1): each sender writes only into its
// own folder, and the collector checks that what a folder holds is from
// that folder's computer.

const (
	// settle is how long a file that can't be read whole yet is left for
	// its sender to finish writing it.
	settle = 10 * time.Minute
	// maxBatchFile is the largest batch file read (SEC3b).
	maxBatchFile = 256 << 20
	// firstSeqWindow is how far past the next batch expected a sender's
	// first_seq may be and still be taken (SEC1).
	firstSeqWindow = 16
	// sumsKept is how many recent batches' hashes are kept per sender.
	sumsKept = 2000
	// liveDays: a computer that reported within this many days is live.
	liveDays = 30
)

// SenderMarker is the file the collector puts in each sender's folder, so
// a sender finds the folder it may write to.
const SenderMarker = "BLACKBOX-SENDER.txt"

// errWriting: the file is still being written; it is tried at the next run.
var errWriting = errors.New("still being written")

// badBatch is a batch whose records can't be read (SEC2).
type badBatch struct{ why string }

func (b *badBatch) Error() string { return b.why }

// checkFolder says why a file in folder ("" for the shared inbox folder)
// that says it is from host and sender ID id can't be accepted, or nil.
func checkFolder(st *store.Store, folder, host, id string) error {
	snd := st.State.Senders[id]
	if folder == "" {
		if snd != nil && snd.Folder != "" {
			return fmt.Errorf("it is in the shared inbox folder, but sender %s (%s) delivers through its own folder %s", id, snd.Host, snd.Folder)
		}
		if f := folderOfHost(st, host); f != "" {
			return fmt.Errorf("it is in the shared inbox folder and says it is from %s, but %s delivers through its own folder %s", host, host, f)
		}
		return nil
	}
	if snd != nil && snd.Folder != "" && !strings.EqualFold(snd.Folder, folder) {
		return fmt.Errorf("its sender ID %s belongs to the folder %s (%s); if this is a cloned computer, run blackbox send --new-id on it", id, snd.Folder, snd.Host)
	}
	if f := folderOfHost(st, host); f != "" && !strings.EqualFold(f, folder) {
		return fmt.Errorf("it says it is from %s, which delivers through the folder %s, not %s", host, f, folder)
	}
	if b := st.State.InboxFolders[strings.ToUpper(folder)]; b != nil && len(b.Hosts) > 0 && !hostIn(b.Hosts, host) {
		return fmt.Errorf("it says it is from %s, but the folder %s is for %s (if the computer was renamed, run blackbox systems rename %s %s)",
			host, folder, strings.Join(b.Hosts, ", "), b.Hosts[len(b.Hosts)-1], host)
	}
	return nil
}

// folderOfHost is the inbox folder that host delivers through, or "".
func folderOfHost(st *store.Store, host string) string {
	for name, b := range st.State.InboxFolders {
		if hostIn(b.Hosts, host) {
			return name
		}
	}
	return ""
}

// bindFolder records host as the computer of folder, the first time a
// file from it is accepted (when the folder was made without one).
func bindFolder(st *store.Store, folder, host string, now time.Time) {
	if folder == "" || host == "" {
		return
	}
	if st.State.InboxFolders == nil {
		st.State.InboxFolders = map[string]*store.InboxFolder{}
	}
	k := strings.ToUpper(folder)
	b := st.State.InboxFolders[k]
	if b == nil {
		b = &store.InboxFolder{Added: now}
		st.State.InboxFolders[k] = b
	}
	if len(b.Hosts) == 0 {
		b.Hosts = []string{host}
	}
}

// hostIn reports whether host is one of hosts: names are compared without
// case, and a full name (dc01.example.mil) matches its first part.
func hostIn(hosts []string, host string) bool {
	short := func(h string) string {
		h, _, _ = strings.Cut(strings.TrimSpace(h), ".")
		return strings.ToUpper(h)
	}
	for _, h := range hosts {
		if h != "" && short(h) == short(host) {
			return true
		}
	}
	return false
}

func hasName(names []string, n string) bool {
	for _, x := range names {
		if strings.EqualFold(x, n) {
			return true
		}
	}
	return false
}

// renameAccepted reports whether an administrator accepted old as a former
// name of host (blackbox systems rename).
func renameAccepted(st *store.Store, old, host string) bool {
	for _, r := range st.State.Renames {
		if strings.EqualFold(r.Old, old) && strings.EqualFold(r.New, host) {
			return true
		}
	}
	return false
}

// liveElsewhere reports whether name is a computer, other than sender id,
// that reported here in the last liveDays: this collector, or another
// sender.
func liveElsewhere(st *store.Store, name, id string, now time.Time) bool {
	cut := now.AddDate(0, 0, -liveDays)
	for sid, s := range st.State.Senders {
		if sid != id && strings.EqualFold(s.Host, name) && s.LastReceived.After(cut) {
			return true
		}
	}
	if sys := st.State.Systems[store.SystemKey(name)]; sys != nil && sys.Removed.IsZero() {
		if snd := st.State.Senders[id]; snd != nil && hasName(snd.Names, name) {
			return false
		}
		return sys.LastRun.After(cut) || sys.LastReceived.After(cut) || (sys.LastReceived.IsZero() && sys.Direct)
	}
	return false
}

// noteSum records the hash of batch seq, keeping the most recent ones.
func noteSum(snd *store.SenderState, seq uint64, sum string) {
	if sum == "" {
		return
	}
	if snd.Sums == nil {
		snd.Sums = map[uint64]string{}
	}
	snd.Sums[seq] = sum
	if len(snd.Sums) > sumsKept {
		for n := range snd.Sums {
			if n+sumsKept <= snd.LastSeq {
				delete(snd.Sums, n)
			}
		}
	}
}

// noteRejected records a batch that was set aside as missing: its number
// is a gap until it is sent again (SEC2).
func noteRejected(st *store.Store, b *Batch, folder string, now time.Time) error {
	snd := st.State.Senders[b.SenderID]
	if snd == nil {
		snd = &store.SenderState{Host: b.Sender, FirstSeen: now}
		st.State.Senders[b.SenderID] = snd
	}
	switch {
	case b.Seq > snd.LastSeq:
		if n := len(snd.Missing); n > 0 && snd.Missing[n-1].To == snd.LastSeq && snd.LastSeq > 0 {
			snd.Missing[n-1].To = b.Seq // one gap for numbers set aside in a row
		} else {
			snd.Missing = append(snd.Missing, store.SeqGap{From: snd.LastSeq + 1, To: b.Seq, Noted: now})
		}
		snd.LastSeq = b.Seq
	default:
		return nil // still missing, or already imported
	}
	return st.Save()
}

// raise records a conflict about sender snd, unless the same one (kind)
// was raised in the last day.
func raise(st *store.Store, snd *store.SenderState, kind, host string, now time.Time, summary string, details ...string) {
	if snd.Raised == nil {
		snd.Raised = map[string]time.Time{}
	}
	if t, ok := snd.Raised[kind]; ok && now.Sub(t) < 24*time.Hour && !t.After(now) {
		return
	}
	snd.Raised[kind] = now
	addConflict(st, store.InboxConflict{Time: now, Host: host, Summary: summary, Details: details})
}

// addConflict keeps a conflict for the next report (and 90 days).
func addConflict(st *store.Store, c store.InboxConflict) {
	cut := c.Time.AddDate(0, 0, -90)
	st.State.InboxConflicts = slices.DeleteFunc(st.State.InboxConflicts, func(x store.InboxConflict) bool { return x.Time.Before(cut) })
	st.State.InboxConflicts = append(st.State.InboxConflicts, c)
}

// ConflictEvents are the High rows for the inbox conflicts recorded after
// after and up to until (SEC1).
func ConflictEvents(st *store.Store, after, until time.Time) []*event.Event {
	var out []*event.Event
	for _, c := range st.State.InboxConflicts {
		if c.Time.After(after) && !c.Time.After(until) {
			out = append(out, conflictEvent(c))
		}
	}
	return out
}

// conflictEvent is a High row about the inbox: data that claims to be
// from a computer but may not be (SEC1).
func conflictEvent(c store.InboxConflict) *event.Event {
	e := &event.Event{Time: c.Time, Collected: c.Time, Host: c.Host, Source: "Blackbox", RecordType: "Blackbox",
		Category: event.CatIntegrity, Severity: event.SevHigh, Action: "blackbox_inbox_conflict", Summary: c.Summary,
		Fields: map[string]string{"blackbox_inbox": "conflict"}}
	for i := 0; i+1 < len(c.Details); i += 2 {
		e.AddDetail(c.Details[i], c.Details[i+1])
	}
	e.AddDetail("Recorded by", "Blackbox on the collector, importing its inbox")
	e.DedupeKey = "bbinbox|" + strings.ToLower(c.Host) + "|" + c.Summary
	return e
}

func folderName(folder string) string {
	if folder == "" {
		return "the shared inbox folder"
	}
	return folder
}

func orUnknown(s string) string {
	if s == "" {
		return "not known"
	}
	return s
}

// AgainName is name with -n before its extension: a file delivered again
// under a new name, because a different file has the first one (SEC1).
func AgainName(name string, n int) string {
	for _, ext := range []string{scapExt, batchExt, archiveExt, whyExt} {
		if strings.HasSuffix(name, ext) {
			return fmt.Sprintf("%s-%d%s", strings.TrimSuffix(name, ext), n, ext)
		}
	}
	return fmt.Sprintf("%s-%d", name, n)
}

// SenderFolder is the folder in the inbox this computer delivers into:
// the one made for it (holding SenderMarker) that it can read, preferring
// one named after host or whose marker names it. "" means the shared inbox
// folder, as with collectors set up before SEC1.
func SenderFolder(inbox, host string) string {
	entries, err := os.ReadDir(inbox)
	if err != nil {
		return ""
	}
	var mine []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == rejectedDir || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(inbox, e.Name(), SenderMarker))
		if err != nil {
			continue
		}
		if strings.EqualFold(e.Name(), safeName(host)) || markerHost(string(b), host) {
			return e.Name()
		}
		mine = append(mine, e.Name())
	}
	if len(mine) == 1 {
		return mine[0]
	}
	return ""
}

// markerHost reports whether a sender folder's marker names host.
func markerHost(text, host string) bool {
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Computer:"); ok {
			for _, h := range strings.Split(v, ",") {
				if hostIn([]string{h}, host) {
					return true
				}
			}
		}
	}
	return false
}

// PrepareSenderFolder makes a sender's folder in the inbox, with its
// marker, and records which computer it is for (host may be "" to learn
// it from the first file). Access is set by the caller (install).
func PrepareSenderFolder(st *store.Store, inbox, folder, account, host string, now time.Time) (string, error) {
	folder = safeName(folder)
	if folder == "." || folder == ".." || strings.EqualFold(folder, rejectedDir) {
		return "", fmt.Errorf("%q can't be a folder name", folder)
	}
	dir := filepath.Join(inbox, folder)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	computer := host
	if computer == "" {
		computer = "(the first computer to deliver here)"
	}
	text := strings.ReplaceAll(fmt.Sprintf(`Blackbox sender folder
Account:  %s
Computer: %s
Created:  %s

Only this account can write here, and the collector accepts only data from
this computer from this folder. It imports the files and removes them.
`, account, computer, now.Format("2006-01-02 15:04")), "\n", "\r\n")
	if err := os.WriteFile(filepath.Join(dir, SenderMarker), []byte(text), 0o644); err != nil {
		return "", err
	}
	if st.State.InboxFolders == nil {
		st.State.InboxFolders = map[string]*store.InboxFolder{}
	}
	b := &store.InboxFolder{Account: account, Added: now}
	if host != "" {
		b.Hosts = []string{host}
	}
	if old := st.State.InboxFolders[strings.ToUpper(folder)]; old != nil && host == "" {
		b.Hosts = old.Hosts
	}
	st.State.InboxFolders[strings.ToUpper(folder)] = b
	return dir, st.Save()
}
