package lan

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// The collector's side of signed deliveries (DESIGN1): which key each
// computer signs with, pinned at its first signed delivery (trust on
// first use).
//
//   - A computer the collector has not seen is pinned to its key. With
//     new_senders = hold its deliveries wait in inbox/rejected/held until
//     "blackbox senders approve NAME".
//   - A known computer delivering under a different key (a reinstall, a
//     re-imaged computer, a restored data folder) is not imported: its
//     files wait in inbox/rejected/held, with a High row, until "blackbox
//     senders rekey NAME".
//   - One key on two computers (a computer cloned with its data folder) is
//     a High row; neither is merged into the other.
//   - Unsigned deliveries (senders before 0.24) are accepted from a
//     computer that has never delivered signed, unless require_signed =
//     yes. Once it has, an unsigned file claiming to be from it is
//     refused: there is no going back.
//
// The 0.23 checks (sender ID, numbering, former names, hashes) still
// apply after these, as a second line.

// heldDir is where held deliveries wait, in inbox/rejected.
const heldDir = "held"

// newSenderDays is how long status names a new sender.
const newSenderDays = 7

// verdict is what a delivery's signature means for it.
type verdict int

const (
	accept verdict = iota
	refuse
	hold
)

// delivery is what a file says about where it is from.
type delivery struct {
	host, id string
	pub      []byte   // the signer's public key; nil when unsigned
	former   []string // a batch's former names (a renamed computer)
}

// heldError is a delivery that waits for an administrator.
type heldError struct {
	why string
	pin *store.SenderKey
}

func (h *heldError) Error() string { return h.why }

// judge decides whether a delivery is taken, refused (and why) or held,
// and pins the key of a computer seen signed for the first time.
func judge(st *store.Store, d delivery, dirs Dirs, now time.Time) (verdict, error) {
	if st.State.SenderKeys == nil {
		st.State.SenderKeys = map[string]*store.SenderKey{}
	}
	hk := store.SystemKey(d.host)
	pin := st.State.SenderKeys[hk]
	snd := st.State.Senders[d.id]
	if d.pub == nil {
		switch {
		case dirs.RequireSigned:
			return refuse, fmt.Errorf("it is not signed, and this collector takes only signed deliveries (require_signed = yes): upgrade %s to Blackbox 0.24 or later", d.host)
		case pin != nil && pin.FirstSeen.Before(now):
			// Pinned in an earlier run: in one run, a sender's unsigned
			// batches from before its upgrade come before its signed ones.
			return refuse, fmt.Errorf("it is not signed, but %s has signed its deliveries since %s: an unsigned file claiming to be from it is refused", d.host, pin.FirstSeen.UTC().Format("2006-01-02 15:04Z"))
		case snd != nil && snd.KeyFP != "":
			return refuse, fmt.Errorf("it is not signed, but sender %s (%s) signs its deliveries: an unsigned file claiming to be from it is refused", d.id, snd.Host)
		}
		return accept, nil
	}
	fp := Fingerprint(d.pub)
	key := base64.StdEncoding.EncodeToString(d.pub)
	if pin == nil {
		pin = &store.SenderKey{Host: d.host, Key: key, FP: fp, FirstSeen: now, Since: now, Held: dirs.HoldNew}
		renamed := false
		for _, other := range st.State.SenderKeys {
			if other.FP != fp {
				continue
			}
			if wasCalled(st, other.Host, d.host, d.former, now) {
				renamed, pin.Held, pin.Since = true, other.Held, other.Since
				continue
			}
			pin.SharedWith = other.Host
			addConflict(st, store.InboxConflict{Time: now, Host: d.host,
				Summary: fmt.Sprintf("%s and %s sign with the same key (%s): a computer copied from another with its data folder? Both are kept, neither is merged into the other. On the copy, run blackbox send --new-id.", other.Host, d.host, fp),
				Details: []string{"Key", fp, "Computers", other.Host + ", " + d.host}})
		}
		st.State.SenderKeys[hk] = pin
		if !renamed && !pin.Held {
			addConflict(st, store.InboxConflict{Time: now, Host: d.host, Severity: "info",
				Summary: fmt.Sprintf("New sender: %s, signing with key %s, first seen %s. Compare the key with blackbox status on that computer.", d.host, fp, now.UTC().Format("2006-01-02 15:04Z")),
				Details: []string{"Key", fp}})
		}
	}
	switch {
	case pin.Held:
		return hold, &heldError{fmt.Sprintf("%s is a new sender (key %s) and new_senders = hold: its deliveries wait here until: blackbox senders approve %s", d.host, pin.FP, d.host), pin}
	case pin.FP != fp:
		if pin.NewFP != fp {
			pin.NewKey, pin.NewFP, pin.NewSeen = key, fp, now
			addConflict(st, store.InboxConflict{Time: now, Host: d.host,
				Summary: fmt.Sprintf("%s is now signing with a different key (%s, was %s). Its deliveries are not imported; they wait in the inbox's rejected\\held folder. If that computer was reinstalled: blackbox senders rekey %s", d.host, fp, pin.FP, d.host),
				Details: []string{"New key", fp, "Pinned key", pin.FP, "Pinned since", pin.Since.UTC().Format("2006-01-02 15:04Z")}})
		}
		return hold, &heldError{KeyChangeText(pin), pin}
	case snd != nil && snd.KeyFP != "" && snd.KeyFP != fp:
		return refuse, fmt.Errorf("its sender ID %s signs with key %s, but it is signed with %s", d.id, snd.KeyFP, fp)
	}
	pin.LastDelivery = now
	return accept, nil
}

// KeyChangeText is the status line for a computer signing with a new key.
func KeyChangeText(k *store.SenderKey) string {
	return fmt.Sprintf("%s is now signing with a different key (%s, was %s). If that computer was reinstalled: blackbox senders rekey %s", k.Host, k.NewFP, k.FP, k.Host)
}

// wasCalled reports whether host is the computer once called old: it says
// so (a former name it gives) and old does not still report here, or an
// administrator accepted it (blackbox systems rename).
func wasCalled(st *store.Store, old, host string, former []string, now time.Time) bool {
	if renameAccepted(st, old, host) {
		return true
	}
	return hasName(former, old) && !liveElsewhere(st, old, "", now)
}

// holdFile moves a delivery to inbox/rejected/held, with a note, and
// remembers it with the computer's pinned key.
func holdFile(inbox, name string, h *heldError, now time.Time) string {
	dir := filepath.Join(inbox, rejectedDir, heldDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Sprintf("%s is held, but could not be moved aside (%v); it stays in the inbox", name, err)
	}
	dest := name
	for i := 2; i < 100; i++ {
		if _, err := os.Lstat(filepath.Join(dir, dest)); err != nil {
			break
		}
		dest = AgainName(name, i)
	}
	if err := os.Rename(filepath.Join(inbox, name), filepath.Join(dir, dest)); err != nil {
		return fmt.Sprintf("%s is held, but could not be moved aside (%v); it stays in the inbox", name, errReason(err))
	}
	if _, err := os.Stat(filepath.Join(inbox, name+sigExt)); err == nil {
		os.Rename(filepath.Join(inbox, name+sigExt), filepath.Join(dir, dest+sigExt))
	}
	note := fmt.Sprintf("%s was held by Blackbox at %s.\n\nWhy: %s\n", name, now.Format("2006-01-02 15:04:05 -07:00"), h.why)
	os.WriteFile(filepath.Join(dir, dest+whyExt), []byte(strings.ReplaceAll(note, "\n", "\r\n")), 0o640)
	if h.pin != nil {
		h.pin.HeldFiles = append(h.pin.HeldFiles, dest)
	}
	return fmt.Sprintf("%s is held in %s: %s", name, dir, h.why)
}

// releaseHeld moves a computer's held files back into the inbox, where
// the next import takes them. It returns how many it moved.
func releaseHeld(inbox string, k *store.SenderKey) int {
	dir := filepath.Join(inbox, rejectedDir, heldDir)
	n := 0
	var left []string
	for _, name := range k.HeldFiles {
		src := filepath.Join(dir, name)
		if _, err := os.Stat(src); err != nil {
			continue // removed by hand
		}
		to := migratedName(name)
		if err := os.Rename(src, filepath.Join(inbox, to)); err != nil {
			left = append(left, name)
			continue
		}
		if _, err := os.Stat(src + sigExt); err == nil {
			os.Rename(src+sigExt, filepath.Join(inbox, to+sigExt))
		}
		os.Remove(src + whyExt)
		n++
	}
	k.HeldFiles = left
	return n
}

// Held lists the files waiting in inbox/rejected/held, with why.
func Held(inbox string) []string {
	dir := filepath.Join(inbox, rejectedDir, heldDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, whyExt) || strings.HasSuffix(n, sigExt) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// KeyAction is an administrator's decision about a computer's key.
type KeyAction string

const (
	Approve KeyAction = "approve" // a new computer held under new_senders = hold
	Rekey   KeyAction = "rekey"   // take the new key a known computer signs with
	Forget  KeyAction = "forget"  // drop the pinned key: the next one is pinned afresh
)

// SetKey carries out an administrator's decision about host's key, and
// moves its held files back into the inbox. It returns how many.
func SetKey(st *store.Store, inbox, host string, act KeyAction, who, why string, now time.Time) (int, error) {
	hk := store.SystemKey(host)
	k := st.State.SenderKeys[hk]
	if k == nil {
		return 0, fmt.Errorf("no sender called %s has signed a delivery here (see blackbox senders)", host)
	}
	moved := 0
	switch act {
	case Approve:
		if !k.Held {
			return 0, fmt.Errorf("%s is not waiting for approval", k.Host)
		}
		k.Held, k.Since = false, now
		k.Changes = append(k.Changes, store.KeyNote{What: "approved", FP: k.FP, Who: who, When: now, Reason: why})
		moved = releaseHeld(inbox, k)
	case Rekey:
		if k.NewFP == "" {
			return 0, fmt.Errorf("%s has not signed with a different key", k.Host)
		}
		old := k.FP
		k.Key, k.FP, k.Since = k.NewKey, k.NewFP, now
		k.NewKey, k.NewFP, k.NewSeen, k.Held = "", "", time.Time{}, false
		k.Changes = append(k.Changes, store.KeyNote{What: "rekeyed", FP: k.FP, Who: who, When: now, Reason: why + " (was " + old + ")"})
		forgetSenderKeys(st, k.Host)
		moved = releaseHeld(inbox, k)
	case Forget:
		delete(st.State.SenderKeys, hk)
		forgetSenderKeys(st, k.Host)
		moved = releaseHeld(inbox, k)
	default:
		return 0, fmt.Errorf("unknown action %q", act)
	}
	return moved, st.Save()
}

// forgetSenderKeys lets host's sender IDs sign with another key.
func forgetSenderKeys(st *store.Store, host string) {
	for _, s := range st.State.Senders {
		if strings.EqualFold(s.Host, host) {
			s.KeyFP = ""
		}
	}
}

// SenderKeys lists the pinned keys, by computer name.
func SenderKeys(st *store.Store) []*store.SenderKey {
	out := make([]*store.SenderKey, 0, len(st.State.SenderKeys))
	for _, k := range st.State.SenderKeys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Host) < strings.ToLower(out[j].Host) })
	return out
}
