package app

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/selfaudit"
	"github.com/casea1/blackbox/internal/store"
)

// Signed deliveries, on the collector (DESIGN1): "blackbox senders" and
// the status lines about senders' keys.

// unsignedDays: a sender that delivered unsigned this recently is listed
// as one to upgrade.
const unsignedDays = 30

// Senders lists each computer that delivers here: its key's fingerprint,
// when it was first seen, its last delivery, and whether it signs.
func (a *App) Senders(w io.Writer) error {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return err
	}
	keys := lan.SenderKeys(st)
	unsigned := unsignedSenders(st, a.now())
	if len(keys) == 0 && len(unsigned) == 0 {
		fmt.Fprintln(w, "No computer has delivered here yet.")
		return nil
	}
	fmt.Fprintf(w, "%-20s %-10s %-52s %-17s %s\n", "COMPUTER", "DELIVERY", "KEY", "FIRST SEEN", "LAST DELIVERY")
	for _, k := range keys {
		state := "signed"
		switch {
		case k.Held:
			state = "HELD (new)"
		case k.NewFP != "":
			state = "NEW KEY"
		}
		fmt.Fprintf(w, "%-20s %-10s %-52s %-17s %s\n", k.Host, state, k.FP, stampLocal(k.FirstSeen, a.loc()), stampLocal(k.LastDelivery, a.loc()))
		if k.NewFP != "" {
			fmt.Fprintf(w, "%-20s %-10s %-52s %-17s (held since then; blackbox senders rekey %s)\n", "", "  now", k.NewFP, stampLocal(k.NewSeen, a.loc()), k.Host)
		}
		if k.SharedWith != "" {
			fmt.Fprintf(w, "%-20s same key as %s\n", "", k.SharedWith)
		}
	}
	for _, s := range unsigned {
		fmt.Fprintf(w, "%-20s %-10s %-52s %-17s %s\n", s.Host, "unsigned", "- (Blackbox before 0.24)", stampLocal(s.FirstSeen, a.loc()), stampLocal(s.LastReceived, a.loc()))
	}
	return nil
}

// unsignedSenders are the senders, not retired, that delivered unsigned
// in the last unsignedDays and have never signed: upgrade these to 0.24.
func unsignedSenders(st *store.Store, now time.Time) []*store.SenderState {
	seen := map[string]bool{}
	var out []*store.SenderState
	for _, s := range st.State.Senders {
		k := store.SystemKey(s.Host)
		if s.Unsigned.IsZero() || now.Sub(s.Unsigned) > unsignedDays*24*time.Hour || st.State.SenderKeys[k] != nil || retiredSender(st, s) || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Host) < strings.ToLower(out[j].Host) })
	return out
}

// retiredKey reports whether a pinned computer was removed with "blackbox
// systems remove" and has delivered nothing since.
func retiredKey(st *store.Store, k *store.SenderKey) bool {
	sys := st.State.Systems[store.SystemKey(k.Host)]
	return sys != nil && !sys.Removed.IsZero() && !k.LastDelivery.After(sys.Removed) && !k.NewSeen.After(sys.Removed)
}

// SenderKey carries out "blackbox senders approve|rekey|forget NAME
// [why]", and records who did it and why, like "reports accept": in
// the spool, and in the Application log (event 102) or the journal.
func (a *App) SenderKey(name string, act lan.KeyAction, why string) (int, error) {
	if a.Cfg.Inbox == "" {
		return 0, errors.New("this computer is not a collector (it has no inbox)")
	}
	why = strings.TrimSpace(why)
	if why == "" {
		why = "no reason given"
	}
	who := selfaudit.Who()
	st, unlock, err := a.open()
	if err != nil {
		return 0, err
	}
	host := name
	if k := st.State.SenderKeys[store.SystemKey(name)]; k != nil {
		host = k.Host
	}
	n, err := lan.SetKey(st, a.Cfg.Inbox, name, act, who, why, a.now())
	unlock()
	if err != nil {
		return 0, err
	}
	done := map[lan.KeyAction]string{lan.Approve: "approved", lan.Rekey: "rekeyed", lan.Forget: "forgotten"}[act]
	a.recordAdmin(event.SelfChange{Kind: "sender_key", Who: who, Setting: host, New: done, Old: why, Program: "blackbox senders " + string(act)})
	return n, nil
}

// senderStatus writes the collector's status lines about senders' keys,
// and returns what needs attention.
func (a *App) senderStatus(st *store.Store, now time.Time, p func(string, string, ...any)) []string {
	var attention []string
	var unsignedNames []string
	for _, s := range unsignedSenders(st, now) {
		unsignedNames = append(unsignedNames, s.Host)
	}
	for _, k := range lan.SenderKeys(st) {
		if retiredKey(st, k) {
			continue
		}
		switch {
		case k.Held:
			attention = append(attention, "a new sender waits for approval")
			p("NEW SENDER HELD:", "%s (key %s, first seen %s). Its deliveries wait until: blackbox senders approve %s", k.Host, k.FP, stampLocal(k.FirstSeen, a.loc()), k.Host)
		case k.NewFP != "":
			attention = append(attention, k.Host+" signs with a different key")
			p("KEY CHANGED:", "%s", lan.KeyChangeText(k))
		case now.Sub(k.FirstSeen) < 7*24*time.Hour && k.FirstSeen.Equal(k.Since):
			p("New sender:", "%s (key %s, first seen %s)", k.Host, k.FP, stampLocal(k.FirstSeen, a.loc()))
		}
		if k.SharedWith != "" {
			attention = append(attention, "two computers sign with one key")
			p("SAME KEY:", "%s and %s sign with the same key (%s): one was copied from the other with its data folder. On the copy, run: blackbox send --new-id", k.SharedWith, k.Host, k.FP)
		}
	}
	if len(unsignedNames) > 0 {
		p("Unsigned:", "%s deliver%s unsigned (Blackbox before 0.24): upgrade these to 0.24", strings.Join(unsignedNames, ", "), map[bool]string{true: "s"}[len(unsignedNames) == 1])
		if a.Cfg.RequireSigned {
			attention = append(attention, "unsigned deliveries are refused")
		}
	}
	if held := lan.Held(lan.SetAsideDir(a.Cfg.DataDir)); len(held) > 0 {
		p("Held:", "%d file%s wait in %s (see the lines above)", len(held), map[bool]string{true: "s"}[len(held) != 1], heldPath(a.Cfg.DataDir))
	}
	return attention
}

func heldPath(dataDir string) string {
	sep := "/"
	if strings.Contains(dataDir, `\`) {
		sep = `\`
	}
	return strings.TrimRight(dataDir, `\/`) + sep + "inbox-set-aside" + sep + "held"
}

// signingStatus writes a sender's status line about its own key, and
// returns what needs attention: a key file others can read.
func (a *App) signingStatus(p func(string, string, ...any)) []string {
	k, err := lan.LoadKey(a.Cfg.DataDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		p("Signing key:", "none yet (made at the next delivery)")
		return nil
	case err != nil:
		p("SIGNING KEY:", "can't be read: %v", err)
		return []string{"the signing key can't be read"}
	}
	p("Signing key:", "%s (the collector shows this in blackbox senders)", k.Fingerprint())
	if prob := lan.KeyProblem(a.Cfg.DataDir); prob != "" {
		p("SIGNING KEY EXPOSED:", "%s", prob)
		return []string{"the signing key can be read by other accounts"}
	}
	return nil
}

// delivery is how host's data reached this collector, for the report
// (DESIGN1): nil for a computer that has not delivered here (this one).
func delivery(st *store.Store, host string, start time.Time) *report.Delivery {
	if k := st.State.SenderKeys[store.SystemKey(host)]; k != nil {
		return &report.Delivery{Signed: true, KeyFP: k.FP, Since: k.Since, New: k.FirstSeen.After(start),
			Held: k.Held, NewKeyFP: k.NewFP, SharedWith: k.SharedWith}
	}
	for _, s := range st.State.Senders {
		if strings.EqualFold(s.Host, host) && !s.Unsigned.IsZero() {
			return &report.Delivery{}
		}
	}
	return nil
}
