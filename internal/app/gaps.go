package app

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/selfaudit"
	"github.com/casea1/blackbox/internal/store"
)

// Gaps lists, on a collector, the batches each sender's numbering says
// never arrived, and those accepted as never arriving (L13b).
func (a *App) Gaps(w io.Writer) error {
	st, unlock, err := a.open()
	if err != nil {
		return err
	}
	defer unlock()
	ids := make([]string, 0, len(st.State.Senders))
	for id := range st.State.Senders {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return st.State.Senders[ids[i]].Host < st.State.Senders[ids[j]].Host })
	n := 0
	for _, id := range ids {
		s := st.State.Senders[id]
		for _, g := range s.Missing {
			n++
			fmt.Fprintf(w, "Missing   %-20s batches %d-%d (noticed %s). %s\n", s.Host, g.From, g.To, stampLocal(g.Noted, a.loc()), ResendAdvice(s, g))
		}
		for _, g := range s.Accepted {
			n++
			fmt.Fprintf(w, "Accepted  %-20s batches %d-%d by %s on %s: %s\n", s.Host, g.From, g.To, g.Who, stampLocal(g.When, a.loc()), g.Reason)
		}
	}
	if n == 0 {
		fmt.Fprintln(w, "No missing batches.")
	}
	return nil
}

// AcceptGap records that batches from to to from a sender will not arrive
// (for example, they went to a previous collector): they are no longer
// missing, so they stop making "blackbox status" exit 4, and the next
// report shows who accepted them, when and why (L13b). Only batches that
// are missing can be accepted.
func (a *App) AcceptGap(host string, from, to uint64, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return errors.New("say why these batches will not arrive")
	}
	who := selfaudit.Who()
	st, unlock, err := a.open()
	if err != nil {
		return err
	}
	var snd *store.SenderState
	for _, s := range st.State.Senders {
		if strings.EqualFold(s.Host, host) {
			snd = s
		}
	}
	if snd == nil {
		unlock()
		return fmt.Errorf("no sender named %s (see blackbox gaps)", host)
	}
	var kept []store.SeqGap
	accepted := false
	for _, g := range snd.Missing {
		if to < g.From || from > g.To {
			kept = append(kept, g)
			continue
		}
		accepted = true
		lo, hi := max(from, g.From), min(to, g.To)
		if g.From < lo {
			kept = append(kept, store.SeqGap{From: g.From, To: lo - 1, Noted: g.Noted})
		}
		if hi < g.To {
			kept = append(kept, store.SeqGap{From: hi + 1, To: g.To, Noted: g.Noted})
		}
		snd.Accepted = append(snd.Accepted, store.AcceptedGap{From: lo, To: hi, Reason: reason, Who: who, When: a.now()})
	}
	if !accepted {
		unlock()
		return fmt.Errorf("batches %d-%d from %s are not missing (see blackbox gaps)", from, to, snd.Host)
	}
	snd.Missing = kept
	err = st.Save()
	unlock() // the record below opens the spool itself
	if err != nil {
		return err
	}
	record := a.RecordSelf
	if record == nil {
		record = selfaudit.Record
	}
	c := event.SelfChange{Kind: "gap_accepted", Who: who, Setting: snd.Host, New: fmt.Sprintf("%d-%d", from, to), Old: reason, Program: "blackbox gaps accept"}
	if rerr := record(a.Cfg.DataDir, c, a.now()); rerr != nil {
		a.logf("the gap was accepted, but recording it failed: %v", rerr)
	}
	return nil
}
