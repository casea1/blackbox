package app

import (
	"errors"
	"strings"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/selfaudit"
	"github.com/casea1/blackbox/internal/store"
)

// The inbox is a trust boundary (SEC1): senders can add files to it but
// not list, read, change or delete anything in it (DESIGN1).

// RenameSystem accepts old as a former name of the computer now called
// name ("blackbox systems rename OLD NEW"): data recorded under old is
// then that computer's (SEC1).
func (a *App) RenameSystem(old, name string) error {
	if strings.EqualFold(old, name) {
		return errors.New("the two names are the same")
	}
	who := selfaudit.Who()
	st, unlock, err := a.open()
	if err != nil {
		return err
	}
	st.State.Renames = append(st.State.Renames, store.Rename{Old: old, New: name, Who: who, When: a.now()})
	if sys := st.State.Systems[store.SystemKey(name)]; sys != nil && !hasFold(sys.Former, old) {
		sys.Former = append(sys.Former, old)
	}
	err = st.Save()
	unlock()
	if err != nil {
		return err
	}
	a.recordAdmin(event.SelfChange{Kind: "setting", Who: who, Setting: "former_names", Old: "", New: old + " is now " + name, Program: "blackbox systems rename"})
	return nil
}

func hasFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// NewSendID gives this computer a new sender ID ("blackbox send
// --new-id"), for a computer cloned from another: the collector then
// tells the two apart (SEC1). Batches not delivered yet are renumbered
// under the new ID; those kept for resending stay with the old one.
func (a *App) NewSendID() (old, id string, err error) {
	st, unlock, err := a.open()
	if err != nil {
		return "", "", err
	}
	old, id, err = lan.NewID(st)
	unlock()
	if err != nil {
		return old, id, err
	}
	a.recordAdmin(event.SelfChange{Kind: "setting", Setting: "sender_id", Old: old, New: id, Program: "blackbox send --new-id"})
	return old, id, nil
}

// recordAdmin records a change made by an administrator command.
func (a *App) recordAdmin(c event.SelfChange) {
	if c.Who == "" {
		c.Who = selfaudit.Who()
	}
	record := a.RecordSelf
	if record == nil {
		record = selfaudit.Record
	}
	if err := record(a.Cfg.DataDir, c, a.now()); err != nil {
		a.logf("recording %s failed: %v", c.Program, err)
	}
}
