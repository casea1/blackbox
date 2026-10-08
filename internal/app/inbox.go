package app

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/install"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/selfaudit"
	"github.com/casea1/blackbox/internal/store"
)

// The inbox is a trust boundary (SEC1): each sender has its own folder in
// it, which only its account can write to.

// AddSenderFolder makes a sender's own folder in this collector's inbox
// ("blackbox inbox add NAME ACCOUNT"): only account can write there, and
// only data from host (or, if host is "", the first computer to deliver
// there) is accepted from it.
func (a *App) AddSenderFolder(name, account, host string) (string, error) {
	if a.Cfg.Inbox == "" {
		return "", errors.New("this computer is not a collector (it has no inbox)")
	}
	if account == "" {
		return "", errors.New("give the account the sender delivers with")
	}
	st, unlock, err := a.open()
	if err != nil {
		return "", err
	}
	dir, err := lan.PrepareSenderFolder(st, a.Cfg.Inbox, name, account, host, a.now())
	unlock()
	if err != nil {
		return "", err
	}
	if err := install.SenderFolderAccess(dir, account); err != nil {
		return dir, err
	}
	a.recordAdmin(event.SelfChange{Kind: "setting", Setting: "inbox_folder", New: filepath.Base(dir) + " for " + account, Program: "blackbox inbox add"})
	return dir, nil
}

// InboxFolders lists the senders' folders in the inbox.
func (a *App) InboxFolders(w io.Writer) error {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(st.State.InboxFolders))
	for n := range st.State.InboxFolders {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		fmt.Fprintln(w, "No sender has its own folder yet: senders deliver into the inbox itself, where every sender can write.")
		fmt.Fprintln(w, "Give each its own folder with: blackbox inbox add NAME ACCOUNT [--host COMPUTER]")
		return nil
	}
	for _, n := range names {
		f := st.State.InboxFolders[n]
		hosts := strings.Join(f.Hosts, ", ")
		if hosts == "" {
			hosts = "(the first computer to deliver there)"
		}
		fmt.Fprintf(w, "%-20s account %-24s computer %s\n", n, orDash(f.Account), hosts)
	}
	if shared := sharedSenders(st, a.now()); len(shared) > 0 {
		fmt.Fprintf(w, "\nStill delivering into the shared inbox folder: %s\n", strings.Join(shared, ", "))
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// RenameSystem accepts old as a former name of the computer now called
// name ("blackbox systems rename OLD NEW"): data recorded under old is
// then that computer's, and a sender folder for old takes name too (SEC1).
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
	for _, f := range st.State.InboxFolders {
		if hasFold(f.Hosts, old) && !hasFold(f.Hosts, name) {
			f.Hosts = append(f.Hosts, name)
		}
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
