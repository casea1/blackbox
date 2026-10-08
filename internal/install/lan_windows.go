//go:build windows

package install

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/hidden"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/share"
)

const isWindows = true

// ShareName is the network share name for a collector's inbox.
const ShareName = "BlackboxInbox"

// DefaultInbox is the suggested inbox folder for a collector.
func DefaultInbox() string { return `C:\BlackboxInbox` }

// FindInboxes lists collector inboxes this computer can already see.
func FindInboxes() []string { return nil }

// TryInbox checks the collector's inbox can be reached with the account.
func TryInbox(sendTo, user, pw string) error {
	if config.IsShare(sendTo) {
		if err := share.Connect(sendTo, user, pw); err != nil {
			return err
		}
	}
	if !lan.IsInbox(sendTo) {
		if _, err := os.Stat(sendTo); err != nil {
			return fmt.Errorf("cannot open %s: %v", sendTo, err)
		}
		return fmt.Errorf("%s is reachable but is not a Blackbox inbox; on the collector, run the installer and choose \"This is the collector\" first", sendTo)
	}
	return nil
}

// prepareInbox creates the collector's inbox: the folder and its marker,
// access for Administrators, SYSTEM and the Blackbox Senders group, the
// accounts allowed to deliver, and (optionally) the network share.
func prepareInbox(opt Options, logf func(string, ...any)) error {
	dir := opt.Inbox
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := lan.PrepareInbox(dir, collect.LocalHost()); err != nil {
		return err
	}
	if out, err := hidden.Command("net.exe", "localgroup", SendersGroup).CombinedOutput(); err != nil {
		if out, err := hidden.Command("net.exe", "localgroup", SendersGroup, "/add",
			"/comment:Accounts that may deliver Blackbox audit data to this collector's inbox").CombinedOutput(); err != nil {
			return fmt.Errorf("create the %q group: %v: %s", SendersGroup, err, strings.TrimSpace(string(out)))
		}
		logf("Local group:         %q created (accounts that may deliver to the inbox)", SendersGroup)
	} else {
		_ = out
	}
	// Folder permissions: full control for Administrators and SYSTEM (by
	// SID, so any language works), and modify for the senders group.
	if out, err := hidden.Command("icacls.exe", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", SendersGroup+":(OI)(CI)M").CombinedOutput(); err != nil {
		return fmt.Errorf("set permissions on %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	for _, u := range append(append([]string{}, opt.InboxWriters...), opt.ShareWriters...) {
		out, err := hidden.Command("net.exe", "localgroup", SendersGroup, u, "/add").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "1378") { // 1378: already a member
			return fmt.Errorf("add %s to %q: %v: %s", u, SendersGroup, err, strings.TrimSpace(string(out)))
		}
		logf("Can deliver:         %s (member of %q; takes effect at that account's next sign-in)", u, SendersGroup)
	}
	logf("Inbox:               %s (Administrators, SYSTEM and %q)", dir, SendersGroup)

	shared := hidden.Command("net.exe", "share", ShareName).Run() == nil
	switch {
	case opt.ShareInbox && !shared:
		if out, err := hidden.Command("net.exe", "share", ShareName+"="+dir, "/GRANT:"+SendersGroup+",CHANGE",
			"/CACHE:None", "/REMARK:Blackbox collector inbox").CombinedOutput(); err != nil {
			return fmt.Errorf("share %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
		}
		fallthrough
	case opt.ShareInbox:
		// Batches cross the network encrypted (N1): SMB 3 encryption on
		// Blackbox's own share. Senders that can't encrypt are refused.
		if out, err := hidden.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			"Set-SmbShare -Name '"+ShareName+"' -EncryptData $true -CachingMode None -Force -ErrorAction Stop").CombinedOutput(); err != nil {
			return fmt.Errorf("could not turn on encryption for the %s share (Set-SmbShare -EncryptData): %v: %s", ShareName, err, strings.TrimSpace(string(out)))
		}
		host, _ := os.Hostname()
		logf("Network share:       \\\\%s\\%s (members of %q may deliver; encrypted; no offline copies)", host, ShareName, SendersGroup)
		// The firewall is reported, never changed (N2).
		if open, err := share.SMBAllowedIn(); err == nil && !open {
			firewallAdvice(logf, share.SMBPort)
		}
		if installed, open, err := share.SSHAllowedIn(); err == nil && installed && !open {
			firewallAdvice(logf, share.SSHPort)
		}
	case shared:
		hidden.Command("net.exe", "share", ShareName, "/delete", "/y").Run()
		logf("Network share:       %s removed", ShareName)
	}
	return nil
}

// removeInbox undoes prepareInbox's share and group (the folder and any
// data in it are kept).
func removeInbox(logf func(string, ...any)) {
	if hidden.Command("net.exe", "share", ShareName).Run() == nil {
		hidden.Command("net.exe", "share", ShareName, "/delete", "/y").Run()
		logf("Removed the %s network share (the folder was kept).", ShareName)
	}
	// The "Blackbox Senders" group is kept. A sender's open connection
	// carries the group's identity: deleting it and making a new one on
	// reinstall would lock out a Linux sender, whose mount never signs in
	// again by itself. It grants nothing once the share is gone.
	if hidden.Command("net.exe", "localgroup", SendersGroup).Run() == nil {
		logf("Kept the %q group, so its members can deliver again if this becomes a collector again.", SendersGroup)
	}
}

// prepareSendTo stores the share password (encrypted) and checks the
// collector can be reached. An unreachable collector is not an error: the
// data waits until it can be.
func prepareSendTo(opt Options, dataDir string, logf func(string, ...any)) error {
	if opt.ShareUser != "" && opt.SharePassword != "" {
		if err := share.SaveSecret(dataDir, opt.SharePassword); err != nil {
			return err
		}
	}
	if opt.ShareUser == "" {
		share.SaveSecret(dataDir, "")
	}
	pw := opt.SharePassword
	if pw == "" && opt.ShareUser != "" {
		pw, _ = share.LoadSecret(dataDir)
	}
	if err := TryInbox(opt.SendTo, opt.ShareUser, pw); err != nil {
		logf("Sends to:            %s (NOT reachable now: %v; data waits here until it is)", opt.SendTo, err)
		return nil
	}
	logf("Sends to:            %s (reachable)", opt.SendTo)
	return nil
}

func removeSendTo(logf func(string, ...any)) {}

var (
	procGetConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleMode")
	procSetConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")
)

// readPassword reads a line from the console without showing it.
func readPassword(r *bufio.Reader) (string, error) {
	h := os.Stdin.Fd()
	var mode uint32
	if ok, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); ok != 0 {
		const enableEchoInput = 0x4
		procSetConsoleMode.Call(h, uintptr(mode&^enableEchoInput))
		defer procSetConsoleMode.Call(h, uintptr(mode))
	}
	s, err := r.ReadString('\n')
	if err != nil && s == "" {
		return "", ErrCancelled
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// InboxShared reports whether the collector's inbox is shared on the network.
func InboxShared() bool { return hidden.Command("net.exe", "share", ShareName).Run() == nil }

// firewallAdvice prints share.FirewallAdvice in setup's layout.
func firewallAdvice(logf func(string, ...any), port int) {
	for i, l := range share.FirewallAdvice(port) {
		label := ""
		if i == 0 {
			label = "FIREWALL:"
		}
		logf("%-20s %s", label, l)
	}
}

// SenderFolderAccess lets only account write into a sender's folder in
// the inbox (SEC1): it can create files and write them, but not delete or
// rename them, change their permissions, or reach another sender's
// folder. Administrators and SYSTEM keep full control, and the account
// joins the senders group, which gives access to the share.
func SenderFolderAccess(dir, account string) error {
	const create = "(OI)(CI)(RD,WD,AD,REA,WEA,X,RA,WA,RC,S)"
	if out, err := hidden.Command("icacls.exe", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", account+":"+create,
		// OWNER RIGHTS: the files the account creates are its own, but
		// owning them gives it nothing more (no changing their permissions).
		"/grant:r", "*S-1-3-4:(OI)(CI)(RD,REA,X,RA,RC,S)").CombinedOutput(); err != nil {
		return fmt.Errorf("set permissions on %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	out, err := hidden.Command("net.exe", "localgroup", SendersGroup, account, "/add").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "1378") { // 1378: already a member
		return fmt.Errorf("add %s to %q: %v: %s", account, SendersGroup, err, strings.TrimSpace(string(out)))
	}
	return nil
}
