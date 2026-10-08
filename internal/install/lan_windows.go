//go:build windows

package install

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
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
	// 0.23's per-sender folders: what waits in them moves into the inbox
	// itself, and the folders go (DESIGN1).
	if n := lan.MigrateSenderFolders(nil, dir, logf); n > 0 {
		logf("Inbox:               moved %d file(s) out of 0.23's per-sender folders; they are imported at the next run", n)
	}
	// Drop-only (DESIGN1): senders can add files, and do nothing else.
	if err := DropOnlyInbox(dir, SendersGroup, filepath.Join(dir, lan.MarkerFile)); err != nil {
		return err
	}
	for _, u := range append(append([]string{}, opt.InboxWriters...), opt.ShareWriters...) {
		out, err := hidden.Command("net.exe", "localgroup", SendersGroup, u, "/add").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "1378") { // 1378: already a member
			return fmt.Errorf("add %s to %q: %v: %s", u, SendersGroup, err, strings.TrimSpace(string(out)))
		}
		logf("Can deliver:         %s (member of %q; takes effect at that account's next sign-in)", u, SendersGroup)
	}
	logf("Inbox:               %s (members of %q can add files to it, and nothing else: not list, read, change or delete)", dir, SendersGroup)

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
