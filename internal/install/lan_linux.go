//go:build linux

package install

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/share"
)

const isWindows = false

// ShareName is the conventional name of a collector's inbox share.
const ShareName = "BlackboxInbox"

// DefaultInbox is the suggested inbox folder for a collector.
func DefaultInbox() string { return filepath.Join(config.DefaultDataDir(), "inbox") }

// FindInboxes lists collector inboxes this computer can already see:
// VirtualBox shared folders (mounted at /media/sf_NAME) and anything
// mounted under /mnt or /media.
func FindInboxes() []string {
	var out []string
	for _, pattern := range []string{"/media/sf_*", "/mnt/*", "/media/*/*", "/media/*"} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if lan.IsInbox(m) {
				out = append(out, m)
			}
		}
	}
	return out
}

// mountUnitName is the systemd unit that mounts an SMB send_to share at
// share.MountPoint (unit names are the escaped mount path).
func mountUnitName() string {
	p := strings.TrimPrefix(share.MountPoint(config.DefaultDataDir()), "/")
	return strings.ReplaceAll(p, "/", "-") + ".mount"
}

func mountUnitFile() string { return "/etc/systemd/system/" + mountUnitName() }

// mountUnit mounts the collector's share for the Blackbox service only
// (the service asks for it before each run). Files are root-only, and
// nothing on the share can be run.
func mountUnit(what string) string {
	return fmt.Sprintf(`[Unit]
Description=Blackbox collector inbox (%s)
Documentation=https://github.com/casea1/blackbox/blob/main/docs/lan.md
After=network-online.target
Wants=network-online.target

[Mount]
What=%s
Where=%s
Type=cifs
Options=credentials=%s,uid=0,gid=0,file_mode=0600,dir_mode=0700,nosuid,nodev,noexec,seal,_netdev
TimeoutSec=30
`, what, what, share.MountPoint(config.DefaultDataDir()), share.CredentialFile)
}

func credentialText(user, pw string) string {
	domain, u := share.SplitUser(user)
	s := "username=" + u + "\npassword=" + pw + "\n"
	if domain != "" {
		s += "domain=" + domain + "\n"
	}
	return s
}

// mountError explains a failed SMB mount. Blackbox asks for an encrypted
// connection (seal, SMB 3); a collector that can't provide one refuses it
// with "operation not supported" (N1).
func mountError(out string) error {
	out = strings.TrimSpace(out)
	l := strings.ToLower(out)
	if strings.Contains(l, "error(95)") || strings.Contains(l, "operation not supported") || strings.Contains(l, "error(22)") {
		return fmt.Errorf("could not connect with an encrypted connection (%s). The collector must offer SMB 3 encryption: install or upgrade Blackbox on it (it turns encryption on for its share), or on the collector run: Set-SmbShare -Name %s -EncryptData $true", out, ShareName)
	}
	return fmt.Errorf("could not connect: %s", out)
}

// TryInbox checks the collector's inbox can be reached: a folder must
// hold the inbox marker; a share is test-mounted with the account.
func TryInbox(sendTo, user, pw string) error {
	if !config.IsShare(sendTo) {
		if !lan.IsInbox(sendTo) {
			if _, err := os.Stat(sendTo); err != nil {
				return fmt.Errorf("cannot open %s (is the shared folder set up and mounted?)", sendTo)
			}
			return fmt.Errorf("%s is not a Blackbox inbox; on the collector, run the installer and choose \"This is the collector\" first", sendTo)
		}
		return nil
	}
	if fipsEnabled() {
		return errFIPS
	}
	if !share.HaveCIFS() {
		return fmt.Errorf("the SMB client (cifs-utils) is not installed; install it from your installation media (Ubuntu: apt install cifs-utils; AlmaLinux: dnf install cifs-utils), or use a VirtualBox shared folder")
	}
	if user == "" {
		return fmt.Errorf("an account on the collector is needed to connect to %s", sendTo)
	}
	dir, err := os.MkdirTemp("", "blackbox-try-")
	if err != nil {
		return err
	}
	defer os.Remove(dir)
	cred, err := os.CreateTemp("", "blackbox-cred-")
	if err != nil {
		return err
	}
	defer os.Remove(cred.Name())
	cred.Chmod(0o600)
	cred.WriteString(credentialText(user, pw))
	cred.Close()
	out, err := exec.Command("mount", "-t", "cifs", sendTo, dir, "-o", "credentials="+cred.Name()+",uid=0,gid=0,file_mode=0600,dir_mode=0700,nosuid,nodev,noexec,seal").CombinedOutput()
	if err != nil {
		return mountError(string(out))
	}
	defer exec.Command("umount", dir).Run()
	if !lan.IsInbox(dir) {
		return fmt.Errorf("connected, but %s is not a Blackbox inbox", sendTo)
	}
	return nil
}

// prepareInbox creates a collector's inbox folder and its marker.
func prepareInbox(opt Options, logf func(string, ...any)) error {
	if err := os.MkdirAll(opt.Inbox, 0o750); err != nil {
		return err
	}
	if err := lan.PrepareInbox(opt.Inbox, collect.LocalHost()); err != nil {
		return err
	}
	logf("Inbox:               %s", opt.Inbox)
	return nil
}

func removeInbox(logf func(string, ...any)) {}

// prepareSendTo sets up delivery to the collector: for an SMB share, the
// credentials file and the mount unit; for a folder (such as a VirtualBox
// shared folder), nothing beyond a reachability check.
func prepareSendTo(opt Options, dataDir string, logf func(string, ...any)) error {
	if !config.IsShare(opt.SendTo) {
		removeSendTo(func(string, ...any) {})
		if err := TryInbox(opt.SendTo, "", ""); err != nil {
			logf("Sends to:            %s (NOT reachable now: %v; data waits here until it is)", opt.SendTo, err)
		} else {
			logf("Sends to:            %s (reachable)", opt.SendTo)
		}
		return nil
	}
	if fipsEnabled() {
		logf("WARNING: FIPS mode is on. SMB sign-in with a password (NTLM) does not work in FIPS mode,")
		logf("         so %s cannot be mounted. Use a folder instead: an SFTP (sshfs) mount or a", opt.SendTo)
		logf("         VirtualBox shared folder. See docs/lan.md.")
	}
	if !share.HaveCIFS() {
		return fmt.Errorf("sending to %s needs the SMB client: install cifs-utils from your installation media (Ubuntu: apt install cifs-utils; AlmaLinux: dnf install cifs-utils)", opt.SendTo)
	}
	if opt.SharePassword != "" {
		if err := os.MkdirAll(filepath.Dir(share.CredentialFile), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(share.CredentialFile, []byte(credentialText(opt.ShareUser, opt.SharePassword)), 0o600); err != nil {
			return err
		}
	} else if _, err := os.Stat(share.CredentialFile); err != nil {
		return fmt.Errorf("no password stored for %s; run the installer again to enter it", opt.ShareUser)
	}
	mp := share.MountPoint(dataDir)
	if err := os.MkdirAll(mp, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(mountUnitFile(), []byte(mountUnit(opt.SendTo)), 0o644); err != nil {
		return err
	}
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "restart", mountUnitName()).Run()
	if lan.IsInbox(mp) {
		logf("Sends to:            %s (mounted for Blackbox only, at %s)", opt.SendTo, mp)
	} else {
		logf("Sends to:            %s (NOT reachable now; data waits here until it is)", opt.SendTo)
	}
	return nil
}

// removeSendTo removes the share mount and its credentials.
func removeSendTo(logf func(string, ...any)) {
	if _, err := os.Stat(mountUnitFile()); err == nil {
		exec.Command("systemctl", "stop", mountUnitName()).Run()
		os.Remove(mountUnitFile())
		exec.Command("systemctl", "daemon-reload").Run()
		logf("Removed the collector share mount.")
	}
	if _, err := os.Stat(share.CredentialFile); err == nil {
		os.Remove(share.CredentialFile)
	}
}

// readPassword reads a line from the terminal without showing it.
func readPassword(r *bufio.Reader) (string, error) {
	fd := os.Stdin.Fd()
	var t syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t))); e == 0 {
		quiet := t
		quiet.Lflag &^= syscall.ECHO
		syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&quiet)))
		defer syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&t)))
	}
	s, err := r.ReadString('\n')
	if err != nil && s == "" {
		return "", ErrCancelled
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// InboxShared reports whether the inbox is shared on the network (Windows
// only; Linux collectors receive through folders the senders can reach).
func InboxShared() bool { return false }

// errFIPS explains why an SMB share cannot be used on a FIPS system.
var errFIPS = fmt.Errorf("FIPS mode is on: SMB sign-in with a password (NTLM) needs algorithms FIPS mode disables, so the share cannot be mounted. Send to a folder instead: an SFTP (sshfs) mount of the collector's inbox, or a VirtualBox shared folder (see docs/lan.md)")

// fipsEnabled reports whether the kernel is in FIPS mode.
func fipsEnabled() bool {
	b, err := os.ReadFile("/proc/sys/crypto/fips_enabled")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// SenderFolderAccess lets only account write into a sender's folder in
// the inbox (SEC1), for an SFTP (sshfs) sender signing in as that
// account: the folder belongs to root and the account's group, which can
// create files there but not list the folder, and (sticky) can't delete
// or rename anyone else's file. Other accounts can't reach it at all.
func SenderFolderAccess(dir, account string) error {
	u, err := user.Lookup(account)
	if err != nil {
		return fmt.Errorf("no account %q on this computer: %v", account, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(dir, 0, gid); err != nil {
		return err
	}
	return os.Chmod(dir, 0o730|os.ModeSticky)
}
