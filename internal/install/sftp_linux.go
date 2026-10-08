package install

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/casea1/blackbox/internal/lan"
)

// SFTPPrompts are the questions SetupSFTP asks; nil (an unattended
// install) accepts the host key it shows and leaves installing the key on
// the collector to an administrator there.
type SFTPPrompts struct {
	Yes func(prompt string, def bool) (bool, error)
}

// SetupSFTP gets this computer ready to deliver to an SFTP inbox
// (USER@HOST:/PATH): it makes its SSH key, pins the collector's host key
// (shown for you to compare), writes a mount unit for SFTPMountPoint and
// offers to install the key on the collector, asking for the account's
// password once. It returns the folder to deliver to.
func SetupSFTP(remote string, p *SFTPPrompts, logf func(string, ...any)) (string, error) {
	u, host, _ := SplitSFTP(remote)
	if u == "" {
		return "", fmt.Errorf("%s is not USER@HOST:/PATH", remote)
	}
	for _, tool := range []string{"ssh", "ssh-keygen", "sshfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			return "", fmt.Errorf("%s is not installed: install sshfs (and openssh-client) from your installation media (Ubuntu: apt install sshfs; AlmaLinux: dnf install fuse-sshfs)", tool)
		}
	}
	if err := os.MkdirAll(SFTPKeyDir, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(SFTPKey); err != nil {
		host, _ := os.Hostname()
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ecdsa", "-b", "384", "-N", "", "-C", "blackbox "+host, "-f", SFTPKey).CombinedOutput(); err != nil {
			return "", fmt.Errorf("make the SSH key: %v: %s", err, out)
		}
	}
	if err := pinHostKey(host, p, logf); err != nil {
		return "", err
	}
	mp := SFTPMountPoint
	if err := os.MkdirAll(mp, 0o700); err != nil {
		return "", err
	}
	unit := "/etc/systemd/system/" + MountUnitFor(mp)
	if b, err := os.ReadFile(unit); err == nil && !strings.HasPrefix(string(b), sftpMarker) {
		return "", fmt.Errorf("%s already exists and was not written by Blackbox; remove it or mount the inbox yourself and enter %s", unit, mp)
	}
	if err := os.WriteFile(unit, []byte(sftpMountUnit(remote, mp)), 0o644); err != nil {
		return "", err
	}
	exec.Command("systemctl", "daemon-reload").Run()
	pub, _ := os.ReadFile(SFTPKey + ".pub")
	line := AuthorizedKeyLine(string(pub))
	if exec.Command("systemctl", "restart", MountUnitFor(mp)).Run() == nil && lan.IsInbox(mp) {
		logf("SFTP inbox:          %s mounted at %s (key already accepted)", remote, mp)
		return mp, nil
	}
	installed := false
	if p != nil {
		ok, err := p.Yes(fmt.Sprintf("Install this computer's key on %s now? You are asked for %s's Windows password once", host, u), true)
		if err != nil {
			return "", err
		}
		if ok {
			if err := installKey(u, host, line); err != nil {
				logf("Could not install the key: %v", err)
			} else {
				installed = true
			}
		}
	}
	if !installed {
		logf("On the collector, as an administrator, add this computer's key:")
		logf("  blackbox senders add-ssh-key %s \"%s\"", u, line)
	}
	if exec.Command("systemctl", "restart", MountUnitFor(mp)).Run() == nil && lan.IsInbox(mp) {
		logf("SFTP inbox:          %s mounted at %s", remote, mp)
	} else {
		logf("SFTP inbox:          %s, not mounted yet; delivery tries again at every run", remote)
	}
	return mp, nil
}

// pinHostKey fetches the collector's host key with ssh itself (as the
// stig-build it-sshfs script does), shows its fingerprint and keeps it in
// Blackbox's own known_hosts once accepted.
func pinHostKey(host string, p *SFTPPrompts, logf func(string, ...any)) error {
	if exec.Command("ssh-keygen", "-F", host, "-f", SFTPKnownHosts).Run() == nil {
		return nil // already pinned
	}
	tmp, err := os.CreateTemp(SFTPKeyDir, "hostkey-")
	if err != nil {
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	out, _ := exec.Command("ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile="+tmp.Name(), "-o", "GlobalKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=none",
		"-o", "LogLevel=ERROR", "blackbox-hostkey@"+host, "exit").CombinedOutput()
	fp, err := exec.Command("ssh-keygen", "-lf", tmp.Name()).Output()
	if err != nil || len(strings.TrimSpace(string(fp))) == 0 {
		return fmt.Errorf("could not reach SSH on %s: %s", host, strings.TrimSpace(string(out)))
	}
	logf("The collector %s offers this host key:", host)
	for _, l := range strings.Split(strings.TrimSpace(string(fp)), "\n") {
		logf("  %s", l)
	}
	logf("Compare it on the collector: ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_ecdsa_key.pub")
	if p != nil {
		ok, err := p.Yes("Is that the collector's key?", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("the collector's host key was not accepted")
		}
	}
	b, _ := os.ReadFile(tmp.Name())
	f, err := os.OpenFile(SFTPKnownHosts, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// installKey adds this computer's key on the collector over SSH, signing
// in with the account's password once (ssh asks for it on the terminal).
func installKey(user, host, line string) error {
	cmd := exec.Command("ssh", "-T", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+SFTPKnownHosts,
		"-o", "PreferredAuthentications=password,keyboard-interactive", user+"@"+host, "powershell -NoProfile -Command -")
	cmd.Stdin = strings.NewReader(AddKeyScript(line) + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeSFTPMountUnless removes the mount unit setup wrote (its marker
// says so), unless sendTo is still its folder.
func removeSFTPMountUnless(sendTo string, logf func(string, ...any)) {
	if sendTo == SFTPMountPoint {
		return
	}
	unit := "/etc/systemd/system/" + MountUnitFor(SFTPMountPoint)
	if b, err := os.ReadFile(unit); err == nil && strings.HasPrefix(string(b), sftpMarker) {
		exec.Command("systemctl", "stop", MountUnitFor(SFTPMountPoint)).Run()
		os.Remove(unit)
		exec.Command("systemctl", "daemon-reload").Run()
		logf("Removed the SFTP inbox mount (%s). The SSH key stays in %s.", SFTPMountPoint, filepath.Dir(SFTPKey))
	}
}

// AddSSHKey is for a Windows collector.
func AddSSHKey(string, string) (string, error) {
	return "", errors.New("adding a sender's SSH key is for a Windows collector; on Linux, add it to the account's ~/.ssh/authorized_keys")
}
