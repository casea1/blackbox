package install

import (
	"fmt"
	"regexp"
	"strings"
)

// An SFTP send_to (USER@HOST:/PATH) is mounted with sshfs at
// SFTPMountPoint by a mount unit setup writes, and Blackbox delivers to
// that folder, as to any folder the site mounts (L8). It works in FIPS
// mode, where SMB with a password (NTLM) does not.

// SFTPMountPoint is where setup mounts an SFTP collector inbox.
const SFTPMountPoint = "/mnt/blackbox-inbox"

// SFTP key and pinned host key, root only. ECDSA P-384: FIPS mode refuses
// ed25519 keys.
const (
	SFTPKeyDir     = "/etc/blackbox/ssh"
	SFTPKey        = SFTPKeyDir + "/id_ecdsa"
	SFTPKnownHosts = SFTPKeyDir + "/known_hosts"
)

// sftpMarker is the first line of a mount unit setup wrote, so uninstall
// removes only its own.
const sftpMarker = "# Written by Blackbox setup for the SFTP collector inbox."

var sftpRE = regexp.MustCompile(`^([^@\s/\\:]+)@([^:\s/\\@]+):(/.+)$`)

// IsSFTP reports whether s names an SFTP inbox: USER@HOST:/PATH, such as
// bbsend@COLLECTOR:/C:/BlackboxInbox.
func IsSFTP(s string) bool { return sftpRE.MatchString(strings.TrimSpace(s)) }

// SplitSFTP is IsSFTP's user, host and path.
func SplitSFTP(s string) (user, host, path string) {
	m := sftpRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", "", ""
	}
	return m[1], m[2], m[3]
}

// sftpMountUnit mounts remote at mp with sshfs, with the pinned host key
// only. nofail and _netdev let the computer start when the collector is
// down; the delivery unit asks for the mount before each send.
func sftpMountUnit(remote, mp string) string {
	return fmt.Sprintf(`%s
[Unit]
Description=Blackbox collector inbox (%s)
Documentation=https://github.com/casea1/blackbox/blob/main/docs/lan.md
After=network-online.target
Wants=network-online.target

[Mount]
What=%s
Where=%s
Type=fuse.sshfs
Options=IdentityFile=%s,UserKnownHostsFile=%s,StrictHostKeyChecking=yes,BatchMode=yes,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,_netdev,nofail
TimeoutSec=30
`, sftpMarker, remote, remote, mp, SFTPKey, SFTPKnownHosts)
}

// AuthorizedKeyLine is a sender's public key as the collector keeps it:
// "restrict" allows file transfer (SFTP) and nothing else.
func AuthorizedKeyLine(pub string) string {
	pub = strings.TrimSpace(pub)
	if strings.HasPrefix(pub, "restrict ") {
		return pub
	}
	return "restrict " + pub
}

// AddKeyScript is the PowerShell that adds a key line for the account it
// runs as on a Windows collector with OpenSSH Server. An administrator's
// keys are read from C:\ProgramData\ssh\administrators_authorized_keys,
// anyone else's from .ssh\authorized_keys in their profile; the file is
// limited to the account, SYSTEM and Administrators, which OpenSSH
// requires (from the stig-build it-sshfs script).
func AddKeyScript(line string) string {
	return strings.Join([]string{
		`$ErrorActionPreference = "Stop"`,
		`$k = '` + strings.ReplaceAll(line, `'`, `''`) + `'`,
		`$admin = ([Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' }) -ne $null`,
		`if ($admin) { $d = "$env:ProgramData\ssh"; $f = "$d\administrators_authorized_keys" } else { $d = "$env:USERPROFILE\.ssh"; $f = "$d\authorized_keys" }`,
		`New-Item -ItemType Directory -Force -Path $d | Out-Null`,
		`if (-not (Test-Path $f)) { New-Item -ItemType File -Path $f | Out-Null }`,
		`if (-not (Select-String -Path $f -SimpleMatch $k -Quiet)) { Add-Content -Path $f -Value $k -Encoding ascii }`,
		`if ($admin) { icacls $f /inheritance:r /grant:r "*S-1-5-32-544:F" /grant:r "*S-1-5-18:F" | Out-Null }`,
		`else { icacls $d /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" | Out-Null; icacls $f /inheritance:r /grant:r "$($env:USERNAME):F" /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" | Out-Null }`,
		`Write-Output ("Key added to " + $f)`,
	}, "\n")
}
