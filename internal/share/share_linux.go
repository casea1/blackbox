//go:build linux

package share

import (
	"os"
	"path/filepath"

	"github.com/casea1/blackbox/internal/config"
)

// MountPoint is where an SMB send_to share is mounted (by the
// blackbox-collector mount unit the installer writes).
func MountPoint(dataDir string) string { return filepath.Join(dataDir, "collector") }

// CredentialFile holds the share account for mount.cifs (root only).
const CredentialFile = "/etc/blackbox/share.cred"

// Destination returns the folder batches are delivered to: the mount
// point for an SMB share, or the folder itself.
func Destination(cfg *config.Config) (string, error) {
	if config.IsShare(cfg.SendTo) {
		return MountPoint(cfg.DataDir), nil
	}
	return cfg.SendTo, nil
}

// HaveCIFS reports whether the SMB mount helper (cifs-utils) is installed.
func HaveCIFS() bool {
	for _, p := range []string{"/sbin/mount.cifs", "/usr/sbin/mount.cifs", "/usr/bin/mount.cifs"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// SMBAllowedIn is only checked on a Windows collector.
func SMBAllowedIn() (bool, error) { return true, nil }

// SSHAllowedIn is only checked on a Windows collector.
func SSHAllowedIn() (installed, open bool, err error) { return false, false, nil }
