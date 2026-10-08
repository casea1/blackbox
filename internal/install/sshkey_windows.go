package install

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/casea1/blackbox/internal/hidden"
)

// AddSSHKey adds a Linux sender's public key for account on this
// collector (OpenSSH Server), so the sender can mount the inbox over SFTP
// with it: in C:\ProgramData\ssh\administrators_authorized_keys if the
// account is an administrator (OpenSSH reads only that file for them),
// otherwise in .ssh\authorized_keys in its profile. The key may only
// transfer files ("restrict"), and the file is limited to the account,
// SYSTEM and Administrators, as OpenSSH requires. It returns the file.
func AddSSHKey(account, pub string) (string, error) {
	f := strings.Fields(pub)
	if len(f) < 2 || !strings.HasPrefix(strings.TrimPrefix(pub, "restrict "), "ecdsa-") && !strings.HasPrefix(strings.TrimPrefix(pub, "restrict "), "ssh-") {
		return "", fmt.Errorf("that is not an SSH public key line (it starts with ecdsa-sha2-… or ssh-…)")
	}
	u, err := user.Lookup(account)
	if err != nil {
		return "", fmt.Errorf("no account %s on this computer: %w", account, err)
	}
	gids, _ := u.GroupIds()
	admin := slices.Contains(gids, "S-1-5-32-544")
	dir := filepath.Join(u.HomeDir, ".ssh")
	file := filepath.Join(dir, "authorized_keys")
	if admin {
		dir = filepath.Join(os.Getenv("ProgramData"), "ssh")
		file = filepath.Join(dir, "administrators_authorized_keys")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return file, err
	}
	line := AuthorizedKeyLine(pub)
	old, _ := os.ReadFile(file)
	if !strings.Contains(string(old), strings.TrimPrefix(line, "restrict ")) {
		if len(old) > 0 && !strings.HasSuffix(string(old), "\n") {
			line = "\r\n" + line
		}
		fh, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return file, err
		}
		_, err = fh.WriteString(line + "\r\n")
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return file, err
		}
	}
	grants := []string{"/inheritance:r", "/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F"}
	if !admin {
		grants = append(grants, "/grant:r", "*"+u.Uid+":F")
		if out, err := hidden.Command("icacls.exe", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F",
			"/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*"+u.Uid+":(OI)(CI)F").CombinedOutput(); err != nil {
			return file, fmt.Errorf("set permissions on %s: %v: %s", dir, err, out)
		}
	}
	if out, err := hidden.Command("icacls.exe", append([]string{file}, grants...)...).CombinedOutput(); err != nil {
		return file, fmt.Errorf("set permissions on %s: %v: %s", file, err, out)
	}
	return file, nil
}

// SFTPPrompts are SetupSFTP's questions.
type SFTPPrompts struct {
	Yes func(prompt string, def bool) (bool, error)
}

// SetupSFTP is for a Linux sender: a Windows sender delivers over SMB.
func SetupSFTP(string, *SFTPPrompts, func(string, ...any)) (string, error) {
	return "", fmt.Errorf("an SFTP inbox (USER@HOST:/PATH) is for Linux senders; enter the collector's share")
}
