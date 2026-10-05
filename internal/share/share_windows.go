//go:build windows

package share

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/hidden"
)

var (
	crypt32       = syscall.NewLazyDLL("crypt32.dll")
	procProtect   = crypt32.NewProc("CryptProtectData")
	procUnprotect = crypt32.NewProc("CryptUnprotectData")
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree = kernel32.NewProc("LocalFree")
	mpr           = syscall.NewLazyDLL("mpr.dll")
	procAddConn   = mpr.NewProc("WNetAddConnection2W")
)

type dataBlob struct {
	size uint32
	data *byte
}

func newBlob(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{size: uint32(len(b)), data: &b[0]}
}

func (b *dataBlob) bytes() []byte {
	out := make([]byte, b.size)
	copy(out, unsafe.Slice(b.data, b.size))
	return out
}

// entropy ties the encrypted password to Blackbox.
var entropy = []byte("blackbox share credential v1")

const (
	cryptprotectUIForbidden  = 0x1
	cryptprotectLocalMachine = 0x4 // any account on this computer with access to the file (SYSTEM runs the task)
)

// SaveSecret stores the share password encrypted with Windows DPAPI, bound
// to this computer. The file is in the data folder, which only
// Administrators and SYSTEM can read.
func SaveSecret(dataDir, password string) error {
	if password == "" {
		os.Remove(SecretFile(dataDir))
		return nil
	}
	var out dataBlob
	r, _, err := procProtect.Call(uintptr(unsafe.Pointer(newBlob([]byte(password)))), 0,
		uintptr(unsafe.Pointer(newBlob(entropy))), 0, 0, cryptprotectUIForbidden|cryptprotectLocalMachine,
		uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return fmt.Errorf("encrypt share password: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))
	return os.WriteFile(SecretFile(dataDir), out.bytes(), 0o600)
}

// LoadSecret returns the stored share password ("" if none).
func LoadSecret(dataDir string) (string, error) {
	enc, err := os.ReadFile(SecretFile(dataDir))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var out dataBlob
	r, _, err := procUnprotect.Call(uintptr(unsafe.Pointer(newBlob(enc))), 0,
		uintptr(unsafe.Pointer(newBlob(entropy))), 0, 0, cryptprotectUIForbidden, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return "", fmt.Errorf("decrypt share password (run the installer again to re-enter it): %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))
	return string(out.bytes()), nil
}

type netResource struct {
	scope, typ, displayType, usage       uint32
	localName, remoteName, comment, prov *uint16
}

const (
	resourcetypeDisk               = 1
	connectTemporary               = 4
	errorSessionCredentialConflict = 1219
	errorAlreadyAssigned           = 85
)

// Connect signs in to the share with the given account. With no account,
// Windows uses the computer's own identity (a domain computer account),
// which needs no connection first.
func Connect(path, user, password string) error {
	if user == "" {
		return nil
	}
	root, _ := Root(path)
	remote, _ := syscall.UTF16PtrFromString(root)
	u, _ := syscall.UTF16PtrFromString(user)
	p, _ := syscall.UTF16PtrFromString(password)
	nr := netResource{typ: resourcetypeDisk, remoteName: remote}
	r, _, _ := procAddConn.Call(uintptr(unsafe.Pointer(&nr)), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(u)), connectTemporary)
	switch r {
	case 0, errorAlreadyAssigned:
		return nil
	case errorSessionCredentialConflict:
		return nil // already connected (with these or other credentials); try the folder anyway
	}
	return fmt.Errorf("connect to %s as %s: %v", root, user, syscall.Errno(r))
}

// Destination returns the folder batches are delivered to, connecting to
// the share first when an account is set.
func Destination(cfg *config.Config) (string, error) {
	if !config.IsShare(cfg.SendTo) || cfg.ShareUser == "" {
		return cfg.SendTo, nil
	}
	pw, err := LoadSecret(cfg.DataDir)
	if err != nil {
		return "", err
	}
	if pw == "" {
		pw = os.Getenv("BLACKBOX_SHARE_PASSWORD") // scripted use without a stored password
	}
	if pw == "" {
		return "", errors.New("no password is stored for share_user; run the installer again to enter it")
	}
	return cfg.SendTo, Connect(cfg.SendTo, cfg.ShareUser, pw)
}

// portInQuery lists the firewall rules for a TCP port, one per line,
// tab-separated, for PortOpen: 445 for Windows file sharing, 22 for the
// OpenSSH server. %d in the format string is the port.
const portInQuery = `Get-NetFirewallPortFilter -Protocol TCP -ErrorAction SilentlyContinue | Where-Object { @($_.LocalPort) -contains '%d' } | Get-NetFirewallRule -ErrorAction SilentlyContinue | ForEach-Object { '{0}{4}{1}{4}{2}{4}{3}' -f $_.DisplayName, $_.Enabled, $_.Direction, $_.Action, [char]9 }`

// SMBAllowedIn reports whether Windows Firewall lets other computers reach
// this computer's file shares (N2). Server 2025 ships "File and Printer
// Sharing (SMB-In)" turned off. Blackbox only reports it; it never changes
// the firewall.
func SMBAllowedIn() (bool, error) { return portAllowedIn(SMBPort) }

// SSHAllowedIn is the same for the OpenSSH server (SFTP senders), and
// false with no error when no OpenSSH server is installed: then nothing
// is to be said about it.
func SSHAllowedIn() (installed, open bool, err error) {
	if hidden.Command("sc.exe", "query", "sshd").Run() != nil {
		return false, false, nil
	}
	open, err = portAllowedIn(SSHPort)
	return true, open, err
}

func portAllowedIn(port int) (bool, error) {
	out, err := hidden.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf(portInQuery, port)).Output()
	if err != nil {
		return false, err
	}
	return PortOpen(string(out)), nil
}
