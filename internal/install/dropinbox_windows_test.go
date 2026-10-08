//go:build windows

package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/casea1/blackbox/internal/lan"
)

var (
	procLogonUserW              = advapi32.NewProc("LogonUserW")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = advapi32.NewProc("RevertToSelf")
)

// asUser runs f on this goroutine's thread while it impersonates the
// account, signed in as over the network (as an SMB sender is).
func asUser(t *testing.T, user, password string, f func()) {
	t.Helper()
	u, _ := syscall.UTF16PtrFromString(user)
	d, _ := syscall.UTF16PtrFromString(".")
	p, _ := syscall.UTF16PtrFromString(password)
	const logonNetwork, providerDefault = 3, 0
	var tok syscall.Handle
	if r, _, err := procLogonUserW.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(p)),
		logonNetwork, providerDefault, uintptr(unsafe.Pointer(&tok))); r == 0 {
		t.Fatalf("sign in as %s: %v", user, err)
	}
	defer syscall.CloseHandle(tok)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, err := procImpersonateLoggedOnUser.Call(uintptr(tok)); r == 0 {
		t.Fatalf("impersonate %s: %v", user, err)
	}
	defer procRevertToSelf.Call()
	f()
}

// DESIGN1: the drop-only inbox, checked as a non-administrator member of
// Blackbox Senders. It can recognise the inbox (read its marker) and
// create a file and write it; it can't list the folder, read another
// file or its own, overwrite, delete or rename its own file, change its
// permissions, write the marker, or make a folder. CI makes the account
// (BLACKBOX_ACL_USER, BLACKBOX_ACL_PASSWORD) and the group; elsewhere the
// test is skipped.
func TestDropOnlyInboxAsSender(t *testing.T) {
	user, pw := os.Getenv("BLACKBOX_ACL_USER"), os.Getenv("BLACKBOX_ACL_PASSWORD")
	if user == "" {
		t.Skip("set BLACKBOX_ACL_USER and BLACKBOX_ACL_PASSWORD to a non-administrator account in Blackbox Senders (CI does)")
	}
	dir := filepath.Join(os.Getenv("SystemDrive")+`\`, "bb-acl-test-inbox")
	os.RemoveAll(dir)
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := lan.PrepareInbox(dir, "COL"); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "OTHER_id_0000000001_0123456789ab.bbx")
	if err := os.WriteFile(other, []byte("another sender's batch"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := DropOnlyInbox(dir, SendersGroup, filepath.Join(dir, lan.MarkerFile)); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(dir, "MINE_id_0000000001_0123456789ab.bbx")
	marker := filepath.Join(dir, lan.MarkerFile)
	type check struct {
		what string
		err  error
	}
	var created error
	var refused []check
	asUser(t, user, pw, func() {
		if !lan.IsInbox(dir) {
			created = errors.New("the inbox marker can't be read, so a sender would not recognise the inbox")
			return
		}
		// Create and write, as lan.drop does.
		f, err := os.OpenFile(mine, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err == nil {
			_, err = f.Write([]byte("my batch"))
			if serr := f.Sync(); err == nil {
				err = serr
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			created = err
			return
		}
		_, err = os.ReadDir(dir)
		refused = append(refused, check{"list the inbox", err})
		_, err = os.ReadFile(other)
		refused = append(refused, check{"read another file", err})
		_, err = os.ReadFile(mine)
		refused = append(refused, check{"read its own file", err})
		_, err = os.OpenFile(mine, os.O_WRONLY|os.O_TRUNC, 0)
		refused = append(refused, check{"overwrite its own file", err})
		_, err = os.OpenFile(other, os.O_WRONLY|os.O_APPEND, 0)
		refused = append(refused, check{"write another file", err})
		_, err = os.OpenFile(marker, os.O_WRONLY|os.O_APPEND, 0)
		refused = append(refused, check{"write the marker", err})
		refused = append(refused, check{"delete its own file", os.Remove(mine)})
		refused = append(refused, check{"delete another file", os.Remove(other)})
		refused = append(refused, check{"rename its own file", os.Rename(mine, filepath.Join(dir, "renamed.bbx"))})
		refused = append(refused, check{"make a folder", os.Mkdir(filepath.Join(dir, "sub"), 0o750)})
		refused = append(refused, check{"change its own file's permissions", setNullDACL(mine)})
		_, err = os.OpenFile(mine, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		refused = append(refused, check{"create a file under a name taken", err})
	})
	if created != nil {
		t.Fatalf("a sender could not deliver: %v", created)
	}
	for _, c := range refused {
		if c.err == nil {
			t.Errorf("a sender could %s", c.what)
		} else {
			t.Logf("refused to %s: %v", c.what, c.err)
		}
	}
	if b, err := os.ReadFile(mine); err != nil || string(b) != "my batch" {
		t.Errorf("the delivered file, read by the collector: %q %v", b, err)
	}
	if b, err := os.ReadFile(other); err != nil || string(b) != "another sender's batch" {
		t.Errorf("another sender's file changed: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("a folder was made")
	}
}

// setNullDACL tries to give path a DACL granting everyone everything:
// what a sender would do to read its own file again.
func setNullDACL(path string) error {
	p, _ := syscall.UTF16PtrFromString(path)
	if r, _, _ := procSetNamedSecurityInfoW.Call(uintptr(unsafe.Pointer(p)), seFileObject, daclSecurityInfo, 0, 0, 0, 0); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}
