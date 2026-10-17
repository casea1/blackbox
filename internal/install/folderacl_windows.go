//go:build windows

package install

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var procGetNamedSecurityInfoW = advapi32.NewProc("GetNamedSecurityInfoW")

// lockFolder points out an existing report or original-logs folder that
// accounts other than Administrators and SYSTEM may write to: the
// scheduled runs write in it as SYSTEM, and such an account could change
// or remove what they write. On Windows its access list is not changed
// (it may be set on purpose, e.g. a share); setup only says so.
func lockFolder(dir string) (string, error) {
	who := writersOtherThanAdmins(dir)
	if len(who) == 0 {
		return "", nil
	}
	return fmt.Sprintf("WARNING: %s can also change files in it, so they could alter or remove reports; give them read access only if that isn't intended", strings.Join(who, ", ")), nil
}

// writersOtherThanAdmins lists the accounts and groups, other than
// SYSTEM, Administrators, TrustedInstaller and CREATOR OWNER, that an
// access list entry lets write, add, delete or change permissions in dir.
func writersOtherThanAdmins(dir string) []string {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return nil
	}
	var dacl *byte
	var sd uintptr
	if r, _, _ := procGetNamedSecurityInfoW.Call(uintptr(unsafe.Pointer(p)), seFileObject, daclSecurityInfo,
		0, 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&sd))); r != 0 || dacl == nil {
		return nil
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	const write = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
	ok := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, "S-1-3-0": true,
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true}
	base := unsafe.Pointer(dacl)
	count := *(*uint16)(unsafe.Add(base, 4))
	var out []string
	seen := map[string]bool{}
	ace := unsafe.Add(base, 8)
	for i := uint16(0); i < count; i++ {
		typ := *(*byte)(ace)
		flags := *(*byte)(unsafe.Add(ace, 1))
		size := *(*uint16)(unsafe.Add(ace, 2))
		mask := *(*uint32)(unsafe.Add(ace, 4))
		if typ == 0 && flags&inheritOnlyAce == 0 && mask&write != 0 { // ACCESS_ALLOWED_ACE on the folder itself
			sid := (*syscall.SID)(unsafe.Add(ace, 8))
			if s, err := sid.String(); err == nil && !ok[s] && !seen[s] {
				seen[s] = true
				name := s
				if acct, dom, _, err := sid.LookupAccount(""); err == nil {
					name = acct
					if dom != "" {
						name = dom + `\` + acct
					}
				}
				out = append(out, name)
			}
		}
		ace = unsafe.Add(ace, int(size))
	}
	return out
}
