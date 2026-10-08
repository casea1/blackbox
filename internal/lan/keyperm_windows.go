//go:build windows

package lan

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	procGetAce                = syscall.NewLazyDLL("advapi32.dll").NewProc("GetAce")
	procInitializeAcl         = syscall.NewLazyDLL("advapi32.dll").NewProc("InitializeAcl")
	procAddAccessAllowedAceEx = syscall.NewLazyDLL("advapi32.dll").NewProc("AddAccessAllowedAceEx")
	procSetNamedSecurityInfoW = syscall.NewLazyDLL("advapi32.dll").NewProc("SetNamedSecurityInfoW")
)

// restrictKey gives the key file to Administrators and SYSTEM alone: its
// whole access list is set, with nothing inherited from the folder (so
// no entry for the account that made it is left over).
func restrictKey(path string) error {
	const aclRevision, fileAllAccess = 2, 0x1F01FF
	const seFileObject, daclSecurityInfo, protectedDacl = 1, 0x4, 0x80000000
	var sids []*syscall.SID
	size := uint32(8)
	for _, s := range []string{"S-1-5-18", "S-1-5-32-544"} {
		sid, err := syscall.StringToSid(s)
		if err != nil {
			return err
		}
		sids = append(sids, sid)
		size += 8 + syscall.GetLengthSid(sid)
	}
	size = (size + 3) &^ 3
	acl := make([]byte, size)
	if r, _, err := procInitializeAcl.Call(uintptr(unsafe.Pointer(&acl[0])), uintptr(size), aclRevision); r == 0 {
		return fmt.Errorf("restrict %s: %w", path, err)
	}
	for _, sid := range sids {
		if r, _, err := procAddAccessAllowedAceEx.Call(uintptr(unsafe.Pointer(&acl[0])), aclRevision, 0, fileAllAccess, uintptr(unsafe.Pointer(sid))); r == 0 {
			return fmt.Errorf("restrict %s: %w", path, err)
		}
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if r, _, _ := procSetNamedSecurityInfoW.Call(uintptr(unsafe.Pointer(p)), seFileObject, daclSecurityInfo|protectedDacl,
		0, 0, uintptr(unsafe.Pointer(&acl[0])), 0); r != 0 {
		return fmt.Errorf("restrict %s: %w", path, syscall.Errno(r))
	}
	return nil
}

// KeyProblem says what is wrong with the signing key file's permissions,
// or "" (DESIGN1): only Administrators and SYSTEM may have access to it.
func KeyProblem(dataDir string) string {
	path := KeyPath(dataDir)
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	const seFileObject, daclSecurityInformation = 1, 4
	var dacl *aclHeader
	var sd uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(p)), seFileObject, daclSecurityInformation,
		0, 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&sd))); r != 0 {
		if syscall.Errno(r) == syscall.ERROR_FILE_NOT_FOUND {
			return ""
		}
		return fmt.Sprintf("the permissions of %s can't be read: %v", path, syscall.Errno(r))
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	if dacl == nil {
		return fmt.Sprintf("%s has no access list: everyone can read it. Run setup again to restrict it", path)
	}
	var others []string
	for i := uint16(0); i < dacl.Count; i++ {
		var ace *allowACE
		if r, _, _ := procGetAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(i), uintptr(unsafe.Pointer(&ace))); r == 0 || ace == nil {
			continue
		}
		const accessAllowed, inheritOnly = 0, 0x8
		if ace.Type != accessAllowed || ace.Flags&inheritOnly != 0 || ace.Mask == 0 {
			continue
		}
		sid := (*syscall.SID)(unsafe.Pointer(&ace.SidStart))
		s, err := sid.String()
		if err != nil || s == "S-1-5-18" || s == "S-1-5-32-544" {
			continue
		}
		name := s
		if acct, dom, _, err := sid.LookupAccount(""); err == nil {
			name = acct
			if dom != "" {
				name = dom + `\` + acct
			}
		}
		others = append(others, name)
	}
	if len(others) > 0 {
		return fmt.Sprintf("%s can be read by %s, not only Administrators and SYSTEM. Run setup again to restrict it", path, strings.Join(others, ", "))
	}
	return ""
}

// aclHeader is an ACL's header.
type aclHeader struct {
	Revision, Sbz1 byte
	Size, Count    uint16
	Sbz2           uint16
}

// allowACE is an ACCESS_ALLOWED_ACE: its SID starts at SidStart.
type allowACE struct {
	Type, Flags byte
	Size        uint16
	Mask        uint32
	SidStart    uint32
}
