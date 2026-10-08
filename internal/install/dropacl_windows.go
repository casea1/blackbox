//go:build windows

package install

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/casea1/blackbox/internal/hidden"
)

// The drop-only inbox (DESIGN1): Blackbox Senders can add files to the
// inbox, and nothing else. They can't list it, read, change, rename or
// delete anything in it (their own files included), make folders, or
// change permissions. Only the marker file, BLACKBOX-INBOX.txt, is
// readable to them, so a sender can tell the collector's inbox from a
// share that is not connected (an empty local folder).

var (
	advapi32                  = syscall.NewLazyDLL("advapi32.dll")
	procInitializeAcl         = advapi32.NewProc("InitializeAcl")
	procAddAccessAllowedAceEx = advapi32.NewProc("AddAccessAllowedAceEx")
	procSetNamedSecurityInfoW = advapi32.NewProc("SetNamedSecurityInfoW")
)

const (
	aclRevision          = 2
	objectInheritAce     = 0x1
	containerInheritAce  = 0x2
	inheritOnlyAce       = 0x8
	fileAllAccess        = 0x1F01FF
	fileAddFile          = 0x2 // FILE_WRITE_DATA on a file: "Create files / write data"
	synchronize          = 0x100000
	fileGenericRead      = 0x120089
	seFileObject         = 1
	ownerSecurityInfo    = 0x1
	daclSecurityInfo     = 0x4
	protectedDaclSecInfo = 0x80000000
)

// dropACE is one entry of the inbox's access list.
type dropACE struct {
	sid   string
	flags uint32
	mask  uint32
}

// dropOnlyACEs is the inbox folder's whole access list (nothing is
// inherited from the folder above):
//   - SYSTEM and Administrators: full control, this folder and everything in it;
//   - the senders' group: Create files / write data and Synchronize, on this
//     folder only, so the files a sender creates inherit no entry for it;
//   - OWNER RIGHTS: no rights, on the files in it, so the account that
//     creates a file gets no implicit Read permissions / Change permissions
//     on it as its owner.
//
// The handle that creates a file keeps the access it asked for, so a
// sender writes the file it just created, and nothing afterwards.
func dropOnlyACEs(senders string) []dropACE {
	return []dropACE{
		{"S-1-5-18", objectInheritAce | containerInheritAce, fileAllAccess},
		{"S-1-5-32-544", objectInheritAce | containerInheritAce, fileAllAccess},
		{senders, 0, fileAddFile | synchronize},
		{"S-1-3-4", objectInheritAce | containerInheritAce | inheritOnlyAce, 0},
	}
}

// DropOnlyInbox gives dir the drop-only access list for the group
// (normally Blackbox Senders), makes Administrators its owner, and lets
// the group read the inbox marker. Files already in it take the new
// access list. Setup and the upgrade apply it on a collector; it changes
// nothing outside Blackbox's own inbox folder.
func DropOnlyInbox(dir, group, marker string) error {
	gsid, _, _, err := syscall.LookupSID("", group)
	if err != nil {
		return fmt.Errorf("find the %q group: %w", group, err)
	}
	senders, err := gsid.String()
	if err != nil {
		return err
	}
	acl, err := buildACL(dropOnlyACEs(senders))
	if err != nil {
		return err
	}
	admins, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if r, _, _ := procSetNamedSecurityInfoW.Call(uintptr(unsafe.Pointer(p)), seFileObject,
		ownerSecurityInfo|daclSecurityInfo|protectedDaclSecInfo,
		uintptr(unsafe.Pointer(admins)), 0, uintptr(unsafe.Pointer(&acl[0])), 0); r != 0 {
		return fmt.Errorf("set the drop-only permissions on %s: %w", dir, syscall.Errno(r))
	}
	// The marker: readable to senders, so they recognise the inbox.
	if marker != "" {
		if out, err := hidden.Command("icacls.exe", marker, "/grant:r", "*"+senders+":(R)").CombinedOutput(); err != nil {
			return fmt.Errorf("let senders read %s: %v: %s", marker, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// buildACL makes an access list from aces, in order.
func buildACL(aces []dropACE) ([]byte, error) {
	type sidBuf struct {
		sid *syscall.SID
		n   uint32
	}
	sids := make([]sidBuf, len(aces))
	size := uint32(8) // ACL header
	for i, a := range aces {
		s, err := syscall.StringToSid(a.sid)
		if err != nil {
			return nil, fmt.Errorf("SID %s: %w", a.sid, err)
		}
		n := syscall.GetLengthSid(s)
		sids[i] = sidBuf{s, n}
		size += 8 + n // ACE header and mask, then the SID
	}
	size = (size + 3) &^ 3
	acl := make([]byte, size)
	if r, _, err := procInitializeAcl.Call(uintptr(unsafe.Pointer(&acl[0])), uintptr(size), aclRevision); r == 0 {
		return nil, fmt.Errorf("InitializeAcl: %w", err)
	}
	for i, a := range aces {
		if r, _, err := procAddAccessAllowedAceEx.Call(uintptr(unsafe.Pointer(&acl[0])), aclRevision,
			uintptr(a.flags), uintptr(a.mask), uintptr(unsafe.Pointer(sids[i].sid))); r == 0 {
			return nil, fmt.Errorf("AddAccessAllowedAceEx %s: %w", a.sid, err)
		}
	}
	return acl, nil
}
