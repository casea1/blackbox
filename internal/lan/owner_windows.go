//go:build windows

package lan

import (
	"syscall"
	"unsafe"
)

var procGetNamedSecurityInfo = syscall.NewLazyDLL("advapi32.dll").NewProc("GetNamedSecurityInfoW")

// fileOwner is the account that owns (wrote) a file, or "".
func fileOwner(path string) string {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	const seFileObject, ownerSecurityInformation = 1, 1
	var owner *syscall.SID
	var sd uintptr
	r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(p)), seFileObject, ownerSecurityInformation,
		uintptr(unsafe.Pointer(&owner)), 0, 0, 0, uintptr(unsafe.Pointer(&sd)))
	if r != 0 || owner == nil {
		return ""
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	acct, dom, _, err := owner.LookupAccount("")
	if err != nil {
		s, _ := owner.String()
		return s
	}
	if dom != "" {
		return dom + `\` + acct
	}
	return acct
}
