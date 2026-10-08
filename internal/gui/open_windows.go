//go:build windows

package gui

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/hidden"
)

// elevate restarts this program with administrator rights (the UAC
// prompt), running the given command.
func elevate(arg string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	r, _, _ := pShellExecuteW.Call(0, ptr("runas"), ptr(exe), ptr(arg), ptr(filepath.Dir(exe)), swShowNormal)
	if r <= 32 {
		messageBox(0, "Blackbox setup needs administrator rights.", "Blackbox setup", mbOK|mbIconWarning)
		return errors.New("setup needs administrator rights")
	}
	return nil
}

// openFolder opens a folder in Explorer. Explorer offers its own Continue
// button when the person's account can't open it without full rights.
func openFolder(owner uintptr, dir string) {
	if dir == "" {
		return
	}
	if err := exec.Command("explorer.exe", dir).Start(); err != nil {
		messageBox(owner, err.Error(), "Blackbox", mbOK|mbIconError)
	}
}

// openReport opens a report in the person's own browser. Setup and the
// status icon run with full administrator rights; the file is handed to
// Explorer, which opens it with the person's normal rights, so the browser
// never runs as administrator. If their account can't read the reports
// folder that way, they are asked before anything is changed
// (SETUP-SPEC.md, "Opening reports").
func openReport(owner uintptr, file, reportsDir string) {
	if file == "" {
		return
	}
	if reportsDir != "" && !userCanRead(file) {
		account, sid := currentAccount()
		if !strings.EqualFold(filepath.Clean(reportsDir), filepath.Join(config.DefaultDataDir(), "reports")) {
			// A folder someone chose and limited (such as an auditors'
			// group): its access is theirs to decide, so nothing is offered.
			messageBox(owner, account+" can't open "+reportsDir+". Only the people given access to that folder can open its reports.", "Blackbox", mbOK|mbIconWarning)
			return
		}
		if messageBox(owner, folderAccessQuestion(reportsDir, account), "Blackbox", mbYesNo|mbIconQuestion) != idYes {
			return // No: nothing is changed
		}
		out, err := hidden.Command("icacls.exe", reportsDir, "/grant", "*"+sid+":(OI)(CI)RX").CombinedOutput()
		if err != nil {
			messageBox(owner, fmt.Sprintf("Read access could not be given: %v\n%s", err, out), "Blackbox", mbOK|mbIconError)
			return
		}
	}
	if err := exec.Command("explorer.exe", file).Start(); err != nil {
		messageBox(owner, err.Error(), "Blackbox", mbOK|mbIconError)
	}
}

// currentAccount names the person running this program.
func currentAccount() (name, sid string) {
	var tok syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(currentProcess()), syscall.TOKEN_QUERY, &tok); err != nil {
		return os.Getenv("USERNAME"), ""
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return os.Getenv("USERNAME"), ""
	}
	sid, _ = u.User.Sid.String()
	if acc, dom, _, err := u.User.Sid.LookupAccount(""); err == nil {
		return dom + `\` + acc, sid
	}
	return os.Getenv("USERNAME"), sid
}

func currentProcess() uintptr {
	h, _ := syscall.GetCurrentProcess()
	return uintptr(h)
}

var (
	pGetFileSecurityW = advapi32.NewProc("GetFileSecurityW")
	pAccessCheck      = advapi32.NewProc("AccessCheck")
)

// userCanRead says whether the person's normal (not elevated) rights can
// read a file. When this program isn't running elevated through UAC there
// is only one set of rights, and the answer is yes.
func userCanRead(path string) bool {
	var tok syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(currentProcess()), syscall.TOKEN_QUERY, &tok); err != nil {
		return true
	}
	defer tok.Close()
	var elevType, n uint32
	if err := syscall.GetTokenInformation(tok, 18, (*byte)(unsafe.Pointer(&elevType)), 4, &n); err != nil || elevType != 2 { // TokenElevationType: full
		return true
	}
	var linked syscall.Handle
	if err := syscall.GetTokenInformation(tok, 19, (*byte)(unsafe.Pointer(&linked)), uint32(unsafe.Sizeof(linked)), &n); err != nil { // TokenLinkedToken
		return true
	}
	defer syscall.CloseHandle(linked)

	const info = 1 | 2 | 4 // owner, group, DACL
	var need uint32
	pGetFileSecurityW.Call(ptr(path), info, 0, 0, uintptr(unsafe.Pointer(&need)))
	if need == 0 {
		return true
	}
	sd := make([]byte, need)
	if r, _, _ := pGetFileSecurityW.Call(ptr(path), info, uintptr(unsafe.Pointer(&sd[0])), uintptr(need), uintptr(unsafe.Pointer(&need))); r == 0 {
		return true
	}
	mapping := [4]uint32{0x120089, 0x120116, 0x1200A0, 0x1F01FF} // file read, write, execute, all
	privs := make([]byte, 256)
	privLen := uint32(len(privs))
	var granted, status uint32
	r, _, _ := pAccessCheck.Call(uintptr(unsafe.Pointer(&sd[0])), uintptr(linked), 0x120089, uintptr(unsafe.Pointer(&mapping)),
		uintptr(unsafe.Pointer(&privs[0])), uintptr(unsafe.Pointer(&privLen)), uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&status)))
	if r == 0 {
		return true // couldn't tell: just try to open it
	}
	return status != 0
}
