package store

import (
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx         = kernel32.NewProc("LockFileEx")
	procUnlockFileEx       = kernel32.NewProc("UnlockFileEx")
	procGetProcessTimes    = kernel32.NewProc("GetProcessTimes")
	procGetExitCodeProcess = kernel32.NewProc("GetExitCodeProcess")
)

const (
	lockfileExclusiveLock   = 0x2
	lockfileFailImmediately = 0x1
	errorLockViolation      = syscall.Errno(33)
	errorIOPending          = syscall.Errno(997)
	processQueryLimitedInfo = 0x1000
	stillActive             = 259
)

// The lock is on one byte far past the end of the file: Windows locks
// stop other handles reading what they cover, and status reads the file.
const lockOffsetHigh = 1 // 4 GiB

func openLockFile(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o640)
}

func lockFile(f *os.File) error {
	var ol syscall.Overlapped
	ol.OffsetHigh = lockOffsetHigh
	r, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r != 0 {
		return nil
	}
	if errors.Is(err, errorLockViolation) || errors.Is(err, errorIOPending) {
		return errLocked
	}
	return err
}

func unlockFile(f *os.File) {
	var ol syscall.Overlapped
	ol.OffsetHigh = lockOffsetHigh
	procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
}

// releaseLock empties the file and releases the lock. The file is kept:
// Windows does not let a file another run has open be removed cleanly.
func releaseLock(f *os.File, _ string) {
	f.Truncate(0)
	unlockFile(f)
	f.Close()
}

// lockHeld tests whether another handle holds the lock on f; a lock taken
// to test is released at once.
func lockHeld(f *os.File) (held, known bool) {
	switch err := lockFile(f); {
	case err == nil:
		unlockFile(f)
		return false, true
	case errors.Is(err, errLocked):
		return true, true
	}
	return false, false
}

// processRunning reports whether process pid is running and started no
// later than since (allowing startSlack): a process that started later
// has only been given the same number.
func processRunning(pid int, since time.Time) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(processQueryLimitedInfo, false, uint32(pid))
	if err != nil {
		// Access denied means it exists; anything else, that it doesn't.
		return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if r, _, _ := procGetExitCodeProcess.Call(uintptr(h), uintptr(unsafe.Pointer(&code))); r != 0 && code != stillActive {
		return false
	}
	var created, exited, kernel, user syscall.Filetime
	if r, _, _ := procGetProcessTimes.Call(uintptr(h), uintptr(unsafe.Pointer(&created)), uintptr(unsafe.Pointer(&exited)),
		uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user))); r != 0 {
		return !time.Unix(0, created.Nanoseconds()).After(since.Add(startSlack))
	}
	return true
}
