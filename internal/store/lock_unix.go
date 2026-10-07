//go:build !windows

package store

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func openLockFile(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o640)
}

// lockFile takes flock on f without waiting.
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			return errLocked
		}
		return err
	}
}

func unlockFile(f *os.File) { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// releaseLock removes the file while still holding the lock, so a run
// waiting on the old file sees it has gone (stillAt) and opens the new
// one, then releases it.
func releaseLock(f *os.File, p string) {
	os.Remove(p)
	unlockFile(f)
	f.Close()
}

// lockHeld tests whether another handle holds the lock on f. A lock
// taken to test is released at once and the file left as it was.
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
	if started, ok := processStart(pid); ok {
		return !started.After(since.Add(startSlack))
	}
	if _, err := os.Stat("/proc/self/stat"); err == nil {
		return false // /proc works, and has no such process
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// processStart reads when a process started, from /proc (Linux).
func processStart(pid int) (time.Time, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return time.Time{}, false
	}
	// The command name, in brackets, may hold spaces: the fields that
	// follow start after the last ")".
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return time.Time{}, false
	}
	fields := strings.Fields(s[i+1:])
	// starttime is field 22 overall; field 3 (state) is fields[0].
	if len(fields) < 20 {
		return time.Time{}, false
	}
	if fields[0] == "Z" || fields[0] == "X" {
		return time.Time{}, false // a zombie: it has ended
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	boot, ok := bootTime()
	if !ok {
		return time.Time{}, false
	}
	const hz = 100 // USER_HZ, 100 on every Linux Blackbox runs on
	return boot.Add(time.Duration(ticks) * time.Second / hz), true
}

func bootTime() (time.Time, bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "btime "); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, false
			}
			return time.Unix(n, 0), true
		}
	}
	return time.Time{}, false
}
