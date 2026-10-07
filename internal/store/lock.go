package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The lock keeps two runs from working on the data folder at once (LOCK1).
// It is an operating-system lock (flock on Linux, LockFileEx on Windows)
// on blackbox.lock, held on a handle kept open for the run, so the kernel
// releases it when the run ends in any way: a crash, kill -9, an
// out-of-memory kill or power loss leave nothing that blocks the next run.
// The file also says which process holds it and since when, for status
// and the log.

// Holder is the run that holds, or last held, the lock.
type Holder struct {
	PID   int       `json:"pid"`
	Since time.Time `json:"since"`
}

// Blocked is collection refused because another run held the lock for
// longer than a scheduled run waits (LOCK1): scheduled runs from First to
// Last (Refused of them) collected nothing.
type Blocked struct {
	Holder  Holder    `json:"holder"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Refused int       `json:"refused"`
	// Until is when the lock was free again: the next run that collected.
	Until time.Time `json:"until,omitzero"`
}

func (h Holder) String() string {
	if h.PID == 0 {
		return "unknown"
	}
	return fmt.Sprintf("PID %d, since %s", h.PID, h.Since.Local().Format("2006-01-02 15:04"))
}

// BusyError is ErrBusy with the run that holds the lock.
type BusyError struct {
	Holder Holder
	Path   string
}

func (e *BusyError) Error() string {
	return fmt.Sprintf("%v (%s; lock file %s)", ErrBusy, e.Holder, e.Path)
}

func (e *BusyError) Unwrap() error { return ErrBusy }

// errLocked is what lockFile returns when another handle holds the lock.
var errLocked = errors.New("locked")

func (s *Store) lockPath() string { return filepath.Join(s.Dir, "blackbox.lock") }

// Lock prevents two runs at once. It fails with a *BusyError (ErrBusy)
// while another run holds it.
func (s *Store) Lock() (unlock func(), err error) {
	p := s.lockPath()
	for attempt := 0; attempt < 5; attempt++ {
		f, err := openLockFile(p)
		if err != nil {
			return nil, err
		}
		if err := lockFile(f); err != nil {
			h, _ := readHolder(f)
			f.Close()
			if errors.Is(err, errLocked) {
				return nil, &BusyError{Holder: h, Path: p}
			}
			return nil, fmt.Errorf("lock %s: %w", p, err)
		}
		// The file may have been removed by the run that held it just
		// before this one took the lock: then the lock is on a file no
		// other run can see, so try again with the one now at p.
		if !stillAt(f, p) {
			unlockFile(f)
			f.Close()
			continue
		}
		// What the file says is left from a run that ended without
		// releasing it (the lock is free), or from a run of a version
		// before 0.18 that held it without an operating-system lock: that
		// one is still running only if its process is (LOCK1).
		if h, ok := readHolder(f); ok && h.PID != os.Getpid() && processRunning(h.PID, h.Since) {
			unlockFile(f)
			f.Close()
			return nil, &BusyError{Holder: h, Path: p}
		}
		if err := writeHolder(f, Holder{PID: os.Getpid(), Since: time.Now()}); err != nil {
			unlockFile(f)
			f.Close()
			return nil, err
		}
		// Only the lock holder may undo an interrupted import; a reader
		// (such as "blackbox status") must never touch the spool.
		release := func() { releaseLock(f, p) }
		if err := s.recoverImport(); err != nil {
			release()
			return nil, err
		}
		return release, nil
	}
	return nil, fmt.Errorf("could not take lock %s", p)
}

// LockHolder reports the run holding the lock now, if one does. It never
// changes the file, so a reader such as "blackbox status" can call it.
func (s *Store) LockHolder() (Holder, bool) {
	p := s.lockPath()
	f, err := os.Open(p)
	if err != nil {
		return Holder{}, false
	}
	defer f.Close()
	h, ok := readHolder(f)
	if held, known := lockHeld(f); known {
		// A run of a version before 0.18 holds it without an
		// operating-system lock.
		return h, held || (ok && h.PID != os.Getpid() && processRunning(h.PID, h.Since))
	}
	// The lock can't be tested from here: trust the file only while its
	// process runs.
	return h, ok && processRunning(h.PID, h.Since)
}

// readHolder reads "PID time" from the lock file.
func readHolder(f *os.File) (Holder, bool) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Holder{}, false
	}
	b, err := io.ReadAll(io.LimitReader(f, 256))
	if err != nil {
		return Holder{}, false
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return Holder{}, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return Holder{}, false
	}
	t, err := time.Parse(time.RFC3339, fields[1])
	if err != nil {
		return Holder{}, false
	}
	return Holder{PID: pid, Since: t}, true
}

func writeHolder(f *os.File, h Holder) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt([]byte(fmt.Sprintf("%d %s\n", h.PID, h.Since.Format(time.RFC3339))), 0); err != nil {
		return err
	}
	return f.Sync()
}

// stillAt reports whether the open file f is the one at path p.
func stillAt(f *os.File, p string) bool {
	a, err := f.Stat()
	if err != nil {
		return false
	}
	b, err := os.Stat(p)
	if err != nil {
		return false
	}
	return os.SameFile(a, b)
}

// startSlack allows for the lock's time being written a moment after the
// process started, and for clocks read differently.
const startSlack = 2 * time.Minute
