package store

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for a Blackbox run holding the
// lock (LOCK1): BLACKBOX_LOCK_HELPER names the data folder; "sleep" only
// sleeps, without taking the lock.
func TestMain(m *testing.M) {
	switch dir := os.Getenv("BLACKBOX_LOCK_HELPER"); {
	case dir == "sleep":
		fmt.Println("ready")
		time.Sleep(time.Minute)
		os.Exit(0)
	case dir != "":
		s, err := Open(dir)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if _, err := s.Lock(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("ready")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// startHelper starts the test binary as a run (or a sleeper) and waits
// until it is ready.
func startHelper(t *testing.T, mode string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "BLACKBOX_LOCK_HELPER="+mode)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, _ := bufio.NewReader(out).ReadString('\n')
	if strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper: %q", line)
	}
	return cmd
}

func TestLockHeldByLiveRun(t *testing.T) {
	dir := t.TempDir()
	child := startHelper(t, dir)
	s, _ := Open(dir)
	_, err := s.Lock()
	var busy *BusyError
	if !errors.As(err, &busy) || !errors.Is(err, ErrBusy) {
		t.Fatalf("Lock while another run holds it = %v, want a BusyError", err)
	}
	if busy.Holder.PID != child.Process.Pid {
		t.Errorf("holder PID %d, want %d", busy.Holder.PID, child.Process.Pid)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("PID %d", child.Process.Pid)) {
		t.Errorf("error does not name the holder: %v", err)
	}
	if h, held := s.LockHolder(); !held || h.PID != child.Process.Pid {
		t.Errorf("LockHolder = %+v, %v; want held by %d", h, held, child.Process.Pid)
	}
	// Reading who holds it changes nothing.
	if _, err := s.Lock(); !errors.Is(err, ErrBusy) {
		t.Errorf("after LockHolder, Lock = %v, want ErrBusy", err)
	}
}

func TestLockLeftByKilledRun(t *testing.T) {
	dir := t.TempDir()
	child := startHelper(t, dir)
	// kill -9 (TerminateProcess on Windows): the run gets no chance to
	// remove anything.
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	child.Wait()
	if b, err := os.ReadFile(dirLock(dir)); err != nil || !strings.HasPrefix(string(b), fmt.Sprint(child.Process.Pid)+" ") {
		t.Fatalf("the killed run's lock file = %q, %v; want its PID", b, err)
	}
	s, _ := Open(dir)
	if _, held := s.LockHolder(); held {
		t.Error("LockHolder says a killed run still holds the lock")
	}
	unlock, err := s.Lock()
	if err != nil {
		t.Fatalf("Lock after the holder was killed = %v, want it taken at once", err)
	}
	if b, _ := os.ReadFile(dirLock(dir)); !strings.HasPrefix(string(b), fmt.Sprint(os.Getpid())+" ") {
		t.Errorf("lock file = %q, want this process's PID", b)
	}
	unlock()
}

// A lock file from a version before 0.18 (no operating-system lock) holds
// only while its process runs, and not when the PID was given to a
// process that started later.
func TestLockFileWithoutOSLock(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	write := func(pid int, since time.Time) {
		os.WriteFile(dirLock(dir), []byte(fmt.Sprintf("%d %s\n", pid, since.Format(time.RFC3339))), 0o640)
	}
	sleeper := startHelper(t, "sleep")
	pid := sleeper.Process.Pid

	write(pid, time.Now())
	if _, err := s.Lock(); !errors.Is(err, ErrBusy) {
		t.Fatalf("old-style lock of a running process: Lock = %v, want ErrBusy", err)
	}
	if _, held := s.LockHolder(); !held {
		t.Error("LockHolder: old-style lock of a running process not held")
	}

	write(pid, time.Now().Add(-time.Hour)) // the PID was reused since
	unlock, err := s.Lock()
	if err != nil {
		t.Fatalf("lock naming a reused PID: Lock = %v, want it taken", err)
	}
	unlock()

	sleeper.Process.Kill()
	sleeper.Wait()
	write(pid, time.Now())
	unlock, err = s.Lock()
	if err != nil {
		t.Fatalf("lock of an ended process: Lock = %v, want it taken", err)
	}
	unlock()
}

func dirLock(dir string) string { s := &Store{Dir: dir}; return s.lockPath() }
