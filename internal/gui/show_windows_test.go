package gui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// TRAY1: started the way the "Blackbox Status" task starts the icon (with
// a hidden show mode in its STARTUPINFO), the first window the menu opens
// must be visible on the first click, with no hidden one left behind.
func TestFirstDialogShows(t *testing.T) {
	if mode := os.Getenv("BB_SHOWTEST"); mode != "" {
		initUI()
		if mode == "tray" {
			consumeStartupShow(newWindow("Blackbox status", 0, 0, 0).hwnd)
		}
		d := newWindow("Make a manual report", 380, 250, 0)
		if mode == "raw" {
			pShowWindow.Call(d.hwnd, swShowNormal) // as 0.16.1 did
		} else {
			d.show()
		}
		v, _, _ := pIsWindowVisible.Call(d.hwnd)
		fmt.Printf("VISIBLE=%d\n", v)
		d.close()
		return
	}
	run := func(mode string) string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFirstDialogShows$")
		cmd.Env = append(os.Environ(), "BB_SHOWTEST="+mode)
		// HideWindow sets STARTF_USESHOWWINDOW with SW_HIDE, as a task
		// that starts a program hidden does.
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "VISIBLE="); ok {
				return v
			}
		}
		t.Fatalf("%s: no result\n%s", mode, out)
		return ""
	}
	// The reproduction: one ShowWindow, as before, under a hidden start.
	t.Logf("0.16.1's single ShowWindow under a hidden start: visible=%s", run("raw"))
	for _, mode := range []string{"dialog", "tray"} {
		if v := run(mode); v != "1" {
			t.Errorf("%s: the first dialog is hidden", mode)
		}
	}
}
