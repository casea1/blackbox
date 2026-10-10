package lan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// L9: a file that can't be moved aside is not said to be set aside.
func TestRejectSaysSetAsideOnlyIfMoved(t *testing.T) {
	inbox := t.TempDir()
	os.WriteFile(filepath.Join(inbox, "x_1.bbx"), []byte("junk"), 0o600)
	// "aside" is a file, so the folder can't be made and nothing moves.
	os.WriteFile(filepath.Join(inbox, "aside"), nil, 0o600)
	msg := reject(filepath.Join(inbox, "aside"), inbox, "", "x_1.bbx", "not a batch", time.Now())
	if strings.Contains(msg, "set aside in") || !strings.Contains(msg, "stays in the inbox") {
		t.Errorf("message: %s", msg)
	}
	if _, err := os.Stat(filepath.Join(inbox, "x_1.bbx")); err != nil {
		t.Errorf("file moved: %v", err)
	}

	inbox = t.TempDir()
	os.WriteFile(filepath.Join(inbox, "x_1.bbx"), []byte("junk"), 0o600)
	if msg := reject(filepath.Join(inbox, "aside"), inbox, "", "x_1.bbx", "not a batch", time.Now()); !strings.Contains(msg, "set aside in") {
		t.Errorf("message: %s", msg)
	}
}

// L9: an inbox file the collector can't read is listed, with why.
func TestUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root Unix user (root reads any file)")
	}
	inbox := t.TempDir()
	os.WriteFile(filepath.Join(inbox, MarkerFile), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(inbox, "ubu_ab12_7.bbx"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(inbox, "ubu_ab12_8.bbx"), []byte("x"), 0o000)
	got := Unreadable(inbox)
	if len(got) != 1 || got[0] != "ubu_ab12_8.bbx (access denied)" {
		t.Errorf("Unreadable = %q", got)
	}
}
