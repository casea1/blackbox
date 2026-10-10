//go:build !windows

package lan

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// SEC6: a sender that makes inbox/rejected first, with a link where the
// collector would write its note, cannot make the collector write
// through it.
func TestSetAsideIgnoresFolderMadeInInbox(t *testing.T) {
	in := inbox(t)
	canary := filepath.Join(t.TempDir(), "canary")
	os.WriteFile(canary, []byte("untouched"), 0o600)
	os.Mkdir(filepath.Join(in, rejectedDir), 0o777)
	os.Symlink(canary, filepath.Join(in, rejectedDir, "AAA_0123456789abcdef_0000000001.bbx"+whyExt))
	os.WriteFile(filepath.Join(in, "AAA_0123456789abcdef_0000000001.bbx"), []byte("junk"), 0o600)
	col, _ := store.Open(t.TempDir())
	res, err := Import(col, in, Dirs{}, time.Now().Add(time.Hour), t.Logf)
	if err != nil || len(res.Rejected) != 1 {
		t.Fatalf("import %+v %v", res, err)
	}
	if b, _ := os.ReadFile(canary); string(b) != "untouched" {
		t.Errorf("the collector wrote through a sender's link: %q", b)
	}
	if _, err := os.Lstat(filepath.Join(in, rejectedDir)); err == nil {
		t.Error("the folder made in the inbox is still there")
	}
	if got := Rejected(SetAsideDir(col.Dir)); len(got) != 1 || !strings.Contains(got[0], "AAA_") {
		t.Errorf("Rejected lists %v", got)
	}
}

// SEC6: a pipe or a link in the inbox is set aside without being opened:
// a pipe would hold up the import, a link would make the collector read
// a file the sender can't.
func TestInboxPipeAndLinkNotOpened(t *testing.T) {
	in := inbox(t)
	if err := syscall.Mkfifo(filepath.Join(in, "AAA_0123456789abcdef_0000000001.bbx"), 0o600); err != nil {
		t.Skip("no pipes:", err)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("root only"), 0o600)
	os.Symlink(secret, filepath.Join(in, "AAA_0123456789abcdef_0000000002.bbx"))
	os.Symlink(secret, filepath.Join(in, "scap_0123456789abcdef_0123456789abcdef.xml.gz"))
	col, _ := store.Open(t.TempDir())
	done := make(chan ImportResult)
	go func() {
		res, _ := Import(col, in, Dirs{Scap: t.TempDir()}, t0.Add(time.Hour), t.Logf)
		done <- res
	}()
	select {
	case res := <-done:
		if len(res.Rejected) != 3 {
			t.Fatalf("set aside: %v", res.Rejected)
		}
		for _, r := range res.Rejected {
			if !strings.Contains(r, "not a regular file") {
				t.Errorf("reason: %s", r)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the import waited on a pipe in the inbox")
	}
	if b, _ := os.ReadFile(secret); string(b) != "root only" {
		t.Error("the linked file changed")
	}
	if bad := Unreadable(in); len(bad) != 0 {
		t.Errorf("unreadable: %v", bad)
	}
}

// Files earlier versions set aside or held in inbox/rejected move to the
// data folder at the next import, and are listed from there.
func TestSetAsideMovedOutOfInbox(t *testing.T) {
	in := inbox(t)
	old := filepath.Join(in, rejectedDir)
	os.MkdirAll(filepath.Join(old, heldDir), 0o750)
	os.WriteFile(filepath.Join(old, "x_1.bbx"), []byte("junk"), 0o640)
	os.WriteFile(filepath.Join(old, "x_1.bbx"+whyExt), []byte("Why:        not a batch\r\n"), 0o640)
	os.WriteFile(filepath.Join(old, heldDir, "y_2.bbx"), []byte("held"), 0o640)
	os.Symlink("/etc/passwd", filepath.Join(old, "link.bbx"))
	col, _ := store.Open(t.TempDir())
	if _, err := Import(col, in, Dirs{}, t0, t.Logf); err != nil {
		t.Fatal(err)
	}
	aside := SetAsideDir(col.Dir)
	if got := Rejected(aside); len(got) != 1 || got[0] != "x_1.bbx (not a batch)" {
		t.Errorf("Rejected lists %v", got)
	}
	if got := Held(aside); len(got) != 1 || got[0] != "y_2.bbx" {
		t.Errorf("Held lists %v", got)
	}
	if _, err := os.Lstat(old); err == nil {
		t.Error("inbox/rejected is still there")
	}
}
