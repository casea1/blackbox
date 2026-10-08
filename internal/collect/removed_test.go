package collect

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/casea1/blackbox/internal/event"
)

// DET1b: the run that collects a command deleting Blackbox's files notes
// which files it names are gone and which are still there; one gone from
// a folder Blackbox empties itself, or a pattern matching nothing, is not
// taken as deleted.
func TestCheckRemoved(t *testing.T) {
	exists := map[string]bool{"/var/lib/blackbox/state.json": true, "/var/lib/blackbox/spool/x.jsonl": true}
	lstat, glob = func(p string) (os.FileInfo, error) {
		if exists[p] {
			return nil, nil
		}
		return nil, fs.ErrNotExist
	}, func(p string) ([]string, error) {
		if p == "/var/lib/blackbox/spool/*" {
			return []string{"/var/lib/blackbox/spool/x.jsonl"}, nil
		}
		return nil, nil
	}
	defer func() { lstat, glob = os.Lstat, filepath.Glob }()
	cmd := `/usr/bin/rm -f /var/lib/blackbox/state.json "/var/lib/blackbox/runs.jsonl" /var/lib/blackbox/collector/stray.txt /var/lib/blackbox/spool/* /var/lib/blackbox/old/*.json notes.txt`
	e := &event.Event{Action: "blackbox_files_removed", Command: cmd}
	checkRemoved(e, []string{"/var/lib/blackbox/collector"})
	want := map[string]string{
		event.RemovedThere: "/var/lib/blackbox/state.json\n/var/lib/blackbox/spool/*",
		event.RemovedGone:  "/var/lib/blackbox/runs.jsonl",
		event.RemovedMoved: "/var/lib/blackbox/collector/stray.txt",
	}
	for k, v := range want {
		if e.Fields[k] != v {
			t.Errorf("%s = %q, want %q", k, e.Fields[k], v)
		}
	}
	other := &event.Event{Action: "sudo_command", Command: cmd}
	checkRemoved(other, nil)
	if other.Fields != nil {
		t.Errorf("another command was checked: %v", other.Fields)
	}
}
