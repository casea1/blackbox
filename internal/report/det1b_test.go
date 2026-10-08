package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// det1bAudit is the 0.25.0 re-test's "sudo rm" of a file in Blackbox's
// inbox: sudo's USER_CMD and rm's execve (success=yes), and, unless
// unlink is "", rm's unlinkat ("ok" or "refused"). On a CIFS share with
// no watch rules there is no unlinkat record at all.
func det1bAudit(at int64, serial, sudoPID int, file, unlink string) []string {
	lines := det1Audit(at, serial, sudoPID, file, unlink == "ok")
	cmd := "/usr/bin/rm /var/lib/blackbox/collector/" + file
	stamp := fmt.Sprintf("msg=audit(%d.%03d:%d):", at, 2, serial+2)
	exec := []string{
		`type=SYSCALL ` + stamp + fmt.Sprintf(` arch=c000003e syscall=59 success=yes exit=0 a0=55d1 a1=55d2 a2=55d3 a3=0 items=2 ppid=%d pid=%d auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="rm" exe="/usr/bin/rm" subj=unconfined key="root_commands"`, sudoPID, sudoPID+1),
		`type=EXECVE ` + stamp + ` argc=2 a0="/usr/bin/rm" a1="/var/lib/blackbox/collector/` + file + `"`,
		`type=PROCTITLE ` + stamp + fmt.Sprintf(` proctitle=%X`, strings.ReplaceAll(cmd, " ", "\x00")),
	}
	out := append([]string{lines[0]}, exec...)
	if unlink != "" {
		out = append(out, lines[1:]...)
	}
	return out
}

// DET1b: with only the command line (sudo's record and rm's execve, no
// record of the delete), the row is "ran rm on Blackbox's files",
// Medium, "whether it worked isn't recorded": not a removal and no High.
func TestCommandOnlyDeleteIsMedium(t *testing.T) {
	r := det1Build(t, det1bAudit(1790730000, 500, 5100, "stray-0.25.txt", ""))
	if got := det1Rows(r, "blackbox_files_removed"); len(got) != 0 {
		t.Fatalf("a delete known only from its command is still a removal: %v", summaries(got))
	}
	rows := det1Rows(r, unconfirmedRemove)
	if len(rows) != 1 {
		t.Fatalf("%d command-only delete rows, want 1: %v", len(rows), summaries(r.Events))
	}
	e := rows[0]
	want := "claude ran rm on Blackbox's files: /usr/bin/rm /var/lib/blackbox/collector/stray-0.25.txt"
	if e.Summary != want || e.Severity != event.SevMedium || e.Category != event.CatIntegrity {
		t.Errorf("row: %q %s %s, want %q Medium", e.Summary, e.Severity, e.Category, want)
	}
	if got := detail(e, "Whether it worked"); !strings.HasPrefix(got, "isn't recorded") {
		t.Errorf("Whether it worked: %q", got)
	}
	for _, f := range r.Findings {
		if f.Severity == event.SevHigh {
			t.Errorf("High detection: %s — %s", f.Title, f.Detail)
		}
	}
	if f := det1RemovedFindings(r); len(f) != 0 {
		t.Errorf("removal detection for a delete not known to have worked: %+v", f[0])
	}
	found := false
	for _, g := range r.Medium {
		if g.Label == "delete command on Blackbox's files (whether it worked isn't recorded)" && g.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("Medium line: %+v", r.Medium)
	}
	h, _ := renderHTML(t, r)
	if strings.Contains(h, "deleted Blackbox") || strings.Contains(h, "files removed") {
		t.Error("the report pages still call it a removal")
	}
}

// DET1b: the command and a successful unlink of the file by rm is a
// removal, High.
func TestCommandWithSuccessfulUnlinkIsHigh(t *testing.T) {
	r := det1Build(t, det1bAudit(1790730000, 500, 5100, "old-batch-1.json", "ok"))
	removed := det1Rows(r, "blackbox_files_removed")
	if len(removed) != 1 || removed[0].Severity != event.SevHigh ||
		removed[0].Summary != "claude deleted Blackbox's files: /usr/bin/rm /var/lib/blackbox/collector/old-batch-1.json" {
		t.Fatalf("removal rows: %v (all: %v)", summaries(removed), summaries(r.Events))
	}
	if n := len(det1Rows(r, unconfirmedRemove)) + len(det1Rows(r, refusedRemove)); n != 0 {
		t.Errorf("%d attempt rows for a delete that worked", n)
	}
}

// DET1b: the command and a refused unlink is the refused attempt, Medium.
func TestCommandWithRefusedUnlinkIsRefused(t *testing.T) {
	r := det1Build(t, det1bAudit(1790730000, 500, 5100, "probe.txt", "refused"))
	refused := det1Rows(r, refusedRemove)
	if len(refused) != 1 || refused[0].Severity != event.SevMedium ||
		refused[0].Summary != "claude tried to delete Blackbox's files (refused): /usr/bin/rm /var/lib/blackbox/collector/probe.txt" {
		t.Fatalf("refused rows: %v (all: %v)", summaries(refused), summaries(r.Events))
	}
	if n := len(det1Rows(r, "blackbox_files_removed")) + len(det1Rows(r, unconfirmedRemove)); n != 0 {
		t.Errorf("%d other delete rows", n)
	}
}

// DET1b: a file the command names that was gone at the Blackbox run that
// collected it shows the delete worked: High, with the file in its
// details. One still there stays Medium and says so.
func TestCommandOnlyDeleteFileGoneOrThere(t *testing.T) {
	at := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	mk := func(file, key string) *event.Event {
		cmd := "rm /var/lib/blackbox/spool/" + file
		return &event.Event{Time: at, Host: "ub", OS: "linux", User: "claude", Action: "blackbox_files_removed", Severity: event.SevHigh,
			Category: event.CatIntegrity, Command: cmd, Summary: "claude deleted Blackbox's files: " + cmd,
			Fields: map[string]string{key: "/var/lib/blackbox/spool/" + file}}
	}
	gone, there, moved := mk("a.json", event.RemovedGone), mk("b.json", event.RemovedThere), mk("c.json", event.RemovedMoved)
	refusedDeletes([]*event.Event{gone, there, moved})
	if gone.Action != "blackbox_files_removed" || gone.Severity != event.SevHigh || detail(gone, "Gone at Blackbox's next run") != "/var/lib/blackbox/spool/a.json" {
		t.Errorf("gone: %s %s %v", gone.Severity, gone.Action, gone.Details)
	}
	if there.Action != unconfirmedRemove || there.Severity != event.SevMedium || there.Summary != "claude ran rm on Blackbox's files: rm /var/lib/blackbox/spool/b.json" ||
		detail(there, "Still there at Blackbox's next run") != "/var/lib/blackbox/spool/b.json" {
		t.Errorf("there: %s %s %q %v", there.Severity, there.Action, there.Summary, there.Details)
	}
	if moved.Action != unconfirmedRemove || !strings.Contains(detail(moved, "Not there at Blackbox's next run"), "Blackbox moves files out of that folder itself") {
		t.Errorf("moved: %s %v", moved.Action, moved.Details)
	}
}
