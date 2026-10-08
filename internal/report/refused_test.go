package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/winevt"
)

// det1Audit is one person's rm of a file in Blackbox's inbox through
// sudo, as auditd writes it with Blackbox's rules (-k blackbox): sudo's
// USER_CMD, then rm's unlinkat. ok false is the refused delete of the
// test (success=no exit=-13, run as the delivery account).
func det1Audit(at int64, serial int, sudoPID int, file string, ok bool) []string {
	cmd := "/usr/bin/rm /var/lib/blackbox/collector/" + file
	stamp := func(n int) string { return fmt.Sprintf("msg=audit(%d.%03d:%d):", at, n, serial+n) }
	uid, name, result := "1002", "bbsend", "success=no exit=-13"
	if ok {
		uid, name, result = "0", "root", "success=yes exit=0"
	}
	return []string{
		`type=USER_CMD ` + stamp(0) + fmt.Sprintf(` pid=%d uid=1000 auid=1000 ses=3 subj=unconfined msg='cwd="/home/claude" cmd=%X exe="/usr/bin/sudo" terminal=pts/0 res=success'`, sudoPID, cmd) +
			"\x1d" + `UID="claude" AUID="claude"`,
		`type=SYSCALL ` + stamp(4) + fmt.Sprintf(` arch=c000003e syscall=263 %s a0=ffffff9c a1=55d1c3a4b4f0 a2=0 a3=0 items=2 ppid=%d pid=%d auid=1000 uid=%s gid=%s euid=%s suid=%s fsuid=%s egid=%s sgid=%s fsgid=%s tty=pts0 ses=3 comm="rm" exe="/usr/bin/rm" subj=unconfined key="blackbox"`,
			result, sudoPID, sudoPID+1, uid, uid, uid, uid, uid, uid, uid, uid) +
			"\x1d" + fmt.Sprintf(`ARCH=x86_64 SYSCALL=unlinkat AUID="claude" UID="%s" GID="%s" EUID="%s" SUID="%s" FSUID="%s" EGID="%s" SGID="%s" FSGID="%s"`, name, name, name, name, name, name, name, name),
		`type=CWD ` + stamp(4) + ` cwd="/home/claude"`,
		`type=PATH ` + stamp(4) + ` item=0 name="/var/lib/blackbox/collector/" inode=393231 dev=08:02 mode=040770 ouid=0 ogid=1002 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0` +
			"\x1d" + `OUID="root" OGID="bbsend"`,
		`type=PATH ` + stamp(4) + ` item=1 name="/var/lib/blackbox/collector/` + file + `" inode=393260 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0` +
			"\x1d" + `OUID="root" OGID="root"`,
		`type=PROCTITLE ` + stamp(4) + fmt.Sprintf(` proctitle=%X`, strings.ReplaceAll(cmd, " ", "\x00")),
	}
}

func det1Build(t *testing.T, lines []string) *Report {
	t.Helper()
	f := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	end := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	evs, _, err := collect.LinuxFiles([]string{f}, nil, "ubuntu-server", "", end)
	if err != nil {
		t.Fatal(err)
	}
	return Build(evs, nil, Options{Location: time.UTC, WindowStart: end.Add(-7 * 24 * time.Hour), WindowEnd: end, Generated: end})
}

func det1Rows(r *Report, action string) []*event.Event {
	var out []*event.Event
	for _, e := range r.Events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func det1RemovedFindings(r *Report) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if strings.Contains(f.Title, "Blackbox's files removed") || strings.Contains(f.Title, "Possible covering of tracks") {
			out = append(out, f)
		}
	}
	return out
}

// DET1: a delete the operating system refused (success=no exit=-13) is
// "tried to delete … (refused)", Medium, and not a removal: no High
// detection, no "Blackbox's files removed", not a step of covering
// tracks.
func TestRefusedDeleteIsNotARemoval(t *testing.T) {
	const at = 1790730000
	var lines []string
	for i, f := range []string{"probe_create.txt", "probe_create2.txt", "probe_create3.txt"} {
		lines = append(lines, det1Audit(at+int64(i)*120, 500+10*i, 5100+10*i, f, false)...)
	}
	r := det1Build(t, lines)
	if got := det1Rows(r, "blackbox_files_removed"); len(got) != 0 {
		t.Errorf("refused deletes counted as removals: %s", got[0].Summary)
	}
	refused := det1Rows(r, refusedRemove)
	if len(refused) != 3 {
		t.Fatalf("%d refused-delete rows, want 3: %v", len(refused), summaries(r.Events))
	}
	e := refused[0]
	want := "claude tried to delete Blackbox's files (refused): /usr/bin/rm /var/lib/blackbox/collector/probe_create.txt"
	if e.Summary != want || e.Severity != event.SevMedium || e.Outcome != "failure" || e.Category != event.CatIntegrity {
		t.Errorf("refused row: %q %s %s %s, want %q Medium failure", e.Summary, e.Severity, e.Outcome, e.Category, want)
	}
	if got := detail(e, "Refused"); got != "/var/lib/blackbox/collector/probe_create.txt (-13)" {
		t.Errorf("Refused detail %q", got)
	}
	if n := len(det1Rows(r, "file_access_denied")); n != 0 {
		t.Errorf("%d separate refused-access rows; the refusal belongs to the command's row", n)
	}
	if f := det1RemovedFindings(r); len(f) != 0 {
		t.Errorf("detection for a refused delete: %+v", f[0])
	}
	for _, f := range r.Findings {
		if f.Severity == event.SevHigh {
			t.Errorf("High detection: %s — %s", f.Title, f.Detail)
		}
	}
	if r.BySev[string(event.SevHigh)] != 0 || r.BySev[string(event.SevMedium)] != 3 {
		t.Errorf("severity counts %v, want 3 Medium and no High", r.BySev)
	}
	var group *AttentionGroup
	for i := range r.Medium {
		if strings.Contains(r.Medium[i].Label, "delete Blackbox's files") {
			group = &r.Medium[i]
		}
	}
	if group == nil || group.Count != 3 || group.Label != "refused attempts to delete Blackbox's files" {
		t.Errorf("Medium line: %+v", r.Medium)
	}
	for _, e := range r.Events {
		if tamperAction(&Row{Event: e}) {
			t.Errorf("counted as tampering: %s", e.Summary)
		}
	}
	// The pages: Detections and Overview have no removal; Search shows the
	// row as Medium.
	h, _ := renderHTML(t, r)
	if strings.Contains(h, "files removed") || strings.Contains(h, "deleted Blackbox") {
		t.Error("the report pages still call the refused delete a removal")
	}
	if !strings.Contains(h, "tried to delete Blackbox") {
		t.Error("the report pages do not show the refused delete")
	}
}

// DET1: a delete that happened keeps its High detection with its own
// count; a refused one beside it is a separate Medium line.
func TestRefusedAndSuccessfulDeletes(t *testing.T) {
	const at = 1790730000
	var lines []string
	lines = append(lines, det1Audit(at, 500, 5100, "probe_create.txt", false)...)
	lines = append(lines, det1Audit(at+120, 510, 5200, "old-batch-1.json", true)...)
	lines = append(lines, det1Audit(at+240, 520, 5300, "old-batch-2.json", true)...)
	r := det1Build(t, lines)
	removed := det1Rows(r, "blackbox_files_removed")
	if len(removed) != 2 {
		t.Fatalf("%d removal rows, want the 2 that happened: %v", len(removed), summaries(r.Events))
	}
	for _, e := range removed {
		if e.Severity != event.SevHigh || !strings.HasPrefix(e.Summary, "claude deleted Blackbox's files: /usr/bin/rm /var/lib/blackbox/collector/old-batch-") {
			t.Errorf("removal row: %s %s", e.Severity, e.Summary)
		}
	}
	var det *Finding
	for i, f := range r.Findings {
		if strings.HasPrefix(f.Title, "Blackbox's files removed") {
			det = &r.Findings[i]
		}
	}
	if det == nil || det.Severity != event.SevHigh || len(det.RowIDs) != 2 || !strings.HasPrefix(det.Detail, "2 Blackbox's files removed") {
		t.Errorf("removal detection: %+v", det)
	}
	refused := det1Rows(r, refusedRemove)
	if len(refused) != 1 || refused[0].Severity != event.SevMedium ||
		refused[0].Summary != "claude tried to delete Blackbox's files (refused): /usr/bin/rm /var/lib/blackbox/collector/probe_create.txt" {
		t.Errorf("refused rows: %v", summaries(refused))
	}
	found := false
	for _, g := range r.Medium {
		if g.Label == "refused attempt to delete Blackbox's files" && g.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("no separate Medium line for the refused delete: %+v", r.Medium)
	}
}

// DET1 on Windows: "del" of a file in C:\ProgramData\Blackbox whose
// delete was refused (4656, audit failure, by the same process) is the
// same Medium attempt; one with no record of the delete is "ran del",
// Medium, as its result isn't recorded (DET1b).
func TestRefusedDeleteWindows(t *testing.T) {
	proc := func(at, pid, cmd string) string {
		return `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="` + at + `"/><EventRecordID>2001</EventRecordID><Correlation/><Execution ProcessID="4" ThreadID="100"/><Channel>Security</Channel><Computer>WIN11-TEST</Computer><Security/></System><EventData>` +
			`<Data Name="SubjectUserSid">S-1-5-21-1111111111-2222222222-3333333333-1001</Data><Data Name="SubjectUserName">jsmith</Data><Data Name="SubjectDomainName">WIN11-TEST</Data><Data Name="SubjectLogonId">0x3e7a1</Data>` +
			`<Data Name="NewProcessId">` + pid + `</Data><Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data><Data Name="TokenElevationType">%%1937</Data><Data Name="ProcessId">0x1f00</Data><Data Name="CommandLine">` + cmd + `</Data>` +
			`<Data Name="TargetUserSid">S-1-0-0</Data><Data Name="TargetUserName">-</Data><Data Name="TargetDomainName">-</Data><Data Name="TargetLogonId">0x0</Data><Data Name="ParentProcessName">C:\Windows\explorer.exe</Data><Data Name="MandatoryLabel">S-1-16-12288</Data></EventData></Event>`
	}
	denied := func(at, pid, file string) string {
		return `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4656</EventID><Version>1</Version><Level>0</Level><Task>12800</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="` + at + `"/><EventRecordID>2002</EventRecordID><Correlation/><Execution ProcessID="4" ThreadID="100"/><Channel>Security</Channel><Computer>WIN11-TEST</Computer><Security/></System><EventData>` +
			`<Data Name="SubjectUserSid">S-1-5-21-1111111111-2222222222-3333333333-1001</Data><Data Name="SubjectUserName">jsmith</Data><Data Name="SubjectDomainName">WIN11-TEST</Data><Data Name="SubjectLogonId">0x3e7a1</Data>` +
			`<Data Name="ObjectServer">Security</Data><Data Name="ObjectType">File</Data><Data Name="ObjectName">C:\ProgramData\Blackbox\` + file + `</Data><Data Name="HandleId">0x0</Data><Data Name="TransactionId">{00000000-0000-0000-0000-000000000000}</Data>` +
			`<Data Name="AccessList">%%1537 %%4423</Data><Data Name="AccessReason">-</Data><Data Name="AccessMask">0x10080</Data><Data Name="PrivilegeList">-</Data><Data Name="RestrictedSidCount">0</Data>` +
			`<Data Name="ProcessId">` + pid + `</Data><Data Name="ProcessName">C:\Windows\System32\cmd.exe</Data><Data Name="ResourceAttributes">-</Data></EventData></Event>`
	}
	xml := "<Events>" +
		proc("2026-09-30T09:00:00.000Z", "0x2a10", `cmd.exe /c del C:\ProgramData\Blackbox\blackbox.conf`) +
		denied("2026-09-30T09:00:00.050Z", "0x2a10", "blackbox.conf") +
		proc("2026-09-30T09:05:00.000Z", "0x2b20", `cmd.exe /c del C:\ProgramData\Blackbox\state.json`) +
		"</Events>"
	tr := winevt.NewTranslator()
	var evs []*event.Event
	if err := winevt.ParseStream(strings.NewReader(xml), func(raw *winevt.Raw) error {
		if e := tr.Translate(raw); e != nil {
			evs = append(evs, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	end := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := Build(evs, nil, Options{Location: time.UTC, WindowStart: end.Add(-7 * 24 * time.Hour), WindowEnd: end, Generated: end})
	refused := det1Rows(r, refusedRemove)
	if len(refused) != 1 || refused[0].Severity != event.SevMedium || !strings.Contains(refused[0].Summary, "jsmith tried to delete Blackbox's files (refused):") ||
		!strings.Contains(refused[0].Summary, `blackbox.conf`) {
		t.Fatalf("refused rows: %v (all: %v)", summaries(refused), summaries(r.Events))
	}
	// The other del has no record of the delete either way (DET1b).
	if removed := det1Rows(r, "blackbox_files_removed"); len(removed) != 0 {
		t.Errorf("removal rows: %v", summaries(removed))
	}
	unknown := det1Rows(r, unconfirmedRemove)
	if len(unknown) != 1 || !strings.Contains(unknown[0].Summary, "jsmith ran del on Blackbox's files:") ||
		!strings.Contains(unknown[0].Summary, "state.json") || unknown[0].Severity != event.SevMedium {
		t.Errorf("command-only rows: %v", summaries(unknown))
	}
	if n := len(det1Rows(r, "file_access_denied")); n != 0 {
		t.Errorf("%d separate refused-access rows", n)
	}
}

func summaries(evs []*event.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, string(e.Severity)+" "+e.Action+": "+e.Summary)
	}
	return out
}

// DET1: with no process IDs (another collector's records), the refusal is
// matched by the person and by the file being named in the command; a
// refusal by someone else, or of another file, is not.
func TestRefusedDeleteWithoutProcessIDs(t *testing.T) {
	at := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	newCmd := func() *event.Event {
		return &event.Event{Time: at, Host: "ub", OS: "linux", User: "claude", Action: "blackbox_files_removed", Severity: event.SevHigh,
			Category: event.CatIntegrity, Command: "rm /var/lib/blackbox/spool/a.json", Summary: "claude deleted Blackbox's files: rm /var/lib/blackbox/spool/a.json"}
	}
	cmd := newCmd()
	other := &event.Event{Time: at.Add(time.Second), Host: "ub", OS: "linux", User: "bob", Action: "file_access_denied", Outcome: "failure",
		Target: "/var/lib/blackbox/spool/a.json"}
	got := refusedDeletes([]*event.Event{cmd, other})
	if len(got) != 2 || cmd.Action != unconfirmedRemove {
		t.Fatalf("someone else's refusal changed the row: %v", summaries(got))
	}
	cmd = newCmd()
	mine := &event.Event{Time: at.Add(time.Second), Host: "UB", OS: "linux", User: "claude", Action: "file_access_denied", Outcome: "failure",
		Target: "/var/lib/blackbox/spool/a.json"}
	got = refusedDeletes([]*event.Event{cmd, other, mine})
	if len(got) != 2 || cmd.Action != refusedRemove || cmd.Severity != event.SevMedium ||
		cmd.Summary != "claude tried to delete Blackbox's files (refused): rm /var/lib/blackbox/spool/a.json" {
		t.Errorf("own refusal: %v", summaries(got))
	}
}
