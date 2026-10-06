package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

// claude, as the 0.16.1 re-test recorded it on WIN11-COL.
var claude = map[string]string{"SubjectUserSid": "S-1-5-21-3923-1001", "SubjectUserName": "claude", "SubjectDomainName": "WIN11-COL", "SubjectLogonId": "0x2d1f7"}

func rawSec(id int, at time.Time, data map[string]string) *winevt.Raw {
	r := &winevt.Raw{Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", EventID: id, Computer: "WIN11-COL", Time: at, Data: data}
	if id == 4663 {
		r.Task, r.Keywords = 12800, "0x8020000000000000"
	}
	return r
}

func with2(base map[string]string, kv ...string) map[string]string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// AR2b: a hand-run Blackbox exports the original logs with wevtutil epl,
// which writes them through the Event Log service: with the folder
// audited, each piece is a 4663 by svchost.exe in the name of whoever ran
// Blackbox. Those are Blackbox's own, not High rows, and no step of
// "Possible covering of tracks" (here paired with delivery accounts made
// the day before). A change by anything else, a delete, or a write with
// no Blackbox run then, stays High.
func TestExportPieceWritesAreBlackbox(t *testing.T) {
	at := time.Date(2026, 10, 6, 11, 2, 0, 0, time.UTC)
	tr := winevt.NewTranslator()
	write := func(obj, proc, access string, when time.Time) *event.Event {
		e := tr.Translate(rawSec(4663, when, with2(claude, "ObjectServer", "Security", "ObjectType", "File", "ObjectName", obj,
			"HandleId", "0x1d4", "AccessList", access, "AccessMask", "0x2", "ProcessId", "0x5a8", "ProcessName", proc, "ResourceAttributes", "S:AI")))
		if e == nil {
			t.Fatalf("no row for %s by %s", obj, proc)
		}
		return e
	}
	svchost := `C:\Windows\System32\svchost.exe`
	piece := `C:\ProgramData\Blackbox\archive-pieces\000001\`
	acct := &event.Event{Time: at.Add(-20 * time.Hour), Host: "WIN11-COL", OS: "windows", Category: event.CatAccount, Severity: event.SevMedium,
		Action: "account_created", User: `WIN11-COL\claude`, Target: "bbsend", Summary: "claude created the local account bbsend."}
	runs := []*store.Run{{Time: at, Host: "WIN11-COL", OS: "windows", Duration: 3.5}}
	var evs []*event.Event
	for i, log := range []string{"Security.evtx", "System.evtx", "Microsoft-Windows-PowerShell-Operational.evtx", "Application.evtx"} {
		e := write(piece+log, svchost, "%%4417", at.Add(time.Duration(5+i)*time.Second))
		if e.Action != "blackbox_files_changed" || e.Severity != event.SevHigh || e.Fields[event.ExportPieceFlag] == "" {
			t.Fatalf("translator: %+v", e)
		}
		evs = append(evs, e)
	}
	opt := Options{WindowStart: at.AddDate(0, 0, -1), WindowEnd: at.Add(time.Hour), Location: time.UTC}
	r := Build(append([]*event.Event{acct}, evs...), runs, opt)
	for _, row := range r.rows {
		if row.Action == "blackbox_files_changed" {
			t.Errorf("an export piece is a row: %s", row.Summary)
		}
	}
	if f := findings(r)["Possible covering of tracks"]; len(f) != 0 {
		t.Errorf("covering of tracks from Blackbox's own export: %+v", f)
	}

	// Not Blackbox's: no run then, another program, a delete, a name that
	// is not a log Blackbox exports.
	for name, e := range map[string]*event.Event{
		"no run":     write(piece+"Security.evtx", svchost, "%%4417", at.Add(3*time.Hour)),
		"notepad":    write(piece+"Security.evtx", `C:\Windows\System32\notepad.exe`, "%%4417", at.Add(5*time.Second)),
		"delete":     write(piece+"Security.evtx", svchost, "%%1537", at.Add(5*time.Second)),
		"other name": write(piece+"evil.evtx", svchost, "%%4417", at.Add(5*time.Second)),
		"other dir":  write(`C:\ProgramData\Blackbox\archive-pieces\x\Security.evtx`, svchost, "%%4417", at.Add(5*time.Second)),
	} {
		r := Build([]*event.Event{acct, e}, runs, opt)
		kept := false
		for _, row := range r.rows {
			kept = kept || row.Action == "blackbox_files_changed" || row.Action == "file_deleted"
		}
		if !kept {
			t.Errorf("%s: dropped: %s", name, e.Summary)
		}
	}
}

// UI4b: the commands Blackbox's installer runs (its Uninstall entry, the
// share, permissions, the task) are folded into Blackbox's record of the
// upgrade, as its own child processes are; with no such record they stay.
func TestInstallerHelpersFolded(t *testing.T) {
	at := time.Date(2026, 10, 6, 10, 30, 0, 0, time.UTC)
	tr := winevt.NewTranslator()
	setup := `C:\Users\claude\Downloads\Blackbox-Setup-0.16.1.exe`
	run := func(proc, cmd string, d time.Duration) *event.Event {
		e := tr.Translate(rawSec(4688, at.Add(d), with2(claude, "NewProcessName", proc, "CommandLine", cmd,
			"TokenElevationType", "%%1937", "MandatoryLabel", "S-1-16-12288", "ParentProcessName", setup)))
		if e == nil || e.Action != "elevated_process" {
			t.Fatalf("translator: %+v", e)
		}
		return e
	}
	helpers := []*event.Event{
		run(`C:\Windows\System32\reg.exe`, `reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Blackbox /v DisplayVersion /d 0.16.1 /f`, -90*time.Second),
		run(`C:\Windows\System32\net.exe`, `net share BlackboxInbox`, -80*time.Second),
		run(`C:\Windows\System32\icacls.exe`, `icacls C:\BlackboxInbox /grant "Blackbox Senders:(OI)(CI)M"`, -70*time.Second),
		run(`C:\Windows\System32\schtasks.exe`, `schtasks /Query /TN "Blackbox Audit Collection" /XML`, -60*time.Second),
	}
	up := event.SelfChange{Kind: "upgraded", Old: "0.16.0", Version: "0.16.1", Who: `WIN11-COL\claude`, Program: "setup"}.Event()
	up.Time, up.Host, up.OS = at, "WIN11-COL", "windows"
	opt := Options{WindowStart: at.AddDate(0, 0, -1), WindowEnd: at.Add(time.Hour), Location: time.UTC}
	r := Build(append([]*event.Event{up}, helpers...), nil, opt)
	var rec *Row
	for _, row := range r.rows {
		if row.Action == "elevated_process" {
			t.Errorf("an installer helper is a row: %s", row.Summary)
		}
		if row.Action == "blackbox_upgraded" {
			rec = row
		}
	}
	if rec == nil || !strings.Contains(detail(rec.Event, "Setup also ran"), "4 commands with administrator rights: reg.exe add") {
		t.Errorf("the upgrade row does not list the commands: %+v", rec)
	}
	// No record of an install: the commands stay rows.
	r = Build(helpers, nil, opt)
	n := 0
	for _, row := range r.rows {
		if row.Action == "elevated_process" {
			n++
		}
	}
	if n != 4 {
		t.Errorf("without an install record, %d of 4 commands kept", n)
	}
}
