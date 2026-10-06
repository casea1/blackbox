package report

import (
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/winevt"
)

// UI4: Blackbox's own installer writing its data folder, with Blackbox's
// record of the upgrade, is neither rows nor a step of covering of tracks.
// The same program with no such record, or deleting a report, still is.
func TestInstallerWritesAreBlackbox(t *testing.T) {
	at := time.Date(2026, 10, 5, 6, 30, 0, 0, time.UTC)
	tr := winevt.NewTranslator()
	write := func(obj, proc string, when time.Time) *event.Event {
		// A 4663 as Windows writes it for the auditing entry on the folder.
		r := &winevt.Raw{Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", EventID: 4663, Computer: "WIN11-COL.corp.example.mil",
			Time: when, Task: 12800, Keywords: "0x8020000000000000", Data: map[string]string{
				"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "casea", "SubjectDomainName": "WIN11-COL", "SubjectLogonId": "0x3e7a1",
				"ObjectServer": "Security", "ObjectType": "File", "ObjectName": obj, "HandleId": "0x5f4", "AccessList": "%%4417\n\t\t\t\t%%4418",
				"AccessMask": "0x6", "ProcessId": "0x1b2c", "ProcessName": proc, "ResourceAttributes": "S:AI"}}
		e := tr.Translate(r)
		if e == nil {
			t.Fatalf("no row for %s by %s", obj, proc)
		}
		return e
	}
	setup := `C:\Users\casea\Downloads\Blackbox-Setup-0.15.0.exe`
	upgraded := event.SelfChange{Kind: "upgraded", Old: "0.14.0", Version: "0.15.0", Who: `WIN11-COL\casea`, Program: "setup"}.Event()
	upgraded.Time, upgraded.Host, upgraded.OS = at, "WIN11-COL", "windows"
	// Setting up a collector: the delivery account, then the installer.
	acct := &event.Event{Time: at.Add(-3 * time.Minute), Host: "WIN11-COL", OS: "windows", Category: event.CatAccount, Severity: event.SevMedium,
		Action: "account_created", User: `WIN11-COL\casea`, Target: "bbsend", Summary: "casea created the account bbsend."}

	evs := []*event.Event{acct, upgraded,
		write(`C:\ProgramData\Blackbox`, setup, at.Add(-2*time.Minute)),
		write(`C:\ProgramData\Blackbox\blackbox.conf.new`, setup, at.Add(-time.Minute))}
	for _, e := range evs[2:] {
		if e.Action != "blackbox_files_changed" || e.Severity != event.SevHigh {
			t.Fatalf("the translator's row: %+v", e)
		}
	}
	r := Build(evs, nil, Options{WindowStart: at.AddDate(0, 0, -1), WindowEnd: at.Add(time.Hour), Location: time.UTC})
	for _, row := range r.rows {
		if row.Action == "blackbox_files_changed" {
			t.Errorf("the installer's write is a row: %s", row.Summary)
		}
	}
	for _, f := range r.Findings {
		if f.Title == "Possible covering of tracks" {
			t.Errorf("the installer made covering of tracks: %+v", f)
		}
	}

	// No record of an install: the same program is still a High row and
	// a step after the new account.
	evs = []*event.Event{acct, write(`C:\ProgramData\Blackbox\blackbox.conf.new`, setup, at.Add(-time.Minute))}
	r = Build(evs, nil, Options{WindowStart: at.AddDate(0, 0, -1), WindowEnd: at.Add(time.Hour), Location: time.UTC})
	found := false
	for _, row := range r.rows {
		found = found || row.Action == "blackbox_files_changed"
	}
	cover := false
	for _, f := range r.Findings {
		cover = cover || f.Title == "Possible covering of tracks"
	}
	if !found || !cover {
		t.Errorf("a program named like the installer with no install record: row %v, covering of tracks %v", found, cover)
	}

	// The installer deleting a report is never dropped.
	del := write(`C:\ProgramData\Blackbox\reports\2026-10-04_2009_WIN11-COL\index.html`, setup, at.Add(-time.Minute))
	if got := installerWrites([]*event.Event{upgraded, del}); len(got) != 2 {
		t.Errorf("a report write by the installer was dropped")
	}
	if !isBlackboxSetup(`C:\x\BLACKBOX-SETUP-0.16.0.EXE`) || isBlackboxSetup(`C:\x\blackbox.exe`) || isBlackboxSetup(`C:\x\setup.exe`) {
		t.Error("isBlackboxSetup")
	}
}
