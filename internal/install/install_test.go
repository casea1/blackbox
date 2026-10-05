package install

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTaskXML(t *testing.T) {
	x := taskXML(`C:\Program Files\Blackbox\blackbox.exe`, 15*time.Minute, time.Date(2026, 9, 29, 10, 5, 0, 0, time.UTC))
	for _, want := range []string{"<Interval>PT15M</Interval>", "<UserId>S-1-5-18</UserId>", "<StartWhenAvailable>true</StartWhenAvailable>", `<Command>C:\Program Files\Blackbox\blackbox.exe</Command>`} {
		if !strings.Contains(x, want) {
			t.Errorf("task XML missing %s", want)
		}
	}
	dec := xml.NewDecoder(strings.NewReader(strings.Replace(x, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)))
	for {
		if _, err := dec.Token(); err != nil {
			if err.Error() != "EOF" {
				t.Fatalf("task XML is not well-formed: %v", err)
			}
			break
		}
	}
	if isoDuration(time.Hour) != "PT1H" {
		t.Error("isoDuration(1h)")
	}
}

func TestSystemdUnits(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Hour: "*-*-* 00/1:05:00", 15 * time.Minute: "*-*-* *:00/15:00", 2 * time.Hour: "*-*-* 00/2:05:00",
	} {
		got, err := onCalendar(d)
		if err != nil || got != want {
			t.Errorf("onCalendar(%s) = %q, %v; want %q", d, got, err, want)
		}
	}
	for _, bad := range []time.Duration{7 * time.Minute, 5 * time.Hour} {
		if _, err := onCalendar(bad); err == nil {
			t.Errorf("onCalendar(%s) should fail", bad)
		}
	}
	timer, _ := systemdTimer(time.Hour)
	svc := systemdService("/usr/local/bin/blackbox", "", false, "/var/lib/blackbox", "/srv/audit-reports", "/var/lib/blackbox")
	for _, want := range []string{"Persistent=true", "WantedBy=timers.target"} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer missing %s", want)
		}
	}
	for _, want := range []string{"ExecStart=/usr/local/bin/blackbox run", "PrivateNetwork=yes", "ProtectSystem=strict", "ReadWritePaths=/var/lib/blackbox /srv/audit-reports\n"} {
		if !strings.Contains(svc, want) {
			t.Errorf("service missing %s", want)
		}
	}
	// A sender to an SMB share asks for the share before each run, and a
	// shared folder that is not mounted does not stop the run.
	lanSvc := systemdService("/usr/local/bin/blackbox", "var-lib-blackbox-collector.mount", false, "/var/lib/blackbox", "/var/lib/blackbox/reports")
	for _, want := range []string{"Wants=var-lib-blackbox-collector.mount\nAfter=var-lib-blackbox-collector.mount", "ReadWritePaths=/var/lib/blackbox /var/lib/blackbox/reports\n"} {
		if !strings.Contains(lanSvc, want) {
			t.Errorf("LAN service missing %q:\n%s", want, lanSvc)
		}
	}
}

func TestPrepareReportDir(t *testing.T) {
	base := t.TempDir()
	newDir := base + "/new/reports"
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, f) }
	if err := PrepareReportDir(newDir, logf); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(newDir); err != nil || !fi.IsDir() {
		t.Fatalf("folder not created: %v", err)
	}
	// An existing folder is used as is.
	if err := PrepareReportDir(base, logf); err != nil {
		t.Fatal(err)
	}
	if err := PrepareReportDir("relative/path", logf); err == nil {
		t.Error("relative path accepted")
	}
	f := base + "/afile"
	os.WriteFile(f, nil, 0o600)
	if err := PrepareReportDir(f, logf); err == nil {
		t.Error("a file was accepted as the report folder")
	}
}

// The status icon starts at logon for members of Administrators, elevated,
// one per person.
func TestTrayTaskXML(t *testing.T) {
	x := trayTaskXML(`C:\Program Files\Blackbox\blackboxw.exe`)
	for _, want := range []string{"<LogonTrigger>", "<GroupId>S-1-5-32-544</GroupId>", "<RunLevel>HighestAvailable</RunLevel>",
		"<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>", "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
		`<Command>C:\Program Files\Blackbox\blackboxw.exe</Command>`, "<Arguments>tray</Arguments>"} {
		if !strings.Contains(x, want) {
			t.Errorf("tray task lacks %s", want)
		}
	}
	if strings.Contains(x, "<UserId>") {
		t.Error("the tray must run as the person logging on, not a fixed account")
	}
}

// S7: when an earlier .old is still in use, the program is set aside as
// .old1, and a rollback restores exactly that file.
func TestSwapInAndRollBack(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blackbox.exe")
	os.WriteFile(p, []byte("v1"), 0o755)
	os.WriteFile(p+".old", []byte("v0 still running"), 0o755)
	old, err := swapIn(p, []byte("v2"))
	if err != nil || old != p+".old1" {
		t.Fatalf("set aside as %q, %v; want .old1", old, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "v2" {
		t.Errorf("new program not in place: %q", b)
	}
	if !rollBack([]kept{{p, old}}) {
		t.Fatal("rollback reported nothing restored")
	}
	if b, _ := os.ReadFile(p); string(b) != "v1" {
		t.Errorf("rollback restored %q, want v1 (not the older .old)", b)
	}
	if b, _ := os.ReadFile(p + ".old"); string(b) != "v0 still running" {
		t.Error("the older .old was touched")
	}
}

// L4: a sender's schedule says it sends; it makes no reports.
func TestScheduleWhat(t *testing.T) {
	if s := scheduleWhat(Options{Answers: Answers{SendTo: "//C/BlackboxInbox", ReportEvery: "weekly"}}); strings.Contains(s, "report") {
		t.Errorf("sender: %q", s)
	}
	if s := scheduleWhat(Options{Answers: Answers{ReportEvery: "weekly"}}); s != "weekly reports" {
		t.Errorf("standalone: %q", s)
	}
}

// T1: the repeating trigger starts at a fixed time in the past, so a clock
// that was ahead at install can't leave the next run hours away.
func TestTaskStartsInThePast(t *testing.T) {
	if TaskStart.Year() > 2001 {
		t.Errorf("task start %s", TaskStart)
	}
	if x := taskXML(`C:\Program Files\Blackbox\blackbox.exe`, 15*time.Minute, TaskStart); !strings.Contains(x, "<StartBoundary>2000-01-01T00:05:00</StartBoundary>") {
		t.Errorf("trigger:\n%s", x)
	}
}
