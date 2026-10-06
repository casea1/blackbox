package install

import (
	"github.com/casea1/blackbox/internal/config"

	"bufio"
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// abs turns a slash path into an absolute path for this OS
// (/srv/x stays /srv/x on Linux and becomes D:\srv\x on Windows).
func abs(p string) string {
	if runtime.GOOS == "windows" {
		return "D:" + filepath.FromSlash(p)
	}
	return p
}

// fakeEnv describes the computer the wizard runs on in a test.
type fakeEnv struct {
	existing  map[string]bool   // folders that exist
	inboxes   []string          // collector inboxes found
	reachable map[string]string // send_to → password that works ("" = any)
	windows   bool
}

// runWizard feeds scripted answers (one per line) to the wizard.
func runWizard(t *testing.T, input string, cur Answers, env fakeEnv, reinstall bool) (Answers, string, error) {
	t.Helper()
	var out bytes.Buffer
	in := bufio.NewReader(strings.NewReader(input))
	w := &wizard{in: in, out: &out,
		dirExists: func(p string) (bool, error) { return env.existing[p], nil },
		dirWritable: func(p string) error {
			if strings.Contains(p, "readonly") {
				return errors.New("access is denied")
			}
			return nil
		},
		password: func(prompt string) (string, error) {
			out.WriteString(prompt)
			return readPasswordPlain(in)
		},
		findInboxes: func() []string { return env.inboxes },
		tryInbox: func(sendTo, user, pw string) error {
			want, ok := env.reachable[sendTo]
			if !ok || (want != "" && pw != want) {
				return errors.New("could not connect")
			}
			return nil
		},
		defaultInbox: abs("/srv/blackbox-inbox"),
		isWindows:    env.windows,
	}
	a, err := w.run(cur, abs("/var/lib/blackbox/reports"), reinstall)
	return a, out.String(), err
}

func readPasswordPlain(r *bufio.Reader) (string, error) {
	s, err := r.ReadString('\n')
	if err != nil && s == "" {
		return "", ErrCancelled
	}
	return strings.TrimSpace(s), nil
}

func lines(l ...string) string { return strings.Join(l, "\n") + "\n" }

func TestWizardDefaults(t *testing.T) {
	// Enter on every question, then Enter to confirm.
	a, out, err := runWizard(t, lines("", "", "", "", "", "", "", "", ""), Answers{}, fakeEnv{}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := Answers{Role: RoleStandalone, ReportEvery: "weekly", ReportAt: config.DefaultReportAt, CollectEvery: 15 * time.Minute} // C6
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
	for _, s := range []string{"1. How will this computer's audit events be reviewed?", "2. Site or system name", "3. How often should a report",
		"4. Which day and time should each weekly report be ready", "5. Where should reports be saved", "6. Where should the original logs wait for the next report",
		"7. How often should events be collected", "8. Where are this computer's SCAP scan results", "Original logs:    " + DefaultArchiveDir(),
		"SCAP results:     " + DefaultScapDir(),
		"weekly, ready Wednesday 00:00 (each covers the week to Tuesday night)", "Summary", "Install these settings?"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestWizardAnswersAndRetries(t *testing.T) {
	input := lines(
		"1",      // standalone
		"Lab 3",  // site
		"9", "1", // invalid choice is asked again, then daily
		"noon", "06:30", // invalid time is asked again
		"reports",               // relative path: asked again
		abs("/srv/readonly"),    // exists but not writable: asked again
		abs("/srv/new-reports"), // does not exist…
		"y",                     // …create it
		abs("/srv/logs"),        // original logs on another volume…
		"y",                     // …create it
		"1",                     // every 15 minutes
		"",                      // SCAP results: the default
		"",                      // confirm
	)
	a, out, err := runWizard(t, input, Answers{}, fakeEnv{existing: map[string]bool{abs("/srv/readonly"): true}}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := Answers{Role: RoleStandalone, Site: "Lab 3", ReportEvery: "daily", ReportAt: config.ReportAt{Day: time.Wednesday, Minute: 6*60 + 30}, ReportDir: abs("/srv/new-reports"), ArchiveDir: abs("/srv/logs"), CollectEvery: 15 * time.Minute}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
	for _, s := range []string{"Please enter a number from 1 to 3", "Please enter a full path", "cannot write to that folder", "does not exist yet"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestWizardReinstallKeepsCurrentSettings(t *testing.T) {
	cur := Answers{Role: RoleStandalone, Site: "Lab 3", ReportEvery: "monthly", ReportAt: config.ReportAt{Day: time.Thursday, Minute: 360}, ReportDir: abs("/srv/locked"), ArchiveDir: abs("/srv/logs"), CollectEvery: 2 * time.Hour}
	a, out, err := runWizard(t, lines("n", "", "", "", "", "", "", "", "", ""), cur, fakeEnv{existing: map[string]bool{abs("/srv/locked"): true, abs("/srv/logs"): true}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, cur) {
		t.Errorf("re-install with Enter everywhere changed settings: %+v", a)
	}
	if !strings.Contains(out, "(current setting)") || !strings.Contains(out, "Apply these settings?") {
		t.Errorf("re-install prompts wrong:\n%s", out)
	}
}

func TestWizardDefaultFolderAndClearSite(t *testing.T) {
	cur := Answers{Site: "Old", ReportEvery: "weekly", ReportDir: abs("/srv/locked"), CollectEvery: time.Hour}
	a, _, err := runWizard(t, lines("n", "", "-", "", "", abs("/var/lib/blackbox/reports"), "", "", "", ""), cur, fakeEnv{existing: map[string]bool{abs("/srv/locked"): true}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Site != "" || a.ReportDir != "" {
		t.Errorf("site should be cleared and folder back to default: %+v", a)
	}
}

func TestWizardCancel(t *testing.T) {
	if _, _, err := runWizard(t, lines("", "", "", "", "", "", "", "", "n"), Answers{}, fakeEnv{}, false); !errors.Is(err, ErrCancelled) {
		t.Errorf("answering no should cancel, got %v", err)
	}
	if _, _, err := runWizard(t, "1\nLab", Answers{}, fakeEnv{}, false); !errors.Is(err, ErrCancelled) {
		t.Errorf("input ending early should cancel, got %v", err)
	}
}

// A Linux virtual machine whose host shares the collector's inbox with it.
func TestWizardSenderFindsVirtualBoxFolder(t *testing.T) {
	sf := abs("/media/sf_BlackboxInbox")
	env := fakeEnv{inboxes: []string{sf}, reachable: map[string]string{sf: ""}}
	a, out, err := runWizard(t, lines("2", "", "", "", ""), Answers{}, env, false)
	if err != nil {
		t.Fatal(err)
	}
	want := Answers{Role: RoleSender, ReportEvery: "weekly", ReportAt: config.DefaultReportAt, SendTo: sf, CollectEvery: 15 * time.Minute}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
	for _, s := range []string{"Found a collector inbox at " + sf, "OK, it is a Blackbox inbox", "Sends to:"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
	if strings.Contains(out, "Where should reports be saved") {
		t.Error("a sender makes no reports, so it is not asked where to save them")
	}
}

// A bare-metal Ubuntu PC sending to the LAN collector's share.
func TestWizardSenderShareWithRetry(t *testing.T) {
	share := "//COLLECTOR/BlackboxInbox"
	env := fakeEnv{reachable: map[string]string{share: "right"}}
	input := lines(
		"2",
		`\\COLLECTOR\BlackboxInbox`, "bbsend", "wrong", // Windows-style name is accepted; wrong password
		"n",                         // do not keep it: ask again
		"", "", "right", "", "", "", // same share and account, new password; interval; SCAP; confirm
	)
	a, out, err := runWizard(t, input, Answers{}, env, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if a.SendTo != share || a.ShareUser != "bbsend" || a.SharePassword != "right" || a.Role != RoleSender {
		t.Errorf("got %+v", a)
	}
	if !strings.Contains(out, "not reachable") || !strings.Contains(out, "Password for bbsend") {
		t.Errorf("output:\n%s", out)
	}
	if strings.Contains(out, "right") {
		t.Error("the password must not be echoed in the summary")
	}
}

// A collector that is offline during setup can still be chosen.
func TestWizardSenderKeepsUnreachableCollector(t *testing.T) {
	sf := abs("/media/sf_BlackboxInbox")
	a, _, err := runWizard(t, lines("2", sf, "y", "", "", ""), Answers{}, fakeEnv{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if a.SendTo != sf {
		t.Errorf("got %+v", a)
	}
}

// The Windows PC that makes the reports, for its own VM and the LAN.
func TestWizardWindowsCollector(t *testing.T) {
	input := lines(
		"3",      // collector
		"Lab 3",  // site
		"1",      // daily
		"",       // at midnight
		"",       // default report folder
		"",       // original logs in the data folder
		"",       // default inbox…
		"y",      // …create it
		"y",      // VMs on this PC send to it
		"vmuser", // account that runs VirtualBox
		"y",      // share it on the network too
		"bbsend", // the account other computers deliver as (S11)
		"",       // hourly
		"y",      // status icon
		"",       // SCAP results: the default
		"",       // confirm
	)
	a, out, err := runWizard(t, input, Answers{}, fakeEnv{windows: true}, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := Answers{Role: RoleCollector, Site: "Lab 3", ReportEvery: "daily", ReportAt: config.DefaultReportAt, CollectEvery: 15 * time.Minute,
		Inbox: abs("/srv/blackbox-inbox"), ShareInbox: true, InboxWriters: []string{"vmuser"}, ShareWriters: []string{"bbsend"}, Tray: true}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
	if !strings.Contains(out, "shared on the network as BlackboxInbox") || !strings.Contains(out, "Can deliver:      vmuser, bbsend") ||
		!strings.Contains(out, "Status icon:      shown to administrators") {
		t.Errorf("summary:\n%s", out)
	}
}

// S12: on a server without VirtualBox, the VirtualBox shared folder is not
// suggested (Enter means no), and no account is filled in for it.
func TestWizardNoVirtualBox(t *testing.T) {
	input := lines("3", "", "", "", "", "", "", "y",
		"",       // VMs on this PC send to it? Enter: no
		"y",      // share it
		"bbsend", // who delivers
		"", "", "", "")
	a, out, err := runWizard(t, input, Answers{}, fakeEnv{windows: true}, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if a.InboxWriters != nil || !a.ShareInbox || strings.Join(a.ShareWriters, ",") != "bbsend" {
		t.Errorf("got %+v", a)
	}
	if !strings.Contains(out, "(VirtualBox shared folder)? (y/N)") {
		t.Errorf("VirtualBox suggested:\n%s", out)
	}
}

// Changing a collector back to standalone clears the LAN settings.
func TestWizardBackToStandalone(t *testing.T) {
	cur := Answers{Role: RoleCollector, Inbox: abs("/srv/blackbox-inbox"), ShareInbox: true, ReportEvery: "weekly", CollectEvery: time.Hour}
	a, _, err := runWizard(t, lines("n", "1", "", "", "", "", "", "", "", ""), cur, fakeEnv{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Inbox != "" || a.ShareInbox || a.Role != RoleStandalone {
		t.Errorf("got %+v", a)
	}
}

// A sender never gets the status icon, and is not asked about it.
func TestWizardSenderNoTray(t *testing.T) {
	env := fakeEnv{windows: true, reachable: map[string]string{`\\COL\BlackboxInbox`: ""}}
	a, out, err := runWizard(t, lines("2", `\\COL\BlackboxInbox`, "", "", "", ""), Answers{Tray: true}, env, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if a.Tray || strings.Contains(out, "notification area") || strings.Contains(out, "Status icon") {
		t.Errorf("a sender should have no status icon: %+v\n%s", a, out)
	}
}

// An upgrade with the settings as they are is one answer: Enter on "Keep
// these settings and upgrade now?" applies them without the questions.
func TestWizardQuickUpgrade(t *testing.T) {
	cur := Answers{Role: RoleCollector, Site: "Lab 3", ReportEvery: "weekly", ReportAt: config.DefaultReportAt, Inbox: abs("/srv/inbox"),
		ArchiveDir: abs("/srv/logs"), ScapResults: abs("/srv/scc"), CollectEvery: 15 * time.Minute}
	a, out, err := runWizard(t, lines(""), cur, fakeEnv{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, WithDefaults(cur)) {
		t.Errorf("settings changed: %+v", a)
	}
	for _, want := range []string{"Current settings", "Receives in:", "SCAP results:     " + abs("/srv/scc"), "Keep these settings and upgrade now? (Y/n)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "1. How will") {
		t.Error("asked the questions anyway")
	}
	// A first install has nothing to keep: no such question.
	_, out, _ = runWizard(t, lines("", "", "", "", "", "", "", "", ""), Answers{}, fakeEnv{}, false)
	if strings.Contains(out, "Keep these settings") {
		t.Error("a first install offered to keep settings")
	}
}

// The SCAP results folder: SCC's folder (asked to confirm while it does
// not exist yet), or none.
func TestWizardScapFolder(t *testing.T) {
	scc := abs("/data/SCC/Sessions")
	a, out, err := runWizard(t, lines("2", "", "", scc, "y", ""), Answers{}, fakeEnv{inboxes: []string{abs("/media/sf_BlackboxInbox")}, reachable: map[string]string{abs("/media/sf_BlackboxInbox"): ""}}, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if a.ScapResults != scc || !strings.Contains(out, "does not exist yet. Use it anyway") || !strings.Contains(out, "SCAP results:     "+scc) {
		t.Errorf("got %+v\n%s", a, out)
	}
	a, _, err = runWizard(t, lines("2", "", "", "none", ""), Answers{}, fakeEnv{inboxes: []string{abs("/media/sf_BlackboxInbox")}, reachable: map[string]string{abs("/media/sf_BlackboxInbox"): ""}}, false)
	if err != nil || a.ScapResults != "none" {
		t.Errorf("none: %+v %v", a, err)
	}
}
