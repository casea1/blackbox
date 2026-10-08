package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/app"
)

func TestReportRange(t *testing.T) {
	now := time.Date(2026, 10, 2, 9, 30, 0, 0, time.UTC)
	f, to, err := reportRange("2026-09-01", "2026-09-15", 0, now, time.UTC)
	if err != nil || !f.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) || !to.Equal(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("dates: %v %v %v", f, to, err)
	}
	if f, to, err := reportRange("", "", 30, now, time.UTC); err != nil || !f.Equal(now.AddDate(0, 0, -30)) || !to.Equal(now) {
		t.Errorf("--days: %v %v %v", f, to, err)
	}
	if f, _, _ := reportRange("", "", 0, now, time.UTC); !f.IsZero() {
		t.Error("no range chosen should mean since the last report")
	}
	for _, bad := range [][2]string{{"2026-09-15", "2026-09-01"}, {"yesterday", ""}, {"", "2026-09-01"}} {
		if _, _, err := reportRange(bad[0], bad[1], 0, now, time.UTC); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
	if f, to, err := parseRangeAnswer("7", now, time.UTC); err != nil || !f.Equal(now.AddDate(0, 0, -7)) || !to.Equal(now) {
		t.Errorf("answer 7: %v %v %v", f, to, err)
	}
	if f, _, err := parseRangeAnswer("", now, time.UTC); err != nil || !f.IsZero() {
		t.Errorf("Enter: %v %v", f, err)
	}
	if f, to, err := parseRangeAnswer("2026-09-01 2026-09-30", now, time.UTC); err != nil || f.Day() != 1 || to.Day() != 1 || to.Month() != 10 {
		t.Errorf("two dates: %v %v %v", f, to, err)
	}
}

// R4: a saved setting is used by the next run of any kind, not only the
// next scheduled one.
func TestSavedText(t *testing.T) {
	got := savedText("site_name", "Lab 3")
	if strings.Contains(got, "next scheduled run") || !strings.Contains(got, "blackbox report") {
		t.Errorf("savedText = %q", got)
	}
}

// E1: clearing a setting says so.
func TestSavedTextEmpty(t *testing.T) {
	if got := savedText("exclude_users", ""); !strings.HasPrefix(got, "Cleared exclude_users.") {
		t.Errorf("savedText = %q", got)
	}
}

// A9, RET1: any retention period needs a typed yes, or --yes, and the
// prompt names the records schedule and legal holds.
func TestConfirmRetention(t *testing.T) {
	err := confirmRetention("retention_days", "400", false, false, strings.NewReader(""))
	if err == nil {
		t.Fatal("400 days, no prompt: changed without asking")
	}
	for _, want := range []string{"records schedule", "ISSM", "not from AU-11", "legal hold", "never put in a report are never deleted"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("prompt missing %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "less than a year") {
		t.Errorf("400 days called less than a year: %v", err)
	}
	if err := confirmRetention("retention_days", "400", true, false, strings.NewReader("")); err != nil {
		t.Errorf("400 days --yes: %v", err)
	}
	if err := confirmRetention("retention_days", "30", false, false, strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "--yes") || !strings.Contains(err.Error(), "less than a year") {
		t.Errorf("30 days, no prompt: %v", err)
	}
	if err := confirmRetention("retention_days", "30", true, false, strings.NewReader("")); err != nil {
		t.Errorf("30 days --yes: %v", err)
	}
	if err := confirmRetention("retention_days", "30", false, true, strings.NewReader("yes\n")); err != nil {
		t.Errorf("30 days, yes typed: %v", err)
	}
	if err := confirmRetention("retention_days", "30", false, true, strings.NewReader("n\n")); err == nil {
		t.Error("30 days, no: changed anyway")
	}
	if err := confirmRetention("retention_days", "0", false, false, strings.NewReader("")); err != nil {
		t.Errorf("0 (keep forever): %v", err)
	}
}

// L11b: "send --resend" fails when nothing could be sent again.
func TestResendOutcome(t *testing.T) {
	lines, err := resendOutcome(app.ResendResult{Missing: []uint64{1, 2, 3}}, nil, "x", 14)
	if err == nil || !strings.Contains(strings.Join(lines, "\n"), "Not kept on this computer: 1, 2, 3") {
		t.Errorf("none kept: %v %v", lines, err)
	}
	if _, err := resendOutcome(app.ResendResult{Sent: []uint64{2}, Missing: []uint64{1}}, nil, "x", 14); err != nil {
		t.Errorf("some sent: %v", err)
	}
	if lines, err := resendOutcome(app.ResendResult{}, nil, "x", 14); err != nil || !strings.Contains(lines[0], "not been delivered yet") {
		t.Errorf("still waiting: %v %v", lines, err)
	}
}

// CLI1: refused its settings, a command says to run it with sudo (or as
// administrator), not only "permission denied".
func TestPermissionHint(t *testing.T) {
	err := fmt.Errorf("open /etc/blackbox/blackbox.conf: %w", fs.ErrPermission)
	old := geteuid
	defer func() { geteuid = old }()
	geteuid = func() int { return 1000 }
	h := permissionHint(err, "status")
	if runtime.GOOS == "windows" {
		if !strings.Contains(h, "administrator prompt") {
			t.Errorf("hint: %q", h)
		}
	} else if h != "Its settings and data are readable by root only: run it with sudo, e.g. sudo blackbox status" {
		t.Errorf("hint: %q", h)
	}
	if permissionHint(errors.New("something else"), "status") != "" {
		t.Error("hint for another error")
	}
}

// CLI1: redirected output on Windows is folded to ASCII, so Windows
// PowerShell 5.1 does not turn "—" into "ΓÇö".
func TestCopyFolded(t *testing.T) {
	var b strings.Builder
	copyFolded(&b, strings.NewReader("Last attempt:     2026-10-07 13:00 — FAILED: 3 files × 8 MB · next…\nno newline"))
	if got := b.String(); got != "Last attempt:     2026-10-07 13:00 - FAILED: 3 files x 8 MB - next...\nno newline" {
		t.Errorf("folded: %q", got)
	}
}

// CLI1: keep_sent_days 0 says it ends resends.
func TestKeepSentZero(t *testing.T) {
	if s := savedText("keep_sent_days", "0"); !strings.Contains(s, "cannot be sent again") {
		t.Errorf("%s", s)
	}
	if s := savedText("keep_sent_days", "14"); strings.Contains(s, "cannot be sent again") {
		t.Errorf("%s", s)
	}
}

// cliFlags is a flag set like the commands': --config, a string flag and a
// bool flag.
func cliFlags() (*flag.FlagSet, *common, *string, *bool) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var c common
	c.register(fs)
	c.configPath = ""
	host := fs.String("host", "", "")
	yes := fs.Bool("yes", false, "")
	return fs, &c, host, yes
}

// CLI2: flags are read wherever they are after the command: before,
// between and after the subcommand's arguments.
func TestParseAnywhere(t *testing.T) {
	cases := []struct {
		args []string
		pos  []string
		cfg  string
		host string
		yes  bool
	}{
		{[]string{"--config", "f", "accept", "PC", "1-5", "why"}, []string{"accept", "PC", "1-5", "why"}, "f", "", false},
		{[]string{"accept", "PC", "--config", "f", "1-5", "why"}, []string{"accept", "PC", "1-5", "why"}, "f", "", false},
		{[]string{"accept", "PC", "1-5", "why", "--config=f", "--yes"}, []string{"accept", "PC", "1-5", "why"}, "f", "", true},
		{[]string{"add", "NAME", "ACCOUNT", "--host", "COMPUTER"}, []string{"add", "NAME", "ACCOUNT"}, "", "COMPUTER", false},
		{[]string{"-yes", "add", "-host=PC", "NAME"}, []string{"add", "NAME"}, "", "PC", true},
		{[]string{"rename", "OLD", "--yes", "NEW"}, []string{"rename", "OLD", "NEW"}, "", "", true},
		// A quoted reason is one argument and keeps its spaces.
		{[]string{"accept", "PC", "1-5", "network was down for the move", "--config", "f"}, []string{"accept", "PC", "1-5", "network was down for the move"}, "f", "", false},
		// "--" ends the flags, so a reason may start with a dash.
		{[]string{"accept", "r1", "--config", "f", "--", "--yes", "-see ticket 4"}, []string{"accept", "r1", "--yes", "-see ticket 4"}, "f", "", false},
		// "--" as a flag's value is not the end of flags.
		{[]string{"add", "--host", "--", "N", "--yes"}, []string{"add", "N"}, "", "--", true},
		{nil, nil, "", "", false},
	}
	for _, tc := range cases {
		fs, c, host, yes := cliFlags()
		pos, err := parseAnywhere(fs, tc.args)
		if err != nil {
			t.Errorf("%q: %v", tc.args, err)
			continue
		}
		if !reflect.DeepEqual(pos, tc.pos) || c.configPath != tc.cfg || *host != tc.host || *yes != tc.yes {
			t.Errorf("%q: positional %q config %q host %q yes %v", tc.args, pos, c.configPath, *host, *yes)
		}
	}
}

// CLI2: an unknown flag anywhere is an error, and -h asks for help.
func TestParseAnywhereErrors(t *testing.T) {
	for _, args := range [][]string{{"accept", "PC", "--nope"}, {"--nope", "accept"}, {"accept", "1-5", "-x", "why"}} {
		fs, _, _, _ := cliFlags()
		if _, err := parseAnywhere(fs, args); err == nil || !strings.Contains(err.Error(), "not defined") {
			t.Errorf("%q: %v", args, err)
		}
	}
	fs, _, _, _ := cliFlags()
	if _, err := parseAnywhere(fs, []string{"accept", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
	fs, _, _, _ = cliFlags()
	if _, err := parseAnywhere(fs, []string{"accept", "--config"}); err == nil {
		t.Error("--config without a value accepted")
	}
}

// CLI2: the commands themselves read flags after the subcommand: the
// settings file named after the arguments is the one used, and an unknown
// flag there is refused.
func TestCommandsFlagsAfterSubcommand(t *testing.T) {
	missing := t.TempDir() + "/no-such.conf"
	for name, run := range map[string]func([]string) error{
		"systems": cmdSystems, "gaps": cmdGaps, "reports": cmdReports, "senders": cmdSenders,
	} {
		err := run([]string{"accept", "PC", "--config", missing, "1-5", "why"})
		if err == nil || !strings.Contains(err.Error(), "no-such.conf") {
			t.Errorf("%s: --config after the subcommand not used: %v", name, err)
		}
		if err := run([]string{"accept", "PC", "--nope"}); err == nil || !strings.Contains(err.Error(), "not defined") {
			t.Errorf("%s: unknown flag: %v", name, err)
		}
	}
}

// DESIGN1: "blackbox inbox" (0.23's per-sender folders) is gone, and says
// what replaced it.
func TestInboxCommandRemoved(t *testing.T) {
	err := cmdInbox([]string{"add", "PC", "bbsend"})
	if err == nil || !strings.Contains(err.Error(), "removed in 0.24") || !strings.Contains(err.Error(), "How the inbox is protected") {
		t.Errorf("inbox: %v", err)
	}
	if strings.Contains(usage, "inbox add") {
		t.Error("usage still lists blackbox inbox add")
	}
}
