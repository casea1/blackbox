package main

import (
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

// A9: less than a year of retention needs a typed yes, or --yes.
func TestConfirmRetention(t *testing.T) {
	if err := confirmRetention("retention_days", "400", false, false, strings.NewReader("")); err != nil {
		t.Errorf("400 days: %v", err)
	}
	if err := confirmRetention("retention_days", "30", false, false, strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "--yes") {
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
