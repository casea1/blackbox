package config

import (
	"fmt"
	"strings"
	"time"
)

// ReportAt is when a report period ends and the report is produced:
// "Wednesday 00:00" for weekly reports (the week runs to Tuesday
// midnight), or just a time such as "06:00" for daily and monthly
// reports (monthly periods end on the 1st). The day is ignored for daily
// and monthly reports.
type ReportAt struct {
	Day    time.Weekday
	Minute int // minutes after midnight
}

// DefaultReportAt gives auditors a fresh weekly report on Wednesday morning.
var DefaultReportAt = ReportAt{Day: time.Wednesday}

// ParseReportAt reads "Wednesday 00:00", "wed 06:30" or "06:30" (the day
// then stays Wednesday).
func ParseReportAt(v string) (ReportAt, error) {
	bad := fmt.Errorf("report_at must look like \"Wednesday 00:00\" or \"06:00\" (got %q)", v)
	f := strings.Fields(v)
	if len(f) == 0 || len(f) > 2 {
		return ReportAt{}, bad
	}
	r := DefaultReportAt
	if len(f) == 2 {
		d, ok := dayIndex(f[0])
		if !ok {
			return ReportAt{}, bad
		}
		r.Day = time.Weekday(d)
	}
	m, ok := clockMinutes(f[len(f)-1])
	if !ok || m >= 24*60 {
		return ReportAt{}, bad
	}
	r.Minute = m
	return r, nil
}

// String writes "Wednesday 00:00".
func (r ReportAt) String() string {
	return fmt.Sprintf("%s %02d:%02d", r.Day, r.Minute/60, r.Minute%60)
}

// Show is the setting as config show gives it: "Wednesday 00:00" for
// weekly reports, the time alone otherwise, where the day does not count
// (UX10).
func (r ReportAt) Show(every string) string {
	if every == "weekly" {
		return r.String()
	}
	return r.Clock()
}

// Clock writes "00:00".
func (r ReportAt) Clock() string { return fmt.Sprintf("%02d:%02d", r.Minute/60, r.Minute%60) }

// Describe says in words when reports are produced, e.g. "weekly, ready
// Wednesday 00:00 (each covers Wednesday 00:00 to Tuesday night)".
func (r ReportAt) Describe(every string) string {
	switch every {
	case "daily":
		return fmt.Sprintf("daily at %s", r.Clock())
	case "monthly":
		return fmt.Sprintf("monthly, on the 1st at %s", r.Clock())
	}
	if r.Minute == 0 {
		return fmt.Sprintf("weekly, ready %s (each covers the week to %s night)", r, (r.Day+6)%7)
	}
	return fmt.Sprintf("weekly, ready %s", r)
}

// LastBoundary is the most recent moment at or before now when a report
// period ended.
func (r ReportAt) LastBoundary(every string, now time.Time, loc *time.Location) time.Time {
	n := now.In(loc)
	b := time.Date(n.Year(), n.Month(), n.Day(), r.Minute/60, r.Minute%60, 0, 0, loc)
	switch every {
	case "weekly":
		b = b.AddDate(0, 0, -((int(b.Weekday()) - int(r.Day) + 7) % 7))
		if b.After(n) {
			b = b.AddDate(0, 0, -7)
		}
	case "monthly":
		b = time.Date(n.Year(), n.Month(), 1, r.Minute/60, r.Minute%60, 0, 0, loc)
		if b.After(n) {
			b = time.Date(n.Year(), n.Month()-1, 1, r.Minute/60, r.Minute%60, 0, 0, loc)
		}
	default:
		if b.After(n) {
			b = b.AddDate(0, 0, -1)
		}
	}
	return b
}

// NextBoundary is the first moment after now when a report period ends.
func (r ReportAt) NextBoundary(every string, now time.Time, loc *time.Location) time.Time {
	b := r.LastBoundary(every, now, loc)
	switch every {
	case "weekly":
		return b.AddDate(0, 0, 7)
	case "monthly":
		return time.Date(b.Year(), b.Month()+1, 1, r.Minute/60, r.Minute%60, 0, 0, loc)
	}
	return b.AddDate(0, 0, 1)
}
