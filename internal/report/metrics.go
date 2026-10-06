package report

import (
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// Metric names, kept in summary.json so later reports can chart them over
// twelve weeks (the Trends page and the Overview's sparklines).
const (
	MDetections     = "detections"
	MHighEvents     = "high_events"
	MEvents         = "events"
	MFailedLogons   = "failed_logons"
	MPrivileged     = "privileged_actions"
	MUSB            = "usb_events"
	MAfterHours     = "after_hours_admin"
	MAccountChanges = "account_changes"
	MSystems        = "systems_reporting"
	MLogsCleared    = "logs_cleared"
	MNewAdmins      = "new_admins"
	MPolicyChanges  = "policy_changes"
	MLockouts       = "lockouts"
	MNewUSB         = "new_usb_devices"
	MSuspiciousPS   = "suspicious_powershell"
	MAccountsOff    = "accounts_disabled"
	MLate           = "late_events"
)

// metrics counts what this report's pages and trends show.
func (r *Report) metrics() map[string]int {
	m := map[string]int{
		MDetections: len(r.Findings),
		MEvents:     len(r.Events),
		MNewUSB:     len(r.NewDevices),
		MLate:       r.Late,
	}
	for _, row := range r.rows {
		addRowMetrics(m, row)
	}
	reporting := 0
	for _, s := range r.SystemRows {
		if s.reporting() {
			reporting++
		}
	}
	if len(r.SystemRows) == 0 && len(r.Hosts) > 0 {
		reporting = len(r.Hosts)
	}
	m[MSystems] = reporting
	return m
}

// reporting says whether a system sent anything this period: not silent,
// and not a virtual machine that sent nothing (UI2).
func (s SystemRow) reporting() bool {
	return s.Status != "silent" && !(s.VM && s.Runs == 0)
}

// addRowMetrics counts one event row into m.
func addRowMetrics(m map[string]int, row *Row) {
	e := row.Event
	if e.Severity == event.SevHigh {
		m[MHighEvents]++
	}
	switch e.Category {
	case event.CatFailedLogon:
		m[MFailedLogons]++
	case event.CatPrivileged:
		m[MPrivileged]++
	case event.CatRemovable:
		m[MUSB]++
	case event.CatAccount:
		m[MAccountChanges]++
	}
	switch {
	case e.Action == "log_cleared":
		m[MLogsCleared]++
	case e.Action == "group_member_added" && e.Severity == event.SevHigh:
		m[MNewAdmins]++
	case e.Action == "audit_policy_changed" || e.Action == "audit_disabled":
		m[MPolicyChanges]++
	case e.Action == "account_locked":
		m[MLockouts]++
	case e.Action == "account_disabled":
		m[MAccountsOff]++
	case strings.HasPrefix(e.Action, "powershell_") && e.Severity.Rank() >= event.SevMedium.Rank():
		m[MSuspiciousPS]++
	}
	for _, f := range row.Flags {
		if f == "Outside working hours" {
			m[MAfterHours]++
		}
	}
}
