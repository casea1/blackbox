package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// The event pages (Events by kind, UI-R1 design 10) are Search with the
// kind of event preset: app.js draws them from the page's data files.
// Each page says how its events are split into kinds (the Kind counts
// and filter) and what its extra value is (shown in the event panel).

// pageSpec says how one event page's events are split up and shown.
type pageSpec struct {
	kindOf    func(e *event.Event) string // the event's kind on this page
	kindLabel string                      // the kind's name, e.g. "Reason"
	extra     func(e *event.Event) string // page-specific value
	xLabel    string                      // its name, e.g. "Device"
	unit      string                      // "failed logons", for "1,204 failed logons"
	desc      string                      // what the page holds, for its breadcrumb
}

// TopItem is one line of a top list (People's systems used).
type TopItem struct {
	Label   string
	Href    string
	N       int
	Pct     int
	Flagged bool
}

func detail(e *event.Event, label string) string {
	for _, d := range e.Details {
		if d.Label == label {
			return d.Value
		}
	}
	return ""
}

func logonSource(e *event.Event) string {
	if e.SourceIP != "" && !localAddress(e.SourceIP) {
		return e.SourceIP
	}
	if w := detail(e, "Source workstation"); w != "" && w != "-" {
		return w
	}
	return e.Host + " console"
}

func logonHow(e *event.Event) string {
	t := strings.ToLower(detail(e, "Logon type") + " " + e.Process + " " + e.RecordType + " " + e.Summary)
	switch {
	case strings.Contains(t, "remote"):
		return "Remote Desktop"
	case strings.Contains(t, "ssh"):
		return "SSH"
	case strings.Contains(t, "network"):
		return "Network"
	case strings.Contains(t, "sudo"):
		return "sudo"
	}
	return "Console"
}

func has(a string, list ...string) bool {
	for _, s := range list {
		if strings.HasPrefix(a, s) {
			return true
		}
	}
	return false
}

var pageSpecs = map[string]pageSpec{
	"failed": {
		kindOf: func(e *event.Event) string {
			r := strings.ToLower(detail(e, "Reason") + " " + e.Summary)
			switch {
			case e.Action == "account_locked" || strings.Contains(r, "locked"):
				return "Locked out"
			case strings.Contains(r, "expired"):
				return "Expired"
			}
			return "Bad password"
		},
		kindLabel: "Reason", extra: logonHow, xLabel: "Logon type", unit: "failed logons",
		desc: "logons that failed: bad passwords, expired and locked-out accounts",
	},
	"privileged": {
		kindOf: func(e *event.Event) string {
			switch {
			case has(e.Action, "admin_logon", "explicit_credentials", "switch_user"):
				return "Admin logon"
			case has(e.Action, "sudo", "elevated_process", "pkexec", "root_command", "privileged_program"):
				return "sudo / run as admin"
			}
			return "Security settings"
		},
		kindLabel: "Kind", unit: "privileged actions", desc: "admin rights, sudo and root commands",
	},
	"usb": {
		kindOf: func(e *event.Event) string {
			switch {
			case strings.Contains(e.Action, "blocked") || e.Outcome == "failure":
				return "Blocked"
			case detail(e, "File") != "" || strings.Contains(e.Action, "file"):
				return "Files copied"
			}
			return "Connected or removed"
		},
		kindLabel: "What happened", extra: usbDevice, xLabel: "Device", unit: "USB events", desc: "USB drives and other removable media",
	},
	"accounts": {
		kindOf: func(e *event.Event) string {
			switch {
			case strings.HasSuffix(e.Action, "_created"):
				return "Created"
			case e.Action == "group_member_added":
				return "Added to group"
			case has(e.Action, "account_disabled", "account_deleted", "group_deleted"):
				return "Disabled"
			}
			return "Changed"
		},
		kindLabel: "Kind", extra: func(e *event.Event) string { return e.Target }, xLabel: "Account", unit: "account changes",
		desc: "accounts created, changed, disabled and added to groups",
	},
	"integrity": {
		// Each kind its own label (UX2): "Logging stopped" is only the
		// event log or audit service stopping, the log full or dropping
		// records.
		kindOf: func(e *event.Event) string {
			switch {
			case has(e.Action, "log_cleared", "log_tampered", "audit_tamper"):
				return "Log cleared"
			case has(e.Action, "audit_policy", "audit_disabled", "audit_enabled", "audit_locked", "audit_rules", "object_audit"):
				return "Audit policy changed"
			case has(e.Action, "audit_stopped", "audit_events_dropped", "eventlog_shutdown", "eventlog_error", "log_full"):
				return "Logging stopped"
			case has(e.Action, "blackbox_"):
				return "Blackbox"
			case has(e.Action, "firewall_"):
				return "Firewall"
			case e.Action == "time_changed":
				return "Clock"
			case has(e.Action, "system_start", "system_stop", "shutdown_initiated", "unexpected_shutdown", "audit_started"):
				return "Startup and shutdown"
			}
			return "Other"
		},
		kindLabel: "Kind", unit: "audit integrity events", desc: "logs cleared, audit policy changes, logging stopped and the clock",
	},
	"powershell": {
		kindOf: func(e *event.Event) string {
			switch {
			case e.Action == "powershell_suspicious" || e.Severity == event.SevHigh:
				return "Suspicious"
			case e.Severity == event.SevMedium:
				return "Warning"
			}
			return "Routine"
		},
		kindLabel: "Kind", unit: "PowerShell scripts", desc: "the PowerShell scripts that ran",
	},
	"other": {
		kindOf: func(e *event.Event) string {
			switch {
			case has(e.Action, "service_", "scheduled_task"):
				return "Services and tasks"
			case has(e.Action, "malware", "av_"):
				return "Malware and antivirus"
			case has(e.Action, "module_", "mac_", "selinux", "apparmor", "promiscuous", "file_"):
				return "Kernel and access control"
			case e.Action == "other_security":
				return "Not translated"
			}
			return "System"
		},
		kindLabel: "Kind", unit: "other security events", desc: "services, antivirus and other security events",
	},
	"logons": {
		kindOf: func(e *event.Event) string {
			if h := logonHow(e); h != "sudo" {
				return h
			}
			return "Console"
		},
		kindLabel: "How", xLabel: "Session", unit: "logons", desc: "logons and logoffs, at the keyboard and remote",
	},
}

// sessions finds how long each logon lasted, by pairing it with the
// logoff for the same logon ID on the same computer.
func (r *Report) sessions() map[int]string {
	open := map[string]int{}
	out := map[int]string{}
	for i, e := range r.Events {
		id := detail(e, "Logon ID")
		if id == "" || e.Category != event.CatLogon {
			continue
		}
		key := e.Host + "|" + strings.ToLower(id)
		switch e.Action {
		case "logon":
			open[key] = i
		case "logoff":
			if j, ok := open[key]; ok {
				out[j] = duration(e.Time.Sub(r.Events[j].Time))
				delete(open, key)
			}
		}
	}
	return out
}

func duration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
}

func usbDevice(e *event.Event) string {
	if e.Target != "" {
		return e.Target
	}
	for _, l := range []string{"Device", "Product", "Device ID"} {
		if v := detail(e, l); v != "" {
			return v
		}
	}
	return ""
}

// fillPages sets each event page's kind label and extra value's name,
// which app.js reads from the page's settings.
func (r *Report) fillPages(pages []*EventPage) {
	for _, p := range pages {
		if spec, ok := pageSpecs[p.ID]; ok {
			p.KindLabel, p.XLabel, p.Unit = spec.kindLabel, spec.xLabel, spec.unit
		}
	}
}

// periodDays lists the report period's days (YYYYMMDD), oldest first.
func (r *Report) periodDays() []string {
	start, end := r.PeriodStart().In(r.Location), r.WindowEnd.In(r.Location)
	if start.IsZero() || !end.After(start) {
		return nil
	}
	var out []string
	d := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, r.Location)
	for ; d.Before(end) && len(out) < 62; d = d.AddDate(0, 0, 1) {
		out = append(out, d.Format("20060102"))
	}
	return out
}

func short(m map[string]bool, max int) string {
	var l []string
	for k := range m {
		l = append(l, k)
	}
	sort.Slice(l, func(a, b int) bool { return naturalLess(l[a], l[b]) })
	if len(l) > max {
		return strings.Join(l[:max], ", ") + fmt.Sprintf(" +%d", len(l)-max)
	}
	return strings.Join(l, ", ")
}

// outsideHours says whether e happened outside the site's working hours.
func (r *Report) outsideHours(e *event.Event) bool {
	if !r.WorkingHours.Set() {
		return false
	}
	return !r.WorkingHours.Contains(e.Time.In(r.Location))
}

// finderData is what the template needs for Search, or for an event page
// (Kind set), which is Search with that kind of event preset.
type finderData struct {
	Kind, KindTitle string // the page's kind of event, if any
	Placeholder     string
	Pages           []*EventPage // the kinds of event with events
	VMs, After      bool         // a Virtual machines choice; working hours set
	Omitted         int          // Info events counted but not listed
	Cols            []string     // the table's column headings
}

// finder is the Search box, filters and results for Search (kind "") or
// one event page.
func (p pageData) finder(kind string) finderData {
	f := finderData{Kind: kind, Placeholder: "Search…", After: p.WorkingHours.Set(),
		Cols: []string{"Time", "System", "Person", "Event", "Details", "ID", "Severity"}}
	for _, ep := range p.Pages {
		if ep.Total > 0 {
			f.Pages = append(f.Pages, ep)
		}
		if ep.ID == kind {
			f.KindTitle, f.Omitted = ep.Title, ep.Omitted
			f.Placeholder = "Search within " + strings.ToLower(ep.Title) + "…"
			f.Cols = []string{"Time", "System", "Person", "Command or action", "Severity"}
		}
		if kind == "" {
			f.Omitted += ep.Omitted
		}
	}
	for _, s := range p.SystemRows {
		f.VMs = f.VMs || s.VM
	}
	return f
}
