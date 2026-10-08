package report

import (
	"fmt"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/casea1/blackbox/internal/event"
)

// The event panel (UI-R1 design 16) shows, for one event: its time to the
// millisecond in local time and UTC, the original record it came from
// (the zip, the file in it and the record number), what started it, and
// the ATT&CK technique its action stands for. These are worked out here
// and kept with the event's raw data (the …-raw.js files), which are read
// only when a row is opened.

// rawExtra is the event panel's extra facts for one event, as the fifth
// item of its raw entry. Empty values are left out.
type rawExtra struct {
	When   string `json:"when,omitempty"`   // "Wed 7 Oct 2026 14:22:05.118 EDT (18:22:05.118 UTC)"
	Piece  string `json:"piece,omitempty"`  // "logs-SRV-DC02.zip › Security.evtx"
	Rec    uint64 `json:"rec,omitempty"`    // record number (Windows) or audit serial
	By     string `json:"by,omitempty"`     // "cmd.exe (from a Remote Desktop session from WS-ADM-01)"
	Attack string `json:"attack,omitempty"` // "T1070.001 Clear Windows Event Logs"
}

// detailer works out the event panel's facts for a report's events.
type detailer struct {
	r      *Report
	zone   string // the report's zone name, for times at its usual offset
	off    int
	logons map[string]*event.Event // host|logon ID → the logon that began it
	pieces map[string][]piece      // host → what its original-log zip holds
}

// piece is one log file in a system's original-log zip, and the part of
// the period it covers.
type piece struct {
	from, to time.Time
	path     string // "logs-HOST.zip › folder/Security.evtx"
	source   string // the log it came from
}

func (r *Report) detailer() *detailer {
	d := &detailer{r: r, logons: map[string]*event.Event{}, pieces: map[string][]piece{}}
	if !r.Generated.IsZero() {
		d.zone = zoneName(r.Generated, r.Location)
		_, d.off = r.Generated.In(r.Location).Zone()
	}
	for _, e := range r.Events {
		if e.Category == event.CatLogon && e.Action == "logon" {
			if id := detail(e, "Logon ID"); id != "" {
				d.logons[e.Host+"|"+strings.ToLower(id)] = e
			}
		}
	}
	for _, a := range r.Archives {
		for _, info := range r.archiveState[a.Name].Contents {
			for _, f := range info.Files {
				d.pieces[a.Host] = append(d.pieces[a.Host], piece{from: info.From, to: info.To, path: a.Name + " › " + info.Dir + f.Name, source: f.Source})
			}
		}
	}
	return d
}

func (d *detailer) extra(e *event.Event) rawExtra {
	return rawExtra{When: d.when(e.Time), Piece: d.piece(e), Rec: e.RecordID, By: d.startedBy(e), Attack: attackOf(e)}
}

// when is a time to the millisecond, local and UTC: "Wed 7 Oct 2026
// 14:22:05.118 EDT (18:22:05.118 UTC)", with the UTC day when it differs
// (just once for a report in UTC).
func (d *detailer) when(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	local := t.In(d.r.Location)
	name, off := local.Zone()
	if off != d.off || d.zone == "" || name == "" || name[0] == '+' || name[0] == '-' {
		name = utcOffset(off)
	}
	if off == 0 {
		return local.Format("Mon 2 Jan 2006 15:04:05.000") + " UTC"
	}
	u := t.UTC()
	utc := u.Format("15:04:05.000") + " UTC"
	if u.Day() != local.Day() {
		utc = u.Format("Mon 2 Jan ") + utc
	}
	return local.Format("Mon 2 Jan 2006 15:04:05.000") + " " + name + " (" + utc + ")"
}

// utcOffset is "UTC-04:00", or "UTC" for none.
func utcOffset(off int) string {
	if off == 0 {
		return "UTC"
	}
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, off/3600, off%3600/60)
}

// piece is the file in the system's original-log zip that holds the
// event: the export covering its time, from its log (AR8, AR9 make the
// record numbers in it complete). "" when the zip is not in the report
// or no file of it matches.
func (d *detailer) piece(e *event.Event) string {
	want := logKey(e.Source)
	if want == "" {
		return ""
	}
	for _, p := range d.pieces[e.Host] {
		if e.Time.Before(p.from) || !e.Time.Before(p.to) {
			continue
		}
		if k := logKey(p.source); k != "" && (k == want || strings.HasPrefix(k, want) || strings.HasPrefix(want, k)) {
			return p.path
		}
	}
	return ""
}

// logKey is a log's name to match an event's log with an exported file:
// "Microsoft-Windows-PowerShell/Operational", "PowerShell-Operational"
// and "powershell_operational.evtx" are all "powershelloperational";
// "/var/log/audit/audit.log" is "audit".
func logKey(s string) string {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "/") {
		s = path.Base(s)
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".evtx"), ".log")
	s = strings.TrimPrefix(s, "microsoft-windows-")
	return strings.Map(func(c rune) rune {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			return c
		}
		return -1
	}, s)
}

// startedBy is what started the event: the program that started it (a
// new process's parent) and the logon session it came from, e.g.
// "cmd.exe (from a Remote Desktop session from WS-ADM-01)".
func (d *detailer) startedBy(e *event.Event) string {
	parent := detail(e, "Started by")
	if parent == "" {
		parent = e.Fields["ParentProcessName"]
	}
	if i := strings.LastIndexAny(parent, `\/`); i >= 0 {
		parent = parent[i+1:]
	}
	session := ""
	if e.Category != event.CatLogon {
		id := e.Fields["SubjectLogonId"]
		if id == "" {
			id = detail(e, "Logon ID")
		}
		if l := d.logons[e.Host+"|"+strings.ToLower(id)]; l != nil && id != "" && l != e {
			switch how := logonHow(l); how {
			case "Console", "sudo":
				session = "a session at the keyboard"
			default:
				from := detail(l, "Source workstation")
				if from == "" || from == "-" {
					from = logonSource(l)
				}
				session = "a " + how + " session from " + from
			}
		}
	}
	switch {
	case parent != "" && session != "":
		return parent + " (from " + session + ")"
	case parent != "":
		return parent
	case session != "":
		return "from " + session
	}
	return ""
}

// attack is the MITRE ATT&CK technique an action stands for, for the
// event panel: only where the mapping is clear, else "".
var attack = map[string][2]string{ // action → Windows, Linux
	"log_cleared":            {"T1070.001 Clear Windows Event Logs", "T1070.002 Clear Linux or Mac System Logs"},
	"audit_tamper_command":   {"T1562.002 Disable Windows Event Logging", "T1562.012 Disable or Modify Linux Audit System"},
	"audit_policy_changed":   {"T1562.002 Disable Windows Event Logging", "T1562.012 Disable or Modify Linux Audit System"},
	"group_member_added":     {"T1098.007 Additional Local or Domain Groups", "T1098.007 Additional Local or Domain Groups"},
	"account_created":        {"T1136 Create Account", "T1136 Create Account"},
	"powershell_suspicious":  {"T1059.001 PowerShell", ""},
	"powershell_download":    {"T1105 Ingress Tool Transfer", ""},
	"powershell_amsi_bypass": {"T1562.001 Disable or Modify Tools", ""},
	"powershell_av_tamper":   {"T1562.001 Disable or Modify Tools", ""},
	"hidden_powershell":      {"T1564.003 Hidden Window", ""},
	"av_disabled":            {"T1562.001 Disable or Modify Tools", "T1562.001 Disable or Modify Tools"},
	"av_exclusion_added":     {"T1562.001 Disable or Modify Tools", "T1562.001 Disable or Modify Tools"},
	"service_installed":      {"T1543.003 Windows Service", "T1543.002 Systemd Service"},
	"firewall_stopped":       {"T1562.004 Disable or Modify System Firewall", "T1562.004 Disable or Modify System Firewall"},
	"firewall_rules_cleared": {"T1562.004 Disable or Modify System Firewall", "T1562.004 Disable or Modify System Firewall"},
	"firewall_reset":         {"T1562.004 Disable or Modify System Firewall", "T1562.004 Disable or Modify System Firewall"},
	"sid_history_added":      {"T1134.005 SID-History Injection", ""},
}

func attackOf(e *event.Event) string {
	m, ok := attack[e.Action]
	switch {
	case !ok && strings.HasPrefix(e.Action, "scheduled_task_") && strings.Contains(e.Action, "creat"):
		return "T1053.005 Scheduled Task"
	case !ok:
		return ""
	case e.Action == "audit_policy_changed" && e.Severity.Rank() < event.SevMedium.Rank():
		// A routine change (auditing turned on) stands for nothing.
		return ""
	case e.Action == "group_member_added" && e.Severity.Rank() < event.SevHigh.Rank():
		// Only a privileged group (High) is a technique.
		return ""
	case e.OS == "linux":
		return m[1]
	}
	return m[0]
}

// eventRights is, for the event panel's Person, each system's accounts
// that the events name, with their rights from its inventory:
// host → person key → "administrator" or "standard user" (", disabled").
func (r *Report) eventRights() map[string]map[string]string {
	used := map[string]bool{}
	for _, e := range r.Events {
		if e.User != "" {
			used[e.Host+"|"+personKey(e.User)] = true
		}
	}
	out := map[string]map[string]string{}
	for _, cs := range r.CheckSets {
		if cs.Inventory == nil {
			continue
		}
		for _, a := range cs.Inventory.Accounts {
			k := personKey(a.Name)
			if !used[cs.Host+"|"+k] {
				continue
			}
			v := "standard user"
			if a.Admin {
				v = "administrator"
			}
			if !a.Enabled {
				v += ", disabled"
			}
			if out[cs.Host] == nil {
				out[cs.Host] = map[string]string{}
			}
			out[cs.Host][k] = v
		}
	}
	return out
}
