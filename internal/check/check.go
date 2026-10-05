// Package check compares a system's audit configuration with what the
// DISA STIGs require and explains what is missing and how it affects the
// report. It only reports; it never changes settings.
package check

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/winevt"
)

// Status of one check.
type Status string

const (
	Pass  Status = "pass"
	Fail  Status = "fail"
	Warn  Status = "warn"
	Info  Status = "info"
	Error Status = "error"
)

// Result is one checked setting.
type Result struct {
	Area    string `json:"area"`
	Item    string `json:"item"`
	Status  Status `json:"status"`
	Have    string `json:"have"`
	Want    string `json:"want"`
	Affects string `json:"affects,omitempty"` // report section that is incomplete without it
	Fix     string `json:"fix,omitempty"`
	STIG    string `json:"stig,omitempty"` // STIG rule IDs, e.g. WN11-AU-000505
	// Dated is when antivirus definitions were made (Defender's version
	// creation time, ClamAV's build time), so the report can show it.
	Dated time.Time `json:"dated,omitzero"`
}

// Summary counts results by status.
func Summary(rs []Result) (pass, fail, warn int) {
	for _, r := range rs {
		switch r.Status {
		case Pass:
			pass++
		case Fail, Error:
			fail++
		case Warn:
			warn++
		}
	}
	return
}

type auditReq struct {
	guid, name string
	succ, fail string // STIG IDs requiring success / failure auditing ("" = not required)
	affects    string
	optional   bool // not a STIG requirement here, but this report needs it
}

func settingText(s, f bool) string {
	switch {
	case s && f:
		return "Success and Failure"
	case s:
		return "Success"
	case f:
		return "Failure"
	}
	return "No Auditing"
}

// ParseAuditpol reads `auditpol /get /category:* /r` CSV output into a
// map of subcategory GUID → (success, failure).
func ParseAuditpol(text string) (map[string][2]bool, error) {
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(text, "\ufeff")))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse auditpol output: %w", err)
	}
	guidCol, setCol := -1, -1
	out := map[string][2]bool{}
	for _, row := range rows {
		if guidCol < 0 {
			for i, h := range row {
				switch strings.TrimSpace(h) {
				case "Subcategory GUID":
					guidCol = i
				case "Inclusion Setting":
					setCol = i
				}
			}
			continue
		}
		if len(row) <= guidCol || len(row) <= setCol {
			continue
		}
		v := strings.ToLower(row[setCol])
		out[strings.ToUpper(strings.TrimSpace(row[guidCol]))] = [2]bool{
			strings.Contains(v, "success"), strings.Contains(v, "failure"),
		}
	}
	if guidCol < 0 || setCol < 0 {
		return nil, fmt.Errorf("auditpol output has no Subcategory GUID / Inclusion Setting columns")
	}
	return out, nil
}

// EvaluateAuditpol compares auditpol settings with a STIG baseline.
func EvaluateAuditpol(b Baseline, have map[string][2]bool) []Result {
	var out []Result
	for _, q := range b.Audit {
		h := have[q.guid]
		wantS, wantF := q.succ != "", q.fail != ""
		if q.optional {
			wantS, wantF = true, true
		}
		r := Result{Area: "Audit policy", Item: q.name, Have: settingText(h[0], h[1]),
			Want: settingText(wantS, wantF), Affects: q.affects, STIG: joinIDs(q.succ, q.fail), Status: Pass}
		if (wantS && !h[0]) || (wantF && !h[1]) {
			r.Status = Fail
			if q.optional {
				r.Status = Info
				r.Want += " (recommended for this report; not a STIG requirement for this system)"
			}
			r.Fix = auditGPO(q.name, settingText(wantS, wantF))
		}
		out = append(out, r)
	}
	return out
}

func joinIDs(ids ...string) string {
	var out []string
	for _, id := range ids {
		if id != "" {
			out = append(out, id)
		}
	}
	return strings.Join(out, ", ")
}

// ParseRegSZ extracts a REG_SZ value from `reg query` output.
func ParseRegSZ(text, name string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.EqualFold(f[0], name) && f[1] == "REG_SZ" {
			return strings.Join(f[2:], " "), true
		}
	}
	return "", false
}

// ParseRegDWORD extracts a REG_DWORD value from `reg query` output.
func ParseRegDWORD(text, name string) (uint64, bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.EqualFold(f[0], name) && f[1] == "REG_DWORD" {
			v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(f[2]), "0x"), 16, 64)
			return v, err == nil
		}
	}
	return 0, false
}

type regReq struct {
	key, value, item, affects, why, stig string
}

// EvaluateRegistry checks the registry settings; query returns `reg query`
// output for a key/value.
func EvaluateRegistry(b Baseline, query func(key, value string) (string, error)) []Result {
	var out []Result
	for _, q := range b.Registry {
		r := Result{Area: "Audit settings", Item: q.item, Want: "Enabled (1)", Affects: q.affects, STIG: q.stig}
		text, err := query(q.key, q.value)
		v, ok := ParseRegDWORD(text, q.value)
		switch {
		case err == nil && ok && v == 1:
			r.Status, r.Have = Pass, "Enabled (1)"
		case ok:
			r.Status, r.Have = Fail, fmt.Sprintf("%d", v)
		default:
			r.Status, r.Have = Fail, "Not set"
		}
		if r.Status == Fail {
			r.Fix = q.why
		}
		out = append(out, r)
	}
	return out
}

// enabledLogs are the logs Blackbox reads that can be switched off, and
// whether they matter.
var enabledLogs = []struct {
	area, name string
	required   bool
	affects    string // report section and what it gives
}{
	{"USB logging", "Microsoft-Windows-Partition/Diagnostic", true, "USB & Removable Media: USB storage make, model, serial number and size (on by default)"},
	{"USB logging", "Microsoft-Windows-Kernel-PnP/Configuration", true, "USB & Removable Media: first-time USB device setup (on by default)"},
	{"USB logging", "Microsoft-Windows-DriverFrameworks-UserMode/Operational", false, "USB & Removable Media: extra USB connect/disconnect detail (optional, off by default)"},
	// Script Block Logging (a STIG setting, checked with the registry)
	// writes here; the log itself is not a STIG item.
	{"PowerShell logging", "Microsoft-Windows-PowerShell/Operational", false, "Audit & System Integrity, Other Security Events: PowerShell script logging details (on by default)"},
	{"Print logging", "Microsoft-Windows-PrintService/Operational", false, "Other Security Events: documents printed, by whom and on which printer (optional, off by default)"},
	{"Remote Desktop logging", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", false, "Logon Activity: Remote Desktop sessions with the client address (on by default)"},
	{"Firewall logging", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", false, "Audit & System Integrity: who changed firewall rules and settings (on by default)"},
}

// EvaluateLogs checks log sizes and that the USB-related and PowerShell
// logs are enabled.
// history reports how far back a log reaches, for a baseline that wants
// the Security log to hold a week of events.
func EvaluateLogs(b Baseline, get func(string) (winevt.LogSettings, error), history func(string) (winevt.LogHistory, error)) []Result {
	var out []Result
	for _, q := range b.Logs {
		r := Result{Area: "Event log size", Item: q.name + " log", STIG: q.stig}
		s, err := get(q.name)
		if err != nil {
			r.Status, r.Have = Error, err.Error()
			out = append(out, r)
			continue
		}
		r.Have = fmt.Sprintf("%s, %s", mb(s.MaxSize), s.OverwriteMode())
		if q.week {
			out = append(out, holdsWeek(r, s, history))
			continue
		}
		r.Want = fmt.Sprintf("at least %s (%d KB)", mb(q.minKB*1024), q.minKB)
		if s.MaxSize >= q.minKB*1024 {
			r.Status = Pass
		} else {
			r.Status = Fail
			r.Affects = "Events may be overwritten before collection on busy systems"
			r.Fix = logSizeGPO(q.name, q.minKB)
		}
		out = append(out, r)
	}
	for _, l := range enabledLogs {
		r := Result{Area: l.area, Item: l.name, Want: "Enabled", Affects: l.affects}
		s, err := get(l.name)
		switch {
		case err != nil:
			r.Status, r.Have = Error, err.Error()
		case s.Enabled:
			r.Status, r.Have = Pass, "Enabled"
		case l.required:
			r.Status, r.Have = Fail, "Disabled"
			r.Fix = enableLogFix(l.name)
		default:
			r.Status, r.Have, r.Want = Info, "Disabled", "Optional"
			r.Fix = enableLogFix(l.name)
		}
		out = append(out, r)
	}
	return out
}

func mb(b uint64) string {
	if b >= 1024*1024*1024 {
		return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
	}
	return fmt.Sprintf("%d MB", b/(1024*1024))
}

// Group Policy locations, for "How to fix": sites set audit policy in
// Group Policy, not with auditpol or the registry.
const (
	gpSecurity = "Computer Configuration > Policies > Windows Settings > Security Settings"
	gpAdmin    = "Computer Configuration > Policies > Administrative Templates"
)

// auditCategories maps each advanced audit subcategory to its Group Policy
// category and setting name.
var auditCategories = map[string][2]string{
	"Credential Validation":           {"Account Logon", "Audit Credential Validation"},
	"Security Group Management":       {"Account Management", "Audit Security Group Management"},
	"User Account Management":         {"Account Management", "Audit User Account Management"},
	"Other Account Management Events": {"Account Management", "Audit Other Account Management Events"},
	"Plug and Play Events":            {"Detailed Tracking", "Audit PNP Activity"},
	"Process Creation":                {"Detailed Tracking", "Audit Process Creation"},
	"Account Lockout":                 {"Logon/Logoff", "Audit Account Lockout"},
	"Group Membership":                {"Logon/Logoff", "Audit Group Membership"},
	"Logoff":                          {"Logon/Logoff", "Audit Logoff"},
	"Logon":                           {"Logon/Logoff", "Audit Logon"},
	"Special Logon":                   {"Logon/Logoff", "Audit Special Logon"},
	"Other Logon/Logoff Events":       {"Logon/Logoff", "Audit Other Logon/Logoff Events"},
	"File Share":                      {"Object Access", "Audit File Share"},
	"Detailed File Share":             {"Object Access", "Audit Detailed File Share"},
	"Other Object Access Events":      {"Object Access", "Audit Other Object Access Events"},
	"Removable Storage":               {"Object Access", "Audit Removable Storage"},
	"File System":                     {"Object Access", "Audit File System"},
	"Handle Manipulation":             {"Object Access", "Audit Handle Manipulation"},
	"Registry":                        {"Object Access", "Audit Registry"},
	"Audit Policy Change":             {"Policy Change", "Audit Audit Policy Change"},
	"Authentication Policy Change":    {"Policy Change", "Audit Authentication Policy Change"},
	"Authorization Policy Change":     {"Policy Change", "Audit Authorization Policy Change"},
	"MPSSVC Rule-Level Policy Change": {"Policy Change", "Audit MPSSVC Rule-Level Policy Change"},
	"Other Policy Change Events":      {"Policy Change", "Audit Other Policy Change Events"},
	"Sensitive Privilege Use":         {"Privilege Use", "Audit Sensitive Privilege Use"},
	"IPsec Driver":                    {"System", "Audit IPsec Driver"},
	"Other System Events":             {"System", "Audit Other System Events"},
	"Security State Change":           {"System", "Audit Security State Change"},
	"Security System Extension":       {"System", "Audit Security System Extension"},
	"System Integrity":                {"System", "Audit System Integrity"},
}

// auditGPO is where to set an advanced audit subcategory in Group Policy.
func auditGPO(subcategory, want string) string {
	c, ok := auditCategories[subcategory]
	if !ok {
		c = [2]string{"…", "Audit " + subcategory}
	}
	return fmt.Sprintf("%s > Advanced Audit Policy Configuration > Audit Policies > %s > %s: Configure the following audit events: %s",
		gpSecurity, c[0], c[1], want)
}

// logSizeGPO is where to set an event log's maximum size in Group Policy.
func logSizeGPO(log string, kb uint64) string {
	return fmt.Sprintf("%s > Windows Components > Event Log Service > %s > Specify the maximum log file size (KB): Enabled, %d",
		gpAdmin, log, kb)
}

// enableLogFix is how to turn on an operational log, which has no Group
// Policy setting of its own.
func enableLogFix(log string) string {
	return fmt.Sprintf("No Group Policy setting turns this log on. In Event Viewer: Applications and Services Logs > %s > right-click > Enable Log (or once, as administrator: wevtutil sl \"%s\" /e:true)",
		strings.ReplaceAll(log, "/", " > "), log)
}
