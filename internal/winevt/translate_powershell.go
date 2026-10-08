// Microsoft Defender detections and the PowerShell script log.

package winevt

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/casea1/blackbox/internal/event"
)

func (t *Translator) defender(r *Raw) *event.Event {
	threat := r.Get("Threat Name")
	path := strings.TrimPrefix(r.Get("Path"), "file:_")
	user := qualifiedAccount(r.Get("Detection User"), r.Computer)
	switch r.EventID {
	case 1116:
		e := &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "malware_detected",
			User: user, Target: threat,
			Summary: fmt.Sprintf("Microsoft Defender detected malware: %s in %s.", threat, orUnknown(path))}
		e.AddDetail("Severity", r.Get("Severity Name"))
		e.AddDetail("Category", r.Get("Category Name"))
		e.AddDetail("File", path)
		e.AddDetail("Process", r.Get("Process Name"))
		return e
	case 1117:
		return &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "malware_action",
			User: user, Target: threat,
			Summary: fmt.Sprintf("Microsoft Defender took action on %s: %s.", threat, orUnknown(r.Get("Action Name")))}
	case 1118, 1119:
		return &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "malware_action_failed",
			User: user, Target: threat,
			Summary: fmt.Sprintf("Microsoft Defender FAILED to remove %s from %s.", threat, orUnknown(path))}
	case 5001:
		return &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "av_disabled",
			Summary: "Microsoft Defender real-time protection was turned off."}
	case 5010, 5012:
		return &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "av_disabled",
			Summary: "Microsoft Defender scanning was turned off."}
	case 5007, 5013:
		return t.defenderSettings(r)
	case 2000, 2014:
		// An update (security intelligence, engine or platform): not a
		// row, but it tells a code integrity failure on a Defender
		// platform file during the update from a changed file (T2b).
		var versions []string
		for _, v := range r.Data {
			versions = append(versions, versionRE.FindAllString(v, -1)...)
		}
		e := &event.Event{Category: event.CatOther, Severity: event.SevInfo, Action: event.DefenderUpdate,
			Summary: "Microsoft Defender updated.", Fields: map[string]string{"versions": strings.Join(versions, " ")}}
		return e
	}
	return nil
}

var versionRE = regexp.MustCompile(`\b\d+\.\d+\.\d+\.\d+(?:-\d+)?\b`)

// psRule is one kind of PowerShell script worth reporting. A script block
// matches when every pattern in find matches somewhere in it; the line
// holding the first pattern's match is shown in the report.
type psRule struct {
	action string
	sev    event.Severity
	cat    event.Category
	what   string // completes "jsmith ran a PowerShell script that …"
	find   []*regexp.Regexp
}

// psRules are the script blocks that are reported, checked in order (the
// first match wins). Everything else PowerShell records is routine:
// management tools, logon scripts and modules loading run thousands of
// script blocks a day. Matching ignores case.
var psRules = []psRule{
	// Clearing logs or weakening auditing: the same commands that are
	// flagged on a command line (auditTamper), plus PowerShell's own.
	{"powershell_tamper", event.SevHigh, event.CatIntegrity, "can clear logs or weaken auditing",
		psPatterns(tamperPattern(), `limit-eventlog`, `wevtutil(?:\.exe)?\s+clear-log`,
			`stop-service\s+(?:-name\s+)?['"]?eventlog\b`)},

	// Turning Microsoft Defender off, excluding files from scanning, or
	// removing it ($false re-enables, so only $true/1 counts).
	{"powershell_av_tamper", event.SevHigh, event.CatOther, "turns off or weakens Microsoft Defender",
		psPatterns(`set-mppreference\b.*-disable\w+(?:\s+|:)(?:\$true|1)\b`,
			`(?:add|set)-mppreference\b.*-exclusion(?:path|process|extension)\b`,
			`(?:uninstall|remove)-windowsfeature\b.*windows-defender`)},

	// Switching off the Antimalware Scan Interface, which lets Defender
	// see the scripts PowerShell runs.
	{"powershell_amsi_bypass", event.SevHigh, event.CatOther, "tries to switch off malware scanning of scripts (AMSI bypass)",
		psPatterns(`amsiutils|amsiinitfailed`)},

	// Tools that steal passwords and logon tokens from memory or Group
	// Policy files.
	{"powershell_credential", event.SevHigh, event.CatOther, "uses a password-stealing tool",
		psPatterns(`mimikatz|\bsekurlsa\b|\blsadump\b|get-gpppassword`,
			`out-minidump.*lsass|lsass.*out-minidump`)},

	// Download cradles: code fetched from the network and run straight
	// away, without ever being saved where it could be scanned.
	{"powershell_download", event.SevHigh, event.CatOther, "downloads and runs code",
		[]*regexp.Regexp{psPattern(`net\.webclient|downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer`),
			psPattern(`invoke-expression|\biex\b`)}},
	{"powershell_download", event.SevHigh, event.CatOther, "decodes hidden (base64) code and runs it",
		[]*regexp.Regexp{psPattern(`frombase64string`), psPattern(`invoke-expression|\biex\b`)}},
}

// psPattern compiles a case-insensitive pattern.
func psPattern(p string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + p) }

// psPatterns is one pattern matching any of the alternatives.
func psPatterns(alts ...string) []*regexp.Regexp {
	return []*regexp.Regexp{psPattern(`(?:` + strings.Join(alts, `)|(?:`) + `)`)}
}

// tamperPattern matches the auditTamper commands with any spacing.
func tamperPattern() string {
	var alts []string
	for _, frag := range auditTamper {
		alts = append(alts, strings.ReplaceAll(regexp.QuoteMeta(frag), " ", `\s+`))
	}
	return strings.Join(alts, "|")
}

// powerShell handles PowerShell/Operational 4104 (Script Block Logging).
// Only suspicious script blocks are reported: those PowerShell itself
// logs as warnings, and those matching psRules. Module logging (4103) is
// skipped: it repeats what the script blocks show, at great volume.
func (t *Translator) powerShell(r *Raw) *event.Event {
	if r.EventID != 4104 {
		return nil
	}
	text := r.Get("ScriptBlockText")
	// A large script is logged in parts sharing one ScriptBlockId; once
	// one part shows it is Windows' own module code, so are the others
	// (W3).
	id := strings.ToLower(r.Get("ScriptBlockId"))
	if id != "" && t.psModule[id] {
		return nil
	}
	var rule *psRule
	var line string
	for i := range psRules {
		if l, ok := psMatch(&psRules[i], text); ok {
			rule, line = &psRules[i], l
			break
		}
	}
	name := scriptName(text, r.Get("Path"))
	var flaggedFor string
	if rule == nil {
		if r.Level != 3 {
			return nil
		}
		// Windows logs a script block as a warning, even when Script Block
		// Logging is off, when it uses commands attackers favour. Windows'
		// own modules do too (the cmdlets it generates for Defender,
		// networking and the like), so those are left out.
		if WindowsModule(text, r.Get("Path")) {
			if id != "" {
				if len(t.psModule) > 4096 {
					t.psModule = map[string]bool{}
				}
				t.psModule[id] = true
			}
			return nil
		}
		rule = &psRule{action: "powershell_suspicious", sev: event.SevMedium, cat: event.CatOther,
			what: "PowerShell itself flagged as suspicious"}
		flaggedFor, line = suspiciousWord(text)
		if line == "" {
			line = firstLine(text)
		}
	}
	user := t.resolve(r.UserSID)
	e := &event.Event{Category: rule.cat, Severity: rule.sev, Action: rule.action, User: user, Target: name}
	switch {
	case flaggedFor != "":
		e.Summary = fmt.Sprintf("%s ran %s, which PowerShell flagged as suspicious for using %s", orUnknown(user), name, flaggedFor)
	case rule.action == "powershell_suspicious":
		e.Summary = fmt.Sprintf("%s ran %s, which PowerShell flagged as suspicious", orUnknown(user), name)
	default:
		e.Summary = fmt.Sprintf("%s ran %s, which %s", orUnknown(user), name, rule.what)
		if line != "" {
			e.Summary += ": " + clip(line, 120)
		}
	}
	if !strings.HasSuffix(e.Summary, ".") {
		e.Summary += "."
	}
	// A large script is logged in parts sharing one ID: matching parts are
	// reported once.
	if id := r.Get("ScriptBlockId"); id != "" {
		e.DedupeKey = "psblock|" + strings.ToLower(id)
		e.Priority = rule.sev.Rank()
	}
	e.AddDetail("Script", name)
	if flaggedFor != "" {
		e.AddDetail("Flagged for", flaggedFor)
	}
	e.AddDetail("Matched line", clip(line, 500))
	e.AddDetail("Script (excerpt)", clip(strings.TrimSpace(text), 2000))
	if n, total := r.Get("MessageNumber"), r.Get("MessageTotal"); total != "" && total != "1" {
		e.AddDetail("Script part", n+" of "+total)
	}
	e.AddDetail("Script path", r.Get("Path"))
	e.AddDetail("Script block ID", r.Get("ScriptBlockId"))
	if r.Level == 3 && rule.action != "powershell_suspicious" {
		e.AddDetail("Note", "PowerShell also flagged this script as suspicious.")
	}
	// The whole script is in the original log; keep only the excerpt.
	e.Fields = trimFields(r.Data, "ScriptBlockText")
	return e
}

// psMatch reports whether every pattern of rule matches text, and returns
// the line holding the first pattern's match.
func psMatch(rule *psRule, text string) (string, bool) {
	if text == "" || len(rule.find) == 0 {
		return "", false
	}
	loc := rule.find[0].FindStringIndex(text)
	if loc == nil {
		return "", false
	}
	for _, re := range rule.find[1:] {
		if !re.MatchString(text) {
			return "", false
		}
	}
	start := strings.LastIndexByte(text[:loc[0]], '\n') + 1
	end := len(text)
	if i := strings.IndexByte(text[loc[0]:], '\n'); i >= 0 {
		end = loc[0] + i
	}
	return strings.TrimSpace(text[start:end]), true
}

// firstLine returns the first non-blank line of s.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// clip shortens s to n characters, marking the cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n])) + " …"
}

// psFlag is a PowerShell parameter and the value after it.
var psFlag = regexp.MustCompile(`(?:^|\s)[-/]([A-Za-z]+)\s+("?)([A-Za-z0-9+/=]{8,})`)

// decodePowerShell returns the command hidden in a PowerShell
// -EncodedCommand argument (base64 of UTF-16LE text), or "".
func decodePowerShell(cmd string) string {
	l := strings.ToLower(cmd)
	if !strings.Contains(l, "powershell") && !strings.Contains(l, "pwsh") {
		return ""
	}
	// PowerShell accepts any prefix of -EncodedCommand (-e, -enc, …) and -ec.
	val := ""
	for _, m := range psFlag.FindAllStringSubmatch(cmd, -1) {
		f := strings.ToLower(m[1])
		if f == "ec" || strings.HasPrefix("encodedcommand", f) {
			val = m[3]
			break
		}
	}
	if val == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(val)
	if err != nil || len(b) < 2 || len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	out := strings.TrimSpace(string(utf16.Decode(u)))
	if len(out) > 2000 {
		out = out[:2000] + " …"
	}
	return out
}

// scriptName names a script block for people: its file, or for a script
// typed or generated in memory, what it is or its first real line.
func scriptName(text, path string) string {
	if path != "" {
		base := path
		if i := strings.LastIndexAny(base, `\/`); i >= 0 {
			base = base[i+1:]
		}
		return fmt.Sprintf("the script %s (%s)", base, path)
	}
	if m := cimClass.FindStringSubmatch(text); m != nil {
		return "the PowerShell commands Windows generates for " + m[1]
	}
	if l := firstLine(text); l != "" {
		return "a PowerShell script typed or run from memory (" + clip(l, 80) + ")"
	}
	return "a PowerShell script"
}

// cimClass finds the WMI class a generated (CDXML) module wraps.
var cimClass = regexp.MustCompile(`(?i)\$script:ClassName\s*=\s*'([^']+)'`)

// WindowsModule reports script blocks Windows itself provides: modules it
// generates from CDXML for its own WMI classes (Defender, networking,
// storage …), and modules installed with Windows.
func WindowsModule(text, path string) bool {
	// Every part of a module generated from a CDXML file (NetSecurity's
	// Get-/Set-NetFirewallRule, Storage, NetAdapter …) uses PowerShell's
	// $__cmdletization_ variables, including the parts after the first,
	// which do not name the CIM class (W3).
	if cmdletizationVar.MatchString(text) {
		return true
	}
	if strings.Contains(text, "Microsoft.PowerShell.Cmdletization") {
		if m := cimClass.FindStringSubmatch(text); m != nil {
			c := strings.ToLower(strings.ReplaceAll(m[1], "/", `\`))
			if strings.HasPrefix(c, `root\microsoft\`) || strings.HasPrefix(c, `root\standardcimv2`) || strings.HasPrefix(c, `root\cimv2`) {
				return true
			}
		}
	}
	p := strings.ToLower(path)
	return strings.Contains(p, `\windows\system32\windowspowershell\v1.0\modules\`) ||
		strings.Contains(p, `\windows\syswow64\windowspowershell\v1.0\modules\`)
}

// cmdletizationVar is a variable PowerShell's CDXML code generator uses.
var cmdletizationVar = regexp.MustCompile(`\$__cmdletization_\w+`)

// psSuspicious are words that make PowerShell log a script block as a
// warning (from its own list), with what they are used for.
var psSuspicious = []struct{ word, what string }{
	{"VirtualAlloc", "memory allocation in another process"}, {"WriteProcessMemory", "writing into another process"},
	{"CreateRemoteThread", "starting code in another process"}, {"GetDelegateForFunctionPointer", "calling raw Windows functions"},
	{"MiniDumpWriteDump", "dumping a process's memory"}, {"ReadProcessMemory", "reading another process's memory"},
	{"AdjustTokenPrivileges", "changing its privileges"}, {"ImpersonateLoggedOnUser", "acting as another user"},
	{"DuplicateTokenEx", "copying a logon token"}, {"GetAsyncKeyState", "reading keystrokes"},
	{"DllImport", "calling Windows functions directly"}, {"Add-Type", "compiling code (Add-Type)"},
	{"FromBase64String", "decoding hidden (base64) data"}, {"EncodedCommand", "an encoded command"},
	{"DefineDynamicAssembly", "building code in memory"}, {"InteropServices", "calling Windows functions directly"},
	{"NonPublic", "reaching into hidden parts of .NET (reflection)"}, {"GetField", "reflection"},
	{"GetMethod", "reflection"}, {"InvokeMember", "reflection"}, {"Marshal", "raw memory access"},
	{"CryptoStream", "encryption"}, {"Bypass", "bypassing a restriction"},
}

// suspiciousWord finds which of PowerShell's warning words a script uses,
// and the line it is on.
func suspiciousWord(text string) (string, string) {
	lower := strings.ToLower(text)
	for _, s := range psSuspicious {
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(s.word) + `\b`)
		if loc := re.FindStringIndex(text); loc != nil {
			start := strings.LastIndex(lower[:loc[0]], "\n") + 1
			end := strings.Index(text[loc[0]:], "\n")
			if end < 0 {
				end = len(text) - loc[0]
			}
			return s.word + " (" + s.what + ")", strings.TrimSpace(text[start : loc[0]+end])
		}
	}
	return "", ""
}
