// Programs and changes made with administrator rights: process starts
// (including hidden PowerShell and audit tampering), services, scheduled
// tasks, audit policy and time changes.

package winevt

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// auditTamper are command fragments that clear logs or weaken auditing.
var auditTamper = []string{
	"wevtutil cl", "wevtutil.exe cl", "clear-eventlog", "clear-winevent", "remove-eventlog",
	"auditpol /clear", "auditpol /remove", "auditpol.exe /clear", "auditpol.exe /remove",
	"auditpol /set", "auditpol.exe /set", "vssadmin delete shadows", "vssadmin.exe delete shadows",
	"bcdedit /set", "bcdedit.exe /set", "fsutil usn deletejournal",
}

var (
	psHidden = regexp.MustCompile(`(^|\s)[-/]w[a-z]*\s+(hidden|1)\b`)
	psBypass = regexp.MustCompile(`(^|\s)[-/](ex[a-z]*|ep)\s+(bypass|unrestricted)\b`)
	psNonInt = regexp.MustCompile(`(^|\s)[-/]noni[a-z]*\b`)
)

// hiddenPowerShell counts the ways a PowerShell command line keeps itself
// out of sight: a hidden window, bypassing the execution policy, no
// prompts, an encoded command. PowerShell accepts any prefix of a
// parameter name (-w, -win, -WindowStyle).
func hiddenPowerShell(proc, cmd, decoded string) int {
	b := strings.ToLower(filepath.Base(strings.ReplaceAll(proc, `\`, "/")))
	if b != "powershell.exe" && b != "pwsh.exe" {
		return 0
	}
	c := strings.ToLower(cmd)
	n := 0
	for _, re := range []*regexp.Regexp{psHidden, psBypass, psNonInt} {
		if re.MatchString(c) {
			n++
		}
	}
	if decoded != "" {
		n++
	}
	return n
}

// psScript is the script a PowerShell command line runs with -File
// (any prefix of it: -f, -fi, -file), "" if none: "powershell -File
// C:\Scripts\backup.ps1" reads "ran the script C:\Scripts\backup.ps1"
// (UI21). Whatever follows -Command or -EncodedCommand is a command, not
// a parameter, so -File is only looked for before them.
func psScript(proc, cmd string) string {
	b := strings.ToLower(filepath.Base(winPath(proc)))
	if b != "powershell.exe" && b != "pwsh.exe" {
		return ""
	}
	args := splitArgs(cmd)
	for i := 1; i < len(args); i++ {
		a := strings.ToLower(args[i])
		if len(a) < 2 || (a[0] != '-' && a[0] != '/') {
			continue
		}
		name := a[1:]
		switch {
		case strings.HasPrefix("command", name) || strings.HasPrefix("encodedcommand", name) || name == "ec":
			return ""
		case strings.HasPrefix("file", name) && i+1 < len(args):
			return args[i+1]
		}
	}
	return ""
}

// splitArgs splits a Windows command line at spaces outside double
// quotes, removing the quotes.
func splitArgs(cmd string) []string {
	var out []string
	var cur strings.Builder
	quoted, any := false, false
	for _, c := range cmd {
		switch {
		case c == '"':
			quoted, any = !quoted, true
		case (c == ' ' || c == '\t') && !quoted:
			if any {
				out = append(out, cur.String())
				cur.Reset()
				any = false
			}
		default:
			cur.WriteRune(c)
			any = true
		}
	}
	if any {
		out = append(out, cur.String())
	}
	return out
}

func (t *Translator) processCreated(r *Raw) *event.Event {
	elev := r.Get("TokenElevationType")
	label := r.Get("MandatoryLabel")
	// %%1937 = elevated via UAC. %%1936 ("default") is also used for
	// standard users, so it only counts when the integrity label is High.
	elevated := elev == "%%1937" || label == "S-1-16-12288" || label == "S-1-16-16384"
	if !elevated || t.ignoredAccount(r, "Subject") {
		return nil
	}
	// Programs Blackbox runs itself (wevtutil, auditpol, reg, powershell
	// for its checks, conhost): part of its own run, not a person's (T4).
	switch strings.ToLower(filepath.Base(winPath(r.Get("ParentProcessName")))) {
	case "blackbox.exe", "blackboxw.exe":
		return nil
	}
	user := t.subject(r)
	proc := r.Get("NewProcessName")
	cmd := r.Get("CommandLine")
	e := &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, Action: "elevated_process",
		User: user, Process: proc, Command: cmd}
	shown := cmd
	if shown == "" {
		shown = proc
	}
	// PowerShell run with -EncodedCommand (as remote management tools do)
	// hides the real command in base64: show it, and check it for tampering.
	decoded := decodePowerShell(cmd)
	if decoded != "" {
		shown = proc + " (encoded command): " + decoded
	}
	e.Summary = fmt.Sprintf("%s ran with administrator rights: %s", user, shown)
	script := ""
	if decoded == "" {
		script = psScript(proc, cmd)
	}
	if script != "" {
		e.Summary = fmt.Sprintf("%s ran the script %s with administrator rights (PowerShell).", user, script)
	}
	// Quotes removed: PowerShell records "C:\...\wevtutil.exe" cl Security.
	lc := strings.Join(strings.Fields(strings.ReplaceAll(strings.ToLower(cmd+" "+decoded), `"`, "")), " ")
	if n := hiddenPowerShell(proc, cmd, decoded); n >= 2 {
		e.Severity, e.Action = event.SevMedium, "hidden_powershell"
		e.Summary = fmt.Sprintf("%s ran PowerShell hidden from view and around the script policy: %s", user, shown)
		if script != "" {
			e.Summary = fmt.Sprintf("%s ran the script %s hidden from view and around the script policy: %s", user, script, shown)
		}
		e.AddDetail("Why flagged", "A hidden window, bypassing the execution policy, no prompts and an encoded command are how scripts are run unseen; this run used "+fmt.Sprint(n)+" of them together.")
	}
	for _, frag := range auditTamper {
		if strings.Contains(lc, frag) {
			e.Severity = event.SevHigh
			e.Action = "audit_tamper_command"
			e.Summary = fmt.Sprintf("%s ran a command that can clear logs or weaken auditing: %s", user, shown)
			break
		}
	}
	if action, sev, what, ok := event.BlackboxChange(cmd + " " + decoded); ok && e.Action != "audit_tamper_command" {
		e.Action, e.Severity, e.Category = action, sev, event.CatIntegrity
		e.Summary = fmt.Sprintf("%s %s: %s", user, what, shown)
	}
	e.AddDetail("Program", proc)
	e.AddDetail("Command line", cmd)
	e.AddDetail("Script", script)
	e.AddDetail("PowerShell command (decoded)", decoded)
	e.AddDetail("Started by", r.Get("ParentProcessName"))
	e.AddDetail("Elevation", expandTokens(elev))
	if cmd == "" {
		e.AddDetail("Note", "Command-line auditing is off, so only the program name is known.")
	}
	return e
}

func (t *Translator) serviceInstalled(r *Raw, name, path, account, by string) *event.Event {
	e := &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "service_installed",
		User: by, Target: name, Process: path, Priority: 1,
		// 7045 names the service by its display name and 4697 by its
		// service name: the program path is what they share.
		DedupeKey: "svc|" + strings.ToLower(strings.Trim(strings.TrimSpace(path), `"`))}
	e.Summary = fmt.Sprintf("A new service was installed: %s (%s)", name, path)
	if by != "" {
		e.Summary += " by " + by
	}
	e.Summary += "."
	e.AddDetail("Service name", name)
	e.AddDetail("Program", path)
	e.AddDetail("Runs as", account)
	return e
}

func (t *Translator) scheduledTask(r *Raw) *event.Event {
	task := r.Get("TaskName")
	if blackboxTask(task) {
		return t.blackboxTask(r, task)
	}
	if t.ignoredAccount(r, "Subject") && r.EventID != 4698 {
		return nil // Windows updates its own tasks constantly
	}
	user := t.subject(r)
	verbs := map[int]string{4698: "created", 4699: "deleted", 4700: "enabled", 4701: "disabled", 4702: "updated"}
	sev := event.SevLow
	if r.EventID == 4698 {
		sev = event.SevMedium
	}
	e := &event.Event{Category: event.CatOther, Severity: sev, Action: "scheduled_task_" + verbs[r.EventID],
		User: user, Target: task,
		Summary: fmt.Sprintf("Scheduled task %s was %s by %s.", task, verbs[r.EventID], orUnknown(user))}
	e.AddDetail("Task", task)
	if cmd := taskCommand(r.Get("TaskContent")); cmd != "" {
		e.AddDetail("Runs", cmd)
	}
	return e
}

// taskCommand pulls <Command> and <Arguments> out of a task definition.
// blackboxTask reports Blackbox's own scheduled tasks.
func blackboxTask(name string) bool {
	n := strings.ToLower(strings.TrimPrefix(name, `\`))
	return n == "blackbox audit collection" || n == "blackbox status"
}

// blackboxTask is a change to Blackbox's own scheduled task (A5): deleted
// or disabled stops collection. Created or updated is an install or
// upgrade.
func (t *Translator) blackboxTask(r *Raw, task string) *event.Event {
	user := t.subject(r)
	e := &event.Event{Category: event.CatIntegrity, User: user, Target: task}
	switch r.EventID {
	case 4699, 4701:
		e.Action, e.Severity = "blackbox_stopped", event.SevHigh
		verb := map[int]string{4699: "deleted", 4701: "disabled"}[r.EventID]
		e.Summary = fmt.Sprintf("Blackbox's scheduled task %s was %s by %s — events are no longer collected.", task, verb, orUnknown(user))
		if strings.EqualFold(strings.TrimPrefix(task, `\`), "Blackbox Status") {
			e.Severity = event.SevMedium
			e.Summary = fmt.Sprintf("Blackbox's status icon task was %s by %s.", verb, orUnknown(user))
		}
	case 4700:
		e.Action, e.Severity = "blackbox_task_changed", event.SevLow
		e.Summary = fmt.Sprintf("Blackbox's scheduled task %s was enabled by %s.", task, orUnknown(user))
	default:
		e.Action, e.Severity = "blackbox_task_changed", event.SevMedium
		verb := map[int]string{4698: "created", 4702: "updated"}[r.EventID]
		e.Summary = fmt.Sprintf("Blackbox's scheduled task %s was %s by %s (an install, upgrade or settings change).", task, verb, orUnknown(user))
		e.DedupeKey = "bbtask|" + strings.ToLower(task)
	}
	e.AddDetail("Task", task)
	if cmd := taskCommand(r.Get("TaskContent")); cmd != "" {
		e.AddDetail("Runs", cmd)
	}
	return e
}

func taskCommand(xmlText string) string {
	get := func(tag string) string {
		i := strings.Index(xmlText, "<"+tag+">")
		j := strings.Index(xmlText, "</"+tag+">")
		if i < 0 || j < i {
			return ""
		}
		return strings.TrimSpace(xmlText[i+len(tag)+2 : j])
	}
	return strings.TrimSpace(get("Command") + " " + get("Arguments"))
}

func (t *Translator) auditPolicyChanged(r *Raw) *event.Event {
	user := t.subject(r)
	sub := AuditSubcategories[strings.ToUpper(r.Get("SubcategoryGuid"))]
	if sub == "" {
		sub = expandTokens(r.Get("SubcategoryId"))
	}
	changes := expandTokens(r.Get("AuditPolicyChanges"))
	sev := event.SevHigh
	by := user
	// Group Policy applies audit policy as SYSTEM, so a change by SYSTEM
	// that turns auditing on is routine. One that turns it off stays
	// High: anyone running auditpol as SYSTEM looks the same.
	if t.ignoredAccount(r, "Subject") && !strings.Contains(strings.ToLower(changes), "removed") {
		sev = event.SevMedium
		by = "the system (usually Group Policy)"
	} else if t.ignoredAccount(r, "Subject") {
		by = "the system (Group Policy, or someone running a command as SYSTEM)"
	}
	e := &event.Event{Category: event.CatIntegrity, Severity: sev, Action: "audit_policy_changed",
		User: user, Target: sub,
		Summary: fmt.Sprintf("Audit policy for \"%s\" was changed by %s: %s.", sub, by, strings.ToLower(changes))}
	e.AddDetail("Category", expandTokens(r.Get("CategoryId")))
	e.AddDetail("Subcategory", sub)
	e.AddDetail("Change", changes)
	return e
}

func (t *Translator) timeChanged(r *Raw) *event.Event {
	prev, err1 := time.Parse(time.RFC3339Nano, r.Get("PreviousTime"))
	next, err2 := time.Parse(time.RFC3339Nano, r.Get("NewTime"))
	svc := t.ignoredAccount(r, "Subject")
	var delta time.Duration
	if err1 == nil && err2 == nil {
		delta = next.Sub(prev)
		// Routine clock sync by the Windows Time service; and a change of
		// under a second, which each Set-Date also logs (TIME1).
		if (svc && delta.Abs() < 5*time.Minute) || delta.Abs() < time.Second {
			return nil
		}
	}
	user := t.subject(r)
	e := &event.Event{Category: event.CatIntegrity, Severity: event.SevMedium, Action: "time_changed",
		User: user, Process: r.Get("ProcessName")}
	if err1 == nil && err2 == nil {
		e.Summary = fmt.Sprintf("System time was changed by %s, moving the clock %s %s.", orUnknown(user), roundDur(delta.Abs()), map[bool]string{true: "forward", false: "back"}[delta >= 0])
		if delta <= -5*time.Minute {
			// Moving the clock back is a way to keep events out of reports
			// (T3), whoever does it; Blackbox's reports follow collection
			// order, so none is lost, but the times around it are wrong.
			e.Severity = event.SevHigh
			e.AddDetail("Why it matters", "Event times before and after this change don't line up; check the time source. Every collected event is still reported.")
		}
	} else {
		e.Summary = fmt.Sprintf("System time was changed by %s.", orUnknown(user))
	}
	e.AddDetail("Previous time", r.Get("PreviousTime"))
	e.AddDetail("New time", r.Get("NewTime"))
	e.AddDetail("Process", r.Get("ProcessName"))
	return e
}
