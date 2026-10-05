package event

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Blackbox watching itself (AU-9): a command that changes what Blackbox
// reports or keeps, stops its schedule, or removes it.

var (
	bbProgram  = `(?:^|[\s/\\"'])blackboxw?(?:\.exe)?["']?`
	bbConfig   = regexp.MustCompile(`(?i)` + bbProgram + `\s+config\s+set\s+(\S+)`)
	bbUninst   = regexp.MustCompile(`(?i)` + bbProgram + `\s+uninstall\b|(?:^|[\s/])uninstall\.sh\b`)
	bbStop     = regexp.MustCompile(`(?i)\bsystemctl\s+(?:\S+\s+)*(stop|disable|mask|kill)\s+(?:\S+\s+)*blackbox(?:\.timer|\.service)?\b`)
	bbTaskOff  = regexp.MustCompile(`(?i)\bschtasks(?:\.exe)?\s+.*(?:/delete|/disable|/end)\b.*\bblackbox|\bschtasks(?:\.exe)?\s+.*\bblackbox\b.*(?:/delete|/disable|/end)\b|(?:disable|unregister|stop)-scheduledtask\b.*\bblackbox`)
	bbRemoveFS = regexp.MustCompile(`(?i)\b(?:rm|del|erase|remove-item|rmdir|rd)\b.*(?:/etc/blackbox|/var/lib/blackbox|programdata[\\/]blackbox|/usr/local/bin/blackbox)`)
)

// sensitiveSettings change what the report shows or how long evidence is
// kept.
var sensitiveSettings = map[string]bool{"exclude_users": true, "exclude_processes": true, "retention_days": true,
	"report_dir": true, "send_to": true, "inbox": true}

// BlackboxChange recognises a command that changes Blackbox itself. ok is
// false for any other command.
func BlackboxChange(cmd string) (action string, sev Severity, what string, ok bool) {
	switch {
	case bbUninst.MatchString(cmd):
		return "blackbox_uninstalled", SevHigh, "removed Blackbox", true
	case bbStop.MatchString(cmd), bbTaskOff.MatchString(cmd):
		return "blackbox_stopped", SevHigh, "stopped or disabled Blackbox's scheduled collection", true
	case bbRemoveFS.MatchString(cmd):
		return "blackbox_files_removed", SevHigh, "deleted Blackbox's files", true
	}
	if m := bbConfig.FindStringSubmatch(cmd); m != nil {
		key := strings.ToLower(strings.Trim(m[1], `"'`))
		if sensitiveSettings[key] {
			return "blackbox_config_changed", SevHigh, "changed Blackbox's " + key + " setting (what it reports or keeps)", true
		}
		return "blackbox_config_changed", SevMedium, "changed Blackbox's " + key + " setting", true
	}
	return "", "", "", false
}

// ConfigSetKey is the setting a "blackbox config set" command line names,
// or "" for any other command.
func ConfigSetKey(cmd string) string {
	if m := bbConfig.FindStringSubmatch(cmd); m != nil {
		return strings.ToLower(strings.Trim(m[1], `"'`))
	}
	return ""
}

// SelfChange is a change Blackbox made to itself and recorded itself
// (A15): a setting written by config set or setup, or Blackbox installed,
// upgraded or removed. Blackbox writes it to its own spool and to the
// operating system's log (the Windows Application log, source Blackbox;
// syslog/journal ident blackbox), so a copy exists outside its folder.
type SelfChange struct {
	Who     string // the person: SUDO_USER or the login user on Linux, the token user on Windows
	Program string // "blackbox config set", "setup", "blackbox uninstall"
	Setting string // "" for install, upgrade and removal
	Old     string
	New     string
	Version string // the version installed (install and upgrade)
	Kind    string // "setting", "installed", "upgraded", "removed", "resent"
	// For "resent": the batches (New, "214-219") and where to (Old).
}

// selfHigh are the settings whose change can hide events or evidence.
var selfHigh = map[string]bool{"exclude_users": true, "exclude_processes": true, "retention_days": true,
	"send_to": true, "scap_results": true, "report_dir": true, "archive_dir": true, "inbox": true}

// Message is the sentence written to the operating system's log; ParseSelfChange reads it back.
func (c SelfChange) Message() string {
	who := c.Who
	if who == "" {
		who = "unknown"
	}
	switch c.Kind {
	case "installed":
		return fmt.Sprintf("Blackbox %s was installed by %s (%s).", c.Version, who, c.Program)
	case "upgraded":
		return fmt.Sprintf("Blackbox was upgraded from %s to %s by %s (%s).", orUnknownVersion(c.Old), c.Version, who, c.Program)
	case "removed":
		return fmt.Sprintf("Blackbox was removed by %s (%s).", who, c.Program)
	case "resent":
		return fmt.Sprintf("Blackbox batches %s were sent again to %s by %s (%s).", c.New, c.Old, who, c.Program)
	}
	return fmt.Sprintf("Blackbox setting %s changed from %q to %q by %s (%s).", c.Setting, c.Old, c.New, who, c.Program)
}

func orUnknownVersion(v string) string {
	if v == "" {
		return "an earlier version"
	}
	return v
}

var (
	selfSettingRE = regexp.MustCompile(`^Blackbox setting (\S+) changed from ("(?:[^"\\]|\\.)*") to ("(?:[^"\\]|\\.)*") by (.+) \(([^()]+)\)\.$`)
	selfInstallRE = regexp.MustCompile(`^Blackbox (\S+) was installed by (.+) \(([^()]+)\)\.$`)
	selfUpgradeRE = regexp.MustCompile(`^Blackbox was upgraded from (.+) to (\S+) by (.+) \(([^()]+)\)\.$`)
	selfRemoveRE  = regexp.MustCompile(`^Blackbox was removed by (.+) \(([^()]+)\)\.$`)
	selfResendRE  = regexp.MustCompile(`^Blackbox batches (\S+) were sent again to (.+) by (.+) \(([^()]+)\)\.$`)
)

// ParseSelfChange reads a Message back, as found in the operating system's log.
func ParseSelfChange(msg string) (SelfChange, bool) {
	msg = strings.TrimSpace(msg)
	if m := selfSettingRE.FindStringSubmatch(msg); m != nil {
		old, err1 := strconv.Unquote(m[2])
		nw, err2 := strconv.Unquote(m[3])
		if err1 != nil || err2 != nil {
			return SelfChange{}, false
		}
		return SelfChange{Kind: "setting", Setting: m[1], Old: old, New: nw, Who: m[4], Program: m[5]}, true
	}
	if m := selfInstallRE.FindStringSubmatch(msg); m != nil {
		return SelfChange{Kind: "installed", Version: m[1], Who: m[2], Program: m[3]}, true
	}
	if m := selfUpgradeRE.FindStringSubmatch(msg); m != nil {
		old := m[1]
		if old == "an earlier version" {
			old = ""
		}
		return SelfChange{Kind: "upgraded", Old: old, Version: m[2], Who: m[3], Program: m[4]}, true
	}
	if m := selfRemoveRE.FindStringSubmatch(msg); m != nil {
		return SelfChange{Kind: "removed", Who: m[1], Program: m[2]}, true
	}
	if m := selfResendRE.FindStringSubmatch(msg); m != nil {
		return SelfChange{Kind: "resent", New: m[1], Old: m[2], Who: m[3], Program: m[4]}, true
	}
	return SelfChange{}, false
}

// SelfFlag marks, in Fields, an event Blackbox recorded about itself.
const SelfFlag = "blackbox_self"

// Event is the report row for the change (Time, Host and OS are the
// caller's). The copy in the operating system's log gives the same
// DedupeKey, so the two are one row.
func (c SelfChange) Event() *Event {
	who := c.Who
	if who == "" {
		who = "Someone"
	}
	e := &Event{Category: CatIntegrity, Source: "Blackbox", RecordType: "Blackbox", User: c.Who, Target: c.Setting,
		Fields: map[string]string{SelfFlag: c.Kind, "setting": c.Setting, "old": c.Old, "new": c.New, "program": c.Program}}
	switch c.Kind {
	case "installed":
		e.Action, e.Severity = "blackbox_installed", SevLow
		e.Summary = fmt.Sprintf("%s installed Blackbox %s.", who, c.Version)
	case "upgraded":
		e.Action, e.Severity = "blackbox_upgraded", SevLow
		e.Summary = fmt.Sprintf("%s upgraded Blackbox from %s to %s.", who, orUnknownVersion(c.Old), c.Version)
	case "removed":
		e.Action, e.Severity = "blackbox_uninstalled", SevHigh
		e.Summary = fmt.Sprintf("%s removed Blackbox (%s).", who, c.Program)
	case "resent":
		// L11: recorded like a setting change. Resending only fills a gap
		// on the collector, but it is a person moving audit data.
		e.Action, e.Severity = "blackbox_batches_resent", SevMedium
		e.Summary = fmt.Sprintf("%s sent Blackbox batches %s to the collector again (%s).", who, c.New, c.Old)
		e.Target = c.Old
		e.AddDetail("Batches", c.New)
		e.AddDetail("Sent to", c.Old)
	default:
		e.Action, e.Severity = "blackbox_config_changed", SevMedium
		if selfHigh[c.Setting] {
			e.Severity = SevHigh
		}
		e.Summary = fmt.Sprintf("%s changed Blackbox's %s setting from %s to %s (%s).", who, c.Setting, shown(c.Old), shown(c.New), c.Program)
		e.AddDetail("Setting", c.Setting)
		e.AddDetail("Before", shown(c.Old))
		e.AddDetail("After", shown(c.New))
	}
	if c.Version != "" {
		e.AddDetail("Version", c.Version)
	}
	e.AddDetail("Changed with", c.Program)
	e.AddDetail("Recorded by", "Blackbox itself (also in the system log)")
	e.DedupeKey = "bbself|" + c.Kind + "|" + c.Setting + "|" + c.New + "|" + c.Version + "|" + strings.ToLower(c.Who)
	return e
}

func shown(v string) string {
	if v == "" {
		return "(empty)"
	}
	return v
}
