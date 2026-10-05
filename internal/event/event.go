// Package event defines the normalized event that every log source is
// translated into. Reports, CSV/JSON exports and (later) Splunk ingestion
// all work from this one shape.
package event

import (
	"strings"
	"time"
)

// Category groups events the way auditors review them.
type Category string

const (
	CatPrivileged  Category = "privileged"
	CatRemovable   Category = "removable_media"
	CatFailedLogon Category = "failed_logon"
	CatAccount     Category = "account_changes"
	CatIntegrity   Category = "audit_integrity"
	CatLogon       Category = "logon_activity"
	CatOther       Category = "other_security"
)

// CategoryInfo describes a report section.
type CategoryInfo struct {
	ID          Category
	Title       string
	Description string
	Controls    []string // NIST SP 800-53 controls the section supports
}

// Categories in report order (auditor priority first).
var Categories = []CategoryInfo{
	{CatPrivileged, "Privileged Activity",
		"Administrator logons, commands run with administrator/root rights (including sudo and su), use of another account's credentials, and changes to sudo rules.",
		[]string{"AC-6(9)", "AU-2", "AU-12"}},
	{CatRemovable, "USB & Removable Media",
		"USB storage and other removable devices connected or disconnected, and files read from or written to removable media.",
		[]string{"MP-7", "AU-2"}},
	{CatFailedLogon, "Failed Logons & Lockouts",
		"Unsuccessful logon attempts with the reason decoded, account lockouts, and repeated-failure patterns.",
		[]string{"AC-7", "AU-2"}},
	{CatAccount, "Account & Group Changes",
		"User accounts created, deleted, enabled, disabled, renamed or reset, and group membership changes.",
		[]string{"AC-2(4)", "AU-2"}},
	{CatIntegrity, "Audit & System Integrity",
		"Logs cleared, auditing stopped or its rules changed, system time changes, and system startup/shutdown.",
		[]string{"AU-5", "AU-8", "AU-9", "AU-2"}},
	{CatOther, "Other Security Events",
		"New services, scheduled tasks and kernel modules, anti-malware detections or protection being turned off, and SELinux/AppArmor denials.",
		[]string{"CM-7", "SI-3", "SI-4"}},
	{CatLogon, "Logon Activity",
		"Successful logons and logoffs by people (service and computer accounts are left out).",
		[]string{"AC-2", "AU-2"}},
}

// Info returns the metadata for a category.
func (c Category) Info() CategoryInfo {
	for _, ci := range Categories {
		if ci.ID == c {
			return ci
		}
	}
	return CategoryInfo{ID: c, Title: string(c)}
}

// Severity ranks how much attention an event needs.
type Severity string

const (
	SevInfo   Severity = "info"
	SevLow    Severity = "low"
	SevMedium Severity = "medium"
	SevHigh   Severity = "high"
)

// Rank orders severities: info=0 … high=3.
func (s Severity) Rank() int {
	switch s {
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

// Detail is one labelled value shown when a report row is expanded.
type Detail struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Event is a single translated, security-relevant event.
type Event struct {
	Time       time.Time `json:"time"`
	Collected  time.Time `json:"collected,omitzero"`
	Host       string    `json:"host"`
	OS         string    `json:"os"`
	Source     string    `json:"source"`                // log/channel name, e.g. "Security"
	EventID    int       `json:"event_id,omitempty"`    // Windows event ID
	RecordID   uint64    `json:"record_id,omitempty"`   // Windows record number or auditd serial
	RecordType string    `json:"record_type,omitempty"` // Linux: auditd record type or syslog program

	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Action   string   `json:"action"`  // stable machine tag, e.g. "logon_failed"
	Summary  string   `json:"summary"` // plain-English sentence

	User     string `json:"user,omitempty"`   // who did it
	Target   string `json:"target,omitempty"` // what it was done to
	SourceIP string `json:"source_ip,omitempty"`
	Process  string `json:"process,omitempty"`
	Command  string `json:"command,omitempty"`
	Outcome  string `json:"outcome,omitempty"` // success | failure

	// Interactive marks a logon by a person at a session (keyboard,
	// graphical console, Remote Desktop or SSH).
	Interactive bool `json:"interactive,omitempty"`

	Details []Detail          `json:"details,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"` // original event data

	// Events with the same DedupeKey on the same host within a short time
	// describe the same thing (e.g. a USB device seen by three different
	// logs). The report keeps the one with the highest Priority.
	DedupeKey string `json:"dedupe_key,omitempty"`
	Priority  int    `json:"priority,omitempty"`

	// Late is set by the report when an event happened before the report
	// period but was collected after the previous report was produced.
	Late bool `json:"late,omitempty"`

	// Unreported is set when the event was read from the spool after the
	// point the last scheduled report had read to: collected since then,
	// whatever the clock said (T3). It is not stored.
	Unreported bool `json:"-"`
}

// AddDetail appends a detail row, skipping empty values.
func (e *Event) AddDetail(label, value string) {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return
	}
	e.Details = append(e.Details, Detail{label, value})
}
