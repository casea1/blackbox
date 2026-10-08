// Package inventory reads what a computer is (ISSO request): its make,
// model and serial number, its drives and their serial numbers, and its
// user accounts. Blackbox only reads this; it changes nothing. An account
// is kept with the last four digits of its SID (or its Linux UID), never
// the whole SID or anything about its password.
package inventory

import (
	"strings"
	"time"
)

// Inventory is one computer's hardware and accounts when it was read.
type Inventory struct {
	Manufacturer string    `json:"manufacturer,omitempty"`
	Model        string    `json:"model,omitempty"`
	Serial       string    `json:"serial,omitempty"` // the system's serial number (BIOS / DMI)
	BIOS         string    `json:"bios,omitempty"`
	OS           string    `json:"os,omitempty"`
	CPU          string    `json:"cpu,omitempty"`
	Memory       uint64    `json:"memory_bytes,omitempty"`
	Domain       string    `json:"domain,omitempty"`
	Drives       []Drive   `json:"drives,omitempty"`
	Accounts     []Account `json:"accounts,omitempty"`
	Notes        []string  `json:"notes,omitempty"` // what could not be read, and why
	// Server is set for a Linux computer with no desktop installed (no
	// graphical session or display manager): grouped with the servers
	// (UX10).
	Server bool `json:"server,omitempty"`
}

// Drive is one physical disk.
type Drive struct {
	Model     string `json:"model,omitempty"`
	Serial    string `json:"serial,omitempty"`
	Size      uint64 `json:"size_bytes,omitempty"`
	Interface string `json:"interface,omitempty"` // NVMe, SATA, USB, VirtIO, …
	Media     string `json:"media,omitempty"`     // SSD, HDD, Removable, …
}

// Account is one user account: a local account, or (Windows) an account
// with a profile on this computer.
type Account struct {
	Name      string    `json:"name"`
	ID        string    `json:"id,omitempty"` // "…1001": the last four digits of the SID; "uid 1001" on Linux
	Enabled   bool      `json:"enabled"`
	Admin     bool      `json:"admin,omitempty"`
	Kind      string    `json:"kind,omitempty"` // Local, Domain (profile), System
	LastLogon time.Time `json:"last_logon,omitzero"`
	Note      string    `json:"note,omitempty"` // e.g. "password locked" (Linux: key or sudo logons only)
}

// SIDTail is the last four digits of a SID's last part (its RID): "…1001"
// for S-1-5-21-…-1001, "…500" for the built-in Administrator.
func SIDTail(sid string) string {
	sid = strings.TrimSpace(sid)
	i := strings.LastIndex(sid, "-")
	if i < 0 || i == len(sid)-1 {
		return ""
	}
	rid := sid[i+1:]
	if len(rid) > 4 {
		rid = rid[len(rid)-4:]
	}
	return "…" + rid
}

// Clean trims what firmware leaves in its strings and drops the
// placeholders some vendors use for "no value".
func Clean(s string) string {
	s = strings.TrimSpace(strings.Trim(s, "\x00"))
	if strings.HasPrefix(s, "0x") {
		return "" // a PCI vendor ID (VirtIO disks), not a name
	}
	switch strings.ToLower(s) {
	case "", "to be filled by o.e.m.", "default string", "system serial number", "not specified", "none", "0", "n/a", "system product name", "system manufacturer":
		return ""
	}
	return s
}
