package check

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Microsoft Defender Antivirus: how old its security intelligence
// (definitions) is, and whether real-time protection is on. Read with
// Get-MpComputerStatus; reported, never changed.

// DefenderQuery is the PowerShell that reads Defender's status as JSON.
const DefenderQuery = "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled," +
	"AntivirusSignatureVersion,AntivirusSignatureLastUpdated,AMProductVersion | ConvertTo-Json -Compress"

// DefenderMaxAge is how old the definitions may be.
const DefenderMaxAge = 30 * 24 * time.Hour

const gpDefender = gpAdmin + " > Windows Components > Microsoft Defender Antivirus"

type defenderStatus struct {
	AMServiceEnabled              bool
	AntivirusEnabled              bool
	RealTimeProtectionEnabled     bool
	AntivirusSignatureVersion     string
	AntivirusSignatureLastUpdated psDate
	AMProductVersion              string
}

// psDate reads a date as Windows PowerShell 5.1 writes it in JSON
// ("/Date(1727712000000)/") or as an ISO time (PowerShell 7).
type psDate struct{ time.Time }

func (d *psDate) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return nil // null or another shape: leave it unset
	}
	if strings.HasPrefix(s, "/Date(") {
		n := strings.TrimSuffix(strings.TrimPrefix(s, "/Date("), ")/")
		if i := strings.IndexAny(n, "+-"); i > 0 {
			n = n[:i]
		}
		ms, err := strconv.ParseInt(n, 10, 64)
		if err == nil {
			d.Time = time.UnixMilli(ms).UTC()
		}
		return nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		d.Time = t
	}
	return nil
}

// EvaluateDefender reads Get-MpComputerStatus output (see DefenderQuery).
func EvaluateDefender(jsonText string, err error, now time.Time) []Result {
	defs := Result{Area: "Antivirus", Item: "Defender security intelligence", Want: "Version created within the last 30 days",
		Affects: "Antivirus definitions", Fix: "Import the latest security intelligence update (mpam-fe.exe) from your update source onto this system. " +
			"Group Policy: " + gpDefender + " > Security Intelligence Updates > Define file shares for downloading security intelligence updates"}
	if err != nil || strings.TrimSpace(jsonText) == "" {
		defs.Status, defs.Have, defs.Fix = Warn, "Could not read Defender's status", ""
		if err != nil {
			defs.Have += ": " + err.Error()
		}
		return []Result{defs}
	}
	var s defenderStatus
	if e := json.Unmarshal([]byte(strings.TrimSpace(jsonText)), &s); e != nil {
		defs.Status, defs.Have, defs.Fix = Warn, "Could not read Defender's status: "+e.Error(), ""
		return []Result{defs}
	}
	rt := Result{Area: "Antivirus", Item: "Defender real-time protection", Want: "On", Have: "On", Status: Pass}
	if !s.AMServiceEnabled || !s.AntivirusEnabled || !s.RealTimeProtectionEnabled {
		rt.Status, rt.Have = Fail, "Off"
		if !s.AMServiceEnabled || !s.AntivirusEnabled {
			rt.Have = "Defender Antivirus is off"
		}
		rt.Fix = "Group Policy: " + gpDefender + " > Real-time Protection > Turn off real-time protection: Disabled (or Not Configured); and " +
			gpDefender + " > Turn off Microsoft Defender Antivirus: Disabled (or Not Configured)"
	}
	created := s.AntivirusSignatureLastUpdated.Time
	defs.Have = orUnknown(s.AntivirusSignatureVersion)
	switch {
	case created.IsZero():
		defs.Status = Warn
		defs.Have += " · creation date unknown"
	default:
		age := now.Sub(created)
		defs.Dated = created
		defs.Have += fmt.Sprintf(" · version created on %s (%s)", created.Local().Format("2 Jan 2006 15:04"), ageText(age))
		defs.Status = Pass
		if age > DefenderMaxAge {
			defs.Status = Fail
		}
	}
	if defs.Status == Pass {
		defs.Fix = ""
	}
	if s.AMProductVersion != "" {
		defs.Have += " · engine " + s.AMProductVersion
	}
	return []Result{defs, rt}
}

func orUnknown(s string) string {
	if s == "" {
		return "Version unknown"
	}
	return s
}

func ageText(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case d < 0:
		return "in the future: check this system's clock"
	case days == 0:
		return "today"
	case days == 1:
		return "1 day old"
	}
	return fmt.Sprintf("%d days old", days)
}
