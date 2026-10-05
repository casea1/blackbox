package check

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ClamAV on Linux: how old its virus definitions are, and whether its
// scanner service is running, checked like Microsoft Defender on Windows.
// Read with `clamscan --version` (or clamdscan) and systemctl; reported,
// never changed.

// ClamAVMaxAge is how old the definitions may be (as for Defender).
const ClamAVMaxAge = DefenderMaxAge

// "ClamAV 1.0.7/27412/Thu Sep 26 08:23:12 2026": engine, daily database
// version, and when that database was built.
var clamVersionRE = regexp.MustCompile(`ClamAV ([0-9][^/\s]*)(?:/(\d+)/(.+))?`)

// EvaluateClamAV reads `clamscan --version` output. installed is false
// when neither clamscan nor clamdscan is on the system; service is the
// `systemctl is-active` answer for its scanner service ("" if none).
func EvaluateClamAV(version string, installed bool, service string, now time.Time) []Result {
	defs := Result{Area: "Antivirus", Item: "ClamAV definitions", Want: "Built within the last 30 days",
		Affects: "Antivirus definitions",
		Fix: "Copy the latest main.cvd, daily.cvd and bytecode.cvd from your update source into /var/lib/clamav " +
			"(owned by clamav), then run: systemctl restart clamav-daemon (Alma: clamd@scan). On a connected mirror, freshclam downloads them."}
	if !installed {
		defs.Status, defs.Have, defs.Want, defs.Fix = Info, "ClamAV is not installed", "ClamAV, or another antivirus (not checked)", ""
		return []Result{defs}
	}
	m := clamVersionRE.FindStringSubmatch(version)
	switch {
	case m == nil:
		defs.Status, defs.Have = Warn, "Could not read ClamAV's version"
		return []Result{defs, clamService(service)}
	case m[2] == "":
		defs.Status, defs.Have = Fail, "No definitions loaded · engine "+m[1]
		return []Result{defs, clamService(service)}
	}
	built, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.TrimSpace(m[3]), time.Local)
	defs.Have = "daily " + m[2]
	if err != nil {
		defs.Status = Warn
		defs.Have += " · build date unknown"
	} else {
		age := now.Sub(built)
		defs.Dated = built
		defs.Have += fmt.Sprintf(" · built on %s (%s)", built.Format("2 Jan 2006 15:04"), ageText(age))
		defs.Status = Pass
		if age > ClamAVMaxAge {
			defs.Status = Fail
		}
	}
	if defs.Status == Pass {
		defs.Fix = ""
	}
	defs.Have += " · engine " + m[1]
	return []Result{defs, clamService(service)}
}

// Scanner service states besides systemctl's own (I3).
const (
	ClamInContainer = "container" // clamd runs in a container (Docker, Podman, Kubernetes)
	ClamMasked      = "masked"    // the host's clamd unit is masked: turned off on purpose
)

// clamService is whether the scanner service (clamd) is running. Without
// it ClamAV only scans when asked, so it is a warning, not a gap.
func clamService(state string) Result {
	r := Result{Area: "Antivirus", Item: "ClamAV scanner service", Want: "Running (clamd)"}
	switch state {
	case "active":
		r.Status, r.Have = Pass, "Running"
	case ClamInContainer:
		r.Status, r.Have = Pass, "Running in a container"
	case ClamMasked:
		// Masked on purpose, usually because a scanner runs in a container
		// or another product is used: enabling it is not the fix (I3).
		r.Status, r.Have = Info, "The host's clamd service is masked (turned off on purpose); no clamd seen running"
	case "":
		r.Status, r.Have = Info, "No clamd service installed (scans only when run)"
	default:
		r.Status, r.Have = Warn, "Not running ("+state+")"
		r.Fix = "systemctl enable --now clamav-daemon (Alma: clamd@scan)"
	}
	return r
}

// EvaluateClamAVFIPS notes ClamAV's limits on a FIPS host (I3): its
// engine is not FIPS 140 validated, and some of its signatures are MD5 and
// SHA-1 hashes. It is information for the ISSM, not a gap.
func EvaluateClamAVFIPS(fips bool) []Result {
	if !fips {
		return nil
	}
	return []Result{{Area: "Antivirus", Item: "ClamAV on a FIPS host", Status: Info, Want: "Known to the ISSM",
		Have: "FIPS mode is on. ClamAV's engine is not FIPS 140 validated, and some signatures are MD5 or SHA-1 hashes; " +
			"check that this is acceptable on this system, or that a validated product covers it"}}
}

// inContainerCgroup reports whether a /proc/PID/cgroup belongs to a
// container runtime.
func inContainerCgroup(cg string) bool {
	for _, w := range []string{"docker", "libpod", "containerd", "kubepods", "crio-", "machine.slice"} {
		if strings.Contains(cg, w) {
			return true
		}
	}
	return false
}
