//go:build linux

package check

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Supported reports whether the live check works on this OS.
const Supported = true

// Run checks the local Linux system.
func Run() []Result {
	var out []Result
	svc := Result{Area: "Audit service", Item: "auditd running", Want: "active",
		Affects: "Logons, sudo, account changes and audit integrity (without it, only auth.log is available)"}
	b, _ := exec.Command("systemctl", "is-active", "auditd").Output()
	svc.Have = strings.TrimSpace(string(b))
	if svc.Have == "active" {
		svc.Status = Pass
	} else {
		svc.Status = Fail
		svc.Fix = "install auditd (apt install auditd, or dnf install audit) and run systemctl enable --now auditd"
		if svc.Have == "" {
			svc.Have = "not installed"
		}
	}
	out = append(out, svc)
	if svc.Status == Pass {
		rules, rerr := exec.Command("auditctl", "-l").Output()
		status, _ := exec.Command("auditctl", "-s").Output()
		if rerr != nil {
			out = append(out, Result{Area: "Audit rules", Item: "auditctl -l", Status: Error,
				Have: "could not read the loaded rules (run as root)", Want: "readable"})
		} else {
			out = append(out, EvaluateAuditRules(string(rules), string(status))...)
		}
		if conf, err := os.ReadFile("/etc/audit/auditd.conf"); err == nil {
			c := ParseAuditdConf(string(conf))
			out = append(out, EvaluateAuditdConf(c)...)
			out = append(out, EvaluateAuditdActions(c)...)
		}
		f, ferr := os.Stat("/var/log/audit/audit.log")
		d, derr := os.Stat("/var/log/audit")
		var fm, dm os.FileMode
		if ferr == nil && derr == nil {
			fm, dm = f.Mode(), d.Mode()
		}
		out = append(out, EvaluateAuditLogPerms(fm, dm, ferr, derr))
		var starts, logins int
		a, serr := os.Open("/var/log/audit/audit.log")
		if serr == nil {
			starts, logins, serr = SSHAuditCounts(a)
			a.Close()
		}
		if r, ok := EvaluateSSHLogons(exists("/usr/sbin/sshd"), starts, logins, serr); ok {
			out = append(out, r)
		}
	}
	if cl, err := os.ReadFile("/proc/cmdline"); err == nil {
		grub, _ := os.ReadFile("/etc/default/grub")
		if more, _ := filepath.Glob("/etc/default/grub.d/*.cfg"); len(more) > 0 {
			for _, m := range more {
				if b, err := os.ReadFile(m); err == nil {
					grub = append(grub, '\n')
					grub = append(grub, b...)
				}
			}
		}
		out = append(out, EvaluateBoot(string(cl), string(grub))...)
	}
	active := map[string]string{}
	for _, s := range []string{"chronyd", "chrony", "systemd-timesyncd", "ntpd", "ntp"} {
		b, _ := exec.Command("systemctl", "is-active", s).Output()
		active[s] = strings.TrimSpace(string(b))
	}
	out = append(out, EvaluateTimeSync(active))
	sudoV, _ := exec.Command("sudo", "-V").Output()
	out = append(out, EvaluateSudo(string(sudoV)))
	out = append(out, clamAV()...)
	sys := Result{Area: "System log", Item: "Kernel and udisks messages kept", Want: "syslog file or persistent journal",
		Affects: "USB & Removable Media (device details and who mounted them)"}
	switch {
	case exists("/var/log/syslog"):
		sys.Status, sys.Have = Pass, "/var/log/syslog"
	case exists("/var/log/messages"):
		sys.Status, sys.Have = Pass, "/var/log/messages"
	case exists("/var/log/journal"):
		sys.Status, sys.Have = Pass, "persistent systemd journal"
	default:
		sys.Status, sys.Have = Fail, "journal is not persistent (lost at reboot)"
		sys.Fix = "mkdir -p /var/log/journal && systemctl restart systemd-journald"
	}
	out = append(out, sys)
	return out
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// OldRulesFilesPresent lists the earlier versions' rules files still in
// rules.d.
func OldRulesFilesPresent() []string {
	var out []string
	for _, f := range OldRulesFiles {
		if exists(f) {
			out = append(out, f)
		}
	}
	return out
}

func init() {
	// Every supported Linux has merged /usr; check rather than assume (I5).
	if t, err := os.Readlink("/sbin"); err == nil && strings.TrimPrefix(t, "/") == "usr/sbin" {
		MergedUsr = true
	}
}

// MissingRulesLive returns the recommended rules this system does not
// already have loaded, ready to save as RulesFile, and whether the loaded
// rules are locked until reboot (-e 2). Rules from an earlier RulesFile are
// kept, so saving the output again never drops them.
func MissingRulesLive() (text string, locked bool, err error) {
	loaded, err := exec.Command("auditctl", "-l").Output()
	if err != nil {
		return "", false, fmt.Errorf("could not read the loaded audit rules (run as root): %w", err)
	}
	status, _ := exec.Command("auditctl", "-s").Output()
	locked = strings.Contains(string(status), "enabled 2")

	// Rules loaded from our own file (or an earlier version's) count as
	// missing, so they stay in it.
	ours := map[string]bool{}
	var old []string
	for _, f := range append([]string{RulesFile}, OldRulesFiles...) {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if f != RulesFile {
			old = append(old, f)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if r, ok := parseAuditRule(l); ok {
				ours[ruleKey(r)] = true
			}
		}
	}
	var others []string
	for _, l := range strings.Split(string(loaded), "\n") {
		if r, ok := parseAuditRule(l); ok && !ours[ruleKey(r)] {
			others = append(others, l)
		}
	}
	missing := MissingRules(AuditRules, strings.Join(others, "\n"), exists)

	var b strings.Builder
	b.WriteString("## Blackbox: audit rules this system did not already have.\n")
	b.WriteString("## Generated by \"blackbox check --audit-rules --missing\"; rules already loaded\n")
	b.WriteString("## (under any key) were left out. Save as " + RulesFile + " (mode 0600).\n")
	for _, f := range old {
		b.WriteString("## It replaces " + f + " from an earlier Blackbox: remove that file\n## (auditctl stops loading at a duplicate rule).\n")
	}
	for _, l := range missing {
		b.WriteString(l + "\n")
	}
	if !locked {
		b.WriteString("## Lock the rules until reboot (the STIG requires this).\n-e 2\n")
	}
	return b.String(), locked, nil
}

// RulesOnlyInAuditRules returns the rules augenrules would drop if it
// rebuilt /etc/audit/audit.rules now (see NotInRulesD). Blackbox's own
// file is left out, since it is being replaced.
func RulesOnlyInAuditRules() []string {
	b, err := os.ReadFile("/etc/audit/audit.rules")
	if err != nil {
		return nil
	}
	files, _ := filepath.Glob("/etc/audit/rules.d/*.rules")
	var d []string
	for _, f := range files {
		if f == RulesFile || slices.Contains(OldRulesFiles, f) {
			continue
		}
		if c, err := os.ReadFile(f); err == nil {
			d = append(d, string(c))
		}
	}
	return NotInRulesD(string(b), d)
}

// clamAV checks ClamAV's definitions and scanner service, if installed.
func clamAV() []Result {
	var version []byte
	installed := false
	for _, prog := range []string{"clamscan", "clamdscan"} {
		if p, err := exec.LookPath(prog); err == nil {
			installed = true
			if version, err = exec.Command(p, "--version").Output(); err == nil && len(version) > 0 {
				break
			}
		}
	}
	service := ""
	for _, unit := range []string{"clamav-daemon", "clamd@scan", "clamd"} {
		out, _ := exec.Command("systemctl", "is-active", unit).Output()
		state := strings.TrimSpace(string(out))
		if en, _ := exec.Command("systemctl", "is-enabled", unit).Output(); strings.TrimSpace(string(en)) == "masked" {
			state = ClamMasked
		} else if exists, _ := exec.Command("systemctl", "cat", unit).Output(); len(exists) == 0 {
			continue
		}
		service = state
		if state == "active" {
			break
		}
	}
	// A scanner in a container: clamd running outside the host's units (I3).
	if service != "active" && clamdInContainer() {
		service, installed = ClamInContainer, true
	}
	fips := false
	if b, err := os.ReadFile("/proc/sys/crypto/fips_enabled"); err == nil {
		fips = strings.TrimSpace(string(b)) == "1"
	}
	out := EvaluateClamAV(string(version), installed, service, time.Now())
	if installed {
		out = append(out, EvaluateClamAVFIPS(fips)...)
	}
	return out
}

// clamdInContainer reports whether a clamd process runs in a container
// (its control group is Docker's, Podman's, containerd's or Kubernetes').
func clamdInContainer() bool {
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		comm, err := os.ReadFile(filepath.Join(d, "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "clamd" {
			continue
		}
		cg, _ := os.ReadFile(filepath.Join(d, "cgroup"))
		if inContainerCgroup(string(cg)) {
			return true
		}
	}
	return false
}
