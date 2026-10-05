// How the report turns records into rows: what is left out, what is merged,
// and what one record is re-read as because of another. Build applies them
// in this order:
//
//  0. formerNames: events recorded under a name no collecting computer has
//     (a new server's name before setup renamed it) are shown on the one
//     computer that could have recorded them (W1).
//  1. exclude: exclude_users / exclude_processes leave out routine events only
//     (routine, excludedBy), and Windows' own PowerShell modules are dropped
//     (dropWindowsModules).
//  2. sshAttempts: sshd's password check (USER_AUTH) and its failed logon
//     (USER_LOGIN) for one try are one row, matched by process ID in either
//     order; the name tried comes from the check (U5).
//     unknownNames: a Linux "wrong password" for a name sshd then calls
//     unknown says "the user name does not exist" (U6).
//  3. mergeAdminLogons: an administrator's 4624 and 4672 (one logon ID) are one
//     logon row with the privileges (U3).
//  4. dedupe: records with the same DedupeKey on one computer within
//     dedupeWindow are one row, keeping the highest Priority; two failed
//     logons of the same kind (recordKind) are two attempts, never merged.
//  4b. selfChanges: a "blackbox config set" command line is joined to
//     Blackbox's own record of the change it made (A15); with no record,
//     on a computer whose Blackbox records its changes, the command
//     changed nothing and says so ("not applied").
//  4c. appPackageRules: firewall rules Windows itself registers for its
//     built-in apps and services (by the firewall service, by name or SID,
//     or SYSTEM) are one Info row per computer and day (A13, A13b-d).
//  4d. defenderState: Defender's own bookkeeping in its settings (5007) is
//     one Info row per computer and day (A16).
//  4e. windowsSetup: the out-of-box setup's defaultuser0 and MINWINPC
//     events are one Info "Windows setup" row per computer and day (A17).
//  5. attributeDevices: a USB device is attributed to whoever mounted it, or
//     to the person at the console.
//  6. auditStoppedBy: auditd stopped "by root" (or by no one) right after a
//     person's sudo command that stops it is theirs; with sudo-rs that
//     command is only in the journal (U8b).
//     shutdownStops: auditd stopping in a reboot or shutdown is routine.
//
// Some merging happens earlier, when the logs are read (package linuxlog):
// the login message and root-shell startup scripts folded into one row
// (startup), the name tried in an unknown-user SSH attempt (triedName), the
// person whose systemctl stopped auditd (stoppedBy), and the sshd,
// sshd-session and sshd-auth programs treated as one (program).

package report

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/linuxlog"
	"github.com/casea1/blackbox/internal/store"
	"github.com/casea1/blackbox/internal/winevt"
)

func (r *Report) exclude(in []*event.Event) []*event.Event {
	in = dropWindowsModules(in)
	if len(r.ExcludeUsers) == 0 && len(r.ExcludeProcesses) == 0 {
		return in
	}
	out := in[:0:0]
	for _, e := range in {
		who := r.excludedBy(e)
		if who == "" || !routine(e) {
			out = append(out, e)
			continue
		}
		r.Excluded++
		if r.ExcludedBy == nil {
			r.ExcludedBy, r.ExcludedOn = map[string]int{}, map[string]bool{}
		}
		r.ExcludedBy[who]++
		r.ExcludedOn[e.Host] = true
	}
	return out
}

// excludedText says what the exclusions left out, e.g. "12 routine
// events by svc_backup ×10, scan.exe ×2", or "".
func (r *Report) excludedText() string {
	if r.Excluded == 0 {
		return ""
	}
	by := joinCounts(r.ExcludedBy)
	if len(r.ExcludedBy) == 1 {
		for k := range r.ExcludedBy {
			by = k // one account: its count is the total (U2: not "bbtest ×1")
		}
	}
	return fmt.Sprintf("%s by %s (exclude_users and exclude_processes in the settings)", plural(r.Excluded, "routine event"), by)
}

// routine reports whether an event is everyday activity that an exclusion
// may leave out. Exclusions never hide failed logons (against the
// account), account and group changes (to it), log clears and audit
// changes (by it), or anything of Medium severity or above: excluding an
// account must not hide an attack on it, or by it.
func routine(e *event.Event) bool {
	switch e.Category {
	case event.CatFailedLogon, event.CatAccount, event.CatIntegrity:
		return false
	}
	return e.Severity.Rank() < event.SevMedium.Rank()
}

// excludedBy names the exclude_users or exclude_processes entry an event
// matches, or "". An entry with a domain (CORP\svc_backup) matches that
// account exactly; one without matches the local account of that name,
// not a domain account that happens to share it.
func (r *Report) excludedBy(e *event.Event) string {
	u := strings.ToLower(e.User)
	for _, x := range r.ExcludeUsers {
		lx := strings.ToLower(x)
		if u == lx {
			return x
		}
		if !strings.Contains(lx, `\`) {
			if i := strings.LastIndex(u, `\`); i >= 0 && u[i+1:] == lx && strings.EqualFold(u[:i], shortName(e.Host)) {
				return x
			}
		}
	}
	if e.Process != "" {
		p := strings.ToLower(e.Process)
		base := strings.ToLower(filepath.Base(strings.ReplaceAll(e.Process, `\`, "/")))
		for _, x := range r.ExcludeProcesses {
			if lx := strings.ToLower(x); p == lx || base == lx {
				return x
			}
		}
	}
	return ""
}

// shortName is a host name without its domain.
func shortName(h string) string {
	if i := strings.Index(h, "."); i > 0 {
		return h[:i]
	}
	return h
}

// dedupeWindow is how close in time two events with the same key must be
// to count as one.
func dedupeWindow(key string) time.Duration {
	switch {
	case strings.HasPrefix(key, "authfail|"):
		return 2 * time.Second
	case strings.HasPrefix(key, "lxlogon|"), strings.HasPrefix(key, "lxlogoff|"):
		return 5 * time.Second // one sign-in recorded more than once
	case strings.HasPrefix(key, "4672|"):
		return 24 * time.Hour
	case strings.HasPrefix(key, "rm|"):
		return time.Minute
	case strings.HasPrefix(key, "svc|"), strings.HasPrefix(key, "psblock|"):
		return 10 * time.Minute
	}
	return 5 * time.Minute
}

// dedupe merges events describing the same thing, keeping the most
// informative one (highest Priority). Input must be sorted by time.
func (r *Report) dedupe(in []*event.Event) []*event.Event {
	type slot struct {
		idx   int
		time  time.Time
		kinds map[string]bool // the kinds of record already merged
	}
	last := map[string]*slot{}
	out := make([]*event.Event, 0, len(in))
	for _, e := range in {
		if e.DedupeKey == "" {
			out = append(out, e)
			continue
		}
		k := e.Host + "|" + e.DedupeKey
		kind := recordKind(e)
		s, ok := last[k]
		// A failed logon is often recorded twice (4625 and 4776, or two
		// audit records), so those are merged; but two records of the
		// same kind are two attempts, and password guessing is many
		// attempts in a second.
		if ok && e.Time.Sub(s.time) <= dedupeWindow(e.DedupeKey) && !(strings.HasPrefix(e.DedupeKey, "authfail|") && s.kinds[kind]) {
			r.Duplicates++
			s.kinds[kind] = true
			kept := out[s.idx]
			if e.Priority > kept.Priority {
				out[s.idx], kept, e = e, e, kept
			}
			// One service, recorded under its service name and its
			// display name: show both.
			if strings.HasPrefix(e.DedupeKey, "svc|") && e.Target != "" && !strings.EqualFold(e.Target, kept.Target) {
				kept.AddDetail("Also named", e.Target)
				kept.Summary = strings.Replace(kept.Summary, kept.Target, kept.Target+" ("+e.Target+")", 1)
			}
			continue
		}
		last[k] = &slot{idx: len(out), time: e.Time, kinds: map[string]bool{kind: true}}
		out = append(out, e)
	}
	return out
}

// sshAttempts makes one row of each failed SSH try (U5). sshd records a
// try more than once with the same process ID: PAM's password check
// (USER_AUTH, which names the account but can't tell a wrong password from
// a name that doesn't exist) and sshd's failed logon (USER_LOGIN, which
// says "(invalid user)" for a name that doesn't exist but not which name).
// OpenSSH 10 writes the check, then the logon record about two seconds
// later; for an unknown name it also writes two logon records when the
// connection opens, before the check. Each logon record belongs to the
// latest check by the same process up to 5 seconds before it, or failing
// that the first one up to 5 seconds after it; a check and its logon
// records are one row: the last logon record, with the name from the
// check. Records of different processes are never joined.
func sshAttempts(events []*event.Event) []*event.Event {
	const near = 5 * time.Second
	isSSHD := func(e *event.Event) bool {
		return e.OS == "linux" && e.Action == "logon_failed" && e.Fields["pid"] != "" &&
			strings.HasPrefix(filepath.Base(strings.ReplaceAll(e.Fields["exe"], "\\", "/")), "sshd")
	}
	type try struct {
		check  *event.Event
		logons []*event.Event
	}
	tries := map[*event.Event]*try{}
	var order []*try
	for i, l := range events {
		if l.RecordType != "USER_LOGIN" || !isSSHD(l) {
			continue
		}
		same := func(a *event.Event) bool {
			return a.RecordType == "USER_AUTH" && isSSHD(a) && a.Host == l.Host && a.Fields["pid"] == l.Fields["pid"]
		}
		var check *event.Event
		for j := i - 1; j >= 0 && l.Time.Sub(events[j].Time) <= near; j-- {
			if same(events[j]) {
				check = events[j]
				break
			}
		}
		if check == nil {
			for j := i + 1; j < len(events) && events[j].Time.Sub(l.Time) <= near; j++ {
				if same(events[j]) {
					check = events[j]
					break
				}
			}
		}
		if check == nil {
			continue
		}
		tr := tries[check]
		if tr == nil {
			tr = &try{check: check}
			tries[check] = tr
			order = append(order, tr)
		}
		tr.logons = append(tr.logons, l)
	}
	if len(order) == 0 {
		return events
	}
	drop := map[*event.Event]bool{}
	for _, tr := range order {
		keep := tr.logons[0]
		for _, l := range tr.logons {
			if l.Time.After(keep.Time) {
				keep = l
			}
		}
		unknown := false
		for _, l := range tr.logons {
			unknown = unknown || strings.Contains(l.Summary, "the user name does not exist")
			if l != keep {
				drop[l] = true
			}
		}
		drop[tr.check] = true
		if name := tr.check.User; name != "" && !strings.HasPrefix(name, "(") && name != keep.User {
			if !unknown {
				// The logon record names a real account: keep it.
				name = keep.User
			}
			keep.Summary = strings.Replace(keep.Summary, keep.User, name, 1)
			keep.User, keep.Target = name, name
		}
		if unknown && !strings.Contains(keep.Summary, "the user name does not exist") {
			keep.Summary = keep.Summary[:strings.LastIndex(keep.Summary, "— ")] + "— the user name does not exist."
		}
		// One try: never merged with another try by dedupe.
		keep.DedupeKey = ""
		keep.AddDetail("Process ID", keep.Fields["pid"])
	}
	out := events[:0]
	for _, e := range events {
		if !drop[e] {
			out = append(out, e)
		}
	}
	return out
}

// formerNames files events recorded under a computer's former name under
// its current one (W1). Systems are the computers that collect; an event
// whose computer is not one of them was read from the logs of a computer
// that was since renamed. When exactly one computer of that OS collects
// its own logs here (not delivered by another), it is that one. New
// collections already do this (collect.OnThisComputer); this covers data
// stored before.
func formerNames(events []*event.Event, systems []SystemInfo) {
	if len(systems) == 0 {
		return
	}
	known := map[string]bool{}
	local := map[string][]string{} // OS → local computers
	for _, s := range systems {
		known[strings.ToUpper(s.Name)] = true
		if s.Via == "" {
			local[s.OS] = append(local[s.OS], s.Name)
		}
	}
	for _, e := range events {
		if e.Host == "" || known[strings.ToUpper(e.Host)] || len(local[e.OS]) != 1 {
			continue
		}
		e.AddDetail("Recorded under", "its former name "+e.Host)
		e.Host = local[e.OS][0]
	}
}

// appPackageRule is a firewall rule change Windows made itself (A13): by
// the firewall service (NT SERVICE\MpsSvc, by name or by its SID in a log
// read on another computer) maintaining the rules of app packages and app
// containers, whatever the rule is called; or by SYSTEM, or naming no one,
// to a rule of an app package (its name a package resource "@{…}", its ID
// a package family name) or of the Defender service. A person's change
// names the person.
func appPackageRule(e *event.Event) bool {
	if e.OS != "windows" || !strings.HasPrefix(e.Action, "firewall_rule_") || e.Action == "firewall_rules_cleared" {
		return false
	}
	u := strings.ToLower(e.User)
	sid := e.Fields["ModifyingUser"]
	if strings.HasSuffix(u, `\mpssvc`) || u == "mpssvc" || sid == mpsSvcSID || u == mpsSvcSID {
		return true
	}
	if !(u == "" || u == "system" || strings.HasSuffix(u, `\system`) || u == "s-1-5-18") {
		return false
	}
	id := e.Fields["RuleId"]
	name := strings.TrimSpace(e.Target)
	lo := strings.ToLower(id + " " + name)
	return strings.HasPrefix(name, "@{") || packageFamily.MatchString(id) || strings.Contains(id, "S-1-15-") ||
		strings.Contains(lo, "windefend") || strings.Contains(lo, "windows defender")
}

// mpsSvcSID is NT SERVICE\MpsSvc, the Windows Firewall service.
const mpsSvcSID = "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052"

// packageFamily is a rule ID starting with an app package family name:
// Microsoft.WindowsTerminal_8wekyb3d8bbwe_….
var packageFamily = regexp.MustCompile(`^[A-Za-z0-9.]+_[a-z0-9]{13}`)

// appPackageRules makes the firewall rules Windows registers for its
// built-in app packages one Info count per computer and day (A13): a
// fresh server registers well over a hundred, and a person opening a port
// was lost among them. Changes made by people keep their own rows.
func (r *Report) appPackageRules(events []*event.Event) []*event.Event {
	type group struct {
		row                     *event.Event
		added, changed, deleted int
		names                   []string
	}
	groups := map[string]*group{}
	out := events[:0]
	for _, e := range events {
		if !appPackageRule(e) {
			out = append(out, e)
			continue
		}
		day := e.Time.In(r.Location).Format("2006-01-02")
		k := strings.ToUpper(e.Host) + "|" + day
		g := groups[k]
		if g == nil {
			g = &group{row: &event.Event{Time: e.Time, Collected: e.Collected, Host: e.Host, OS: e.OS, Source: e.Source,
				Category: event.CatIntegrity, Severity: event.SevInfo, Action: "firewall_app_rules", User: e.User,
				Fields: map[string]string{}}}
			groups[k] = g
			out = append(out, g.row)
		}
		switch e.Action {
		case "firewall_rule_added":
			g.added++
		case "firewall_rule_deleted":
			g.deleted++
		default:
			g.changed++
		}
		if len(g.names) < 20 && !slices.Contains(g.names, e.Target) {
			g.names = append(g.names, e.Target)
		}
	}
	for _, g := range groups {
		var parts []string
		for _, p := range []struct {
			n    int
			verb string
		}{{g.added, "added"}, {g.changed, "changed"}, {g.deleted, "deleted"}} {
			if p.n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", p.n, p.verb))
			}
		}
		g.row.Summary = fmt.Sprintf("Windows updated the firewall rules of its built-in apps and services: %s (by the Windows Firewall service or SYSTEM).",
			strings.Join(parts, ", "))
		g.row.Target = fmt.Sprintf("%d app package rules", g.added+g.changed+g.deleted)
		g.row.AddDetail("Rules (first 20)", strings.Join(g.names, "; "))
		g.row.AddDetail("Why one row", "Windows registers these for the apps that come with it; changes made by people are listed separately.")
	}
	return out
}

// windowsSetupEvent is part of Windows setup (OOBE) on a new computer
// (A17): its image was built under the name MINWINPC, and setup works as
// its temporary account defaultuser0, which it creates, adds to
// Administrators and deletes. Only what Windows itself (SYSTEM, or no one
// named) does to defaultuser0 counts: a person creating an account of that
// name keeps its rows.
func windowsSetupEvent(e *event.Event) bool {
	if e.OS != "windows" {
		return false
	}
	for _, v := range []string{e.User, e.Target, e.Fields["SubjectDomainName"], e.Fields["TargetDomainName"]} {
		if strings.EqualFold(strings.SplitN(v, `\`, 2)[0], "MINWINPC") || strings.EqualFold(v, "MINWINPC") {
			return true
		}
	}
	if strings.Contains(e.Summary, "MINWINPC") {
		return true
	}
	name := func(v string) string {
		if i := strings.LastIndex(v, `\`); i >= 0 {
			v = v[i+1:]
		}
		return strings.ToLower(v)
	}
	if name(e.Target) != "defaultuser0" && name(e.User) != "defaultuser0" {
		return false
	}
	u := name(e.User)
	return u == "" || u == "system" || u == "defaultuser0" || e.User == "S-1-5-18"
}

// windowsSetup makes Windows setup's own account and image events one Info
// row per computer and day (A17), instead of a High "SYSTEM added
// defaultuser0 to Administrators" and Medium rows for MINWINPC.
func (r *Report) windowsSetup(events []*event.Event) []*event.Event {
	groups := map[string]*event.Event{}
	counts := map[*event.Event]int{}
	out := events[:0]
	for _, e := range events {
		if !windowsSetupEvent(e) {
			out = append(out, e)
			continue
		}
		k := strings.ToUpper(e.Host) + "|" + e.Time.In(r.Location).Format("2006-01-02")
		g := groups[k]
		if g == nil {
			g = &event.Event{Time: e.Time, Collected: e.Collected, Host: e.Host, OS: e.OS, Source: e.Source,
				Category: event.CatAccount, Severity: event.SevInfo, Action: "windows_setup", Fields: map[string]string{}}
			groups[k] = g
			out = append(out, g)
		}
		counts[g]++
		if len(g.Details) < 12 {
			g.AddDetail(e.Time.In(r.Location).Format("15:04:05"), e.Summary)
		}
	}
	for g, n := range counts {
		g.Summary = fmt.Sprintf("Windows setup prepared this computer: its temporary account defaultuser0 and the image's own accounts and policy (MINWINPC) (%d event%s).",
			n, map[bool]string{true: "s"}[n != 1])
		g.Target = "Windows setup"
	}
	return out
}

// defenderState makes Microsoft Defender recording its own state (5007
// for keys that are not configuration, translated as av_state_recorded)
// one Info count per computer and day (A16): a fresh Windows 11 wrote 240
// in its first day, some every minute.
func (r *Report) defenderState(events []*event.Event) []*event.Event {
	type group struct {
		row  *event.Event
		n    int
		keys []string
	}
	groups := map[string]*group{}
	out := events[:0]
	for _, e := range events {
		if e.Action != "av_state_recorded" {
			out = append(out, e)
			continue
		}
		k := strings.ToUpper(e.Host) + "|" + e.Time.In(r.Location).Format("2006-01-02")
		g := groups[k]
		if g == nil {
			g = &group{row: &event.Event{Time: e.Time, Collected: e.Collected, Host: e.Host, OS: e.OS, Source: e.Source,
				Category: event.CatOther, Severity: event.SevInfo, Action: "av_state_recorded", Fields: map[string]string{}}}
			groups[k] = g
			out = append(out, g.row)
		}
		g.n++
		key, _, _ := strings.Cut(e.Target, " = ")
		if i := strings.LastIndex(key, `\Windows Defender\`); i >= 0 {
			key = key[i+len(`\Windows Defender\`):]
		}
		if len(g.keys) < 15 && !slices.Contains(g.keys, key) {
			g.keys = append(g.keys, key)
		}
	}
	for _, g := range groups {
		g.row.Summary = fmt.Sprintf("Microsoft Defender recorded its own state %d time%s (service state, configuration hash, cloud checks): not setting changes.",
			g.n, map[bool]string{true: "s"}[g.n != 1])
		g.row.Target = fmt.Sprintf("%d Defender state records", g.n)
		g.row.AddDetail("Keys (first 15)", strings.Join(g.keys, "; "))
		g.row.AddDetail("Why one row", "Defender writes these as it runs. Its settings (exclusions, protections, tamper protection, policy) are listed separately.")
	}
	return out
}

// selfRecording is the first version that records its own changes (A15).
var selfRecording = [3]int{0, 11, 0}

// parseVersion reads "0.11.0" (or "v0.11.0-rc1"); ok is false for "dev".
func parseVersion(v string) (out [3]int, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v, _, _ = strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func versionAtLeast(v string, min [3]int) bool {
	p, ok := parseVersion(v)
	if !ok {
		return false
	}
	for i := range p {
		if p[i] != min[i] {
			return p[i] > min[i]
		}
	}
	return true
}

// selfChanges joins each "blackbox config set" command line to the record
// Blackbox made of the change (A15): the record says who, which setting,
// and the value before and after, so the command row is dropped and its
// command line kept on the record. A command with no record changed
// nothing (refused, answered "no", failed, or the value was already set),
// but only on a computer whose Blackbox, when the command ran, records
// its changes; older versions keep the command row as it is.
func selfChanges(events []*event.Event, runs []*store.Run) []*event.Event {
	// The Blackbox version on each computer over time.
	type ver struct {
		t time.Time
		v string
	}
	versions := map[string][]ver{}
	for _, r := range runs {
		k := strings.ToUpper(r.Host)
		versions[k] = append(versions[k], ver{r.Time, r.Version})
	}
	for _, vs := range versions {
		sort.Slice(vs, func(i, j int) bool { return vs[i].t.Before(vs[j].t) })
	}
	records := func(host string, at time.Time) bool {
		v := ""
		for _, x := range versions[strings.ToUpper(host)] {
			if x.t.After(at) {
				break
			}
			v = x.v
		}
		return versionAtLeast(v, selfRecording)
	}
	drop := map[*event.Event]bool{}
	for _, c := range events {
		if c.Action != "blackbox_config_changed" || c.Fields[event.SelfFlag] != "" {
			continue
		}
		cmd := c.Command
		if cmd == "" {
			cmd = detail(c, "Command")
		}
		key := event.ConfigSetKey(cmd)
		if key == "" {
			continue
		}
		var rec *event.Event
		for _, s := range events {
			if s.Fields[event.SelfFlag] == "setting" && s.Fields["setting"] == key && strings.EqualFold(s.Host, c.Host) &&
				!s.Time.Before(c.Time.Add(-time.Minute)) && !s.Time.After(c.Time.Add(20*time.Minute)) {
				rec = s
				break
			}
		}
		switch {
		case rec != nil:
			rec.AddDetail("Command", cmd)
			if rec.User == "" {
				rec.User = c.User
			}
			drop[c] = true
		case records(c.Host, c.Time):
			who := c.User
			if who == "" {
				who = "Someone"
			}
			c.Action = "blackbox_config_not_applied"
			if c.Severity == event.SevHigh {
				c.Severity = event.SevMedium
			} else {
				c.Severity = event.SevLow
			}
			c.Summary = fmt.Sprintf("%s tried to change Blackbox's %s setting (not applied): %s", who, key, cmd)
			c.AddDetail("Why not applied", "Blackbox records every setting it changes; there is no record of this one, so the command was refused, cancelled, failed, or set the value it already had.")
		}
	}
	if len(drop) == 0 {
		return events
	}
	out := events[:0]
	for _, e := range events {
		if !drop[e] {
			out = append(out, e)
		}
	}
	return out
}

// unknownNames corrects the reason of a Linux password check that failed
// because the account doesn't exist: PAM records it as a wrong password,
// and sshd says a moment later that the name was unknown.
func unknownNames(events []*event.Event) {
	const unknown = "the user name does not exist"
	for i, e := range events {
		if e.OS != "linux" || e.Action != "logon_failed" || !strings.HasSuffix(e.Summary, "— "+unknown+".") {
			continue
		}
		for j := i - 1; j >= 0 && e.Time.Sub(events[j].Time) <= 10*time.Second; j-- {
			x := events[j]
			if x.Host != e.Host || x.Action != "logon_failed" || x.Target != e.Target || x.SourceIP != e.SourceIP ||
				!strings.HasSuffix(x.Summary, "— wrong password.") {
				continue
			}
			x.Summary = strings.TrimSuffix(x.Summary, "wrong password.") + unknown + "."
			for k := range x.Details {
				if x.Details[k].Label == "Reason" {
					x.Details[k].Value = unknown
				}
			}
		}
	}
}

// mergeAdminLogons makes an administrator's logon one row (U3): Windows
// records it as a logon (4624) and as special privileges assigned to it
// (4672), with the same logon ID. The logon row is kept, with the
// privileges, and counts as using administrator rights.
func mergeAdminLogons(events []*event.Event) []*event.Event {
	logons := map[string]*event.Event{}
	for _, e := range events {
		if e.OS == "windows" && e.Action == "logon" && e.EventID == 4624 {
			if id := detail(e, "Logon ID"); id != "" {
				logons[e.Host+"|"+strings.ToLower(id)] = e
			}
		}
	}
	out := events[:0]
	for _, e := range events {
		if e.Action == "admin_logon" && e.EventID == 4672 {
			l := logons[e.Host+"|"+strings.ToLower(detail(e, "Logon ID"))]
			if l != nil && absDur(e.Time.Sub(l.Time)) <= 10*time.Second {
				l.AddDetail("Privileges", detail(e, "Privileges"))
				if !strings.Contains(l.Summary, "administrator") {
					l.Summary = strings.TrimSuffix(l.Summary, ".") + " with administrator privileges."
				}
				if l.Severity.Rank() < event.SevLow.Rank() {
					l.Severity = event.SevLow
				}
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// rebootCmd is a command that restarts or shuts down the system.
var rebootCmd = regexp.MustCompile(`(^|/|\s)(reboot|poweroff|halt|shutdown)(\s|$)|systemctl\s+(reboot|poweroff|halt|kexec)`)

// shutdownStops marks the audit service stopping as part of a restart or
// shutdown (a SYSTEM_SHUTDOWN record, or a reboot command, on the same
// computer within minutes) as routine: it is how every planned restart
// ends, not someone switching auditing off. A stop with neither stays High.
func auditStoppedBy(events []*event.Event) {
	for i, e := range events {
		if e.Action != "audit_stopped" || e.OS == "windows" || (person(e.User) && !isRoot(e.User)) {
			continue
		}
		var by *event.Event
		for j := i - 1; j >= 0 && e.Time.Sub(events[j].Time) <= 2*time.Minute && by == nil; j-- {
			if x := events[j]; x.Host == e.Host && person(x.User) && !isRoot(x.User) && linuxlog.StopsAuditd(x.Command) {
				by = x
			}
		}
		for j := i + 1; j < len(events) && events[j].Time.Sub(e.Time) <= 5*time.Second && by == nil; j++ {
			if x := events[j]; x.Host == e.Host && person(x.User) && !isRoot(x.User) && linuxlog.StopsAuditd(x.Command) {
				by = x
			}
		}
		if by == nil {
			continue
		}
		e.User, e.Command, e.Severity = by.User, by.Command, event.SevHigh
		e.Summary = fmt.Sprintf("The audit service (auditd) was stopped by %s (%s) — events are not recorded while it is stopped.", by.User, by.Command)
		e.AddDetail("Command", by.Command)
	}
}

func isRoot(u string) bool { return strings.EqualFold(u, "root") }

func shutdownStops(events []*event.Event) {
	for i, e := range events {
		if e.Action != "audit_stopped" || e.Severity != event.SevHigh || e.OS == "windows" {
			continue
		}
		near := func(x *event.Event) bool {
			if x.Host != e.Host {
				return false
			}
			return x.Action == "system_stop" || (x.Command != "" && rebootCmd.MatchString(strings.ToLower(x.Command)))
		}
		found := false
		for j := i - 1; j >= 0 && e.Time.Sub(events[j].Time) <= 5*time.Minute && !found; j-- {
			found = near(events[j])
		}
		for j := i + 1; j < len(events) && events[j].Time.Sub(e.Time) <= time.Minute && !found; j++ {
			found = near(events[j])
		}
		if found {
			e.Severity = event.SevInfo
			e.Summary = fmt.Sprintf("The audit service (auditd) stopped as part of a restart or shutdown by %s (normal).", orUnknown(e.User))
		}
	}
}

// recordKind identifies the kind of record an event came from: its log,
// event ID and (Linux audit) record type.
func recordKind(e *event.Event) string {
	return e.Source + "|" + strconv.Itoa(e.EventID) + "|" + e.RecordType
}

// attributeDevices names the person most likely using a removable device:
// device events do not record a user, so use whoever is logged on at the
// console of that host (not remotely: a remote user cannot plug in a
// device). When several people are, the most recent is named and the
// others are listed.
func attributeDevices(events []*event.Event) {
	// Best evidence: the person who mounted the device right after it was
	// connected (recorded by udisks on Linux).
	for i, e := range events {
		if e.Action != "usb_connected" || e.User != "" {
			continue
		}
		for _, m := range events[i+1:] {
			if m.Time.Sub(e.Time) > 2*time.Minute {
				break
			}
			if m.Host == e.Host && m.Action == "removable_mounted" && m.User != "" {
				e.User = m.User
				e.AddDetail("User", m.User+" (opened the device right after it was connected)")
				break
			}
		}
	}
	active := map[string][]string{} // host → console users, oldest first
	remove := func(host, user string) {
		l := active[host]
		for i := len(l) - 1; i >= 0; i-- {
			if l[i] == user {
				active[host] = append(l[:i:i], l[i+1:]...)
				return
			}
		}
	}
	for _, e := range events {
		switch {
		case e.Action == "logon" && consoleLogon(e):
			remove(e.Host, e.User)
			active[e.Host] = append(active[e.Host], e.User)
		case e.Action == "logoff":
			remove(e.Host, e.User)
		case e.Category == event.CatRemovable && e.User == "":
			l := active[e.Host]
			if len(l) == 0 {
				continue
			}
			e.User = l[len(l)-1]
			e.AddDetail("User", e.User+" (logged on at the console at the time; device events do not record a user)")
			if len(l) > 1 {
				e.AddDetail("Also logged on at the console", strings.Join(l[:len(l)-1], ", "))
			}
		}
	}
}

// consoleLogon reports a logon made at the machine itself.
func consoleLogon(e *event.Event) bool {
	switch e.Fields["LogonType"] {
	case "2", "7", "11", "13":
		return true
	}
	for _, d := range e.Details {
		if d.Label == "Logon type" && (d.Value == "Graphical console" || d.Value == "Text console") {
			return true
		}
	}
	return false
}

// dropWindowsModules leaves out script blocks of Windows' own PowerShell
// modules that PowerShell flagged as suspicious, collected before
// Blackbox learned to skip them (see winevt.WindowsModule).
func dropWindowsModules(in []*event.Event) []*event.Event {
	out := in[:0:0]
	for _, e := range in {
		if e.Action == "powershell_suspicious" {
			var text, path string
			for _, d := range e.Details {
				switch d.Label {
				case "Script (excerpt)":
					text = d.Value
				case "Script path":
					path = d.Value
				}
			}
			if winevt.WindowsModule(text, path) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}
