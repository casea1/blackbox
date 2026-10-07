package report

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// Detections look for patterns across events: several steps that are
// ordinary on their own but suspicious together, and things done for the
// first time. They run on events already collected, so they add nothing
// to what computers collect or send.
//
// Rows from before the report period (Options.Context, ID "") let a
// pattern that started in the previous period be completed in this one;
// a detection is only reported when its last step is in this period.

const (
	sprayWindow     = 30 * time.Minute
	sprayHosts      = 3
	coverWindow     = 24 * time.Hour
	shortLivedLimit = 24 * time.Hour
	afterUSBWindow  = 30 * time.Minute

	// baselineExpiry is how long something unseen is remembered: after a
	// year it counts as new again.
	baselineExpiry = 365 * 24 * time.Hour
)

// setupActions prepare access: a new account, a privileged group or new
// sudo rules.
func setupAction(r *Row) bool {
	if !person(r.User) {
		return false // Windows setup or a service, not someone preparing access (A17)
	}
	switch r.Action {
	case "account_created", "sudoers_changed":
		return true
	case "group_member_added":
		return r.Severity == event.SevHigh // privileged groups only
	}
	return false
}

// deliverySettings are the settings setup changes to send to or receive
// from other computers, or to say where reports go.
var deliverySettings = map[string]bool{"inbox": true, "send_to": true, "share_user": true, "report_dir": true, "archive_dir": true, "scap_results": true}

// tamperAction hides activity: logs cleared or altered, auditing or
// anti-malware stopped or changed, by a person. Changes the system makes
// itself (Group Policy refreshes, rules loaded at boot) do not count.
func tamperAction(r *Row) bool {
	switch r.Action {
	case "log_cleared", "log_tampered":
		return r.User == "" || person(r.User)
	case "audit_disabled", "audit_policy_changed", "audit_rule_added", "audit_rule_removed", "audit_config_changed", "audit_rules_refused",
		"audit_tamper_command", "powershell_tamper", "powershell_av_tamper":
		return person(r.User)
	case "av_disabled", "av_exclusion_added", "firewall_stopped", "firewall_rules_cleared":
		return r.User == "" || person(r.User) // Defender's own events name no user
	case "blackbox_stopped", "blackbox_uninstalled", "blackbox_files_removed", "blackbox_files_changed", "object_audit_changed":
		return person(r.User)
	case "blackbox_config_changed":
		// Blackbox's own record of setting up delivery (A17b): creating
		// the delivery account and then running setup is how a collector
		// or sender is set up, not someone hiding what they did.
		if r.Fields[event.SelfFlag] != "" && deliverySettings[r.Fields["setting"]] {
			return false
		}
		return person(r.User) && r.Severity == event.SevHigh
	case "audit_stopped":
		return r.Severity == event.SevHigh // stopped by a person, not at shutdown
	}
	return false
}

var systemAccounts = map[string]bool{"system": true, "local service": true, "network service": true,
	"-": true, "unknown": true, "unset": true, "(unset)": true, "": true}

// person reports whether an account is a person's rather than the system's
// or a computer's.
func person(u string) bool {
	l := strings.ToLower(u)
	if strings.HasPrefix(l, `virtual users\`) {
		return false // OpenSSH for Windows' per-connection sshd_<pid> account (W2)
	}
	if i := strings.LastIndex(l, `\`); i >= 0 {
		l = l[i+1:]
	}
	return !systemAccounts[l] && !strings.HasSuffix(l, "$")
}

// adminActivity is something done with administrator rights by a person.
func adminActivity(r *Row) bool {
	if r.Action == "logon" && detail(r.Event, "Privileges") != "" {
		return person(r.User) // a logon with administrator rights (U3)
	}
	return r.Category == event.CatPrivileged && person(r.User)
}

func inPeriod(r *Row) bool { return r.ID != "" }

// addFinding records a detection. related are the events it is made of,
// shown in order on the Detections page (at and link when not given).
func (r *Report) addFinding(sev event.Severity, cat event.Category, at *Row, link *Row, title, detail string, related ...*Row) {
	if len(related) == 0 {
		related = []*Row{at, link}
	}
	r.Findings = append(r.Findings, Finding{Severity: sev, Category: cat, Host: at.Host, Time: at.Time,
		RowID: link.ID, RowIDs: rowIDs(related), Title: title, Detail: detail})
}

// between lists the notable events (Low and above) on host from a to b,
// at most max of them, for a detection's "what happened".
func between(all []*Row, host string, a, b *Row, max int) []*Row {
	var out []*Row
	for _, x := range all {
		if x.Time.Before(a.Time) || x.Time.After(b.Time) || x.Host != host {
			continue
		}
		if x == a || x == b || x.Severity.Rank() >= event.SevLow.Rank() {
			out = append(out, x)
		}
	}
	if len(out) > max {
		out = append(out[:max-1], b)
	}
	return out
}

// detect runs every detection over the rows of this period (rows) and
// all rows including the context before it (all), both sorted by time.
func (r *Report) detect(rows, all []*Row) {
	r.detectSprayAcrossComputers(all)
	r.detectCoverTracks(all)
	r.detectShortLivedAccounts(all)
	r.detectAdminAfterNewDevice(rows)
	r.detectOffHours(rows)
	r.detectFirstTime(rows)
	r.detectClockMoved(rows)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.Time.Before(b.Time)
	})
}

// firstInPeriod returns the first row of the list that is in this period.
func firstInPeriod(list []*Row) *Row {
	for _, x := range list {
		if inPeriod(x) {
			return x
		}
	}
	return nil
}

// One account failing on several computers: someone trying a password
// across the network. Only a collector sees this.
func (r *Report) detectSprayAcrossComputers(all []*Row) {
	byAcct := map[string][]*Row{}
	var order []string
	for _, x := range all {
		if x.Action != "logon_failed" || x.Target == "" {
			continue
		}
		k := strings.ToLower(x.Target)
		if byAcct[k] == nil {
			order = append(order, k)
		}
		byAcct[k] = append(byAcct[k], x)
	}
	for _, k := range order {
		for _, c := range clusters(byAcct[k], sprayWindow) {
			hosts := distinctList(c, func(x *Row) string { return x.Host })
			last := c[len(c)-1]
			if len(hosts) < sprayHosts || !inPeriod(last) {
				continue
			}
			r.addFinding(event.SevHigh, event.CatFailedLogon, c[0], firstInPeriod(c),
				"Same account failing on several computers",
				fmt.Sprintf("%d failed logons for %s on %d computers (%s) between %s and %s. Someone may be trying a password across the network.",
					len(c), c[0].Target, len(hosts), strings.Join(hosts, ", "), r.stamp(c[0].Time), r.clock(last.Time)), c...)
		}
	}
}

// Access set up (an account, a privileged group, sudo rules), then the
// logs cleared or auditing changed on the same computer.
func (r *Report) detectCoverTracks(all []*Row) {
	used := map[*Row]bool{}
	for i, t := range all {
		if !inPeriod(t) || !tamperAction(t) {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			s := all[j]
			if t.Time.Sub(s.Time) > coverWindow {
				break
			}
			if s.Host != t.Host || !setupAction(s) || used[s] {
				continue
			}
			used[s] = true
			link := s
			if !inPeriod(s) {
				link = t
			}
			r.addFinding(event.SevHigh, event.CatIntegrity, t, link, "Possible covering of tracks",
				fmt.Sprintf("On %s at %s: %s %s later: %s The second step can hide what was done with the first.",
					t.Host, r.stamp(s.Time), s.Summary, capitalize(roughDuration(t.Time.Sub(s.Time))), t.Summary),
				between(all, t.Host, s, t, 12)...)
			break
		}
	}
}

// An account created and deleted within a day: used for something, then
// removed.
func (r *Report) detectShortLivedAccounts(all []*Row) {
	for i, d := range all {
		if !inPeriod(d) || d.Action != "account_deleted" || d.Target == "" {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			c := all[j]
			if d.Time.Sub(c.Time) > shortLivedLimit {
				break
			}
			if c.Host != d.Host || c.Action != "account_created" || !strings.EqualFold(c.Target, d.Target) {
				continue
			}
			link := c
			if !inPeriod(c) {
				link = d
			}
			r.addFinding(event.SevHigh, event.CatAccount, d, link, "Account created and deleted within a day",
				fmt.Sprintf("The account %s on %s was created by %s at %s and deleted by %s %s later. A short-lived account can be used and then removed to hide who did something.",
					c.Target, d.Host, orUnknown(c.User), r.stamp(c.Time), orUnknown(d.User), roughDuration(d.Time.Sub(c.Time))))
			break
		}
	}
}

// highDetections makes every High row part of a detection (UX6): one
// that no detection rule took is a detection of its own, one per kind of
// event on each system ("Log cleared on WS-07", 2 events). High means
// "investigate", and Detections is where that is listed; a High row
// outside it, as before, was a second list of things to look at.
func (r *Report) highDetections(rows []*Row) {
	in := map[string]bool{}
	for _, f := range r.Findings {
		for _, id := range f.RowIDs {
			in[id] = true
		}
		in[f.RowID] = true
	}
	type group struct {
		rows []*Row
	}
	groups := map[string]*group{}
	var order []string
	for _, x := range rows {
		if !inPeriod(x) || x.Severity != event.SevHigh || in[x.ID] {
			continue
		}
		k := x.Host + "|" + x.Action
		if groups[k] == nil {
			groups[k] = &group{}
			order = append(order, k)
		}
		groups[k].rows = append(groups[k].rows, x)
	}
	for _, k := range order {
		g := groups[k].rows
		first, last := g[0], g[len(g)-1]
		label := highLabel(first.Action, len(g))
		title := capitalize(label) + " on " + first.Host
		detail := first.Summary
		if len(g) > 1 {
			detail = fmt.Sprintf("%d %s on %s between %s and %s. The first: %s", len(g), label, first.Host, r.stamp(first.Time), r.stamp(last.Time), first.Summary)
		}
		r.addFinding(event.SevHigh, first.Category, first, first, title, detail, g...)
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.Time.Before(b.Time)
	})
}

// highLabel names a kind of High event for its detection: "log cleared",
// "3 audit policy changes".
func highLabel(action string, n int) string {
	if l, ok := actionLabels[action]; ok {
		if n == 1 {
			return l[0]
		}
		return l[1]
	}
	if l, ok := highNames[action]; ok {
		return l
	}
	return strings.ReplaceAll(action, "_", " ")
}

// highNames name High events with no entry in actionLabels.
var highNames = map[string]string{
	"log_cleared": "log cleared", "log_tampered": "log altered or deleted", "audit_disabled": "auditing switched off",
	"audit_stopped": "auditing stopped", "audit_tamper_command": "command that can clear logs or weaken auditing",
	"blackbox_files_changed": "Blackbox's files changed", "blackbox_config_changed": "Blackbox's settings changed",
	"blackbox_stopped": "Blackbox stopped", "blackbox_uninstalled": "Blackbox removed", "blackbox_files_removed": "Blackbox's files removed",
	"av_disabled": "anti-malware switched off", "av_exclusion_added": "anti-malware exclusion added", "firewall_stopped": "firewall stopped",
	"setuid_set": "program made to run as its owner (setuid)", "sudoers_changed": "sudo rules changed", "admin_group_added": "added to a privileged group",
	"usb_new": "USB device never seen before", "logon_config_changed": "logon settings changed", "log_full": "Security log full",
	"time_changed": "clock moved back", "usb_network_adapter": "USB network adapter connected", "malware_detected": "malware detected",
}

// clockMovedLimit is how far a person must move the clock to be a
// detection: the time service's small corrections are not (TIME1).
const clockMovedLimit = 5 * time.Minute

// A person moving the clock more than a few minutes (AU-8): event times
// around it don't line up, and moving it is a way to hide activity (T3).
// Back is High, forward Medium.
func (r *Report) detectClockMoved(rows []*Row) {
	for _, x := range rows {
		if !inPeriod(x) || x.Action != "time_changed" || !person(x.User) {
			continue
		}
		prev, err1 := time.Parse(time.RFC3339Nano, x.Fields["PreviousTime"])
		next, err2 := time.Parse(time.RFC3339Nano, x.Fields["NewTime"])
		if err1 != nil || err2 != nil {
			continue
		}
		d := next.Sub(prev)
		if d.Abs() <= clockMovedLimit {
			continue
		}
		sev, way := event.SevMedium, "forward"
		if d < 0 {
			sev, way = event.SevHigh, "back"
		}
		r.addFinding(sev, event.CatIntegrity, x, x, "The clock was moved "+way+" by a person",
			fmt.Sprintf("%s moved the clock on %s %s by %s at %s%s. Event times around the change don't line up with other systems, and moving the clock is a way to make activity look as if it happened at another time. Every collected event is still reported, in the order it was collected.",
				x.User, x.Host, way, roughDuration(d.Abs()), r.stamp(x.Time), usingText(x.Process)))
	}
}

func usingText(proc string) string {
	if proc == "" {
		return ""
	}
	if i := strings.LastIndexAny(proc, `/\`); i >= 0 {
		proc = proc[i+1:]
	}
	return " (using " + proc + ")"
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown account"
	}
	return s
}

// A USB device never seen before, then administrator activity on the same
// computer soon after.
func (r *Report) detectAdminAfterNewDevice(rows []*Row) {
	for i, d := range rows {
		if !hasFlag(d, "New device") {
			continue
		}
		var acts []*Row
		for _, x := range rows[i+1:] {
			if x.Time.Sub(d.Time) > afterUSBWindow {
				break
			}
			if x.Host == d.Host && adminActivity(x) {
				acts = append(acts, x)
			}
		}
		if len(acts) == 0 {
			continue
		}
		r.addFinding(event.SevMedium, event.CatRemovable, d, d, "New USB device, then administrator activity",
			fmt.Sprintf("A USB device not seen before was connected to %s at %s (%s), and %s used administrator rights %d times in the next %d minutes, starting with: %s",
				d.Host, r.clock(d.Time), d.Target, distinct(acts, func(x *Row) string { return x.User }), len(acts),
				int(afterUSBWindow.Minutes()), acts[0].Summary))
	}
}

func hasFlag(r *Row, f string) bool {
	for _, x := range r.Flags {
		if x == f {
			return true
		}
	}
	return false
}

// Administrator activity outside the configured working hours, one
// detection per person, computer and day.
func (r *Report) detectOffHours(rows []*Row) {
	if !r.WorkingHours.Set() {
		return
	}
	groups := map[string][]*Row{}
	var order []string
	for _, x := range rows {
		if !adminActivity(x) || r.WorkingHours.Contains(x.Time.In(r.Location)) {
			continue
		}
		k := x.Host + "|" + strings.ToLower(x.User) + "|" + x.Time.In(r.Location).Format("2006-01-02")
		if groups[k] == nil {
			order = append(order, k)
		}
		groups[k] = append(groups[k], x)
		x.Flags = append(x.Flags, "Outside working hours")
	}
	for _, k := range order {
		g := groups[k]
		first, last := g[0], g[len(g)-1]
		when := r.clock(first.Time)
		if len(g) > 1 {
			when = "between " + when + " and " + r.clock(last.Time)
		} else {
			when = "at " + when
		}
		r.addFinding(event.SevMedium, event.CatPrivileged, first, first, "Administrator activity outside working hours",
			fmt.Sprintf("%s used administrator rights on %s %s on %s (%s; working hours are %s).",
				first.User, first.Host, when, first.Time.In(r.Location).Format("Mon 2 Jan"),
				plural(len(g), "action"), r.WorkingHours.Text), g...)
	}
}

// localAddress reports addresses that are not another computer.
func localAddress(s string) bool {
	ip := net.ParseIP(s)
	return ip == nil || ip.IsLoopback() || ip.IsUnspecified()
}

// firstTimeKeys lists what a row does for the first time, if it is:
// a person logging on to a computer, a person using administrator rights
// on it, or a logon from another computer's address.
func firstTimeKeys(x *Row) (keys []string, labels []string) {
	host := strings.ToLower(x.Host)
	if x.Action == "logon" && x.Interactive && person(x.User) {
		keys = append(keys, "logon|"+host+"|"+strings.ToLower(x.User))
		labels = append(labels, "logon")
		if !localAddress(x.SourceIP) {
			keys = append(keys, "src|"+host+"|"+x.SourceIP)
			labels = append(labels, "source")
		}
	}
	if adminActivity(x) {
		keys = append(keys, "admin|"+host+"|"+strings.ToLower(x.User))
		labels = append(labels, "admin")
	}
	return keys, labels
}

// detectFirstTime points out the first logon by a person to a computer,
// their first use of administrator rights on it, and the first logon from
// a new address. A computer's first report only learns what is normal for
// it, so installing Blackbox does not flag everyone.
func (r *Report) detectFirstTime(rows []*Row) {
	if r.Baseline == nil {
		return
	}
	learning := map[string]bool{}
	for _, x := range rows {
		keys, labels := firstTimeKeys(x)
		if len(keys) == 0 {
			continue
		}
		_, known := r.BaselineHosts[strings.ToLower(x.Host)]
		if !known && !learning[x.Host] {
			learning[x.Host] = true
			r.Learning = append(r.Learning, x.Host)
		}
		for i, k := range keys {
			_, before := r.Baseline[k]
			_, thisPeriod := r.Learned[k]
			r.Learned[k] = x.Time
			if before || thisPeriod || !known {
				continue
			}
			x.Flags = append(x.Flags, "First time")
			switch labels[i] {
			case "logon":
				r.addFinding(event.SevMedium, event.CatLogon, x, x, "First logon to this computer",
					fmt.Sprintf("%s logged on to %s for the first time (as far as Blackbox has seen): %s", x.User, x.Host, x.Summary))
			case "source":
				r.addFinding(event.SevMedium, event.CatLogon, x, x, "First logon from this address",
					fmt.Sprintf("%s had not been logged on to from %s before. %s", x.Host, x.SourceIP, x.Summary))
			case "admin":
				r.addFinding(event.SevMedium, event.CatPrivileged, x, x, "First use of administrator rights",
					fmt.Sprintf("%s used administrator rights on %s for the first time (as far as Blackbox has seen): %s", x.User, x.Host, x.Summary))
			}
		}
	}
	sort.Strings(r.Learning)
}

// UpdateBaseline merges what a report saw into the remembered baseline,
// marks its computers as learned, and forgets what has not been seen for
// a year.
func UpdateBaseline(baseline, hosts map[string]time.Time, r *Report, now time.Time) {
	for k, t := range r.Learned {
		if t.After(baseline[k]) {
			baseline[k] = t
		}
	}
	for _, h := range r.Hosts {
		h = strings.ToLower(h)
		if _, ok := hosts[h]; !ok {
			hosts[h] = now
		}
	}
	for k, t := range baseline {
		if now.Sub(t) > baselineExpiry {
			delete(baseline, k)
		}
	}
}
