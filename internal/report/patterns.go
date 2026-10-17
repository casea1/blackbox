// Detections across failed logons (password guessing, one source trying
// several accounts, success after failures) and auditing switched off; the
// rest are in detect.go.

package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

const (
	guessWindow    = 15 * time.Minute
	guessThreshold = 5
	sprayThreshold = 3
	successWindow  = 30 * time.Minute
	// runGap: bursts of failed logons for one account from one source
	// less than this apart are one continuing run, one detection (DET5).
	runGap = time.Hour
)

// guessRuns keeps the bursts of at least guessThreshold failures and
// joins those from the same source less than runGap apart: a program or
// sender with an old password fails every few minutes for days, which is
// one thing to look at, not one detection per 15 minutes (DET5).
func guessRuns(bursts [][]*Row) [][]*Row {
	var out [][]*Row
	src := func(c []*Row) string { return distinct(c, func(x *Row) string { return x.SourceIP }) }
	for _, c := range bursts {
		if len(c) < guessThreshold {
			continue
		}
		if n := len(out); n > 0 {
			prev := out[n-1]
			if c[0].Time.Sub(prev[len(prev)-1].Time) < runGap && src(c) == src(prev) {
				out[n-1] = append(prev, c...)
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// guessFinding is the "Possible password guessing" detection for one run.
func (r *Report) guessFinding(c []*Row, rows []*Row) Finding {
	first, last := c[0], c[len(c)-1]
	src := distinct(c, func(x *Row) string { return x.SourceIP })
	d := fmt.Sprintf("%d failed logons for %s on %s %s", len(c), first.Target, first.Host, r.span(first.Time, last.Time))
	if src != "" {
		d += " from " + src
	}
	d += "."
	if last.Time.Sub(first.Time) > guessWindow {
		d += fmt.Sprintf(" One continuing run: about %s from first to last.", roughDuration(last.Time.Sub(first.Time)))
		if !r.WindowEnd.IsZero() && r.WindowEnd.Sub(last.Time) < runGap {
			d += " Still going at the end of this period."
		}
	}
	for _, x := range c {
		if detail(x.Event, "Reason") == "the user name does not exist" {
			d += fmt.Sprintf(" The account %s does not exist on %s.", first.Target, first.Host)
			break
		}
	}
	f := Finding{Severity: event.SevHigh, Category: event.CatFailedLogon,
		Host: first.Host, Time: first.Time, RowID: first.ID, RowIDs: rowIDs(c),
		Title: "Possible password guessing", Detail: d}
	if r.fromSender(c, rows) {
		f.Detail += " Probably a sender with an old or wrong password: it delivers to this computer with this account."
		f.senderRun = true
	}
	return f
}

// fromSender says whether failed logons look like a Blackbox sender's: the
// account is or was in the Blackbox Senders group, or they came from a
// computer that reports here.
func (r *Report) fromSender(c []*Row, rows []*Row) bool {
	acct := acctKey(c[0].Target)
	for _, x := range rows {
		if (x.Action == "group_member_added" || x.Action == "group_member_removed") && acctKey(x.Target) == acct &&
			strings.EqualFold(detail(x.Event, "Group"), "Blackbox Senders") {
			return true
		}
	}
	for _, x := range c {
		ws := detail(x.Event, "Source workstation")
		for _, h := range r.Hosts {
			if ws != "" && !strings.EqualFold(h, x.Host) && strings.EqualFold(shortHost(h), shortHost(ws)) {
				return true
			}
		}
	}
	return false
}

// noteSilentSenders names, on a sender's failed-logon run, the computers
// that sent nothing or little in this period (known only once the
// Systems page is built).
func (r *Report) noteSilentSenders() {
	var quiet []string
	for _, s := range r.Silent {
		quiet = append(quiet, s.Name)
	}
	for _, s := range r.SystemRows {
		if s.Status == "warn" && strings.Contains(strings.ToLower(s.StatusMsg), "late") {
			quiet = append(quiet, s.Name)
		}
	}
	if len(quiet) == 0 {
		return
	}
	for i := range r.Findings {
		if r.Findings[i].senderRun {
			r.Findings[i].Detail += " Silent or late in this period: " + strings.Join(quiet, ", ") + "."
		}
	}
}

// acctKey compares account names without their domain: a failed logon
// over the network carries whatever domain the client sent (WORKGROUP,
// its own name), while the password check and the logon name the account
// alone.
func acctKey(name string) string {
	name = strings.ToLower(name)
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

func (r *Report) findPatterns(rows []*Row) {
	var fails []*Row
	for _, row := range rows {
		if row.Action == "logon_failed" {
			fails = append(fails, row)
		}
	}
	// Repeated failures for one account.
	byUser := map[string][]*Row{}
	for _, f := range fails {
		k := f.Host + "|" + acctKey(f.Target)
		byUser[k] = append(byUser[k], f)
	}
	for _, list := range byUser {
		for _, c := range guessRuns(clusters(list, guessWindow)) {
			r.Findings = append(r.Findings, r.guessFinding(c, rows))
		}
	}
	// One source trying several accounts.
	bySrc := map[string][]*Row{}
	for _, f := range fails {
		src := f.SourceIP
		if src == "" {
			continue
		}
		bySrc[f.Host+"|"+src] = append(bySrc[f.Host+"|"+src], f)
	}
	for _, list := range bySrc {
		for _, c := range clusters(list, guessWindow) {
			users := distinctList(c, func(x *Row) string { return x.Target })
			if len(users) < sprayThreshold {
				continue
			}
			first := c[0]
			r.Findings = append(r.Findings, Finding{Severity: event.SevHigh, Category: event.CatFailedLogon,
				Host: first.Host, Time: first.Time, RowID: first.ID, RowIDs: rowIDs(c),
				Title: "One source tried several accounts",
				Detail: fmt.Sprintf("%s tried %d different accounts on %s (%s) with %d failed logons %s.",
					first.SourceIP, len(users), first.Host, strings.Join(users, ", "), len(c), r.span(first.Time, c[len(c)-1].Time))})
		}
	}
	// Several failures followed by a success (reported once per burst).
	reported := map[string]bool{}
	for _, row := range rows {
		if row.Action != "logon" {
			continue
		}
		var n int
		var firstFail *Row
		for _, f := range byUser[row.Host+"|"+acctKey(row.User)] {
			if f.Time.Before(row.Time) && row.Time.Sub(f.Time) <= successWindow {
				if firstFail == nil {
					firstFail = f
				}
				n++
			}
		}
		if n >= 3 && !reported[firstFail.ID] {
			reported[firstFail.ID] = true
			r.Findings = append(r.Findings, Finding{Severity: event.SevMedium, Category: event.CatFailedLogon,
				Host: row.Host, Time: row.Time, RowID: firstFail.ID, RowIDs: rowIDs([]*Row{firstFail, row}),
				Title: "Successful logon after failures",
				Detail: fmt.Sprintf("%s logged on to %s at %s after %d failed attempts in the previous %d minutes.",
					row.User, row.Host, r.clock(row.Time), n, int(successWindow.Minutes()))})
		}
	}
	// Auditing switched off by a person, until it came back.
	for i, row := range rows {
		if row.Action != "audit_stopped" || row.Severity != event.SevHigh {
			continue
		}
		var until *Row
		for _, next := range rows[i+1:] {
			if next.Host == row.Host && next.Action == "audit_started" {
				until = next
				break
			}
		}
		f := Finding{Severity: event.SevHigh, Category: event.CatIntegrity, Host: row.Host, Time: row.Time, RowID: row.ID,
			RowIDs: []string{row.ID}, Title: "Auditing was switched off"}
		if until != nil {
			f.RowIDs = append(f.RowIDs, until.ID)
			f.Detail = fmt.Sprintf("The audit service on %s was off for %s (%s to %s). Nothing done in that time was recorded.",
				row.Host, roughDuration(until.Time.Sub(row.Time)), r.clock(row.Time), r.clock(until.Time))
			r.Health.AuditOff = append(r.Health.AuditOff, fmt.Sprintf("%s: auditing was off for %s (%s to %s).",
				row.Host, roughDuration(until.Time.Sub(row.Time)), r.stamp(row.Time), r.stamp(until.Time)))
		} else {
			f.Detail = fmt.Sprintf("The audit service on %s was stopped at %s and had not restarted by the end of this report.", row.Host, r.clock(row.Time))
			r.Health.AuditOff = append(r.Health.AuditOff, fmt.Sprintf("%s: auditing was stopped at %s and not restarted.", row.Host, r.stamp(row.Time)))
		}
		r.Findings = append(r.Findings, f)
	}
}

// clusters splits time-sorted rows into runs where each row is within
// window of the first row of its run.
func clusters(rows []*Row, window time.Duration) [][]*Row {
	var out [][]*Row
	var cur []*Row
	for _, x := range rows {
		if len(cur) > 0 && x.Time.Sub(cur[0].Time) > window {
			out = append(out, cur)
			cur = nil
		}
		cur = append(cur, x)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// rowIDs lists the IDs of rows in this report's period (rows read only
// for context have none).
func rowIDs(rows []*Row) []string {
	var ids []string
	seen := map[string]bool{}
	for _, x := range rows {
		if x.ID != "" && !seen[x.ID] {
			seen[x.ID] = true
			ids = append(ids, x.ID)
		}
	}
	return ids
}

func distinctList(rows []*Row, f func(*Row) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range rows {
		v := f(x)
		if v != "" && !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	return out
}

func distinct(rows []*Row, f func(*Row) string) string {
	return strings.Join(distinctList(rows, f), ", ")
}
