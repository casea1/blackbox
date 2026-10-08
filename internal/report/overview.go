package report

import (
	"fmt"
	"github.com/casea1/blackbox/internal/rollover"
	"slices"
	"sort"
	"strings"
)

// The Overview page's health checklist and detection cards (the page
// itself is built in overviewpage.go).

// EventCard is one of the important-event cards.
type EventCard struct {
	Icon, Label, Value, Note string
	Level                    string // "bad", "warn", "" or "zero"
	Href                     string
	// Filter, on an event page, filters the table below instead of going
	// elsewhere: a query string of kind, sev, host, user, day, text or
	// flag ("all" clears the filters). Scroll goes to an element on the
	// same page.
	Filter, Scroll string
}

// CheckLine is one line of a health checklist.
type CheckLine struct {
	Level string // ok | warn | bad
	Icon  string
	Title string
	Who   string // the system named, if one fails
	What  string
	Count string // e.g. "23/24"
	Href  string // where it leads
	Ev    string // or: an event to open (see evRef)
}

// DetectionCard is one detection in a list grouped by day.
type DetectionCard struct {
	Day                           string
	Severity, Title, Detail, Host string
	Time                          string
	Index                         int    // position in Findings, for links
	Slots                         string // on a person's page: the weekday-hour slots (heatmap) it involved them
}

// joinOr is "a, b or c".
func joinOr(l []string) string {
	if len(l) < 2 {
		return strings.Join(l, "")
	}
	return strings.Join(l[:len(l)-1], ", ") + " or " + l[len(l)-1]
}

func osLabel(s SystemRow) string {
	if s.Checks != nil && s.Checks.Baseline != "" {
		b := s.Checks.Baseline
		if i := strings.Index(b, " STIG"); i > 0 {
			b = b[:i]
			if j := strings.Index(b, " ("); j > 0 && !strings.Contains(b[j:], ")") {
				b = b[:j] // "Alma 8 (RHEL 8 STIG)" → "Alma 8"
			}
			return b
		}
		return b
	}
	return s.OSName()
}

// isServer reports a Windows Server, an Alma/RHEL computer, or a Linux
// computer with no desktop installed, such as Ubuntu Server (UX10).
func isServer(s SystemRow) bool {
	if s.Checks == nil {
		return false
	}
	b := s.Checks.Baseline
	if inv := s.Checks.Inventory; inv != nil && inv.Server {
		return true
	}
	return strings.Contains(b, "Server") || strings.Contains(b, "RHEL") || strings.Contains(b, "Alma")
}

// checklist is the six-line health checklist.
func (r *Report) checklist(systems []SystemRow, cleared map[string][]*Row) []CheckLine {
	total := len(systems)
	// How many systems a line is about, said in words (UX10): "1 of 3
	// systems" for a problem, "all 3 systems" when fine.
	frac := func(bad int) string {
		switch {
		case total <= 1:
			return ""
		case bad == 0:
			return fmt.Sprintf("all %d systems", total)
		}
		return fmt.Sprintf("%d of %d systems", bad, total)
	}
	var lines []CheckLine

	var who []string
	var all []*Row
	seen := map[string]bool{}
	for _, s := range systems {
		if rows := cleared[strings.ToLower(s.Name)]; len(rows) > 0 {
			who = append(who, s.Name)
			all = append(all, rows...)
			seen[strings.ToLower(s.Name)] = true
		}
	}
	// A clear on a computer not in the systems list is still a clear:
	// never "Logs intact" next to one (UX10).
	var others []string
	for h := range cleared {
		if !seen[h] {
			others = append(others, h)
		}
	}
	sort.Strings(others)
	for _, h := range others {
		who = append(who, cleared[h][0].Host)
		all = append(all, cleared[h]...)
	}
	if len(who) > 0 {
		lines = append(lines, CheckLine{Level: "bad", Icon: "file-warning", Title: "Logs cleared", Who: strings.Join(who, ", "), What: clearedWhat(all) + " cleared", Count: frac(len(who))})
	} else {
		lines = append(lines, CheckLine{Level: "ok", Icon: "file-warning", Title: "Logs intact", What: "No logs cleared", Count: frac(0)})
	}

	who = nil
	var since string
	for _, s := range systems {
		if s.Status == "silent" {
			who = append(who, s.Name)
			if !s.LastRun.IsZero() {
				since = "no data since " + s.LastRun.In(r.Location).Format("2 Jan 15:04")
			}
		}
	}
	if len(who) > 0 {
		if since == "" || len(who) > 1 {
			since = "no data in this period"
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "clock-alert", Title: "Not every system reporting", Who: strings.Join(who, ", "), What: since, Count: frac(len(who))})
	} else {
		what := "Every system sent its events"
		var quiet []string
		for _, s := range systems {
			if s.VM && s.Runs == 0 {
				quiet = append(quiet, s.Name)
			} else if s.VM {
				what = "VMs reported whenever they were on"
			}
		}
		if len(quiet) > 0 {
			lines = append(lines, CheckLine{Level: "warn", Icon: "clock-alert", Title: "Not every system reporting", Who: strings.Join(quiet, ", "),
				What: "Worth a look: a virtual machine sent nothing this period", Count: frac(len(quiet))})
		} else {
			lines = append(lines, CheckLine{Level: "ok", Icon: "clock-alert", Title: "Every system reporting", What: what, Count: frac(0)})
		}
	}

	if r.Late > 0 {
		lines = append(lines, CheckLine{Level: "warn", Icon: "history", Title: "Events arrived late", What: fmt.Sprintf("%s arrived late · nothing lost", plural(r.Late, "event")), Count: ""})
	} else {
		lines = append(lines, CheckLine{Level: "ok", Icon: "history", Title: "Reports on time", What: "All on time", Count: frac(0)})
	}

	who = nil
	gaps := 0
	checked := 0
	for _, s := range systems {
		if s.Checks != nil {
			checked++
			if s.Checks.Fail > 0 {
				who = append(who, s.Name)
				gaps += s.Checks.Fail
			}
		}
	}
	switch {
	case len(who) > 0:
		lines = append(lines, CheckLine{Level: "warn", Icon: "shield-check", Title: "Audit settings to fix", Who: strings.Join(who, ", "),
			What: fmt.Sprintf("%s to fix · see Audit health", plural(gaps, "setting")), Count: frac(len(who))})
	case checked == 0:
		lines = append(lines, CheckLine{Level: "warn", Icon: "shield-check", Title: "Audit settings not checked", What: "Not checked in this period", Count: ""})
	default:
		lines = append(lines, CheckLine{Level: "ok", Icon: "shield-check", Title: "Audit settings match STIG", What: "All systems checked", Count: frac(0)})
	}

	// Events lost from the audit record are a failing line; from other
	// logs (the PowerShell log), a warning of their own, named (LOG1).
	lost, other := uint64(0), uint64(0)
	var lostOn, otherOn []string
	otherBy := map[string]uint64{}
	var otherNames []string
	for _, g := range r.Health.Gaps {
		if g.Lost == 0 {
			continue
		}
		if !rollover.Critical(g.Channel) {
			other += g.Lost
			if !slices.Contains(otherOn, g.Host) {
				otherOn = append(otherOn, g.Host)
			}
			k := g.Host + "\x00" + rollover.Name(g.Channel)
			if _, ok := otherBy[k]; !ok {
				otherNames = append(otherNames, k)
			}
			otherBy[k] += g.Lost
			continue
		}
		lost += g.Lost
		if !slices.Contains(lostOn, g.Host) {
			lostOn = append(lostOn, g.Host)
		}
	}
	if lost > 0 {
		// A failing line says what went wrong, not what was checked: never
		// "No events lost" above "95,229 events were overwritten".
		var names []string
		seen := map[string]bool{}
		for _, g := range r.Health.Gaps {
			if g.Lost > 0 && rollover.Critical(g.Channel) && !seen[g.Channel] {
				seen[g.Channel] = true
				names = append(names, rollover.Name(g.Channel))
			}
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "circle-check", Title: "Events lost to log rollover", Who: strings.Join(lostOn, ", "),
			What: fmt.Sprintf("%s: %s overwritten before they were collected", strings.Join(names, ", "), plural(int(lost), "event")), Count: frac(len(lostOn))})
	} else {
		lines = append(lines, CheckLine{Level: "ok", Icon: "circle-check", Title: "No events lost from the audit logs", What: fmt.Sprintf("%s collection runs", commas(r.Health.Runs)), Count: frac(0)})
	}
	if other > 0 {
		var parts []string
		for _, k := range otherNames {
			host, name, _ := strings.Cut(k, "\x00")
			if len(otherOn) > 1 {
				name += " on " + host // the line names the systems once
			}
			parts = append(parts, fmt.Sprintf("%s: %s overwritten", name, plural(int(otherBy[k]), "event")))
		}
		lines = append(lines, CheckLine{Level: "warn", Icon: "circle-check", Title: "Other logs overwrote events", Who: strings.Join(otherOn, ", "),
			What: strings.Join(parts, "; ") + " · see Audit health", Href: "#health/@logs", Count: frac(len(otherOn))})
	}

	if n := len(r.MissingReports); n > 0 {
		var names []string
		for _, m := range r.MissingReports {
			names = append(names, m.Name)
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "history", Title: "Earlier reports missing or changed",
			What: plural(n, "scheduled report") + " deleted, moved or changed, with the only copy of their original logs: " + strings.Join(names, ", "), Href: "#logs", Count: ""})
	}
	if l, ok := r.avCheckLine(r.avRows()); ok {
		lines = append(lines, l)
	}
	if l, ok := r.scapCheckLine(); ok {
		lines = append(lines, l)
	}
	if len(r.Removed) > 0 {
		lines = append(lines, CheckLine{Level: "warn", Icon: "history", Title: "Older reports removed",
			What: fmt.Sprintf("%s deleted under retention_days = %d, with their original logs: %s", plural(len(r.Removed), "report"), r.RetentionDays, strings.Join(r.Removed, ", ")), Count: ""})
	}
	if t := r.excludedText(); t != "" {
		lines = append(lines, CheckLine{Level: "warn", Icon: "user-x", Title: "Left out by your settings", What: t, Href: "#health", Count: ""})
	}

	// "Original logs archived" only when they were (AR7).
	bad := false
	if f := r.PackFailing; f != nil {
		bad = true
		lines = append(lines, CheckLine{Level: "bad", Icon: "hard-drive", Title: "Original logs not archived", Who: f.Host,
			What: "not archived since " + r.stamp(f.Since) + ": " + strings.TrimRight(f.Reason, ". "), Count: ""})
	}
	if hosts := r.leftOutHosts(); len(hosts) > 0 {
		bad = true
		var why []string
		for _, l := range r.LeftOut {
			w := strings.TrimRight(l.Reason, ". ")
			if l.Report != "" {
				w = l.Report + ": " + w
			}
			why = append(why, w)
		}
		title := "Original logs not in this report"
		if r.Interim {
			title = "Original logs left out of a report"
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "hard-drive", Title: title, Who: strings.Join(hosts, ", "),
			What: "archive failed its check and was set aside: " + strings.Join(why, "; "), Count: frac(len(hosts))})
	}
	// Original logs that waited past retention_days without a report
	// (RET1): kept, and raised here as well as on Original logs.
	if len(r.Overdue) > 0 {
		bad = true
		var hosts []string
		most := 0
		for _, o := range r.Overdue {
			if !containsFold(hosts, o.Host) {
				hosts = append(hosts, o.Host)
			}
			most = max(most, o.Days)
		}
		lines = append(lines, CheckLine{Level: "bad", Icon: "hard-drive", Title: "Original logs never put in a report", Who: strings.Join(hosts, ", "),
			What: fmt.Sprintf("waiting up to %d days; kept, as they may be the only copy", most), Href: "#logs", Count: frac(len(hosts))})
	}
	switch {
	case len(r.NoArchive) > 0:
		lines = append(lines, CheckLine{Level: "warn", Icon: "hard-drive", Title: "Original logs missing", Who: strings.Join(r.NoArchive, ", "), What: "no original logs for this period", Count: frac(len(r.NoArchive))})
	case bad:
	case len(r.Archives) > 0:
		var size uint64
		for _, a := range r.Archives {
			size += a.Bytes
		}
		lines = append(lines, CheckLine{Level: "ok", Icon: "hard-drive", Title: "Original logs archived", What: fmt.Sprintf("%s · %s · SHA-256 in manifest", plural(len(r.Archives), "zip"), humanBytes(size)), Count: frac(0)})
	default:
		what := "Kept with the scheduled report"
		if w := r.Waiting; w != nil && w.Dir != "" {
			what = "Waiting in " + w.Dir + " for the next scheduled report"
		}
		lines = append(lines, CheckLine{Level: "ok", Icon: "hard-drive", Title: "Original logs archived", What: what, Count: ""})
	}
	for i := range lines {
		lines[i].Href = checklistLink(lines[i])
	}
	return lines
}

// detectionCards lists the detections newest first, labelled by day.
// FoundAtReport labels a detection Blackbox's own check made when the
// report was made, after its period (UI21).
const FoundAtReport = "Found when this report was made"

func (r *Report) detectionCards() []DetectionCard {
	idx := make([]int, len(r.Findings))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return r.Findings[idx[a]].Time.After(r.Findings[idx[b]].Time) })
	var out []DetectionCard
	for _, i := range idx {
		f := r.Findings[i]
		t := f.Time.In(r.Location)
		c := DetectionCard{Day: t.Format("Mon 2 Jan"), Severity: string(f.Severity), Title: f.Title, Detail: f.Detail,
			Host: f.Host, Time: t.Format("15:04"), Index: i}
		if f.Check != "" && !f.Time.Before(r.WindowEnd) {
			// Found by Blackbox's own check after the period (UI21).
			c.Day, c.Time = FoundAtReport, ""
		}
		out = append(out, c)
	}
	return out
}

func times(n int) string {
	if n == 1 {
		return ""
	}
	if n == 2 {
		return " twice"
	}
	return fmt.Sprintf(" %d times", n)
}

func shortOS(s SystemRow) string {
	b := ""
	if s.Checks != nil {
		b = s.Checks.Baseline
	}
	switch {
	case strings.Contains(b, "Server 2025"):
		return "WS 2025"
	case strings.Contains(b, "Windows 11"):
		return "WIN 11"
	case strings.Contains(b, "Ubuntu"):
		if strings.Contains(b, "22") {
			return "UBU 22"
		}
		return "UBU 24"
	case strings.Contains(b, "Alma") || strings.Contains(b, "RHEL"):
		return "ALMA 8"
	}
	return strings.ToUpper(s.OSName())
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%d MB", b>>20)
	}
	return fmt.Sprintf("%d KB", (b+1023)>>10)
}

// naturalLess sorts WS-2 before WS-10.
func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		da, db := digits(a), digits(b)
		if da != "" && db != "" {
			if len(da) != len(db) {
				return len(da) < len(db)
			}
			if da != db {
				return da < db
			}
			a, b = a[len(da):], b[len(db):]
			continue
		}
		ca, cb := strings.ToLower(a[:1]), strings.ToLower(b[:1])
		if ca != cb {
			return ca < cb
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func digits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// checklistLink is where a health checklist line leads: the system named,
// or the page with the detail.
func checklistLink(l CheckLine) string {
	first := strings.SplitN(l.Who, ", ", 2)[0]
	switch l.Title {
	case "Logs intact", "Logs cleared":
		if first != "" {
			return searchLink("page", "integrity", "host", first)
		}
		return "#integrity"
	case "Every system reporting", "Not every system reporting":
		if first != "" {
			return "#systems/" + first
		}
		return "#systems"
	case "Audit settings match STIG", "Audit settings to fix", "Audit settings not checked":
		if first != "" && !strings.Contains(l.Who, ", ") {
			return "#health/" + first
		}
		return "#health"
	case "Original logs archived", "Original logs missing", "Original logs not archived", "Original logs not in this report", "Original logs left out of a report":
		if first != "" {
			return "#logs/" + first
		}
		return "#logs"
	}
	return "#health"
}
