package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The Original logs page (designs O1 and O3): the raw Windows and Linux
// logs this report was built from, one zip per system in the report
// folder, with their hashes; and for one system, what is inside its zip.

// LogArchive is one system's line on the Original logs page.
type LogArchive struct {
	Host, OS, Logs, Size, Short, SHA256, Name, Covers string
	// Coverage says, when the zip ends before the period does, where the
	// rest is (AR10).
	Coverage      string
	Bytes         uint64
	Status, Class string // Verified / Missing / Hash mismatch
	Files         []LogFile
	// Issues are logs that do not cover the whole period (AR2), and Notes
	// what the archives say about the period, e.g. a clock change (AR1).
	Issues, Notes []string

	// UI-R1 (design 09): the status chip (Complete, Gap, Missing, Set
	// aside, Hash mismatch) and its level, a short note (Brief; NoteFull
	// on hover), and what is inside ("3 .evtx · 3 pieces").
	Chip, ChipLevel, Brief, NoteFull, Inside string
}

// LogFile is one log inside a zip.
type LogFile struct {
	File, Log, Covers, Events, Size, Hash, Note string
	NoteBad                                     bool
}

// LogsPage is the Original logs page.
type LogsPage struct {
	Cards    []HealthCard
	Archives []*LogArchive
	Groups   []LogGroup
	// Table is every system's line, grouped Servers / Workstations, gaps
	// and missing first (UI-R1); AllN and GapsN count them for the switch.
	Table       []Group[*LogArchive]
	AllN, GapsN int
	Range       string
	Kept        bool
	// Manual: a manual report keeps no original logs; Waiting says where
	// they wait instead (UI5).
	Manual  bool
	Waiting string
	// Failing says the original logs on this computer could not be
	// archived, and why (AR5).
	Failing []string
}

// WaitingLogs is what of the original logs waits in archive_dir for the
// next scheduled report: the folder, the period and size so far, how many
// systems, and when that report is due (zero: at the next scheduled run).
type WaitingLogs struct {
	Dir      string
	From, To time.Time
	Bytes    uint64
	Systems  int
	Next     time.Time
}

// waitingText is the manual report's Original logs page in one paragraph.
func (r *Report) waitingText() string {
	w := r.Waiting
	next := "the next scheduled report"
	if w != nil && !w.Next.IsZero() {
		next = "the scheduled report due " + w.Next.In(r.Location).Format("Mon 2 Jan 15:04")
	}
	if w == nil || w.From.IsZero() {
		where := "where Blackbox keeps them"
		if w != nil && w.Dir != "" {
			where = "in " + w.Dir
		}
		return fmt.Sprintf("A manual report does not take the original logs: they stay %s, and %s holds them in its folder.", where, next)
	}
	return fmt.Sprintf("A manual report does not take the original logs: they wait in %s. So far they cover %s to %s, %s from %s. %s holds them in its folder.",
		w.Dir, r.stamp(w.From), r.stamp(w.To), humanBytes(w.Bytes), plural(w.Systems, "system"), capitalize(next))
}

// LogGroup is a group of systems in the O3 list.
type LogGroup struct {
	Title    string
	Archives []*LogArchive
}

func (r *Report) logsPage() *LogsPage {
	lp := &LogsPage{Kept: r.ArchivesKept || len(r.Archives) > 0}
	if f := r.PackFailing; f != nil {
		lp.Failing = append(lp.Failing, f.Text(r.stamp))
	}
	for _, l := range r.LeftOut {
		lp.Failing = append(lp.Failing, l.Text(r.stamp))
	}
	for _, o := range r.Overdue {
		lp.Failing = append(lp.Failing, o.Text(r.stamp))
	}
	// Earlier reports deleted or changed hold the only copy of their
	// period's original logs (on Audit health before UI-R1).
	if len(r.MissingReports) > 0 {
		t := "Earlier reports missing or changed: a scheduled report holds the only copy of its period's original logs and their hashes. These were deleted, moved or changed after they were written:"
		for _, m := range r.MissingReports {
			what := "missing"
			if m.Problem == "changed" {
				what = "changed (its manifest no longer matches)"
				if m.What != "" {
					what = "changed (" + m.What + ")"
				}
			}
			t += fmt.Sprintf(" %s (%s to %s), %s;", m.Name, r.stamp(m.From), r.stamp(m.To), what)
		}
		t = strings.TrimSuffix(t, ";") + ". Restore them from the backup. If they were moved or removed on purpose, record why: blackbox reports accept <name> \"why\"."
		lp.Failing = append(lp.Failing, t)
	}
	if r.Interim && len(r.Archives) == 0 {
		lp.Manual, lp.Waiting = true, r.waitingText()
		return lp
	}
	byHost := map[string]*LogArchive{}
	osOf := map[string]SystemRow{}
	for _, s := range r.SystemRows {
		osOf[strings.ToLower(s.Name)] = s
	}
	// Clears, by host and log (LC1): a 104 for the PowerShell log is
	// noted on that log, not on Security.
	cleared := map[string][]time.Time{}
	for _, row := range r.rows {
		if row.Action == "log_cleared" {
			log := row.Target
			if log == "" {
				log = "Security"
			}
			k := strings.ToLower(row.Host + "|" + log)
			cleared[k] = append(cleared[k], row.Time)
		}
	}
	lossAt := map[string]time.Time{} // when a log first overwrote events, by host and log
	for _, g := range r.Health.Gaps {
		k := strings.ToLower(g.Host + "|" + g.Channel)
		if g.Lost > 0 && (lossAt[k].IsZero() || g.From.Before(lossAt[k])) {
			lossAt[k] = g.From
		}
	}
	clock := func(t time.Time) string {
		if r.WindowEnd.Sub(r.WindowStart) <= 25*time.Hour {
			return t.In(r.Location).Format("15:04")
		}
		return t.In(r.Location).Format("2 Jan 15:04")
	}
	kinds := map[string]int{} // gaps by kind, for the "With a gap" card
	var kindOrder []string
	kind := func(k string) {
		if kinds[k] == 0 {
			kindOrder = append(kindOrder, k)
		}
		kinds[k]++
	}
	read := map[string]int{} // records read, by host and log
	lost := map[string]uint64{}
	for _, c := range r.Health.Channels {
		read[strings.ToLower(c.Host+"|"+c.Channel)] += c.Read
		lost[strings.ToLower(c.Host+"|"+c.Channel)] += c.Lost
	}
	var total uint64
	verified := 0
	var from, to time.Time
	for _, a := range r.Archives {
		h := strings.ToLower(a.Host)
		la := &LogArchive{Host: a.Host, Name: a.Name, SHA256: a.SHA256, Bytes: a.Bytes, Size: humanBytes(a.Bytes),
			Covers: a.From.In(r.Location).Format("2 Jan 15:04") + " – " + a.To.In(r.Location).Format("2 Jan 15:04")}
		if len(a.SHA256) > 6 {
			la.Short = a.SHA256[:6] + "…"
		}
		if s, ok := osOf[h]; ok {
			la.OS = osLabel(s)
		}
		// Each computer archives once a day on its own schedule, so its
		// zip need not line up with the period (AR10): say what it covers
		// and where the rest is.
		if ws := r.WindowStart; !ws.IsZero() && a.From.Before(ws.Add(-time.Minute)) {
			la.Notes = append(la.Notes, fmt.Sprintf("Starts at %s, before this period (%s): %s archives its logs once a day on its own schedule, so its zip holds them from there.",
				r.stamp(a.From), r.stamp(ws), a.Host))
		}
		if we := r.WindowEnd; !we.IsZero() && a.To.Before(we.Add(-time.Minute)) {
			la.Notes = append(la.Notes, fmt.Sprintf("Ends at %s: its logs from then to the end of this period (%s) are in the next scheduled report's folder.",
				r.stamp(a.To), r.stamp(we)))
			la.Coverage = "to " + a.To.In(r.Location).Format("2 Jan 15:04") + "; the rest in the next report"
		}
		la.Status, la.Class = "Verified", "ok"
		if st, ok := r.archiveState[a.Name]; ok && !st.Verified {
			la.Status, la.Class = "Hash mismatch", "bad"
		} else {
			verified++
		}
		total += a.Bytes
		if from.IsZero() || a.From.Before(from) {
			from = a.From
		}
		if a.To.After(to) {
			to = a.To
		}
		// What is inside, by log: the days of a bundle, and the pieces
		// exported at each collection, added together.
		type agg struct {
			file, log string
			from, to  time.Time
			covFrom   time.Time // oldest record present (AR2)
			lostOut   uint64    // overwritten before it could be exported
			bytes     int64
			hash      string
			files     int
			notes     []string
			gaps      []string
			lostFiles []string // exports deleted or unreadable before packing (AR5)
			clears    []string // the log cleared, by whom and when (LC2b)
			missing   []string // records missing, by position (AR8, AR9)
			changed   bool     // an export changed before packing (AR6)
		}
		logs := map[string]*agg{}
		var order []string
		var infoBytes int64
		var briefs []string
		pieces, gap := 0, false
		seenNote := map[string]bool{}
		for _, info := range r.archiveState[a.Name].Contents {
			for _, f := range info.Files {
				base := f.Name
				if i := strings.LastIndex(base, "/"); i >= 0 {
					base = base[i+1:]
				}
				key := strings.ToLower(f.Source)
				if key == "" {
					key = base
				}
				g := logs[key]
				if g == nil {
					g = &agg{file: base, log: f.Source, from: info.From}
					logs[key] = g
					order = append(order, key)
				}
				g.to = info.To
				g.bytes += f.Bytes
				g.files++
				g.hash = f.SHA256
				g.changed = g.changed || f.Changed
			}
			for _, c := range info.Logs {
				g := logs[strings.ToLower(c.Source)]
				if g == nil {
					// Nothing new from this log in the period, but what it
					// overwrote still counts.
					if c.Overwritten == 0 {
						continue
					}
					g = &agg{file: "—", log: c.Source, from: info.From, to: info.To}
					logs[strings.ToLower(c.Source)] = g
					order = append(order, strings.ToLower(c.Source))
				}
				if g.covFrom.IsZero() {
					g.covFrom = c.From
				}
				g.lostOut += c.Overwritten
			}
			for _, gp := range info.Gaps {
				if gp.Reason != "" && logs[strings.ToLower(gp.Source)] == nil {
					// Its only export was lost: the log is still listed.
					logs[strings.ToLower(gp.Source)] = &agg{file: "—", log: gp.Source, from: info.From, to: info.To}
					order = append(order, strings.ToLower(gp.Source))
				}
				for _, g := range logs {
					if strings.EqualFold(g.log, gp.Source) {
						span := gp.From.In(r.Location).Format("2 Jan 15:04") + " – " + gp.To.In(r.Location).Format("2 Jan 15:04")
						if gp.Records != "" {
							// Found by position (AR8, AR9).
							g.missing = append(g.missing, gp.Records+" ("+span+")")
							continue
						}
						if gp.Reason != "" {
							g.lostFiles = append(g.lostFiles, span)
							continue
						}
						if gp.Cleared != "" {
							g.clears = append(g.clears, gp.Cleared)
							continue
						}
						g.gaps = append(g.gaps, span)
					}
				}
			}
			for _, n := range info.Notes {
				matched := false
				for _, g := range logs {
					if strings.Contains(n, g.log) {
						g.notes = append(g.notes, n)
						matched = true
					}
				}
				if !matched && !seenNote[n] && n != "no new log records in this period" {
					seenNote[n] = true
					la.Notes = append(la.Notes, n)
				}
			}
			infoBytes += 1024
		}
		sort.SliceStable(order, func(i, j int) bool { return logRank(logs[order[i]].log) < logRank(logs[order[j]].log) })
		var names []string
		for _, key := range order {
			g := logs[key]
			names = append(names, shortLog(g.log))
			start := g.from
			late := !g.covFrom.IsZero() && g.covFrom.Sub(g.from) > time.Minute
			if late {
				start = g.covFrom
			}
			lf := LogFile{File: g.file, Log: shortLog(g.log), Size: humanBytes(uint64(g.bytes)),
				Covers: start.In(r.Location).Format("2 Jan 15:04") + " – " + g.to.In(r.Location).Format("2 Jan 15:04")}
			if g.files > 1 {
				lf.File = fmt.Sprintf("%s + %d more", g.file, g.files-1)
				lf.Hash = fmt.Sprintf("%d files", g.files)
			} else if len(g.hash) > 6 {
				lf.Hash = g.hash[:6] + "…"
			}
			if n := read[h+"|"+strings.ToLower(g.log)]; n > 0 {
				lf.Events = commas(n)
			}
			var parts []string
			pieces += g.files
			logName := shortLog(g.log) + " log"
			if late {
				parts = append(parts, "Covers from "+g.covFrom.In(r.Location).Format("2 Jan 15:04"))
				briefs = append(briefs, logName+" starts at "+clock(g.covFrom))
			}
			over := g.lostOut
			if over == 0 {
				over = lost[h+"|"+strings.ToLower(g.log)]
			}
			if over > 0 {
				b := fmt.Sprintf("%s overwrote %s", logName, plural(int(over), "event"))
				if t := lossAt[h+"|"+strings.ToLower(g.log)]; !t.IsZero() {
					b += " " + clock(t)
				}
				briefs = append(briefs, b)
				kind(shortLog(g.log) + " overwrite")
			}
			if g.changed {
				briefs = append(briefs, logName+" changed after it was exported")
				kind("changed")
			}
			if len(g.lostFiles) > 0 {
				briefs = append(briefs, logName+" export lost "+strings.Join(g.lostFiles, ", "))
				kind("export lost")
			}
			if len(g.gaps) > 0 {
				briefs = append(briefs, logName+" missing "+strings.Join(g.gaps, ", "))
				kind("missing")
			}
			if len(g.missing) > 0 {
				briefs = append(briefs, logName+" records missing")
				kind("missing")
			}
			if len(g.clears) > 0 {
				briefs = append(briefs, logName+" cleared "+strings.Join(g.clears, ", "))
				kind("log cleared")
			}
			switch {
			case g.lostOut > 0:
				what := commas(int(g.lostOut)) + " events were overwritten before they could be exported"
				if g.lostOut == 1 {
					what = "1 event was overwritten before it could be exported"
				}
				parts = append(parts, what)
				lf.NoteBad = true
			case lost[h+"|"+strings.ToLower(g.log)] > 0:
				parts = append(parts, plural(int(lost[h+"|"+strings.ToLower(g.log)]), "event")+" overwritten before export")
				lf.NoteBad = true
			}
			if g.changed {
				parts = append(parts, "Changed after it was exported: packed as it was found (see Detections)")
				lf.NoteBad = true
			}
			if len(g.lostFiles) > 0 {
				parts = append(parts, "Missing "+strings.Join(g.lostFiles, ", ")+": the export was deleted or unreadable before it was archived")
				lf.NoteBad = true
			}
			if len(g.gaps) > 0 {
				parts = append(parts, "Missing "+strings.Join(g.gaps, ", ")+": overwritten before it was saved")
				lf.NoteBad = true
			}
			if len(g.missing) > 0 {
				parts = append(parts, "Missing "+strings.Join(g.missing, ", ")+": not in the log when it was exported")
				lf.NoteBad = true
			}
			if len(g.clears) > 0 {
				// Cleared, not overwritten (LC2b): see Detections.
				parts = append(parts, "Cleared "+strings.Join(g.clears, ", ")+": its events from before then are not in this archive (see Detections)")
				lf.NoteBad = true
			}
			switch {
			case len(parts) > 0:
				lf.Note = strings.Join(parts, "; ")
				if late || lf.NoteBad {
					la.Issues = append(la.Issues, shortLog(g.log)+": "+strings.ToLower(lf.Note[:1])+lf.Note[1:])
				}
			case len(cleared[h+"|"+strings.ToLower(g.log)]) > 0:
				at := cleared[h+"|"+strings.ToLower(g.log)][0]
				lf.Note, lf.NoteBad = "Cleared "+at.In(r.Location).Format("2 Jan")+" · nothing lost", true
				briefs = append(briefs, logName+" cleared "+clock(at)+"; nothing lost")
				kind("log cleared")
			case len(g.notes) > 0:
				lf.Note = g.notes[0]
			}
			gap = gap || lf.NoteBad || late
			la.Files = append(la.Files, lf)
		}
		if len(r.archiveState[a.Name].Contents) > 0 {
			la.Files = append(la.Files, LogFile{File: "archive.json", Log: "—", Size: humanBytes(uint64(infoBytes)), Note: "File list + hashes"})
		}
		la.Logs = strings.Join(names, ", ")
		// Problems the collector found in the archive itself, with what
		// to do (on Audit health before UI-R1).
		for _, g := range a.Gaps {
			switch {
			case g.Records != "":
				gap = true
				la.Notes = appendOnce(la.Notes, "Records not in the log when it was exported ("+g.Source+": "+g.Records+"): the logs are exported in record order, so this is not the clock. To keep it from happening again, make the log larger (blackbox check gives the size); for audit serials, check auditd's lost count (auditctl -s).")
			case g.Reason != "":
				gap = true
				la.Notes = appendOnce(la.Notes, "Exports deleted or unreadable before they were archived ("+g.Reason+"): their events are in this report, the original copy of that time is not. Find who or what removed them: Blackbox's own folder is only changed by Blackbox.")
			}
		}
		if len(a.Changed) > 0 {
			gap = true
			var names []string
			for _, f := range a.Changed {
				names = append(names, f.Name)
			}
			la.Notes = append(la.Notes, "Changed after they were exported, and archived as found: "+strings.Join(names, ", ")+". Compare them with the events in this report (see Detections), and find who could write to the Blackbox data folder.")
		}
		if len(briefs) == 0 && gap {
			briefs = append(briefs, "a log is incomplete: see "+a.Host)
		}
		la.Brief = strings.Join(briefs, "; ")
		la.NoteFull = strings.Join(append(append([]string(nil), la.Issues...), la.Notes...), " ")
		la.Inside = insideText(la.Files, pieces)
		switch {
		case la.Class == "bad":
			la.Chip, la.ChipLevel = "Hash mismatch", "bad"
		case gap:
			la.Chip, la.ChipLevel = "Gap", "warn"
		default:
			la.Chip, la.ChipLevel = "Complete", "ok"
		}
		byHost[h] = la
		lp.Archives = append(lp.Archives, la)
	}
	silent := 0
	for _, h := range r.NoArchive {
		la := &LogArchive{Host: h, Status: "Missing", Class: "bad", Logs: "—", Size: "—", Short: "—", Chip: "Missing", ChipLevel: "bad",
			Brief: "no original logs for this period"}
		if s, ok := osOf[strings.ToLower(h)]; ok {
			la.OS = osLabel(s)
			if s.Status == "silent" {
				silent++
				la.Brief = "nothing received in this period"
				if !s.LastRun.IsZero() {
					la.Covers = "no data since " + s.LastRun.In(r.Location).Format("2 Jan 15:04")
					la.Brief = "nothing received since " + s.LastRun.In(r.Location).Format("2 Jan 15:04")
				}
			}
		}
		lp.Archives = append(lp.Archives, la)
	}
	// This report's archives set aside because they failed their check
	// (AR7): a line of their own, as well as the warning at the top.
	setAside := 0
	if !r.Interim {
		for _, l := range r.LeftOut {
			if l.Report != "" || byHost[strings.ToLower(l.Host)] != nil {
				continue
			}
			setAside++
			la := &LogArchive{Host: l.Host, Status: "Missing", Class: "bad", Logs: "—", Size: "—", Short: "—", Chip: "Set aside", ChipLevel: "bad",
				Brief: "archive failed its check; set aside in " + l.SetAside, Notes: []string{l.Text(r.stamp)}}
			if s, ok := osOf[strings.ToLower(l.Host)]; ok {
				la.OS = osLabel(s)
			}
			byHost[strings.ToLower(l.Host)] = la
			lp.Archives = append(lp.Archives, la)
		}
	}
	sort.SliceStable(lp.Archives, func(i, j int) bool {
		a, b := lp.Archives[i], lp.Archives[j]
		if (a.Class == "bad") != (b.Class == "bad") {
			return a.Class == "bad"
		}
		return naturalLess(a.Host, b.Host)
	})
	if !from.IsZero() {
		lp.Range = from.In(r.Location).Format("2 Jan 15:04") + " – " + to.In(r.Location).Format("2 Jan 15:04")
	}
	n := len(r.Archives)
	all := n + len(r.NoArchive) + setAside
	c1 := HealthCard{Label: "Original logs in this report", Value: fmt.Sprintf("%d / %d", n, all), Note: "one zip per system"}
	var miss []string
	if silent > 0 {
		miss = append(miss, plural(silent, "system")+" sent nothing (see Systems)")
	}
	if k := len(r.NoArchive) - silent; k > 0 {
		miss = append(miss, plural(k, "system")+" with no archive")
		c1.Level = "bad"
	}
	if setAside > 0 {
		miss = append(miss, fmt.Sprintf("%d set aside: failed its check", setAside))
		c1.Level = "bad"
	}
	if len(miss) > 0 {
		c1.Note = strings.Join(miss, " · ")
	}
	complete, gaps := 0, 0
	for _, la := range lp.Archives {
		switch la.Chip {
		case "Complete":
			complete++
		case "Gap":
			gaps++
		}
	}
	c2 := HealthCard{Label: "Complete", Value: commas(complete), Note: "every collection exported, nothing missing", Level: "ok"}
	if complete == 0 {
		c2.Level = ""
	}
	c3 := HealthCard{Label: "With a gap", Value: commas(gaps), Note: "nothing overwritten, cleared or lost"}
	if gaps > 0 {
		c3.Level = "warn"
		var parts []string
		for _, k := range kindOrder {
			w := k
			if kinds[k] > 1 && !strings.HasSuffix(k, "missing") && !strings.HasSuffix(k, "changed") && !strings.HasSuffix(k, "lost") {
				w += "s"
			}
			parts = append(parts, fmt.Sprintf("%d %s", kinds[k], w))
		}
		c3.Note = strings.Join(parts, " · ")
	}
	c4 := HealthCard{Label: "Checked", Value: "—", Note: "no zips in this report"}
	switch {
	case n > 0 && verified == n:
		c4.Value, c4.Level = "✓", "ok"
		// Each zip is checked whole against the SHA-256 recorded when it
		// was made; the files inside are not hashed one by one.
		c4.Note = fmt.Sprintf("all %s match their SHA-256 · %s", plural(n, "zip"), humanBytes(total))
		if n == 1 {
			c4.Note = "the zip matches its SHA-256 · " + humanBytes(total)
		}
	case n > 0:
		c4.Value, c4.Level = "✕", "bad"
		c4.Note = fmt.Sprintf("%d of %s do not match their SHA-256 · %s", n-verified, plural(n, "zip"), humanBytes(total))
		if n-verified == 1 {
			c4.Note = fmt.Sprintf("1 of %s does not match its SHA-256 · %s", plural(n, "zip"), humanBytes(total))
		}
	}
	lp.Cards = []HealthCard{c1, c2, c3, c4}

	// The table: grouped, gaps and missing first (UI-R1).
	rows := append([]*LogArchive(nil), lp.Archives...)
	problemsFirst(rows, func(a *LogArchive) string { return a.ChipLevel }, func(a *LogArchive) string { return a.Host })
	lp.Table = groupByKind(rows, func(a *LogArchive) string { return r.hostKind(a.Host) })
	lp.AllN = len(rows)
	for _, a := range rows {
		if a.Chip != "Complete" {
			lp.GapsN++
		}
	}

	// Grouped for the O3 list.
	groups := []*LogGroup{{Title: "Servers"}, {Title: "Workstations"}, {Title: "Virtual machines"}}
	for _, la := range lp.Archives {
		g := groups[1]
		if s, ok := osOf[strings.ToLower(la.Host)]; ok {
			switch {
			case s.VM:
				g = groups[2]
			case isServer(s):
				g = groups[0]
			}
		}
		g.Archives = append(g.Archives, la)
	}
	for _, g := range groups {
		if len(g.Archives) > 0 {
			lp.Groups = append(lp.Groups, *g)
		}
	}
	return lp
}

// shortLog is a log's everyday name: "PowerShell" for the PowerShell
// Operational log.
func shortLog(name string) string {
	if strings.Contains(name, "PowerShell") {
		return "PowerShell"
	}
	return name
}

// logRank orders logs the way people expect: the security logs first.
func logRank(name string) int {
	for i, n := range []string{"security", "audit", "auth", "system", "syslog", "application", "powershell"} {
		if strings.Contains(strings.ToLower(name), n) {
			return i
		}
	}
	return 99
}

// insideText is what a zip holds, short: "3 .evtx · 3 pieces", or
// "audit.log + 2 more · 3 pieces" when the logs are of different kinds.
func insideText(files []LogFile, pieces int) string {
	var names []string
	ext := ""
	same := true
	for _, f := range files {
		if f.File == "archive.json" || f.File == "—" {
			continue
		}
		name, _, _ := strings.Cut(f.File, " + ")
		names = append(names, name)
		e := ""
		if i := strings.LastIndex(name, "."); i > 0 {
			e = name[i:]
		}
		if len(names) == 1 {
			ext = e
		} else if e != ext {
			same = false
		}
	}
	var s string
	switch {
	case len(names) == 0:
		return ""
	case len(names) == 1:
		s = names[0]
	case same && ext != "":
		s = fmt.Sprintf("%d %s", len(names), ext)
	default:
		s = fmt.Sprintf("%s + %d more", names[0], len(names)-1)
	}
	return s + " · " + plural(pieces, "piece")
}

// appendOnce appends s to list unless it is there already.
func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
