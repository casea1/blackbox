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
}

// LogFile is one log inside a zip.
type LogFile struct {
	File, Log, Covers, Events, Size, Hash, Note string
	NoteBad                                     bool
}

// LogsPage is the Original logs page.
type LogsPage struct {
	Stats    []EventCard
	Archives []*LogArchive
	Groups   []LogGroup
	Range    string
	Kept     bool
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
			changed   bool     // an export changed before packing (AR6)
		}
		logs := map[string]*agg{}
		var order []string
		var infoBytes int64
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
			if late {
				parts = append(parts, "Covers from "+g.covFrom.In(r.Location).Format("2 Jan 15:04"))
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
				lf.Note, lf.NoteBad = "Cleared "+cleared[h+"|"+strings.ToLower(g.log)][0].In(r.Location).Format("2 Jan")+" · nothing lost", true
			case len(g.notes) > 0:
				lf.Note = g.notes[0]
			}
			la.Files = append(la.Files, lf)
		}
		if len(r.archiveState[a.Name].Contents) > 0 {
			la.Files = append(la.Files, LogFile{File: "archive.json", Log: "—", Size: humanBytes(uint64(infoBytes)), Note: "File list + hashes"})
		}
		la.Logs = strings.Join(names, ", ")
		byHost[h] = la
		lp.Archives = append(lp.Archives, la)
	}
	var missingWho []string
	for _, h := range r.NoArchive {
		la := &LogArchive{Host: h, Status: "Missing", Class: "bad", Logs: "—", Size: "—", Short: "—"}
		if s, ok := osOf[strings.ToLower(h)]; ok {
			la.OS = osLabel(s)
			if s.Status == "silent" && !s.LastRun.IsZero() {
				missingWho = append(missingWho, h+" · no data since "+s.LastRun.In(r.Location).Format("2 Jan"))
				la.Covers = "no data since " + s.LastRun.In(r.Location).Format("2 Jan 15:04")
			} else {
				missingWho = append(missingWho, h)
			}
		}
		lp.Archives = append(lp.Archives, la)
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
	lvl := func(bad bool, l string) string {
		if bad {
			return l
		}
		return ""
	}
	lp.Stats = []EventCard{
		{Icon: "hard-drive", Label: "Archives", Value: commas(n), Note: "one zip per system"},
		{Icon: "file-text", Label: "Total size", Value: humanBytes(total), Note: "compressed"},
		{Icon: "fingerprint", Label: "Hashes verified", Value: fmt.Sprintf("%d / %d", verified, n), Note: "SHA-256 match", Level: lvl(verified < n, "bad")},
		{Icon: "clock-alert", Label: "Missing", Value: commas(len(r.NoArchive)), Note: strings.Join(missingWho, ", "), Level: lvl(len(r.NoArchive) > 0, "bad")},
	}
	// Archives set aside count as missing (AR7).
	if left := r.leftOutHosts(); len(left) > 0 && !r.Interim {
		missing := len(r.NoArchive) + len(r.LeftOut)
		lp.Stats[3] = EventCard{Icon: "clock-alert", Label: "Missing", Value: commas(missing),
			Note: strings.Join(append(missingWho, plural(len(r.LeftOut), "day")+" set aside: "+strings.Join(left, ", ")), ", "), Level: "bad"}
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
