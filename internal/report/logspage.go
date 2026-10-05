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
	Bytes                                             uint64
	Status, Class                                     string // Verified / Missing / Hash mismatch
	Files                                             []LogFile
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
}

// LogGroup is a group of systems in the O3 list.
type LogGroup struct {
	Title    string
	Archives []*LogArchive
}

func (r *Report) logsPage() *LogsPage {
	lp := &LogsPage{Kept: r.ArchivesKept || len(r.Archives) > 0}
	byHost := map[string]*LogArchive{}
	osOf := map[string]SystemRow{}
	for _, s := range r.SystemRows {
		osOf[strings.ToLower(s.Name)] = s
	}
	cleared := map[string][]time.Time{}
	for _, row := range r.rows {
		if row.Action == "log_cleared" {
			cleared[strings.ToLower(row.Host)] = append(cleared[strings.ToLower(row.Host)], row.Time)
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
		// What is inside, by log: the days of a bundle added together.
		type agg struct {
			file, log string
			from, to  time.Time
			bytes     int64
			hash      string
			days      int
			notes     []string
			gaps      []string
		}
		logs := map[string]*agg{}
		var order []string
		var infoBytes int64
		for _, info := range r.archiveState[a.Name].Contents {
			for _, f := range info.Files {
				base := f.Name
				if i := strings.LastIndex(base, "/"); i >= 0 {
					base = base[i+1:]
				}
				g := logs[base]
				if g == nil {
					g = &agg{file: base, log: f.Source, from: info.From}
					logs[base] = g
					order = append(order, base)
				}
				g.to = info.To
				g.bytes += f.Bytes
				g.days++
				g.hash = f.SHA256
			}
			for _, gp := range info.Gaps {
				for _, g := range logs {
					if strings.EqualFold(g.log, gp.Source) {
						g.gaps = append(g.gaps, gp.From.In(r.Location).Format("2 Jan 15:04")+" – "+gp.To.In(r.Location).Format("2 Jan 15:04"))
					}
				}
			}
			for _, n := range info.Notes {
				for _, g := range logs {
					if strings.Contains(n, g.log) {
						g.notes = append(g.notes, n)
					}
				}
			}
			infoBytes += 1024
		}
		sort.SliceStable(order, func(i, j int) bool { return logRank(logs[order[i]].log) < logRank(logs[order[j]].log) })
		var names []string
		for _, base := range order {
			g := logs[base]
			names = append(names, shortLog(g.log))
			lf := LogFile{File: g.file, Log: shortLog(g.log), Size: humanBytes(uint64(g.bytes)),
				Covers: g.from.In(r.Location).Format("2 Jan") + " – " + g.to.In(r.Location).Format("2 Jan")}
			if g.days == 1 && len(g.hash) > 6 {
				lf.Hash = g.hash[:6] + "…"
			} else if g.days > 1 {
				lf.Hash = fmt.Sprintf("%d days", g.days)
			}
			if n := read[h+"|"+strings.ToLower(g.log)]; n > 0 {
				lf.Events = commas(n)
			}
			isSec := strings.EqualFold(g.log, "Security") || strings.Contains(strings.ToLower(g.log), "audit")
			switch {
			case len(g.gaps) > 0:
				lf.Note, lf.NoteBad = "Missing "+strings.Join(g.gaps, ", ")+": overwritten before it was saved", true
			case lost[h+"|"+strings.ToLower(g.log)] > 0:
				lf.Note, lf.NoteBad = plural(int(lost[h+"|"+strings.ToLower(g.log)]), "event")+" overwritten before export", true
			case isSec && len(cleared[h]) > 0:
				lf.Note, lf.NoteBad = "Cleared "+cleared[h][0].In(r.Location).Format("2 Jan")+" · nothing lost", true
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

	// Grouped for the O3 list.
	groups := []*LogGroup{{Title: "Servers"}, {Title: "Workstations"}, {Title: "Virtual machines"}}
	for _, la := range lp.Archives {
		g := groups[1]
		if s, ok := osOf[strings.ToLower(la.Host)]; ok {
			switch {
			case s.Via != "":
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
