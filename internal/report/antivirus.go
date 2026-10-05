package report

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/check"
)

// Antivirus on each system (Microsoft Defender on Windows, ClamAV on
// Linux): when its definitions were made, and whether it is protecting.
// Read from each system's latest settings check; Blackbox never updates
// or changes the antivirus.

// AVRow is one system on the Antivirus table.
type AVRow struct {
	Host, Product, Version string
	Dated                  string // when the definitions were made
	Age                    string // "3 days old"
	Protection             string // real-time protection, or the scanner service
	ProtectionBad          bool
	Status, Level          string // Current / Out of date / Unknown / Not checked; ok | bad | warn
	Checked                string // when the system was checked
	dated                  time.Time
}

// datedRE reads the date from a check made before 0.13, which had it only
// in the text: "version created on 2 Oct 2026 14:05" or "built on …".
var datedRE = regexp.MustCompile(`(?:created|built) on (\d{1,2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2})`)

func (r *Report) avRows() []AVRow {
	var out []AVRow
	for _, cs := range r.CheckSets {
		var defs, prot *check.Result
		for i := range cs.Results {
			res := &cs.Results[i]
			switch res.Item {
			case "Defender security intelligence", "ClamAV definitions":
				defs = res
			case "Defender real-time protection", "ClamAV scanner service":
				prot = res
			}
		}
		if defs == nil {
			continue
		}
		row := AVRow{Host: cs.Host, Checked: cs.Time.In(r.Location).Format("2 Jan 15:04"), Product: "Microsoft Defender"}
		if strings.HasPrefix(defs.Item, "ClamAV") {
			row.Product = "ClamAV"
		}
		if defs.Status == check.Info { // ClamAV not installed
			row.Product, row.Version, row.Status, row.Level = "None found", defs.Have, "Not checked", "warn"
			out = append(out, row)
			continue
		}
		row.Version, _, _ = strings.Cut(defs.Have, " · ")
		row.dated = defs.Dated
		if row.dated.IsZero() {
			if m := datedRE.FindStringSubmatch(defs.Have); m != nil {
				row.dated, _ = time.ParseInLocation("2 Jan 2006 15:04", m[1], r.Location)
			}
		}
		if !row.dated.IsZero() {
			row.Dated = row.dated.In(r.Location).Format("2 Jan 2006 15:04")
			row.Age = roughDuration(r.WindowEnd.Sub(row.dated)) + " old"
		}
		switch defs.Status {
		case check.Pass:
			row.Status, row.Level = "Current", "ok"
		case check.Fail:
			row.Status, row.Level = "Out of date", "bad"
		default:
			row.Status, row.Level = "Unknown", "warn"
		}
		if prot != nil {
			row.Protection = prot.Have
			row.ProtectionBad = prot.Status == check.Fail
			if row.ProtectionBad {
				row.Level = "bad"
			}
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank(out[i].Level) != rank(out[j].Level) {
			return rank(out[i].Level) < rank(out[j].Level)
		}
		return naturalLess(out[i].Host, out[j].Host)
	})
	return out
}

func rank(level string) int {
	return map[string]int{"bad": 0, "warn": 1, "ok": 2}[level]
}

// avCheckLine is the Overview's antivirus line: the oldest definitions,
// and any system that is out of date or not protecting.
func (r *Report) avCheckLine(rows []AVRow) (CheckLine, bool) {
	if len(rows) == 0 {
		return CheckLine{}, false
	}
	l := CheckLine{Icon: "shield", Title: "Antivirus definitions", Href: "#health/@av", Level: "ok"}
	var oldest *AVRow
	var bad, warn []string
	for i := range rows {
		row := &rows[i]
		if !row.dated.IsZero() && (oldest == nil || row.dated.Before(oldest.dated)) {
			oldest = row
		}
		switch row.Level {
		case "bad":
			bad = append(bad, row.Host)
		case "warn":
			warn = append(warn, row.Host)
		}
	}
	switch {
	case len(bad) > 0:
		l.Level, l.Who = "bad", strings.Join(bad, ", ")
		l.What = "out of date or not protecting"
	case len(warn) > 0:
		l.Level, l.Who = "warn", strings.Join(warn, ", ")
		l.What = "definitions date unknown, or no antivirus found"
	}
	if oldest != nil {
		s := "oldest definitions dated " + oldest.Dated + " (" + oldest.Age + ", " + oldest.Host + ")"
		if l.What == "" {
			l.What = s
		} else {
			l.What += " · " + s
		}
	}
	return l, true
}
