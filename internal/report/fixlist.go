package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The fix list (FIX1) is a page for the administrators who fix what the
// report found: for each system with something to fix, the audit
// settings that don't match, the logs too small to keep their events,
// and the open SCAP findings by CAT, each with its fix and, where there is
// one, a command to copy. It has no events and no people in it.

//go:embed fixlist.html
var fixListHTML string

var fixListTmpl = template.Must(template.New("fixlist").Parse(fixListHTML))

// FixList is the page's data.
type FixList struct {
	Site, Period, Generated, Version string
	Systems                          []*FixSystem
	Settings, Logs, Cat1, Cat2, Cat3 int
	NoFixText                        bool // some SCAP findings came without fix text
}

// FixSystem is one system's fixes.
type FixSystem struct {
	Name, OS, Anchor string
	Windows          bool
	Settings         []FixItem
	Logs             []FixItem
	Scap             []FixScap
	Cat              [4]int
}

// FixItem is one setting or log to fix.
type FixItem struct {
	Title, STIG, Have, Want, Fix, Note, Level string
	Advice                                    bool
	Cmds                                      []FixCmd
}

// FixCmd is a command to copy, and where to run it.
type FixCmd struct{ Text, Where string }

// FixScap is one benchmark's open findings on a system.
type FixScap struct {
	Benchmark, When string
	Rules           []FixRule
}

// FixRule is one open SCAP finding.
type FixRule struct {
	OpenRule
	Cmds []FixCmd
}

// FixList builds the fix list from the report: every system with a
// setting to fix, a log losing events, or an open SCAP finding.
func (r *Report) FixList() *FixList {
	loc := r.Location
	if loc == nil {
		loc = time.Local
	}
	fl := &FixList{Site: r.Site, Version: r.Version, Generated: r.Generated.In(loc).Format("2 Jan 2006 15:04")}
	if !r.WindowStart.IsZero() {
		fl.Period = r.WindowStart.In(loc).Format("2 Jan 2006") + " – " + r.WindowEnd.In(loc).Format("2 Jan 2006")
	}
	hp := r.healthPage()
	if hp == nil {
		return fl // no systems
	}
	losses := map[string][]LossRow{}
	for _, l := range hp.Losses {
		losses[strings.ToUpper(l.Host)] = append(losses[strings.ToUpper(l.Host)], l)
	}
	var rows []*HealthRow
	for _, g := range hp.Groups {
		rows = append(rows, g.Rows...)
	}
	for _, row := range rows {
		s := &FixSystem{Name: row.Name, OS: row.Line, Anchor: "sys-" + safeAnchor(row.Name)}
		if i := strings.Index(s.OS, " · "); i > 0 {
			s.OS = s.OS[:i]
		}
		s.Windows = strings.HasPrefix(s.OS, "Windows")
		for _, l := range row.Table {
			if (l.Class != "bad" && l.Class != "warn") || l.Check == "Logs intact" || l.Check == "Reporting" || l.Check == "STIG compliance (SCAP)" {
				continue
			}
			it := FixItem{Title: l.Check, STIG: l.STIG, Have: l.Have, Want: l.Want, Fix: l.Fix, Level: l.Class, Advice: l.Advice}
			if it.STIG == "—" {
				it.STIG = ""
			}
			it.Cmds = fixCommands(l.Check, l.Fix, s.Windows)
			s.Settings = append(s.Settings, it)
		}
		for _, l := range losses[strings.ToUpper(row.Name)] {
			s.Logs = append(s.Logs, FixItem{Title: l.Log, Have: l.Lost + " events overwritten before Blackbox read them", Fix: l.Advice, Level: l.Level,
				Cmds: fixCommands(l.Log, l.Advice, s.Windows)})
		}
		for _, so := range row.Scap {
			fs := FixScap{Benchmark: so.Benchmark, When: so.When}
			for _, o := range so.Rules {
				fr := FixRule{OpenRule: o}
				if o.Script != "" {
					where := "Run as root"
					if o.Lang == "powershell" {
						where = "Run in PowerShell as administrator"
					}
					fr.Cmds = []FixCmd{{Text: o.Script, Where: where}}
				}
				if o.Fix == "" {
					fl.NoFixText = true
				}
				switch o.Cat {
				case "CAT I":
					s.Cat[1]++
				case "CAT II":
					s.Cat[2]++
				default:
					s.Cat[3]++
				}
				fs.Rules = append(fs.Rules, fr)
			}
			if len(fs.Rules) > 0 {
				s.Scap = append(s.Scap, fs)
			}
		}
		if len(s.Settings)+len(s.Logs)+len(s.Scap) == 0 {
			continue
		}
		fl.Settings += len(s.Settings)
		fl.Logs += len(s.Logs)
		fl.Cat1, fl.Cat2, fl.Cat3 = fl.Cat1+s.Cat[1], fl.Cat2+s.Cat[2], fl.Cat3+s.Cat[3]
		fl.Systems = append(fl.Systems, s)
	}
	// CAT I findings and STIG gaps first: what to fix first.
	gaps := func(s *FixSystem) int {
		n := 0
		for _, it := range s.Settings {
			if it.Level == "bad" && !it.Advice {
				n++
			}
		}
		return n
	}
	sort.SliceStable(fl.Systems, func(i, j int) bool {
		a, b := fl.Systems[i], fl.Systems[j]
		if a.Cat[1] != b.Cat[1] {
			return a.Cat[1] > b.Cat[1]
		}
		if ga, gb := gaps(a), gaps(b); ga != gb {
			return ga > gb
		}
		return naturalLess(a.Name, b.Name)
	})
	return fl
}

var anchorRE = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

func safeAnchor(s string) string { return anchorRE.ReplaceAllString(s, "-") }

var (
	auditWantRE = regexp.MustCompile(`Configure the following audit events: (Success and Failure|Success|Failure)`)
	logSizeRE   = regexp.MustCompile(`Event Log Service > ([^>]+?) > Specify the maximum log file size \(KB\): Enabled, (\d+)`)
	wevtutilRE  = regexp.MustCompile(`wevtutil sl "[^"]+" /(?:ms:\d+|e:true)`)
	// cmdStart are the commands a Linux fix may start with.
	cmdStart = regexp.MustCompile(`^(auditctl|systemctl|chmod|augenrules|blackbox|update-grub|grub2-mkconfig|apt|dnf|sed|install) `)
)

// fixCommands are the commands, ready to copy, that carry out a fix
// written in words: Windows audit policy and log sizes from their Group
// Policy settings, and the Linux commands a fix names.
func fixCommands(item, fix string, windows bool) []FixCmd {
	var out []FixCmd
	if windows {
		const where = "Run as administrator (Command Prompt or PowerShell), or set it in Group Policy as above"
		if m := auditWantRE.FindStringSubmatch(fix); m != nil && strings.Contains(fix, "Advanced Audit Policy") {
			c := `auditpol /set /subcategory:"` + item + `"`
			if strings.Contains(m[1], "Success") {
				c += " /success:enable"
			}
			if strings.Contains(m[1], "Failure") {
				c += " /failure:enable"
			}
			out = append(out, FixCmd{c, where})
		}
		if m := logSizeRE.FindStringSubmatch(fix); m != nil {
			kb, _ := strconv.ParseUint(m[2], 10, 64)
			out = append(out, FixCmd{fmt.Sprintf(`wevtutil sl "%s" /ms:%d`, strings.TrimSpace(m[1]), kb*1024), where})
		}
		for _, c := range wevtutilRE.FindAllString(fix, -1) {
			out = append(out, FixCmd{c, "Run as administrator (Command Prompt or PowerShell)"})
		}
		return out
	}
	// Linux: each part of "A, then B" that is a command, without what
	// follows it in brackets.
	for _, part := range regexp.MustCompile(`, then |; then |; and `).Split(fix, -1) {
		part = strings.TrimSpace(part)
		if i := strings.Index(part, " ("); i > 0 {
			part = part[:i]
		}
		if cmdStart.MatchString(part) {
			out = append(out, FixCmd{part, "Run as root"})
		}
	}
	return out
}

// WriteFixList writes the fix list page.
func (r *Report) WriteFixList(w io.Writer) error {
	return fixListTmpl.Execute(w, r.FixList())
}

// WriteFixListFile writes the fix list page to path.
func (r *Report) WriteFixListFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if err := r.WriteFixList(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
