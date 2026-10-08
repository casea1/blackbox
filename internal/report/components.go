package report

import (
	"fmt"
	"sort"
	"strings"
)

// Shared building blocks of the report's pages (UI-R1). Each has a Go
// type or helper here, a template define in template.html and CSS in
// style.css; pages put them together instead of making their own.
//
//   - systemKind / (*Report).hostKind: a system is a "server", a
//     "workstation" or a "vm" (UX10: Windows Server, RHEL/Alma, a Linux
//     computer with no desktop are servers).
//   - groupByKind: a list of systems (or anything about one) as the groups
//     "Servers · n", "Workstations · n", "Virtual machines · n", empty
//     groups left out. Group.Label is the heading; with problems counted it
//     reads "Servers · 5 with problems".
//   - problemsFirst: sorts by level, problems first (bad, warn, ok, no
//     data), then by name. levelRank gives the order.
//   - CheckCell and {{template "cell" .}}: one small square, ok / warning /
//     problem / no data, with its meaning in words for screen readers and on
//     hover; {{template "cellkey"}} is the legend.
//   - FoldRow and {{template "foldrow" .}}: "22 more systems with no
//     problems (14 with warnings, 8 all OK) · Show". The folded items are
//     in an element with data-folded="<ID>" and the hidden attribute; Show
//     opens it (app.js), Hide closes it again.
//   - ListItem and {{template "li1" .}}: a compact one-line item (title,
//     short reason, system, time) that links to its detail, for summary
//     lists: "a detection opens on Detections at that detection".
//
// Levels everywhere are "bad" (a problem), "warn" (a warning), "ok", and ""
// (no data).

// systemKind classifies a system: "vm", "server" or "workstation".
func systemKind(s SystemRow) string {
	switch {
	case s.VM:
		return "vm"
	case isServer(s):
		return "server"
	}
	return "workstation"
}

// hostKind is systemKind by name ("workstation" for a name not among the
// report's systems).
func (r *Report) hostKind(host string) string {
	for _, list := range [][]SystemRow{r.SystemRows, r.Retired} {
		for _, s := range list {
			if strings.EqualFold(s.Name, host) {
				return systemKind(s)
			}
		}
	}
	return "workstation"
}

// kindTitles are the groups' headings, in the order they are shown.
var kindTitles = []struct{ Kind, Title string }{{"server", "Servers"}, {"workstation", "Workstations"}, {"vm", "Virtual machines"}}

// Group is one group of a list: its heading and its items.
type Group[T any] struct {
	Kind     string // server | workstation | vm
	Title    string // Servers, Workstations, Virtual machines
	Items    []T
	Problems int // items with a problem, when the list counts them (see CountProblems)
}

// Label is the group's heading: "Servers · 11", or "Servers · 5 with
// problems" once problems are counted.
func (g Group[T]) Label() string {
	if g.Problems > 0 {
		return fmt.Sprintf("%s · %d with %s", g.Title, g.Problems, map[bool]string{true: "a problem", false: "problems"}[g.Problems == 1])
	}
	return fmt.Sprintf("%s · %d", g.Title, len(g.Items))
}

// groupByKind splits items into Servers, Workstations and Virtual
// machines, keeping their order within each group; kind names an item's
// kind (systemKind, or r.hostKind of its system).
func groupByKind[T any](items []T, kind func(T) string) []Group[T] {
	var out []Group[T]
	for _, k := range kindTitles {
		g := Group[T]{Kind: k.Kind, Title: k.Title}
		for _, it := range items {
			if kind(it) == k.Kind {
				g.Items = append(g.Items, it)
			}
		}
		if len(g.Items) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// systemsByKind is the report's systems in list order: servers, then
// workstations, then virtual machines, by name within each.
func (r *Report) systemsByKind() []SystemRow {
	list := append([]SystemRow(nil), r.SystemRows...)
	sort.SliceStable(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	var out []SystemRow
	for _, g := range groupByKind(list, systemKind) {
		out = append(out, g.Items...)
	}
	return out
}

// CountProblems sets each group's Problems from the items' levels.
func CountProblems[T any](groups []Group[T], level func(T) string) {
	for i := range groups {
		groups[i].Problems = 0
		for _, it := range groups[i].Items {
			if level(it) == "bad" {
				groups[i].Problems++
			}
		}
	}
}

// levelRank orders levels for problemsFirst: bad, warn, ok, no data.
func levelRank(level string) int {
	switch level {
	case "bad":
		return 0
	case "warn":
		return 1
	case "ok":
		return 2
	}
	return 3
}

// problemsFirst sorts items in place: problems first, then warnings, OK
// and no data; by name within a level (case-insensitive).
func problemsFirst[T any](items []T, level func(T) string, name func(T) string) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := levelRank(level(items[i])), levelRank(level(items[j]))
		if a != b {
			return a < b
		}
		return strings.ToLower(name(items[i])) < strings.ToLower(name(items[j]))
	})
}

// CheckCell is one square of a system's checks: Level is bad, warn, ok or
// "" (no data). Label names the check ("Reporting"), Title says what was
// found ("nothing since 6 Oct"), Href opens the detail.
type CheckCell struct {
	Level, Label, Title, Href string
}

// Word is the level in words, for the legend and screen readers.
func (c CheckCell) Word() string {
	switch c.Level {
	case "bad":
		return "problem"
	case "warn":
		return "warning"
	case "ok":
		return "ok"
	}
	return "no data"
}

// Class is the square's CSS class.
func (c CheckCell) Class() string {
	if c.Level == "" {
		return "na"
	}
	return c.Level
}

// FoldRow is the line in place of quiet items: "22 more systems with no
// problems (14 with warnings, 8 all OK) · Show". ID ties it to the element
// holding them (data-folded="ID").
type FoldRow struct {
	ID   string
	Text string
}

// foldText is the usual wording: "22 more systems with no problems", with
// what they are in brackets when given ("14 with warnings, 8 all OK").
func foldText(n int, noun, what, detail string) string {
	s := fmt.Sprintf("%s more %s", commas(n), noun)
	if n == 1 {
		s = "1 more " + strings.TrimSuffix(noun, "s")
	}
	if what != "" {
		s += " " + what
	}
	if detail != "" {
		s += " (" + detail + ")"
	}
	return s
}

// ListItem is one line of a summary list: a title, one short reason, the
// system and the time, linking to the detail (Href, or Ev to open one
// event). Level colours its dot: bad (high), warn (medium), "" none.
type ListItem struct {
	Title, Reason, System, Time string
	Href, Ev                    string
	Level                       string
}

// systemLevel is a system's level on Overview's Systems at a glance and
// on the Systems page, decided once for both (owner, UI-R1): a problem
// ("bad") is a red check, a high detection or a red Delivery line (its
// deliveries wait for approval or a rekey, or its key is on another
// computer too); a warning ("warn") an amber check, a medium detection
// or an unsigned sender; otherwise "ok". cells are its six checks
// (sysChecks); high and med its detections; deliv its Delivery's Level.
func systemLevel(cells []CheckCell, high, med int, deliv string) string {
	level := "ok"
	for _, c := range cells {
		if levelRank(c.Level) < levelRank(level) {
			level = c.Level
		}
	}
	switch {
	case high > 0 || deliv == "bad":
		return "bad"
	case (med > 0 || deliv == "warn") && level == "ok":
		return "warn"
	}
	return level
}

// deliveryShort is a red or amber Delivery line in a few words, for a
// system's chip and Systems at a glance.
func deliveryShort(d *Delivery) string {
	switch {
	case d == nil:
		return ""
	case d.Held:
		return "delivery waiting for approval"
	case d.NewKeyFP != "":
		return "delivery signed with a new key"
	case d.SharedWith != "":
		return "delivery key shared with " + d.SharedWith
	case !d.Signed:
		return "unsigned deliveries"
	}
	return ""
}

// sysDets is how many high and other detections each system has (by
// lower-case name), and the newest high one's title, for systemLevel.
type sysDets struct {
	High, Med int
	FirstHigh string
}

func (r *Report) detsBySystem() map[string]*sysDets {
	out := map[string]*sysDets{}
	for _, c := range r.detectionCards() { // newest first
		h := strings.ToLower(c.Host)
		d := out[h]
		if d == nil {
			d = &sysDets{}
			out[h] = d
		}
		if c.Severity == "high" {
			if d.High == 0 {
				d.FirstHigh = c.Title
			}
			d.High++
		} else {
			d.Med++
		}
	}
	return out
}

// checkCells are a system's checks' squares.
func checkCells(checks []SysCheck) []CheckCell {
	out := make([]CheckCell, 0, len(checks))
	for _, c := range checks {
		out = append(out, c.CheckCell)
	}
	return out
}
