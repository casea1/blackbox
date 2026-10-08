package report

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// What each scheduled report saw (UI-R1, Trends' "New this week"): the
// administrators and accounts of each system, who used which system and
// how, the source addresses, the services installed and the USB devices.
// summary.json keeps these sets, so a later report can say what is new
// this week ("never seen in 8 weeks") and, for one event, whether its
// person was on its system before ("never on SRV-DC02 in 30 reports").
// The sets are read back from earlier reports' summaries like the weekly
// counts (weeks.go).

// Seen is summary.json's "seen". The sets by system are system → names
// (lower case); the others are lists of keys.
type Seen struct {
	Admins   map[string][]string `json:"admins,omitempty"`      // members of the administrators group, by system
	Accounts map[string][]string `json:"accounts,omitempty"`    // accounts, by system
	Paths    []string            `json:"logon_paths,omitempty"` // "person|SYSTEM|how": who logged on where, and how
	Active   []string            `json:"active,omitempty"`      // "person|SYSTEM": who did anything where
	Sources  []string            `json:"source_ips,omitempty"`  // addresses events came from
	Services map[string][]string `json:"services,omitempty"`    // services installed, by system
	USB      []string            `json:"usb,omitempty"`         // "SYSTEM|device id": removable devices connected
}

// The kinds of thing seen, in the order "New this week" lists them.
const (
	SeenAdmin   = "admin"
	SeenAccount = "account"
	SeenPath    = "path"
	SeenSource  = "source"
	SeenService = "service"
	SeenUSB     = "usb"
	SeenActive  = "active"
)

// seenKinds are the kinds "New this week" lists, with their labels and
// dot levels.
var seenKinds = []struct{ Kind, Label, Level string }{
	{SeenAdmin, "Admin", "bad"}, {SeenAccount, "Account", "warn"}, {SeenPath, "Logon path", "warn"},
	{SeenSource, "Source address", "warn"}, {SeenService, "Service", ""}, {SeenUSB, "USB device", ""},
}

// maxSeen bounds each list in summary.json (a network under attack from
// thousands of addresses): the first kept, in order.
const maxSeen = 5000

// seenSet is a Seen as kind → key → true. Keys by system are
// "SYSTEM\name".
type seenSet map[string]map[string]bool

func (s seenSet) add(kind, key string) {
	if key == "" {
		return
	}
	if s[kind] == nil {
		s[kind] = map[string]bool{}
	}
	s[kind][key] = true
}

func (s seenSet) addAll(o seenSet) {
	for k, keys := range o {
		for key := range keys {
			s.add(k, key)
		}
	}
}

// set flattens a Seen.
func (s *Seen) set() seenSet {
	out := seenSet{}
	if s == nil {
		return out
	}
	byHost := func(kind string, m map[string][]string) {
		for h, names := range m {
			for _, n := range names {
				out.add(kind, h+`\`+n)
			}
		}
	}
	byHost(SeenAdmin, s.Admins)
	byHost(SeenAccount, s.Accounts)
	byHost(SeenService, s.Services)
	for kind, list := range map[string][]string{SeenPath: s.Paths, SeenActive: s.Active, SeenSource: s.Sources, SeenUSB: s.USB} {
		for _, k := range list {
			out.add(kind, k)
		}
	}
	return out
}

// setKeyed is set with each person (the first part of an active or logon
// path key) keyed by pk: people_aliases applied to an earlier report's
// keys, so they match the People page.
func (s *Seen) setKeyed(pk func(string) string) seenSet {
	out := s.set()
	if pk == nil {
		return out
	}
	for _, kind := range []string{SeenActive, SeenPath} {
		keys := out[kind]
		if keys == nil {
			continue
		}
		out[kind] = map[string]bool{}
		for k := range keys {
			p, rest, ok := strings.Cut(k, "|")
			if ok {
				k = pk(p) + "|" + rest
			}
			out[kind][k] = true
		}
	}
	return out
}

// seenOf makes a Seen of a set, sorted, each list at most maxSeen.
func seenOf(set seenSet) *Seen {
	list := func(kind string) []string {
		var l []string
		for k := range set[kind] {
			l = append(l, k)
		}
		sort.Strings(l)
		if len(l) > maxSeen {
			l = l[:maxSeen]
		}
		return l
	}
	byHost := func(kind string) map[string][]string {
		var m map[string][]string
		for _, k := range list(kind) {
			h, n, ok := strings.Cut(k, `\`)
			if !ok {
				continue
			}
			if m == nil {
				m = map[string][]string{}
			}
			m[h] = append(m[h], n)
		}
		return m
	}
	return &Seen{Admins: byHost(SeenAdmin), Accounts: byHost(SeenAccount), Services: byHost(SeenService),
		Paths: list(SeenPath), Active: list(SeenActive), Sources: list(SeenSource), USB: list(SeenUSB)}
}

// seenNow is what this report saw: from its events, and the accounts of
// each system's latest inventory.
func (r *Report) seenNow() seenSet {
	if r.seenCache != nil {
		return r.seenCache
	}
	s := seenSet{}
	for _, cs := range r.CheckSets {
		if cs.Inventory == nil {
			continue
		}
		for _, a := range cs.Inventory.Accounts {
			s.add(SeenAccount, cs.Host+`\`+strings.ToLower(a.Name))
			if a.Admin {
				s.add(SeenAdmin, cs.Host+`\`+strings.ToLower(a.Name))
			}
		}
	}
	for _, row := range r.rows {
		for kind, key := range r.seenKeys(row.Event) {
			s.add(kind, key)
		}
	}
	r.seenCache = s
	return s
}

// seenKeys are the keys one event adds to what a report saw. People are
// keyed as on the People page (r.pkey, people_aliases applied).
func (r *Report) seenKeys(e *event.Event) map[string]string {
	out := map[string]string{}
	if pk := r.pkey(e.User); person(e.User) && !strings.HasPrefix(pk, "(") {
		out[SeenActive] = pk + "|" + e.Host
		if e.Category == event.CatLogon && (e.Action == "logon" || e.Action == "ssh_accepted" || e.Action == "admin_logon") {
			out[SeenPath] = pk + "|" + e.Host + "|" + logonHow(e)
		}
	}
	if ip := sourceAddr(e.SourceIP); ip != "" {
		out[SeenSource] = ip
	}
	switch e.Action {
	case "group_member_added":
		// Added to a privileged group: an administrator from now on.
		if e.Severity == event.SevHigh && e.Target != "" {
			out[SeenAdmin] = e.Host + `\` + personKey(e.Target)
		}
	case "account_created":
		if e.Target != "" {
			out[SeenAccount] = e.Host + `\` + personKey(e.Target)
		}
	case "service_installed":
		if n := serviceName(e); n != "" {
			out[SeenService] = e.Host + `\` + strings.ToLower(n)
		}
	case "usb_connected":
		if k := usbKey(e); k != "" {
			out[SeenUSB] = k
		}
	}
	return out
}

// sourceAddr is an event's source address worth keeping: not empty, a
// placeholder or this computer.
func sourceAddr(s string) string {
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

func serviceName(e *event.Event) string {
	if e.Target != "" {
		return e.Target
	}
	return detail(e, "Service name")
}

// usbKey names a removable device on its system: the device ID the
// event gives (deviceKey), else its name.
func usbKey(e *event.Event) string {
	if k := deviceKey(e); k != "" {
		return k
	}
	if e.Target != "" {
		return e.Host + "|" + strings.ToLower(e.Target)
	}
	return ""
}

// seenHistory is what each earlier scheduled report saw, oldest first:
// nil for a report made before the sets were kept.
func (r *Report) seenHistory() []seenSet {
	if r.seenHist != nil {
		return *r.seenHist
	}
	out := []seenSet{}
	defer func() { r.seenHist = &out }()
	for _, s := range r.History {
		if s.Interim {
			continue
		}
		if s.Seen == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, s.Seen.setKeyed(r.pkey))
	}
	return out
}

// SeenBefore says whether earlier reports saw the person of an event on
// its system (or, with no person, its source address, USB device or
// service): Seen of Reports earlier scheduled reports that kept what they
// saw. For the Event-detail panel's "Seen before".
type SeenBefore struct {
	Kind, Key string
	Where     string // "on SRV-DC02", "from 203.0.113.50"
	Seen      int
	Reports   int
}

// Text is "never on SRV-DC02 in 30 reports", "on SRV-DC02 in 12 of 30
// reports", or "" when no earlier report kept what it saw.
func (s SeenBefore) Text() string {
	if s.Reports == 0 || s.Key == "" {
		return ""
	}
	if s.Seen == 0 {
		return fmt.Sprintf("never %s in %s", s.Where, plural(s.Reports, "report"))
	}
	if s.Seen == s.Reports {
		return fmt.Sprintf("%s in all %s", s.Where, plural(s.Reports, "earlier report"))
	}
	return fmt.Sprintf("%s in %d of %s", s.Where, s.Seen, plural(s.Reports, "report"))
}

// seenBefore is SeenBefore for one event.
func (r *Report) seenBefore(e *event.Event) SeenBefore {
	keys := r.seenKeys(e)
	var sb SeenBefore
	switch {
	case keys[SeenActive] != "":
		sb = SeenBefore{Kind: SeenActive, Key: keys[SeenActive], Where: "on " + e.Host}
	case keys[SeenUSB] != "":
		sb = SeenBefore{Kind: SeenUSB, Key: keys[SeenUSB], Where: "on " + e.Host}
	case keys[SeenService] != "":
		sb = SeenBefore{Kind: SeenService, Key: keys[SeenService], Where: "on " + e.Host}
	case keys[SeenSource] != "":
		sb = SeenBefore{Kind: SeenSource, Key: keys[SeenSource], Where: "from " + keys[SeenSource]}
	default:
		return sb
	}
	sb.Seen, sb.Reports = r.seenCount(sb.Kind, sb.Key)
	return sb
}

// seenCount is how many earlier scheduled reports saw key, of those that
// kept what they saw.
func (r *Report) seenCount(kind, key string) (seen, reports int) {
	for _, s := range r.seenHistory() {
		if s == nil {
			continue
		}
		reports++
		if s[kind][key] {
			seen++
		}
	}
	return seen, reports
}
