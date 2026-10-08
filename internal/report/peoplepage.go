package report

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// The People page (UI-R1 §5, images 06 and 07). With local accounts only,
// the same person has a separate account on each system: accounts with
// the same name (and the spellings people_aliases lists) are one row.
//
//   - The list: Administrators, Users, and Shared and service accounts,
//     each name with one short line and a detection count, quiet ones
//     folded; All / Detections / Admins and a search box above it.
//   - A person: a summary line, six facts, Where and when (one lane per
//     system with their sessions and detections), Notable actions, and
//     Accounts named <name> (one row per system's account).
//   - A shared or built-in account (root, Administrator, a service
//     account): who acted as it (sudo, su, RunAs by a person; jobs and
//     services; direct logons), a plain statement of whether anyone logged
//     on as it directly, and Where and when.

// PersonView is one account on the People page.
type PersonView struct {
	Key, Name string
	Group     string // admin | user | shared
	Shared    bool   // a shared, built-in or service account (image 07)
	Sub       string // the list's line: "admin on 9 systems"
	Find      string // other spellings, for the search box
	Det, High int    // detections involving them
	Level     string // bad (a high detection) | warn | ""
	Line      string // "Local account on 9 systems · administrator on all 9 · used on 5 this period"
	Chip      string // "3 detections · 2 high"
	Facts     []PFact

	// A shared account: who acted as it, and the box saying whether
	// anyone logged on as it directly.
	Acted, ActedMore, ActedFixed []ActedRow
	ActedFold                    FoldRow
	CallLead, CallText, CallEnd  string
	CallBad                      bool

	Lanes        *Lanes
	Notable      []NoteLine
	NotableCount int
	AllEvents    int
	AllHref      string

	// Accounts named <name>: the systems' accounts used this period, and
	// those that exist (inventory) but were not used.
	Accounts []AcctRow
	AcctMore []AcctRow // folded: "+18 more accounts used · Show"
	AcctFold FoldRow
	Unused   []AcctRow
	AcctAll  int
	Merged   []string // other spellings merged by people_aliases
	Example  string   // a different spelling, for the note ("j.lee")

	Detections []DetectionCard
	Trend      *PersonTrend // activity over the earlier reports

	systems int // for sorting the list
}

// PFact is one of the six facts at the top of a person.
type PFact struct {
	Label, Value, Note, Href string
	Bad                      bool
}

// ActedRow is one line of "Who acted as root".
type ActedRow struct {
	Person, How, Systems string
	N                    int
	Href                 string
	Quiet                bool // a row with nothing in it ("none")
}

// NoteLine is one of a person's notable actions.
type NoteLine struct {
	Level, Time, Host, Text, Ev string
}

// AcctRow is one system's account in "Accounts named <name>".
type AcctRow struct {
	Host, Account, Rights, Last, Note string
	Logons                            int
	Href                              string
}

// PeopleGroup is one group of the People page's list. Shown are listed;
// Folded are behind "N more … · Show".
type PeopleGroup struct {
	Title  string
	People []*PersonView
	Shown  []*PersonView
	Folded []*PersonView
	Fold   FoldRow
}

// PeoplePage is the People page.
type PeoplePage struct {
	Groups          []PeopleGroup
	Count           int
	DetN, AdminN    int
	Example         string // the name on most systems, for the footnote
	ExampleN        int
	Unused, Systems int // local accounts not used this period, on Systems systems with an inventory
	HasInventory    bool
	people          map[string]*PersonView
	csvRows         [][]string
}

// personKey is how an account is matched across events and systems: lower
// case, without its domain or computer name. people_aliases is applied by
// (*Report).pkey.
func personKey(u string) string {
	l := strings.ToLower(strings.TrimSpace(u))
	if i := strings.LastIndex(l, `\`); i >= 0 {
		l = l[i+1:]
	}
	if i := strings.Index(l, "@"); i > 0 {
		l = l[:i]
	}
	return l
}

// pkey is personKey with people_aliases applied: "j.lee" → "jlee" when
// people_aliases = jlee=j.lee.
func (r *Report) pkey(u string) string {
	k := personKey(u)
	if a, ok := r.PeopleAliases[k]; ok {
		return a
	}
	return k
}

func serviceAccount(k string) bool {
	return strings.HasPrefix(k, "svc") || strings.HasPrefix(k, "service") || strings.HasSuffix(k, "_svc") || strings.HasPrefix(k, "sa_")
}

// builtinAccount is an account the operating system makes on every
// system: root, Administrator.
func builtinAdmin(k string) bool { return k == "administrator" || k == "root" || k == "admin" }

// sharedAccount is an account that is not one person: a built-in one, or
// a service account.
func sharedAccount(k string) bool { return builtinAdmin(k) || serviceAccount(k) }

// actedAs says which account a person's event acted as, and how: sudo,
// su and pkexec on Linux (root unless another account is named), RunAs
// (explicit credentials) on Windows. "" when it did not act as another
// account.
func actedAs(e *event.Event) (acct, how string) {
	target := e.Target
	switch e.Action {
	case "sudo", "sudo_command", "root_shell":
		how = "sudo"
	case "root_command":
		how = "root shell"
	case "audit_tamper_command":
		if e.OS != "linux" {
			return "", ""
		}
		how = "root shell"
		if strings.HasSuffix(e.Process, "sudo") || e.RecordType == "USER_CMD" {
			how = "sudo"
		}
	case "switch_user":
		how = "su"
	case "pkexec":
		how = "pkexec"
	case "explicit_credentials":
		if target == "" {
			return "", ""
		}
		how = "RunAs"
	default:
		return "", ""
	}
	if target == "" {
		target = "root"
	}
	return target, how
}

// logonWay says how a logon was made: Remote Desktop, SSH, console,
// network, job (a scheduled task or batch), service, or "" (not known).
func logonWay(e *event.Event) string {
	lt := strings.ToLower(detail(e, "Logon type"))
	sum := strings.ToLower(e.Summary)
	switch {
	case strings.Contains(lt, "remote desktop") || strings.Contains(sum, "remote desktop"):
		return "Remote Desktop"
	case strings.Contains(lt, "ssh") || e.RecordType == "sshd" || strings.Contains(sum, "ssh"):
		return "SSH"
	case strings.Contains(lt, "scheduled") || strings.Contains(lt, "batch"):
		return "job"
	case strings.Contains(lt, "service"):
		return "service"
	case strings.Contains(lt, "keyboard") || strings.Contains(lt, "console") || strings.Contains(lt, "unlock") || strings.Contains(lt, "interactive"):
		return "console"
	case strings.Contains(lt, "network") || strings.Contains(lt, "runas"):
		return "network"
	}
	return ""
}

// hostStat is one person's activity on one system.
type hostStat struct {
	events, logons, admin int
	last                  time.Time
	names                 map[string]*spelling // the account spellings used there (personKey before aliases)
}

// spelling is one account spelling's use on one system.
type spelling struct {
	logons, admin int
	last          time.Time
}

type actedStat struct {
	person, how string
	hosts       map[string]bool
	n           int
}

type personData struct {
	key, name, domainName string
	hosts                 map[string]*hostStat
	logons, admin         int
	ways                  map[string]int
	failed                int
	failedHosts           map[string]bool
	afterHours            int
	created, admined      bool
	notable               []*Row
	events                int
	findings              map[int]bool
	lane                  []laneEvent // own events and events acting as this account, in time order

	// A shared account.
	acted                   map[string]*actedStat // person|how → who acted as it
	jobs, direct            int
	jobHosts, directHosts   map[string]bool
	directWays              map[string]int
	jobsAfter               int
	actedAfter, directAfter int
}

func (r *Report) peoplePage() *PeoplePage {
	totals := map[string]PersonSummary{}
	for _, t := range r.peopleTotals() {
		totals[t.Key] = t
	}
	labels := r.weekLabels()
	people := map[string]*personData{}
	get := func(u string) *personData {
		k := r.pkey(u)
		p := people[k]
		if p == nil {
			p = &personData{key: k, hosts: map[string]*hostStat{}, ways: map[string]int{}, failedHosts: map[string]bool{}, findings: map[int]bool{},
				acted: map[string]*actedStat{}, jobHosts: map[string]bool{}, directHosts: map[string]bool{}, directWays: map[string]int{}}
			people[k] = p
		}
		name := u
		if i := strings.LastIndex(u, `\`); i >= 0 {
			name = u[i+1:]
		}
		// The name as written, preferring the spelling it is listed under.
		if p.name == "" || personKey(p.name) != k && personKey(name) == k {
			p.name = name
		}
		if strings.Contains(u, `\`) && p.domainName == "" {
			p.domainName = u
		}
		return p
	}
	host := func(p *personData, h string) *hostStat {
		s := p.hosts[h]
		if s == nil {
			s = &hostStat{names: map[string]*spelling{}}
			p.hosts[h] = s
		}
		return s
	}
	// Accounts in a detection: by who did it, and who it was done to.
	findingRows := map[int][]int{}
	for fi, f := range r.Findings {
		for _, id := range f.RowIDs {
			findingRows[rowIndex(id)] = append(findingRows[rowIndex(id)], fi)
		}
	}
	for i, row := range r.rows {
		e := row.Event
		fis := findingRows[i]
		if person(e.User) {
			p := get(e.User)
			k := p.key
			hs := host(p, e.Host)
			hs.events++
			sp := hs.names[personKey(e.User)]
			if sp == nil {
				sp = &spelling{}
				hs.names[personKey(e.User)] = sp
			}
			if e.Time.After(hs.last) {
				hs.last = e.Time
			}
			if e.Time.After(sp.last) {
				sp.last = e.Time
			}
			p.events++
			after := r.outsideHours(e)
			switch {
			case e.Category == event.CatLogon && e.Action == "logon":
				p.logons++
				hs.logons++
				sp.logons++
				way := logonWay(e)
				p.ways[way]++
				if sharedAccount(k) {
					if way == "job" || way == "service" {
						p.jobs++
						p.jobHosts[e.Host] = true
					} else {
						p.direct++
						p.directHosts[e.Host] = true
						p.directWays[way]++
						if after {
							p.directAfter++
						}
					}
				}
			case e.Category == event.CatPrivileged:
				p.admin++
				hs.admin++
				sp.admin++
				if after {
					p.afterHours++
				}
			}
			if sharedAccount(k) && e.Category != event.CatLogon {
				p.jobs++
				p.jobHosts[e.Host] = true
				if after {
					p.jobsAfter++
				}
			}
			for _, fi := range fis {
				p.findings[fi] = true
			}
			if notableRow(row, len(fis) > 0) {
				p.notable = append(p.notable, row)
			}
			p.lane = append(p.lane, laneEvent{row: row, own: true, finds: fis})
			// Acting as another account: sudo, su, RunAs.
			if acct, how := actedAs(e); acct != "" && person(acct) && r.pkey(acct) != k {
				a := get(acct)
				s := a.acted[k+"|"+how]
				if s == nil {
					s = &actedStat{person: p.name, how: how, hosts: map[string]bool{}}
					a.acted[k+"|"+how] = s
				}
				s.n++
				s.hosts[e.Host] = true
				if after {
					a.actedAfter++
				}
				a.lane = append(a.lane, laneEvent{row: row, finds: fis})
				for _, fi := range fis {
					a.findings[fi] = true
				}
			}
		}
		// Failed logons against an account.
		if e.Category == event.CatFailedLogon {
			who := e.Target
			if who == "" {
				who = e.User
			}
			if person(who) && people[r.pkey(who)] == nil && len(fis) > 0 {
				get(who) // a guessed-at account in a detection is listed
			}
			if p := people[r.pkey(who)]; p != nil && person(who) {
				for _, fi := range fis {
					p.findings[fi] = true
				}
			}
		}
		// The account something was done to.
		if e.Target != "" && person(e.Target) && r.pkey(e.Target) != r.pkey(e.User) && e.Category != event.CatFailedLogon {
			k := r.pkey(e.Target)
			switch {
			case strings.HasSuffix(e.Action, "account_created"):
				get(e.Target).created = true
			case e.Action == "group_member_added" && e.Severity == event.SevHigh:
				get(e.Target).admined = true
			}
			if people[k] != nil {
				for _, fi := range fis {
					people[k].findings[fi] = true
				}
			}
		}
	}
	if len(people) == 0 {
		return nil
	}
	// Failed logons against each listed account.
	for _, row := range r.rows {
		e := row.Event
		if e.Category != event.CatFailedLogon {
			continue
		}
		who := e.Target
		if who == "" {
			who = e.User
		}
		if !person(who) {
			continue
		}
		if p := people[r.pkey(who)]; p != nil {
			p.failed++
			p.failedHosts[e.Host] = true
		}
	}

	inv := r.accountInventory()
	pp := &PeoplePage{Count: len(people), people: map[string]*PersonView{}, HasInventory: len(inv.systems) > 0, Systems: len(inv.systems)}
	cards := r.detectionCards()
	ps, pe := r.periodBounds()
	used := map[string]bool{} // host|account key (before aliases) used this period
	for _, p := range people {
		for h, hs := range p.hosts {
			for n := range hs.names {
				used[strings.ToLower(h)+"|"+n] = true
			}
		}
	}
	for _, a := range inv.all {
		if !used[strings.ToLower(a.host)+"|"+personKey(a.name)] {
			pp.Unused++
		}
	}
	groups := map[string]*PeopleGroup{"admin": {Title: "Administrators"}, "user": {Title: "Users"}, "shared": {Title: "Shared and service accounts"}}
	for k, p := range people {
		v := r.personView(p, inv.byKey[k], cards, ps, pe)
		now, ok := totals[k]
		if !ok {
			now = PersonSummary{Key: k}
		}
		v.Trend = r.personTrend(now, labels)
		pp.people[k] = v
		groups[v.Group].People = append(groups[v.Group].People, v)
		if v.Det > 0 {
			pp.DetN++
		}
		if v.Group == "admin" {
			pp.AdminN++
		}
		if !v.Shared && (v.systems > pp.ExampleN || v.systems == pp.ExampleN && naturalLess(v.Key, pp.Example)) && v.systems > 1 {
			pp.Example, pp.ExampleN = v.Name, v.systems
		}
		pp.csvRows = append(pp.csvRows, r.personCSV(v)...)
	}
	for _, id := range []string{"admin", "user", "shared"} {
		g := groups[id]
		if len(g.People) == 0 {
			continue
		}
		sort.SliceStable(g.People, func(i, j int) bool {
			a, b := g.People[i], g.People[j]
			if a.High != b.High {
				return a.High > b.High
			}
			if (a.Det > 0) != (b.Det > 0) {
				return a.Det > 0
			}
			if a.systems != b.systems {
				return a.systems > b.systems
			}
			return naturalLess(a.Key, b.Key)
		})
		// Problems first, quiet ones folded: everyone with a detection,
		// then the most used up to ten in all.
		for _, v := range g.People {
			if v.Det > 0 || len(g.Shown) < 10 {
				g.Shown = append(g.Shown, v)
			} else {
				g.Folded = append(g.Folded, v)
			}
		}
		if n := len(g.Folded); n > 0 {
			noun := map[string]string{"admin": "administrators", "user": "users", "shared": "shared and service accounts"}[id]
			what := "with no detections"
			if id == "user" {
				what = "with no privileged actions or detections"
			}
			g.Fold = FoldRow{ID: "pf-" + id, Text: "+" + foldText(n, noun, what, "")}
		}
		pp.Groups = append(pp.Groups, *g)
	}
	sort.SliceStable(pp.csvRows, func(i, j int) bool {
		if pp.csvRows[i][0] != pp.csvRows[j][0] {
			return naturalLess(pp.csvRows[i][0], pp.csvRows[j][0])
		}
		return naturalLess(pp.csvRows[i][2], pp.csvRows[j][2])
	})
	return pp
}

// periodBounds is the period the page's lanes cover.
func (r *Report) periodBounds() (time.Time, time.Time) {
	ps, pe := r.WindowStart, r.WindowEnd
	if ps.IsZero() {
		ps = r.FirstEvent
	}
	if pe.IsZero() {
		pe = r.LastEvent
	}
	// Events from before the period (collected late) still get a place.
	if !r.FirstEvent.IsZero() && r.FirstEvent.Before(ps) {
		ps = r.FirstEvent.In(r.Location).Truncate(time.Hour)
	}
	if r.LastEvent.After(pe) {
		pe = r.LastEvent.In(r.Location).Truncate(time.Hour).Add(time.Hour)
	}
	if !pe.After(ps) {
		pe = ps.Add(time.Hour)
	}
	return ps, pe
}

// invAccount is one account in a system's inventory.
type invAccount struct {
	host, name, os string
	admin, enabled bool
	lastLogon      time.Time
}

type accountInv struct {
	all     []invAccount
	byKey   map[string][]invAccount
	systems map[string]bool
}

// accountInventory is every system's accounts (from its inventory), by
// person key.
func (r *Report) accountInventory() accountInv {
	out := accountInv{byKey: map[string][]invAccount{}, systems: map[string]bool{}}
	for _, s := range r.SystemRows {
		if s.Checks == nil || s.Checks.Inventory == nil {
			continue
		}
		out.systems[s.Name] = true
		for _, a := range s.Checks.Inventory.Accounts {
			ia := invAccount{host: s.Name, name: a.Name, os: s.OS, admin: a.Admin, enabled: a.Enabled, lastLogon: a.LastLogon}
			out.all = append(out.all, ia)
			k := r.pkey(a.Name)
			out.byKey[k] = append(out.byKey[k], ia)
		}
	}
	return out
}

// personView builds one person's (or shared account's) part of the page.
func (r *Report) personView(p *personData, inv []invAccount, cards []DetectionCard, ps, pe time.Time) *PersonView {
	k := p.key
	v := &PersonView{Key: k, Name: p.name, Shared: sharedAccount(k)}
	if v.Name == "" {
		v.Name = k
	}
	// The systems with this account (inventory), with administrator rights.
	have, adminOn := map[string]bool{}, map[string]bool{}
	oses := map[string]bool{}
	for _, a := range inv {
		have[a.host] = true
		oses[a.os] = true
		if a.admin {
			adminOn[a.host] = true
		}
	}
	for h, hs := range p.hosts {
		if hs.admin > 0 {
			adminOn[h] = true
		}
		if os := r.hostOS(h); os != "" {
			oses[os] = true
		}
	}
	usedN := len(p.hosts)
	on := len(have)
	if on < usedN {
		on = usedN
		for h := range p.hosts {
			have[h] = true
		}
	}
	if !v.Shared {
		on = len(have)
	}
	v.systems = max(on, usedN)
	osWord := osWords(oses)
	switch {
	case v.Shared:
		v.Group = "shared"
		if builtinAdmin(k) {
			v.Sub = "built-in"
		} else {
			v.Sub = "service"
		}
		if osWord != "" && builtinAdmin(k) {
			v.Sub += ", " + osWord
		}
		v.Sub += " · on " + plural(v.systems, "system")
	case len(adminOn) > 0 || p.admined:
		v.Group = "admin"
		v.Sub = "admin on " + plural(max(len(adminOn), 1), "system")
	default:
		v.Group = "user"
		v.Sub = plural(max(v.systems, 1), "system")
		if v.systems == 0 {
			v.Sub = "not used on any system"
		}
	}
	switch {
	case p.created:
		v.Sub += " · new account"
	case p.admined:
		v.Sub += " · made an administrator"
	}
	// Detections.
	for fi := range p.findings {
		v.Det++
		if r.Findings[fi].Severity == event.SevHigh {
			v.High++
		}
	}
	for _, c := range cards {
		if p.findings[c.Index] {
			v.Detections = append(v.Detections, c)
		}
	}
	switch {
	case v.High > 0:
		v.Level = "bad"
	case v.Det > 0:
		v.Level = "warn"
	}
	if v.Det > 0 {
		v.Chip = plural(v.Det, "detection")
		if v.High > 0 && v.High < v.Det {
			v.Chip += fmt.Sprintf(" · %d high", v.High)
		} else if v.High > 0 {
			v.Chip += " · high"
		}
	}
	for a := range r.PeopleAliases {
		if r.PeopleAliases[a] == k {
			v.Merged = append(v.Merged, a)
		}
	}
	sort.Strings(v.Merged)
	v.Find = strings.Join(v.Merged, " ")

	v.Lanes = r.lanes(p, ps, pe)
	v.Notable, v.NotableCount = r.notableLines(p.notable)
	v.AllEvents, v.AllHref = p.events, searchLink("user", k)
	if v.Shared {
		r.sharedView(v, p, len(have), osWord)
		return v
	}

	// A person: the summary line.
	var line []string
	switch {
	case p.domainName != "":
		line = append(line, "Domain account "+p.domainName)
	case len(inv) > 0:
		line = append(line, "Local account on "+plural(len(have), "system"))
		switch a := len(adminOnInv(inv)); {
		case a == len(have) && a > 1:
			line = append(line, fmt.Sprintf("administrator on all %d", a))
		case a == len(have):
			line = append(line, "administrator")
		case a > 0:
			line = append(line, fmt.Sprintf("administrator on %d", a))
		default:
			line = append(line, "not an administrator")
		}
	}
	if usedN > 0 {
		u := "used on " + plural(usedN, "system") + " this period"
		if len(inv) > 0 {
			u = fmt.Sprintf("used on %d this period", usedN)
		}
		line = append(line, u)
	} else {
		line = append(line, "not used this period")
	}
	if len(line) > 0 {
		line[0] = strings.ToUpper(line[0][:1]) + line[0][1:]
	}
	v.Line = strings.Join(line, " · ")

	// The six facts.
	sysNote := ""
	if len(inv) > 0 {
		sysNote = "of " + commas(len(have)) + " with this account"
	}
	var ways []string
	for _, w := range []string{"Remote Desktop", "SSH", "console"} {
		if n := p.ways[w]; n > 0 {
			ways = append(ways, fmt.Sprintf("%d %s", n, w))
		}
	}
	after := PFact{Label: "After hours", Value: commas(p.afterHours), Bad: p.afterHours > 0, Href: searchLink("user", k, "when", "@after")}
	if !r.WorkingHours.Set() {
		after = PFact{Label: "After hours", Value: "—", Note: "working_hours not set"}
	}
	v.Facts = []PFact{
		{Label: "Systems used", Value: commas(usedN), Note: sysNote},
		{Label: "Logons", Value: commas(p.logons), Note: strings.Join(ways, " · "), Href: partLink("logons", "user", k)},
		{Label: "Failed logons", Value: commas(p.failed), Note: hostsNote(p.failedHosts), Bad: p.failed > 0, Href: partLink("failed", "text", k)},
		{Label: "Privileged actions", Value: commas(p.admin), Href: partLink("privileged", "user", k)},
		after,
		{Label: "Detections", Value: commas(v.Det), Bad: v.Det > 0, Href: detHref(v)},
	}

	// Accounts named <name>.
	type acc struct {
		AcctRow
		inv     bool
		last    time.Time
		invLast time.Time
	}
	rows := map[string]*acc{}
	keyOf := func(h, n string) string { return strings.ToLower(h) + "|" + personKey(n) }
	for _, a := range inv {
		rights := "user"
		if a.admin {
			rights = "admin"
		}
		if !a.enabled {
			rights += ", disabled"
		}
		rows[keyOf(a.host, a.name)] = &acc{AcctRow: AcctRow{Host: a.host, Account: a.host + `\` + a.name, Rights: rights}, inv: true, invLast: a.lastLogon}
	}
	for h, hs := range p.hosts {
		for n, sp := range hs.names {
			x := rows[keyOf(h, n)]
			if x == nil {
				rights := "—"
				if sp.admin > 0 {
					rights = "admin"
				}
				x = &acc{AcctRow: AcctRow{Host: h, Account: h + `\` + n, Rights: rights}}
				rows[keyOf(h, n)] = x
			}
			x.Logons += sp.logons
			x.last = sp.last
		}
	}
	for _, x := range rows {
		if n := personKey(x.Account); n != k {
			x.Note = "spelled " + n + " · merged by people_aliases"
		}
		if !x.last.IsZero() {
			x.Last = r.shortTime(x.last, ps, pe)
			x.Href = searchLink("user", k, "host", x.Host)
			v.Accounts = append(v.Accounts, x.AcctRow)
		} else {
			x.Last = "never"
			if !x.invLast.IsZero() {
				x.Last = "last logon " + x.invLast.In(r.Location).Format("2 Jan 2006")
			}
			v.Unused = append(v.Unused, x.AcctRow)
		}
	}
	byHost := func(l []AcctRow) {
		sort.Slice(l, func(i, j int) bool {
			if l[i].Host != l[j].Host {
				return naturalLess(l[i].Host, l[j].Host)
			}
			return l[i].Account < l[j].Account
		})
	}
	byHost(v.Accounts)
	byHost(v.Unused)
	v.AcctAll = len(v.Accounts) + len(v.Unused)
	if len(v.Accounts) > 10 {
		v.AcctMore, v.Accounts = v.Accounts[8:], v.Accounts[:8]
		v.AcctFold = FoldRow{ID: "pacc-" + k, Text: "+" + foldText(len(v.AcctMore), "accounts used this period", "", "")}
	}
	if n := []rune(v.Name); len(n) > 2 && !strings.ContainsAny(v.Name, "._-") {
		v.Example = string(n[:1]) + "." + string(n[1:])
	}
	return v
}

func adminOnInv(inv []invAccount) map[string]bool {
	out := map[string]bool{}
	for _, a := range inv {
		if a.admin {
			out[a.host] = true
		}
	}
	return out
}

// sharedView fills in a shared or built-in account (image 07).
func (r *Report) sharedView(v *PersonView, p *personData, systems int, osWord string) {
	kind := "Shared built-in account"
	if !builtinAdmin(p.key) {
		kind = "Service account"
	}
	each := "a separate account on each of " + plural(systems, "system")
	if osWord != "" && osWord != "Windows and Linux" {
		each = fmt.Sprintf("a separate account on each of %d %s %s", systems, osWord, map[bool]string{true: "system", false: "systems"}[systems == 1])
	}
	if systems == 1 {
		each = "an account on 1 system"
	}
	v.Line = kind + " · " + each + " · not one person"

	// Who acted as it.
	var acted []*actedStat
	actedN := 0
	people := map[string]bool{}
	for _, s := range p.acted {
		acted = append(acted, s)
		actedN += s.n
		people[s.person] = true
	}
	sort.Slice(acted, func(i, j int) bool {
		if acted[i].n != acted[j].n {
			return acted[i].n > acted[j].n
		}
		return naturalLess(acted[i].person+acted[i].how, acted[j].person+acted[j].how)
	})
	var names []string
	for i, s := range acted {
		row := ActedRow{Person: s.person, How: s.how, Systems: r.hostsWord(s.hosts), N: s.n, Href: searchLink("user", r.pkey(s.person))}
		if i < 6 {
			v.Acted = append(v.Acted, row)
		} else {
			v.ActedMore = append(v.ActedMore, row)
		}
		if !slices.Contains(names, s.person) {
			names = append(names, s.person)
		}
	}
	if n := len(v.ActedMore); n > 0 {
		v.ActedFold = FoldRow{ID: "pa-" + p.key, Text: "+" + foldText(n, "rows", "with fewer actions", "")}
	}
	jobs := ActedRow{Person: "Jobs and services", How: "no person", Systems: r.hostsWord(p.jobHosts), N: p.jobs, Href: searchLink("user", p.key)}
	direct := ActedRow{Person: "Direct logon as " + v.Name, How: map[string]string{"Linux": "console or SSH", "Windows": "console or Remote Desktop"}[osWord], Systems: r.hostsWord(p.directHosts), N: p.direct,
		Href: partLink("logons", "user", p.key)}
	if p.jobs == 0 {
		jobs.Systems, jobs.Quiet, jobs.Href = "none", true, ""
	}
	if p.direct == 0 {
		direct.Systems, direct.Quiet, direct.Href = "none", true, ""
	}
	v.ActedFixed = []ActedRow{jobs, direct}

	// The box: who used it, and whether anyone logged on as it directly.
	via := map[bool]string{true: "sudo or su", false: "RunAs"}[osWord == "Linux"]
	if osWord == "Windows and Linux" {
		via = "sudo, su or RunAs"
	}
	v.CallLead = "Who used " + v.Name + ":"
	switch {
	case len(names) > 3:
		v.CallText = fmt.Sprintf("Blackbox lists each %s action under the person who ran %s (%s and %d others). ", v.Name, via, strings.Join(names[:3], ", "), len(names)-3)
	case len(names) > 0:
		v.CallText = fmt.Sprintf("Blackbox lists each %s action under the person who ran %s (%s). ", v.Name, via, strings.Join(names, ", "))
	default:
		v.CallText = fmt.Sprintf("No one used %s to act as %s this period. ", via, v.Name)
	}
	v.CallText += fmt.Sprintf("Actions by %s with no person behind them are scheduled jobs and services.", v.Name)
	if p.direct == 0 {
		v.CallEnd = fmt.Sprintf("No one logged on as %s directly.", v.Name)
	} else {
		var ways []string
		for w, n := range p.directWays {
			if w == "" {
				w = "other"
			}
			ways = append(ways, fmt.Sprintf("%d %s", n, w))
		}
		sort.Strings(ways)
		v.CallEnd = fmt.Sprintf("%s logged on directly %s on %s (%s): the person is not recorded.", v.Name, timesWord(p.direct), r.hostsWord(p.directHosts), strings.Join(ways, ", "))
		v.CallBad = true
	}
	if p.failed > 0 {
		v.CallEnd += fmt.Sprintf(" %s to log on as %s failed (%s).", plural(p.failed, "attempt"), v.Name, hostsNote(p.failedHosts))
	}

	// The six facts.
	sysNote := ""
	if osWord != "" {
		sysNote = map[bool]string{true: "all " + osWord, false: osWord}[osWord != "Windows and Linux"]
	}
	viaLabel := "Via " + via
	afterNote := ""
	if after := p.jobsAfter + p.actedAfter + p.directAfter; after > 0 && p.jobsAfter*2 >= after {
		afterNote = "mostly jobs"
	}
	after := PFact{Label: "After hours", Value: commas(p.jobsAfter + p.actedAfter + p.directAfter), Note: afterNote, Href: searchLink("user", p.key, "when", "@after")}
	if !r.WorkingHours.Set() {
		after = PFact{Label: "After hours", Value: "—", Note: "working_hours not set"}
	}
	detNote := ""
	if len(v.Detections) > 0 {
		detNote = v.Detections[0].Title
	}
	v.Facts = []PFact{
		{Label: "Systems", Value: commas(systems), Note: sysNote},
		{Label: "Direct logons", Value: commas(p.direct), Bad: p.direct > 0, Href: map[bool]string{true: partLink("logons", "user", p.key)}[p.direct > 0]},
		{Label: viaLabel, Value: commas(actedN)},
		{Label: "Jobs and services", Value: commas(p.jobs), Href: map[bool]string{true: searchLink("user", p.key)}[p.jobs > 0]},
		after,
		{Label: "Detections", Value: commas(v.Det), Note: detNote, Bad: v.Det > 0, Href: detHref(v)},
	}
	if len(people) == 1 {
		v.Facts[2].Note = "1 person"
	} else if len(people) > 1 {
		v.Facts[2].Note = fmt.Sprintf("%d people", len(people))
	}
}

func detHref(v *PersonView) string {
	if v.Det == 0 {
		return ""
	}
	return "#detections/" + fmt.Sprint(v.Detections[0].Index)
}

func setOf(l []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range l {
		m[s] = true
	}
	return m
}

func timesWord(n int) string {
	if n == 1 {
		return "once"
	}
	return commas(n) + " times"
}

// hostsWord is "6 servers", "all 15", "SRV-DC01", "3 systems".
func (r *Report) hostsWord(h map[string]bool) string {
	if len(h) == 0 {
		return "none"
	}
	if len(h) == 1 {
		for n := range h {
			return n
		}
	}
	kinds := map[string]int{}
	for n := range h {
		kinds[r.hostKind(n)]++
	}
	if len(h) == len(r.SystemRows) && len(h) > 1 {
		return fmt.Sprintf("all %d", len(h))
	}
	if len(kinds) == 1 {
		for kd := range kinds {
			if kd != "vm" {
				return plural(len(h), kd)
			}
		}
	}
	return plural(len(h), "system")
}

// hostsNote names one or two systems, else counts them.
func hostsNote(h map[string]bool) string {
	if len(h) == 0 {
		return ""
	}
	if len(h) <= 2 {
		var l []string
		for n := range h {
			l = append(l, n)
		}
		sort.Strings(l)
		return strings.Join(l, ", ")
	}
	return plural(len(h), "system")
}

// osWords is "Linux", "Windows" or "Windows and Linux".
func osWords(oses map[string]bool) string {
	switch {
	case oses["windows"] && oses["linux"]:
		return "Windows and Linux"
	case oses["windows"]:
		return "Windows"
	case oses["linux"]:
		return "Linux"
	}
	return ""
}

func (r *Report) hostOS(h string) string {
	for _, s := range r.SystemRows {
		if strings.EqualFold(s.Name, h) {
			return s.OS
		}
	}
	return ""
}

// shortTime is a time on the page: "14:25" in a one-day period, else
// "Wed 14:25".
func (r *Report) shortTime(t, ps, pe time.Time) string {
	t = t.In(r.Location)
	if pe.Sub(ps) <= 26*time.Hour {
		return t.Format("15:04")
	}
	return t.Format("Mon 15:04")
}

// notableRow says whether one of a person's events is worth a line of its
// own: High events, events in a detection or flagged, and changes to
// accounts and auditing. Routine Medium events (a USB stick plugged in)
// are on their own pages.
func notableRow(x *Row, inFinding bool) bool {
	if x.Severity == event.SevHigh || inFinding {
		return true
	}
	for _, f := range x.Flags {
		if f == "New device" || f == "First time" || f == "Outside working hours" {
			return true
		}
	}
	return x.Severity == event.SevMedium && (x.Category == event.CatAccount || x.Category == event.CatIntegrity)
}

// notableLines turns a person's notable events into one line each, the
// same thing on the same system counted once ("… twice"), high first then
// in time order.
func (r *Report) notableLines(rows []*Row) ([]NoteLine, int) {
	type group struct {
		first *Row
		n     int
	}
	var order []string
	groups := map[string]*group{}
	for _, x := range rows {
		k := x.Action + "|" + x.Host + "|" + x.Target
		g := groups[k]
		if g == nil {
			g = &group{first: x}
			groups[k] = g
			order = append(order, k)
		}
		g.n++
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := groups[order[i]].first, groups[order[j]].first
		if (a.Severity == event.SevHigh) != (b.Severity == event.SevHigh) {
			return a.Severity == event.SevHigh
		}
		return a.Time.Before(b.Time)
	})
	ps, pe := r.periodBounds()
	var out []NoteLine
	for _, k := range order {
		if len(out) == 8 {
			break
		}
		g := groups[k]
		x := g.first
		text := strings.TrimSuffix(x.Summary, ".")
		if u := x.User + " "; x.User != "" && strings.HasPrefix(text, u) { // "jlee cleared…" → "cleared…"
			text = strings.TrimPrefix(text, u)
		}
		text += times(g.n)
		lv := "warn"
		if x.Severity == event.SevHigh {
			lv = "bad"
		}
		out = append(out, NoteLine{Level: lv, Time: r.shortTime(x.Time, ps, pe), Host: x.Host, Text: text, Ev: r.evRef(x)})
	}
	return out, len(order)
}

// personCSV is a person's rows in the page's CSV: one per system's
// account.
func (r *Report) personCSV(v *PersonView) [][]string {
	kind := map[string]string{"admin": "administrator", "user": "user", "shared": "shared or service account"}[v.Group]
	var out [][]string
	if len(v.Accounts)+len(v.AcctMore)+len(v.Unused) == 0 {
		return [][]string{{v.Name, kind, "", "", "", "", fmt.Sprint(v.Det)}}
	}
	for _, a := range append(append([]AcctRow(nil), v.Accounts...), v.AcctMore...) {
		out = append(out, []string{v.Name, kind, a.Account, a.Rights, fmt.Sprint(a.Logons), a.Last, fmt.Sprint(v.Det)})
	}
	for _, a := range v.Unused {
		out = append(out, []string{v.Name, kind, a.Account, a.Rights, "0", a.Last, fmt.Sprint(v.Det)})
	}
	return out
}

// csv is the page's "This page" CSV: one row per person per system's
// account.
func (pp *PeoplePage) csv() CSVFile {
	rows := [][]string{{"person", "kind", "account", "rights", "logons this period", "last used", "detections"}}
	return csvFile("People and their accounts", "people", append(rows, pp.csvRows...))
}

func lerpColor(r1, g1, b1, r2, g2, b2 int, t float64) string {
	t = math.Max(0, math.Min(1, t))
	f := func(a, b int) int { return int(math.Round(float64(a) + (float64(b)-float64(a))*t)) }
	return fmt.Sprintf("#%02X%02X%02X", f(r1, r2), f(g1, g2), f(b1, b2))
}
