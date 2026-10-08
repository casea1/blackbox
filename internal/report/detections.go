package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// The Detections page (UI-R1, design 02 layout A): filters, a list
// grouped High / Medium, and for the one selected a plain sentence, four
// facts, why it matters, what happened ten minutes either side on that
// system for that person, and related detections.

// whyFlagged explains each kind of detection in plain words.
var whyFlagged = map[string]string{
	"Possible covering of tracks":                  "Access was set up (an account, an administrator, or sudo rules), and soon after, on the same computer, the logs were cleared or auditing was changed. Together these can hide what was done with the new access.",
	"Possible password guessing":                   "Many failed logons for one account on one computer in a short time. This is how password guessing looks; it can also be a person who forgot a changed password, or a program with an old password.",
	"One source tried several accounts":            "One address tried to log on as several different accounts in a short time. People rarely do this; tools that try common account names do.",
	"Same account failing on several computers":    "One account failed to log on to several computers within minutes. Someone may be trying a password across the network, or a service with an old password is running on several computers.",
	"Successful logon after failures":              "Several failed logons were followed by a successful one for the same account. Usually a mistyped password; after guessing, it can mean the password was found.",
	"Auditing was switched off":                    "The audit service was stopped by a person. Nothing done while it was off was recorded.",
	"Administrator activity outside working hours": "Administrator rights were used outside the working hours set for this site. It may be planned maintenance; if not, it is worth asking who and why.",
	"Account created and deleted within a day":     "An account was created and deleted again within a day: used for something, then removed.",
	"New USB device, then administrator activity":  "A USB device never seen before was connected, and administrator rights were used on the same computer soon after.",
	"First logon to this computer":                 "This person logged on to this computer for the first time since Blackbox started learning what is normal here.",
	"First use of administrator rights":            "This person used administrator rights on this computer for the first time since Blackbox started learning what is normal here.",
	"First logon from this address":                "A logon came from an address that has not logged on to this computer before.",
}

// KV is a labelled value.
type KV struct {
	Label, Value string
	Links        []KVLink // the value's parts, each linked
}

// KVLink is one linked part of a value.
type KVLink struct{ Text, Href string }

// whyAction explains a High event's own detection ("Log cleared on
// SRV-DC02"), by the action of its events.
var whyAction = map[string]string{
	"log_cleared":          "Clearing a log removes the record of everything before it.",
	"log_tampered":         "A log that was altered or deleted no longer shows what happened on this system.",
	"audit_policy_changed": "Weakening the audit policy stops the system recording what people do.",
	"audit_disabled":       "Nothing done while auditing was off was recorded.",
	"audit_stopped":        "Nothing done while auditing was stopped was recorded.",
	"group_member_added":   "A new member of a privileged group can do anything on the system, including hide what they did.",
	"account_created":      "A new account is a new way in; check someone asked for it.",
	"sudoers_changed":      "New sudo rules give an account root rights.",
	"time_changed":         "Moving the clock back makes later events look older and can hide when something was done.",
	"usb_new":              "A USB device never seen before can carry data in or out.",
	"av_disabled":          "With anti-malware off, nothing checks what runs on the system.",
	"av_exclusion_added":   "An anti-malware exclusion lets anything in that place run unchecked.",
	"firewall_stopped":     "With the firewall stopped, the system takes connections it normally refuses.",
	"malware_detected":     "Anti-malware found something on this system.",
}

// DetFact is one of a detection's four facts.
type DetFact struct {
	Label, Value, Sub, Href string
}

// TLine is one line of a detection's "What happened": an event on the
// system around it, Key when it is one of the detection's own; Gap, when
// set, is a line saying how many events are left out there.
type TLine struct {
	Time, Label, Text, ID, Ev string
	Key                       bool
	Gap                       string
}

// DetectionView is one detection on the Detections page (UI-R1, design
// 02): its line in the list, and when selected a plain sentence, four
// facts, why it matters, what happened around it and related detections.
type DetectionView struct {
	DetectionCard
	Pos        int    // its row in the detections CSV (1 = the first after the header)
	Short      string // the title without " on <system>"
	When       string // its time in the list
	HostKind   string // server | workstation | vm
	PersonKey  string // who it is about, for the Person filter ("" if no one)
	Facts      []DetFact
	Why        string
	Timeline   []TLine
	TLHead     string // "adm-jlee on SRV-DC02, 14:12–14:32"
	SearchHref string // "Open in Search (±10 min)"
	Person     string // "Everything <Person> did"
	PersonHref string
	Related    []ListItem
	RelNote    string
	// Range, Steps and Involved are kept for Blackbox's own checks (UI21).
	Range    string
	Steps    []TLine
	Involved []KV
}

// DetFilter is one choice of a Detections filter.
type DetFilter struct{ Value, Label string }

// DetectionsPage is the Detections page: its list (high, then medium,
// newest first within each) and the filters' choices.
type DetectionsPage struct {
	Views         []DetectionView
	High, Med     []DetectionView
	Hosts, People []DetFilter
	Kinds         bool // servers and workstations both: the filter is worth showing
}

const tlWindow = 10 * time.Minute

func (r *Report) detectionsPage() *DetectionsPage {
	views := r.detectionViews()
	p := &DetectionsPage{Views: views}
	hosts, people, kinds := map[string]bool{}, map[string]string{}, map[string]bool{}
	for _, v := range views {
		if v.Severity == "high" {
			p.High = append(p.High, v)
		} else {
			p.Med = append(p.Med, v)
		}
		hosts[v.Host] = true
		if v.PersonKey != "" {
			people[v.PersonKey] = v.Person
		}
		kinds[v.HostKind] = true
	}
	for h := range hosts {
		p.Hosts = append(p.Hosts, DetFilter{h, h})
	}
	sort.Slice(p.Hosts, func(i, j int) bool { return naturalLess(p.Hosts[i].Value, p.Hosts[j].Value) })
	for k, n := range people {
		p.People = append(p.People, DetFilter{k, n})
	}
	sort.Slice(p.People, func(i, j int) bool { return p.People[i].Value < p.People[j].Value })
	p.Kinds = len(kinds) > 1
	return p
}

func (r *Report) detectionViews() []DetectionView {
	cards := r.detectionCards()
	multiDay := len(r.periodDays()) > 1
	zone := r.zoneLabel()
	var out []DetectionView
	for pos, c := range cards {
		f := r.Findings[c.Index]
		v := DetectionView{DetectionCard: c, Pos: pos + 1, Short: shortTitle(f.Title, f.Host), When: r.detTime(f, c, multiDay),
			HostKind: r.hostKind(f.Host)}
		var rows []*Row
		for _, id := range f.RowIDs {
			if i := rowIndex(id); i >= 0 && i < len(r.rows) {
				rows = append(rows, r.rows[i])
			}
		}
		if len(rows) == 0 && f.RowID != "" {
			if i := rowIndex(f.RowID); i >= 0 && i < len(r.rows) {
				rows = append(rows, r.rows[i])
			}
		}
		sort.SliceStable(rows, func(a, b int) bool { return rows[a].Time.Before(rows[b].Time) })
		sys := DetFact{Label: "System", Value: f.Host, Href: systemLink(f.Host), Sub: r.hostLine(f.Host)}
		when := f.Time.In(r.Location)
		v.Range = c.Host + " · " + when.Format("Mon 2 Jan 2006, 15:04")
		if f.Check != "" && len(rows) == 0 {
			// Blackbox's own check, not an event (UI21): said so, with
			// what it found.
			if c.Day == FoundAtReport {
				v.Range = c.Host + " · found when this report was made (" + when.Format("Mon 2 Jan 2006, 15:04") + ")"
			}
			v.Steps = []TLine{{Time: when.Format("15:04:05"), Label: "Blackbox", Text: "Found by " + f.Check + ".", Key: true}}
			v.Timeline = v.Steps
			v.Involved = append([]KV{{Label: "System", Value: c.Host}, {Label: "Found by", Value: "Blackbox"}}, f.Facts...)
			rec := DetFact{Label: "Record", Value: "Blackbox's check"}
			for _, kv := range f.Facts {
				switch kv.Label {
				case "Log":
					rec.Value = kv.Value
				case "File":
					rec.Sub = kv.Value
				}
			}
			whenF := DetFact{Label: "When", Value: when.Format("2 Jan 15:04:05"), Sub: zone}
			if c.Day == FoundAtReport {
				whenF.Sub = "when this report was made · " + zone
			}
			v.Facts = []DetFact{sys, {Label: "Found by", Value: "Blackbox", Sub: "its own check"}, whenF, rec}
			v.Why = "Blackbox checks the original logs it saves before it bundles them; a file that changed in between may not be what the system wrote."
			v.SearchHref = searchLink("host", f.Host, "when", when.Format("20060102"))
			v.Related, v.RelNote = r.relatedDetections(cards, c, "")
			out = append(out, v)
			continue
		}
		anyKey := false
		for _, x := range rows {
			anyKey = anyKey || keyStep(x)
		}
		var key []*Row
		for _, x := range rows {
			if !anyKey || keyStep(x) {
				key = append(key, x)
			}
		}
		// Who it is about: the person who did it, else the account it was
		// done to.
		var who string
		for _, x := range key {
			if person(x.User) {
				who = x.User
				break
			}
		}
		if who == "" {
			for _, x := range key {
				if person(x.Target) {
					who = x.Target
					break
				}
			}
		}
		pk := ""
		if who != "" {
			pk = personKey(who)
			v.PersonKey, v.Person, v.PersonHref = pk, displayName(who), searchLink("user", pk)
		}
		first := f.Time
		last := f.Time
		if len(key) > 0 {
			first, last = key[0].Time, key[len(key)-1].Time
		}
		from, to := first.Add(-tlWindow), last.Add(tlWindow)
		// Search's at and span: the same window, ten minutes either side of
		// the key events, centred on them (span is 600 for a single event).
		half := last.Sub(first) / 2
		at := first.Add(half)
		v.SearchHref = searchLink("host", f.Host, "user", pk,
			"at", fmt.Sprint(at.Unix()), "span", fmt.Sprint(int64((tlWindow+half+time.Second-1)/time.Second)))

		// The four facts.
		pf := DetFact{Label: "Person", Value: "—", Sub: "no account named"}
		if who != "" {
			pf = DetFact{Label: "Person", Value: displayName(who), Href: personLink(who), Sub: r.personRole(pk, f.Host)}
		}
		rec := DetFact{Label: "Record", Value: "—"}
		if len(key) > 0 {
			x := key[0]
			rec.Value = x.Source
			if x.EventID != 0 {
				rec.Value = fmt.Sprintf("%s %d", x.Source, x.EventID)
			} else if x.RecordType != "" {
				rec.Value = strings.TrimSpace(x.Source + " " + x.RecordType)
			}
			if x.RecordID != 0 {
				rec.Sub = "record " + commas(int(x.RecordID))
			}
			if len(key) > 1 {
				rec.Sub = strings.TrimPrefix(rec.Sub+" · ", " · ") + fmt.Sprintf("first of %d", len(key))
			}
		}
		v.Facts = []DetFact{sys, pf, {Label: "When", Value: when.Format("2 Jan 15:04:05"), Sub: zone}, rec}
		v.Why = r.whyLine(f, key)

		// What happened: that system, that person, ten minutes either side.
		var tl []*Row
		isKey := map[*Row]bool{}
		for _, x := range key {
			isKey[x] = true
		}
		for _, x := range r.rows {
			if !strings.EqualFold(x.Host, f.Host) || x.Time.Before(from) || x.Time.After(to) {
				continue
			}
			if isKey[x] || pk == "" || personKey(x.User) == pk || personKey(x.Target) == pk {
				tl = append(tl, x)
			}
		}
		sort.SliceStable(tl, func(a, b int) bool { return tl[a].Time.Before(tl[b].Time) })
		line := func(x *Row) TLine {
			id := ""
			if x.EventID != 0 {
				id = fmt.Sprint(x.EventID)
			}
			return TLine{Time: x.Time.In(r.Location).Format("15:04:05"), Label: actionLabel(x.Action), Text: x.Summary, ID: id, Ev: r.evRef(x), Key: isKey[x]}
		}
		const most = 10
		for i, x := range tl {
			if len(tl) > most && i == most/2 {
				n := len(tl) - most
				v.Timeline = append(v.Timeline, TLine{Gap: fmt.Sprintf("%s more in between · in Search", plural(n, "event"))})
			}
			if len(tl) > most && i >= most/2 && i < len(tl)-most/2 {
				continue
			}
			v.Timeline = append(v.Timeline, line(x))
		}
		v.Steps = v.Timeline
		head := f.Host
		if who != "" {
			head = displayName(who) + " on " + f.Host
		}
		v.TLHead = head + ", " + from.In(r.Location).Format("15:04") + "–" + to.In(r.Location).Format("15:04")
		v.Related, v.RelNote = r.relatedDetections(cards, c, pk)
		out = append(out, v)
	}
	return out
}

// relatedDetections are the other detections with the same person or
// system, one line each, and a note on what was looked for.
func (r *Report) relatedDetections(cards []DetectionCard, c DetectionCard, pk string) ([]ListItem, string) {
	multiDay := len(r.periodDays()) > 1
	var out []ListItem
	samePerson, sameHost := false, false
	for _, o := range cards {
		if o.Index == c.Index {
			continue
		}
		f := r.Findings[o.Index]
		h := strings.EqualFold(o.Host, c.Host)
		p := pk != "" && r.findingPerson(f) == pk
		if !h && !p {
			continue
		}
		samePerson = samePerson || p
		sameHost = sameHost || h
		if len(out) < 6 {
			out = append(out, ListItem{Title: shortTitle(f.Title, f.Host), System: f.Host, Time: r.detTime(f, o, multiDay),
				Href: fmt.Sprintf("#detections/%d", o.Index), Level: map[bool]string{true: "bad", false: "warn"}[o.Severity == "high"]})
		}
	}
	var note []string
	if pk != "" {
		if samePerson {
			note = append(note, "Same person: "+pk+".")
		} else {
			note = append(note, "Nothing else by "+pk+".")
		}
	}
	if !sameHost {
		note = append(note, "Nothing else on "+c.Host+".")
	}
	return out, strings.Join(note, " ")
}

// findingPerson is the person a detection is about (personKey), or "".
func (r *Report) findingPerson(f Finding) string {
	var target string
	for _, id := range append([]string{f.RowID}, f.RowIDs...) {
		i := rowIndex(id)
		if i < 0 || i >= len(r.rows) {
			continue
		}
		x := r.rows[i]
		if person(x.User) {
			return personKey(x.User)
		}
		if target == "" && person(x.Target) {
			target = personKey(x.Target)
		}
	}
	return target
}

// whyLine is why a detection matters, and what the original logs still
// hold of it.
func (r *Report) whyLine(f Finding, key []*Row) string {
	why := whyFlagged[f.Title]
	action := ""
	if len(key) > 0 {
		action = key[0].Action
	}
	if why == "" {
		why = whyAction[action]
	}
	if why == "" {
		why = "High-severity events are always listed here to be looked at."
	}
	zip := ""
	for _, a := range r.Archives {
		if strings.EqualFold(a.Host, f.Host) {
			zip = a.Name
		}
	}
	switch {
	case zip == "":
		return why
	case action == "log_cleared":
		// The last collection before the clear: up to then the
		// original logs have it.
		var last time.Time
		for _, s := range r.SystemRows {
			if strings.EqualFold(s.Name, f.Host) {
				for _, t := range s.runTimes {
					if t.Before(f.Time) && t.After(last) {
						last = t
					}
				}
			}
		}
		if !last.IsZero() {
			return why + fmt.Sprintf(" The original logs in this report (%s) keep a copy up to the last collection (%s).", zip, last.In(r.Location).Format("15:04"))
		}
	}
	return why + " The original logs in this report keep a copy (" + zip + ")."
}

// hostLine is a system's OS and role: "Windows Server 2025 · server".
func (r *Report) hostLine(host string) string {
	for _, s := range r.SystemRows {
		if strings.EqualFold(s.Name, host) {
			return osLabel(s) + " · " + map[string]string{"server": "server", "workstation": "workstation", "vm": "virtual machine"}[systemKind(s)]
		}
	}
	return ""
}

// personRole is what an account is on a system, from this report:
// "administrator" when it used administrator rights there, a service or
// built-in account, else "user".
func (r *Report) personRole(key, host string) string {
	switch {
	case key == "root" || key == "administrator":
		return "built-in account"
	case serviceAccount(key):
		return "service account"
	}
	for _, x := range r.rows {
		if strings.EqualFold(x.Host, host) && personKey(x.User) == key && adminActivity(x) {
			return "administrator on " + host
		}
	}
	return "user"
}

// displayName is an account without its domain or computer.
func displayName(u string) string {
	if i := strings.LastIndex(u, `\`); i >= 0 {
		return u[i+1:]
	}
	return u
}

// zoneLabel is the report's zone with its offset: "EDT (UTC−4)".
func (r *Report) zoneLabel() string {
	t := r.Generated
	if t.IsZero() {
		t = r.WindowEnd
	}
	name, off := t.In(r.Location).Zone()
	s := "UTC"
	if off != 0 {
		sign := "+"
		if off < 0 {
			sign, off = "−", -off
		}
		s += sign + fmt.Sprint(off/3600)
		if m := off % 3600 / 60; m != 0 {
			s += fmt.Sprintf(":%02d", m)
		}
	}
	if name == "" || name == "UTC" || strings.HasPrefix(name, "+") || strings.HasPrefix(name, "-") {
		return s
	}
	return name + " (" + s + ")"
}

// keyStep says whether a row is one of the events a detection is about,
// rather than what happened around it.
func keyStep(x *Row) bool {
	if x.Severity.Rank() >= event.SevMedium.Rank() {
		return true
	}
	for _, f := range x.Flags {
		if f == "Outside working hours" || f == "New device" {
			return true
		}
	}
	return false
}

// actionLabel turns an action tag into words: "logon_failed" → "Logon failed".
func actionLabel(a string) string {
	s := strings.ReplaceAll(a, "_", " ")
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
