package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// The Detections page (design D2): a list by day, and for the one selected,
// why it was flagged, what happened in order, who and what was involved,
// related detections and the events themselves.

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

// Step is one event in a detection's "what happened".
type Step struct {
	Time, Text, Sub string
	Ev              string // opens the event (see evRef)
	Key             bool   // the events the detection is about
}

// KV is a labelled value.
type KV struct {
	Label, Value string
	Links        []KVLink // the value's parts, each linked
}

// KVLink is one linked part of a value.
type KVLink struct{ Text, Href string }

// EventLine is one event in a detection's events table.
type EventLine struct {
	Time, ID, Event, Account, Details string
	Ev                                string
}

// DetectionView is one detection on the Detections page.
type DetectionView struct {
	DetectionCard
	Range    string
	Count    int
	Why      string
	Steps    []Step
	Involved []KV
	Related  []DetectionCard
	Events   []EventLine
	Archive  string // the original-log zip the events are in
}

func (r *Report) detectionViews() []DetectionView {
	cards := r.detectionCards()
	var out []DetectionView
	for _, c := range cards {
		f := r.Findings[c.Index]
		v := DetectionView{DetectionCard: c, Why: whyFlagged[f.Title]}
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
		v.Count = len(rows)
		v.Range = c.Host + " · " + f.Time.In(r.Location).Format("Mon 2 Jan 2006, 15:04")
		if f.Check != "" && len(rows) == 0 {
			// Blackbox's own check, not an event (UI21): said so, with
			// what it found, and no empty panels.
			when := f.Time.In(r.Location).Format("Mon 2 Jan 2006, 15:04")
			if c.Day == FoundAtReport {
				v.Range = c.Host + " · found when this report was made (" + when + ")"
			}
			v.Steps = []Step{{Time: f.Time.In(r.Location).Format("15:04:05"), Text: "Found by " + f.Check + ".", Sub: "Blackbox", Key: true}}
			v.Involved = append([]KV{{Label: "System", Value: c.Host, Links: []KVLink{{Text: c.Host, Href: systemLink(c.Host)}}},
				{Label: "Found by", Value: "Blackbox", Links: []KVLink{{Text: "Blackbox"}}}}, f.Facts...)
			for i := range v.Involved {
				if v.Involved[i].Links == nil {
					v.Involved[i].Links = []KVLink{{Text: v.Involved[i].Value}}
				}
			}
			for _, a := range r.Archives {
				if strings.EqualFold(a.Host, c.Host) {
					v.Archive = a.Name
				}
			}
			out = append(out, v)
			continue
		}
		if len(rows) > 1 {
			a, b := rows[0].Time.In(r.Location), rows[len(rows)-1].Time.In(r.Location)
			v.Range = fmt.Sprintf("%s · %s – %s", c.Host, a.Format("Mon 2 Jan 2006, 15:04"), b.Format("15:04"))
			if b.Sub(a) < time.Minute {
				v.Range = fmt.Sprintf("%s · %s – %s", c.Host, a.Format("Mon 2 Jan 2006, 15:04:05"), b.Format("15:04:05"))
			} else if a.YearDay() != b.YearDay() {
				v.Range = fmt.Sprintf("%s · %s – %s", c.Host, a.Format("Mon 2 Jan 15:04"), b.Format("Mon 2 Jan 15:04"))
			}
			v.Range += fmt.Sprintf(" · %d related events", len(rows))
		}
		anyKey := false
		for _, x := range rows {
			anyKey = anyKey || keyStep(x)
		}
		users, targets, sources, hosts := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
		for i, x := range rows {
			if i < 12 {
				sub := x.Host
				if x.EventID != 0 {
					sub = fmt.Sprintf("Event %d · %s", x.EventID, x.Source)
				} else if x.RecordType != "" {
					sub = x.Source + " · " + x.RecordType
				}
				v.Steps = append(v.Steps, Step{Time: x.Time.In(r.Location).Format("15:04:05"), Text: x.Summary, Sub: sub,
					Key: anyKey && keyStep(x), Ev: r.evRef(x)})
			}
			if len(v.Events) < 50 {
				id := ""
				if x.EventID != 0 {
					id = fmt.Sprint(x.EventID)
				}
				who := x.User
				if who == "" {
					who = x.Target
				}
				v.Events = append(v.Events, EventLine{Time: x.Time.In(r.Location).Format("2 Jan 15:04:05"), ID: id,
					Event: actionLabel(x.Action), Account: who, Details: x.Summary, Ev: r.evRef(x)})
			}
			hosts[x.Host] = true
			if anyKey && !keyStep(x) {
				continue // context around the detection, not part of it
			}
			if person(x.User) {
				users[x.User] = true
			}
			if x.Target != "" && x.Target != x.User {
				targets[x.Target] = true
			}
			if x.SourceIP != "" && !localAddress(x.SourceIP) {
				sources[x.SourceIP] = true
			}
		}
		add := func(label string, m map[string]bool) {
			if len(m) == 0 {
				return
			}
			var l []string
			for k := range m {
				l = append(l, k)
			}
			sort.Strings(l)
			more := ""
			if len(l) > 4 {
				l, more = l[:4], fmt.Sprintf("and %d more", len(l)-4)
			}
			kv := KV{Label: label, Value: strings.Join(l, ", ")}
			for _, x := range l {
				href := ""
				switch label {
				case "System":
					href = systemLink(strings.SplitN(x, " · ", 2)[0])
				case "Done by", "Affected":
					href = personLink(x)
				case "Source":
					href = searchLink("text", x)
				}
				kv.Links = append(kv.Links, KVLink{Text: x, Href: href})
			}
			if more != "" {
				kv.Links = append(kv.Links, KVLink{Text: more})
				kv.Value += ", " + more
			}
			v.Involved = append(v.Involved, kv)
		}
		if len(hosts) == 1 {
			for _, sr := range r.SystemRows {
				if hosts[sr.Name] {
					if l := osLabel(sr); l != "" {
						delete(hosts, sr.Name)
						hosts[sr.Name+" · "+l] = true
					}
				}
			}
		}
		add("System", hosts)
		add("Done by", users)
		add("Affected", targets)
		add("Source", sources)
		for _, other := range cards {
			if other.Index != c.Index && strings.EqualFold(other.Host, c.Host) && len(v.Related) < 4 {
				v.Related = append(v.Related, other)
			}
		}
		for _, a := range r.Archives {
			if strings.EqualFold(a.Host, c.Host) {
				v.Archive = a.Name
			}
		}
		out = append(out, v)
	}
	return out
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
