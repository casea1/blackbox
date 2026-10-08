package report

import (
	"net/url"
	"strconv"
	"strings"
)

// Links between the report's pages: a search with its fields filled in,
// and a reference that opens one event's panel from anywhere.

// searchLink is a link to Search with these fields set: page (an event
// page's ID), user (a person's key), host (a system, or @server …), when
// (a day YYYYMMDD or @after), text.
func searchLink(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			v.Set(kv[i], kv[i+1])
		}
	}
	return "#search?" + v.Encode()
}

// evRef is "page:index" for an event, which app.js opens in the event
// panel; "" if no event page lists it.
func (r *Report) evRef(row *Row) string {
	if row == nil {
		return ""
	}
	if r.evPages == nil {
		pages := eventPages()
		r.evPages = make([]string, len(r.Events))
		for i, e := range r.Events {
			for _, p := range pages {
				if p.on(e) {
					r.evPages[i] = p.ID
					break
				}
			}
		}
	}
	i := rowIndex(row.ID)
	if i < 0 || i >= len(r.evPages) || r.evPages[i] == "" {
		return ""
	}
	return r.evPages[i] + ":" + strconv.Itoa(i)
}

// personLink is a person's People page.
func personLink(u string) string {
	if !person(u) {
		return ""
	}
	return "#people/" + personKey(u)
}

func systemLink(h string) string {
	if h == "" || strings.Contains(h, " ") {
		return ""
	}
	return "#systems/" + h
}

// partLink is a link to Search showing one part of the events (an
// EventPage ID, e.g. "failed"): its kind of event, narrowed to the part
// with part= when the kind holds more than one (owner, UI-R1).
func partLink(part string, kv ...string) string {
	args := []string{"page", partKind(part)}
	if sharedKind(part) {
		args = append(args, "part", part)
	}
	return searchLink(append(args, kv...)...)
}

// partPage is the event page showing one part: "#integrity", or
// "#logons?part=failed".
func partPage(part string) string {
	if sharedKind(part) {
		return "#" + partKind(part) + "?part=" + part
	}
	return "#" + partKind(part)
}

// sharedKind says whether a part's kind holds other parts too.
func sharedKind(part string) bool {
	k, n := partKind(part), 0
	for _, p := range eventPages() {
		if p.Kind == k {
			n++
		}
	}
	return n > 1
}
