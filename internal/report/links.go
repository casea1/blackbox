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

// cardFilter is a stat card's filter for the event table below it (see
// EventCard.Filter): kind, sev, host, user, day, text or flag, as a query
// string. A kind may list several with "|".
func cardFilter(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}
