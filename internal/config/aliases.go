package config

import (
	"fmt"
	"sort"
	"strings"
)

// People aliases (UI-R1): with local accounts only, the same person can
// have accounts spelled differently on different systems ("jlee" on one,
// "j.lee" on another). people_aliases names them, so the report's People
// page shows them as one person:
//
//	people_aliases = jlee=j.lee,jlee2; mchen=m.chen
//
// Each group is "name=other,other"; groups are separated by ";". Names
// are matched without case and without a domain or computer name, as the
// report matches accounts.

// ParsePeopleAliases reads a people_aliases value into a map from each
// other spelling to the name it is shown under (all lower case). An empty
// value is no aliases.
func ParsePeopleAliases(v string) (map[string]string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	bad := func(why string) error {
		return fmt.Errorf("people_aliases: %s; it must look like \"jlee=j.lee,jlee2\" (groups separated by \";\")", why)
	}
	out := map[string]string{}
	mains := map[string]bool{}
	for _, g := range strings.Split(v, ";") {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		name, others, ok := strings.Cut(g, "=")
		name = aliasKey(name)
		if !ok || name == "" {
			return nil, bad(fmt.Sprintf("%q has no name before \"=\"", g))
		}
		if strings.Contains(others, "=") {
			return nil, bad(fmt.Sprintf("%q has more than one \"=\"", g))
		}
		if _, dup := out[name]; dup || mains[name] {
			return nil, bad(fmt.Sprintf("%s is named twice", name))
		}
		mains[name] = true
		n := 0
		for _, o := range strings.Split(others, ",") {
			o = aliasKey(o)
			if o == "" {
				continue
			}
			if o == name {
				continue
			}
			if _, dup := out[o]; dup || mains[o] {
				return nil, bad(fmt.Sprintf("%s is named twice", o))
			}
			out[o] = name
			n++
		}
		if n == 0 {
			return nil, bad(fmt.Sprintf("%q names no other spelling after \"=\"", g))
		}
	}
	return out, nil
}

// FormatPeopleAliases writes aliases back as a people_aliases value,
// sorted: "jlee=j.lee,jlee2; mchen=m.chen".
func FormatPeopleAliases(m map[string]string) string {
	by := map[string][]string{}
	for o, n := range m {
		by[n] = append(by[n], o)
	}
	names := make([]string, 0, len(by))
	for n := range by {
		names = append(names, n)
		sort.Strings(by[n])
	}
	sort.Strings(names)
	var out []string
	for _, n := range names {
		out = append(out, n+"="+strings.Join(by[n], ","))
	}
	return strings.Join(out, "; ")
}

// aliasKey is how the report matches an account: lower case, without a
// domain or computer name ("SRV-DC02\jlee" → "jlee") or "@domain".
func aliasKey(u string) string {
	l := strings.ToLower(strings.TrimSpace(u))
	if i := strings.LastIndex(l, `\`); i >= 0 {
		l = l[i+1:]
	}
	if i := strings.Index(l, "@"); i > 0 {
		l = l[:i]
	}
	return l
}
