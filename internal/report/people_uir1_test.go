package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// UI-R1 §5 People with the 30-system network: the same local name on
// several systems is one row, people_aliases merges other spellings, and
// a shared account (root, Administrator) says who acted as it.

func TestPeopleMergeDemo30(t *testing.T) {
	r, net := demo30(t)
	pp := r.peoplePage()
	if pp == nil {
		t.Fatal("no People page")
	}
	jlee := pp.people["jlee"]
	if jlee == nil || jlee.Shared || jlee.Group != "admin" {
		t.Fatalf("jlee: %+v", jlee)
	}
	// One row, with one account per system: jlee is in every system's
	// inventory and used on every system that reported.
	reported := 0
	for _, s := range net.Systems {
		if !s.Silent {
			reported++
		}
	}
	used := len(jlee.Accounts) + len(jlee.AcctMore)
	if used != reported || jlee.AcctAll != 30 || len(jlee.Unused) != 30-reported {
		t.Errorf("jlee accounts: %d used (want %d), %d in all, %d unused", used, reported, jlee.AcctAll, len(jlee.Unused))
	}
	for k := range pp.people {
		if strings.Contains(k, `\`) {
			t.Errorf("a person keyed with a system name: %s", k)
		}
	}
	if !strings.HasPrefix(jlee.Line, "Local account on 30 systems · administrator on all 30 · used on ") {
		t.Errorf("jlee line: %s", jlee.Line)
	}
	if len(jlee.Facts) != 6 || jlee.Facts[0].Value != commas(reported) || jlee.Facts[0].Note != "of 30 with this account" {
		t.Errorf("jlee facts: %+v", jlee.Facts)
	}
	if !strings.Contains(jlee.Facts[1].Note, "Remote Desktop") || !strings.Contains(jlee.Facts[1].Note, "SSH") {
		t.Errorf("logons note: %q", jlee.Facts[1].Note)
	}
	// Where and when: sessions from the logon/logoff pairs, a detection
	// mark on WS-ADM-02 (the PowerShell download), the rest folded.
	l := jlee.Lanes
	if l == nil || len(l.Rows) != maxLanes+1 || l.Rows[0].Label != "WS-ADM-02" || len(l.Rows[0].Marks) != 1 || !strings.HasPrefix(l.Rows[maxLanes].Label, "… ") {
		t.Fatalf("lanes: %+v", l)
	}
	if len(l.Ticks) != 5 || l.Ticks[0].Label != "00:00" || l.Ticks[4].Label != "24:00" {
		t.Errorf("ticks: %+v", l.Ticks)
	}
	// The list: groups, counts, quiet ones folded, and the footnote.
	var titles []string
	for _, g := range pp.Groups {
		titles = append(titles, g.Title)
		if len(g.Shown) > 10 && len(g.Folded) > 0 {
			for _, v := range g.Shown[10:] {
				if v.Det == 0 {
					t.Errorf("%s: %s shown past ten with no detection", g.Title, v.Key)
				}
			}
		}
	}
	if strings.Join(titles, "|") != "Administrators|Users|Shared and service accounts" && strings.Join(titles, "|") != "Administrators|Shared and service accounts" {
		t.Errorf("groups: %v", titles)
	}
	if pp.Unused < 1000 || pp.Systems != 30 || pp.ExampleN < 9 {
		t.Errorf("footnote: %d unused on %d systems, example %s on %d", pp.Unused, pp.Systems, pp.Example, pp.ExampleN)
	}
	if root := pp.people["root"]; root == nil || root.Sub != "built-in, Linux · on 15 systems" {
		t.Errorf("root's line: %+v", root)
	}
}

func TestPeopleSharedAccountsDemo30(t *testing.T) {
	r, _ := demo30(t)
	pp := r.peoplePage()
	acted := func(v *PersonView) map[string]ActedRow {
		m := map[string]ActedRow{}
		for _, a := range append(append(append([]ActedRow(nil), v.Acted...), v.ActedMore...), v.ActedFixed...) {
			m[a.Person+"|"+a.How] = a
		}
		return m
	}
	root := pp.people["root"]
	if root == nil || !root.Shared || root.Group != "shared" {
		t.Fatalf("root: %+v", root)
	}
	if root.Line != "Shared built-in account · a separate account on each of 15 Linux systems · not one person" {
		t.Errorf("root line: %s", root.Line)
	}
	m := acted(root)
	if a := m["kpatel|su"]; a.N != 1 || a.Systems != "ubu-git01" {
		t.Errorf("kpatel su: %+v", a)
	}
	if a := m["kpatel|sudo"]; a.N < 10 {
		t.Errorf("kpatel sudo: %+v", a)
	}
	if a := m["Jobs and services|no person"]; a.N < 50 || a.Quiet {
		t.Errorf("root's jobs: %+v", a)
	}
	if a := m["Direct logon as root|console or SSH"]; a.N != 0 || !a.Quiet || a.Systems != "none" {
		t.Errorf("direct root logons: %+v", a)
	}
	if root.CallBad || !strings.HasPrefix(root.CallEnd, "No one logged on as root directly.") || !strings.Contains(root.CallEnd, "412 attempts to log on as root failed (ubu-web01)") {
		t.Errorf("root box: %q", root.CallEnd)
	}
	if root.Facts[1].Label != "Direct logons" || root.Facts[1].Value != "0" || root.Facts[2].Label != "Via sudo or su" {
		t.Errorf("root facts: %+v", root.Facts)
	}
	// Administrator: RunAs by two people, one direct logon at the keyboard.
	adm := pp.people["administrator"]
	if adm == nil || !adm.Shared {
		t.Fatalf("Administrator: %+v", adm)
	}
	m = acted(adm)
	if a := m["jlee|RunAs"]; a.N != 3 || a.Systems != "2 servers" {
		t.Errorf("jlee RunAs: %+v", a)
	}
	if a := m["tlopez|RunAs"]; a.N != 1 || a.Systems != "WS-LAB-01" {
		t.Errorf("tlopez RunAs: %+v", a)
	}
	if a := m["Direct logon as Administrator|console or Remote Desktop"]; a.N != 1 || a.Systems != "WS-LAB-01" {
		t.Errorf("direct Administrator logon: %+v", a)
	}
	if !adm.CallBad || !strings.Contains(adm.CallEnd, "Administrator logged on directly once on WS-LAB-01 (1 console)") {
		t.Errorf("Administrator box: %q", adm.CallEnd)
	}
	// RunAs and sudo stay on the person's own page too.
	if jlee := pp.people["jlee"]; jlee.Facts[3].Value == "0" {
		t.Errorf("jlee's privileged actions: %+v", jlee.Facts[3])
	}
}

func TestPeopleAliasesDemo30(t *testing.T) {
	net := demo30Network(t)
	at := net.Start.Add(10 * time.Hour)
	net.Events = append(net.Events,
		&event.Event{Time: at, Host: "SRV-APP01", OS: "windows", Source: "Security", Category: event.CatLogon, Action: "logon", User: "j.lee", Summary: "j.lee logged on (Remote Desktop).", EventID: 4624},
		&event.Event{Time: at.Add(time.Minute), Host: "ubu-db01", OS: "linux", Source: "audit", Category: event.CatPrivileged, Severity: event.SevLow, Action: "sudo", User: "JLEE2", Summary: "JLEE2 ran as root with sudo: ls"})
	// Without aliases: three people.
	r := Build(append([]*event.Event(nil), net.Events...), net.Runs, net.Options)
	pp := r.peoplePage()
	if pp.people["j.lee"] == nil || pp.people["jlee2"] == nil {
		t.Fatalf("j.lee and jlee2 should be people of their own without people_aliases")
	}
	// With them: one.
	opt := net.Options
	opt.PeopleAliases = map[string]string{"j.lee": "jlee", "jlee2": "jlee"}
	r = Build(append([]*event.Event(nil), net.Events...), net.Runs, opt)
	pp = r.peoplePage()
	if pp.people["j.lee"] != nil || pp.people["jlee2"] != nil {
		t.Fatal("aliases not merged")
	}
	jlee := pp.people["jlee"]
	if jlee.Name != "jlee" || strings.Join(jlee.Merged, ",") != "j.lee,jlee2" {
		t.Errorf("jlee: name %q, merged %v", jlee.Name, jlee.Merged)
	}
	found := 0
	for _, a := range append(append([]AcctRow(nil), jlee.Accounts...), jlee.AcctMore...) {
		switch a.Account {
		case `SRV-APP01\j.lee`:
			found++
			if a.Note != "spelled j.lee · merged by people_aliases" || a.Logons != 1 {
				t.Errorf("j.lee row: %+v", a)
			}
		case `ubu-db01\jlee2`:
			found++
		}
	}
	if found != 2 {
		t.Errorf("merged spellings not in Accounts named jlee: %d", found)
	}
	// The page says so, Search and links resolve the spellings.
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	html := string(b)
	for _, want := range []string{"the spellings people_aliases lists (<b>j.lee</b>, <b>jlee2</b>)", `"palias":{"j.lee":"jlee","jlee2":"jlee"}`,
		"Who acted as root", "Accounts named jlee", `class="lm bad"`, "Find a person or account", `data-ptab="adm"`, "see Inventory →", `data-folded="pf-admin"`} {
		if !strings.Contains(html, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

// A logon and its logoff are one session; activity with no logon in the
// period is a short stretch; a logon with no logoff ends at the last
// thing done in it.
func TestPeopleSessions(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	ev := func(m int, action string, id string) laneEvent {
		e := &event.Event{Time: t0.Add(time.Duration(m) * time.Minute), Host: "H", User: "bob", Action: action, Category: event.CatPrivileged}
		if action == "logon" || action == "logoff" {
			e.Category = event.CatLogon
		}
		if id != "" {
			e.AddDetail("Logon ID", id)
		}
		return laneEvent{row: &Row{Event: e}, own: true}
	}
	got := sessions([]laneEvent{ev(0, "sudo", ""), ev(5, "sudo", ""), ev(60, "logon", "0x1"), ev(70, "sudo", ""), ev(65, "x", ""), ev(90, "logoff", "0x1"),
		ev(200, "logon", ""), ev(230, "sudo", "")})
	want := []string{"Session 60-90", "Session 200-230", "Activity 0-5"}
	var have []string
	for _, s := range got {
		have = append(have, s.what+" "+itoa(int(s.from.Sub(t0).Minutes()))+"-"+itoa(int(s.to.Sub(t0).Minutes())))
	}
	if strings.Join(have, ",") != strings.Join(want, ",") {
		t.Errorf("sessions %v, want %v", have, want)
	}
}
