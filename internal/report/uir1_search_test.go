package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// UI-R1 Search (design 03) and the event pages (design 10): one search
// box with the filters, Common searches as one menu, field counts, the
// chart and the results; each event page is Search with its kind preset,
// without its own chart, cards or top lists.
func TestSearchPagesUIR1(t *testing.T) {
	r, _ := demo30(t)
	h, meta := renderHTML(t, r)
	search := between2(h, `<section class="view" data-view="search">`, `</section>`)
	for _, want := range []string{`<div class="sq" data-sq="">`, `data-q="text"`, `searches every field`, `data-q="page"`, `data-q="user"`,
		`data-q="host"`, `data-q="role"`, `data-q="sev"`, `data-q="when"`, `data-q="group"`, `data-common`, `data-facets`, `data-hist`, `data-qmore`,
		`<th scope="col">Event</th><th scope="col">Details</th><th scope="col">ID</th><th scope="col">Severity</th>`, `data-act="pagecsv"`} {
		if !strings.Contains(search, want) {
			t.Errorf("Search lacks %s", want)
		}
	}
	if n := strings.Count(search, `data-preset=`); n != 8 {
		t.Errorf("Common searches: %d, want the 8 in one menu", n)
	}
	if strings.Contains(h, `class="saved"`) || strings.Contains(h, `data-cats`) {
		t.Error("the old tiles or category chips are still there")
	}
	priv := between2(h, `<section class="view" data-view="privileged">`, `</section>`)
	for _, want := range []string{`<div class="sq" data-sq="privileged">`, `<b>Privileged activity</b><button type="button" data-kindclear`,
		`placeholder="Search within privileged activity…"`, `<th scope="col">Command or action</th>`, "admin rights, sudo and root commands"} {
		if !strings.Contains(priv, want) {
			t.Errorf("Privileged activity lacks %s", want)
		}
	}
	for _, gone := range []string{`data-q="page"`, `data-common`, `class="ev6"`, "per day", "Top people", `data-cardfilter`, `data-events=`} {
		if strings.Contains(priv, gone) {
			t.Errorf("Privileged activity still has %s", gone)
		}
	}
	// What app.js needs: each page's kind label, extra name and unit; the
	// people for the Person filter; each account's rights.
	var pages []struct{ ID, KindLabel, XLabel, Unit string }
	if err := json.Unmarshal(meta["pages"], &pages); err != nil {
		t.Fatal(err)
	}
	for _, p := range pages {
		if p.ID == "failed" && (p.KindLabel != "Reason" || p.XLabel != "Logon type" || p.Unit != "failed logons") {
			t.Errorf("failed page settings %+v", p)
		}
	}
	var rights map[string]map[string]string
	if err := json.Unmarshal(meta["rights"], &rights); err != nil {
		t.Fatal(err)
	}
	if rights["SRV-DC02"]["adm-jlee"] != "administrator" || rights["SRV-DC02"]["jdoe"] != "standard user" {
		t.Errorf("rights on SRV-DC02: %v", rights["SRV-DC02"])
	}
	if !strings.Contains(string(meta["people"]), `["adm-jlee","adm-jlee"]`) {
		t.Errorf("people for the Person filter: %.200s", meta["people"])
	}
}

// UI-R1 Event detail (design 16): the time to the millisecond in local
// time and UTC, the file in the original-log zip and the record number,
// what started it (the parent and the logon session), and ATT&CK.
func TestEventDetailUIR1(t *testing.T) {
	r, _ := demo30(t)
	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	extra := func(page, find string) rawExtra {
		t.Helper()
		data, _ := os.ReadFile(filepath.Join(dir, "data", page+"-20261007.js"))
		raw, _ := os.ReadFile(filepath.Join(dir, "data", page+"-20261007-raw.js"))
		var c struct{ Rows [][]any }
		var rs [][]json.RawMessage
		if err := json.Unmarshal([]byte(unpackData(t, data)), &c); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(unpackData(t, raw)), &rs); err != nil {
			t.Fatal(err)
		}
		for i, row := range c.Rows {
			if s, _ := row[8].(string); strings.Contains(s, find) {
				var x rawExtra
				if len(rs[i]) < 5 {
					t.Fatalf("%s: raw entry has no extra", find)
				}
				if err := json.Unmarshal(rs[i][4], &x); err != nil {
					t.Fatal(err)
				}
				return x
			}
		}
		t.Fatalf("no %q on %s", find, page)
		return rawExtra{}
	}
	x := extra("privileged", `wevtutil.exe`)
	if x.When != "Wed 7 Oct 2026 14:22:05.118 EDT (18:22:05.118 UTC)" {
		t.Errorf("when %q", x.When)
	}
	if x.Piece != "logs-SRV-DC02.zip › Security.evtx" || x.Rec == 0 {
		t.Errorf("original record %q, record %d", x.Piece, x.Rec)
	}
	if x.By != "cmd.exe (from a Remote Desktop session from WS-ADM-01)" {
		t.Errorf("started by %q", x.By)
	}
	if x.Attack != "" {
		t.Errorf("a program run has no clear technique, got %q", x.Attack)
	}
	x = extra("integrity", "Security log was cleared")
	if x.Attack != "T1070.001 Clear Windows Event Logs" || x.Piece != "logs-SRV-DC02.zip › Security.evtx" {
		t.Errorf("log cleared: %+v", x)
	}
	x = extra("powershell", "Invoke-WebRequest")
	if x.Piece != "logs-WS-ADM-02.zip › PowerShell-Operational.evtx" {
		t.Errorf("PowerShell event's file %q", x.Piece)
	}
	x = extra("privileged", "sudo -i")
	if x.Piece != "logs-ubu-db01.zip › audit.log" {
		t.Errorf("Linux event's file %q", x.Piece)
	}
}

func TestEventDetailParts(t *testing.T) {
	for in, want := range map[string]string{"Microsoft-Windows-PowerShell/Operational": "powershelloperational", "PowerShell-Operational.evtx": "powershelloperational",
		"/var/log/audit/audit.log": "audit", "Security": "security"} {
		if got := logKey(in); got != want {
			t.Errorf("logKey(%q) = %q, want %q", in, got, want)
		}
	}
	for _, c := range []struct {
		e    event.Event
		want string
	}{
		{event.Event{Action: "log_cleared", OS: "linux"}, "T1070.002 Clear Linux or Mac System Logs"},
		{event.Event{Action: "group_member_added", Severity: event.SevHigh}, "T1098.007 Additional Local or Domain Groups"},
		{event.Event{Action: "group_member_added", Severity: event.SevLow}, ""},
		{event.Event{Action: "audit_policy_changed", Severity: event.SevLow}, ""},
		{event.Event{Action: "service_installed", OS: "windows"}, "T1543.003 Windows Service"},
		{event.Event{Action: "logon"}, ""},
	} {
		if got := attackOf(&c.e); got != c.want {
			t.Errorf("%s: %q, want %q", c.e.Action, got, c.want)
		}
	}
	rr := &Report{}
	rr.Location = time.FixedZone("EDT", -4*3600)
	d := &detailer{r: rr, zone: "EDT", off: -4 * 3600}
	at := time.Date(2026, 10, 7, 22, 0, 5, 7e6, time.FixedZone("EDT", -4*3600))
	if got := d.when(at); got != "Wed 7 Oct 2026 22:00:05.007 EDT (Thu 8 Oct 02:00:05.007 UTC)" {
		t.Errorf("when across midnight UTC: %q", got)
	}
}
