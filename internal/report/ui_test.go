package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// The antivirus date is its own table on Audit health, a line on the
// Overview and on each system, read from the check's date (or, for checks
// made before it had one, from its text).
func TestAntivirusTable(t *testing.T) {
	end := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	evs := []*event.Event{
		{Time: end.Add(-time.Hour), Host: "WS-07", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
		{Time: end.Add(-time.Hour), Host: "ubu-01", OS: "linux", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"},
	}
	sets := []CheckSet{
		NewCheckSet("WS-07", end.Add(-2*time.Hour), []check.Result{
			{Area: "Antivirus", Item: "Defender security intelligence", Status: check.Pass, Dated: end.Add(-72 * time.Hour),
				Have: "1.419.123.0 · version created on 2 Oct 2026 12:00 (3 days ago) · engine 1.1.24"},
			{Area: "Antivirus", Item: "Defender real-time protection", Status: check.Pass, Have: "On"}}),
		NewCheckSet("ubu-01", end.Add(-time.Hour), []check.Result{ // made before the date had its own field
			{Area: "Antivirus", Item: "ClamAV definitions", Status: check.Fail, Have: "daily 27001 · built on 1 Aug 2026 09:30 (65 days ago) · engine 1.0.7"},
			{Area: "Antivirus", Item: "ClamAV scanner service", Status: check.Pass, Have: "Running"}}),
	}
	runs := []*store.Run{{Time: end.Add(-2 * time.Hour), Host: "WS-07", OS: "windows"}, {Time: end.Add(-time.Hour), Host: "ubu-01", OS: "linux"}}
	r := Build(evs, runs, Options{WindowEnd: end, Location: time.UTC, CheckSets: sets})
	rows := r.avRows()
	if len(rows) != 2 || rows[0].Host != "ubu-01" || rows[0].Status != "Out of date" || rows[0].Dated != "1 Aug 2026 09:30" || rows[0].Version != "daily 27001" ||
		rows[1].Product != "Microsoft Defender" || rows[1].Dated != "2 Oct 2026 12:00" || rows[1].Age != "3 days old" || rows[1].Protection != "On" {
		t.Fatalf("rows: %+v", rows)
	}
	l, ok := r.avCheckLine(rows)
	if !ok || l.Level != "bad" || l.Who != "ubu-01" || !strings.Contains(l.What, "oldest definitions dated 1 Aug 2026 09:30") || l.Href != "#health/@av" {
		t.Errorf("overview line: %+v", l)
	}
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, want := range []string{`id="h-av"`, "Definitions dated", "<b>2 Oct 2026 12:00</b>", "Antivirus definitions", "Defender, definitions 2 Oct"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

// An event page is Search with its kind preset (UI-R1, its stat cards
// are gone); the People heatmap links its hours; All reports is a link in
// the sidebar's report card.
func TestClickableCardsAndHeatmap(t *testing.T) {
	end := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	at := time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC) // a Monday
	evs := []*event.Event{
		{Time: at, Host: "WS-07", OS: "windows", Category: event.CatFailedLogon, Severity: event.SevMedium, Action: "account_locked", User: "bob", Target: "bob", Summary: "bob was locked out"},
		{Time: at, Host: "WS-07", OS: "windows", Category: event.CatPrivileged, Severity: event.SevLow, Action: "special_logon", User: "admin_jd", Summary: "admin"},
	}
	r := Build(evs, nil, Options{WindowEnd: end, Location: time.UTC, InReportsDir: true})
	dir := filepath.Join(t.TempDir(), "rep")
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	html := string(b)
	for _, want := range []string{
		`<div class="sq" data-sq="failed">`, // Failed logons is Search with its kind preset
		`data-kindclear`,
		`href="../index.html" title="Every report in this folder, newest first"`,
		`href="#search?host=WS-07&amp;user=admin_jd"`, // a person's lane on People opens Search
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report lacks %s", want)
		}
	}
	// UI-R1: the period and All reports are in the sidebar's report card,
	// not the page header.
	if strings.Contains(html, `<a class="btn" href="../index.html"`) || strings.Contains(html, `<span class="btn static"`) {
		t.Error("the page header still has the period or All reports")
	}
}
