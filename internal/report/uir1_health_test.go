package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// UI-R1 Audit health (design 08) with the 30-system report: four cards,
// the tabs, one row per setting (most systems first, the first 8 then the
// rest folded), and nothing that is not a setting.
func TestUIR1AuditHealth(t *testing.T) {
	r, _ := demo30(t)
	hp := r.healthPage()
	var labels []string
	for _, c := range hp.Cards {
		labels = append(labels, c.Label)
	}
	if got := strings.Join(labels, " | "); got != "Audit settings match the STIG | SCAP (latest scans) | Antivirus | Logs" {
		t.Errorf("cards: %s", got)
	}
	if c := hp.Cards[0]; c.Value != "8 / 30" || !c.HasMeter || c.Meter != 26 || !strings.HasSuffix(c.Note, "settings to fix on 22 systems") {
		t.Errorf("STIG card: %+v", c)
	}
	if c := hp.Cards[2]; c.Value != "25 / 30" || c.Note != "current · 5 out of date" {
		t.Errorf("antivirus card: %+v", c)
	}
	if c := hp.Cards[3]; c.Value != "3" || c.Note != "systems overwrote events (PowerShell log) · 0 Security/audit lost" || c.Level != "warn" {
		t.Errorf("logs card: %+v", c)
	}
	var tabs []string
	for _, tb := range hp.Tabs {
		tabs = append(tabs, tb.Label+" "+tb.Count)
	}
	if got := strings.Join(tabs, " · "); got != "Settings to fix 24 · By system 30 · SCAP 4 CAT I · Antivirus 5 · Log sizes 3" {
		t.Errorf("tabs: %s", got)
	}

	// Settings only: no cleared logs, silent systems, lost events,
	// original logs or antivirus.
	for i, g := range hp.Gaps {
		for _, bad := range []string{"cleared", "No data", "lost", "Original logs", "Defender", "ClamAV", "Collection"} {
			if strings.Contains(g.Title, bad) {
				t.Errorf("not a setting: %q", g.Title)
			}
		}
		if i > 0 && len(g.Systems) > len(hp.Gaps[i-1].Systems) {
			t.Errorf("%q (%d systems) after %q (%d)", g.Title, len(g.Systems), hp.Gaps[i-1].Title, len(hp.Gaps[i-1].Systems))
		}
	}
	if len(hp.Top) != 8 || len(hp.More) != len(hp.Gaps)-8 || hp.MoreText != "16 more settings, each on 1–8 systems" {
		t.Errorf("fold: %d + %d, %q", len(hp.Top), len(hp.More), hp.MoreText)
	}
	var cv *GapCard
	for i := range hp.Gaps {
		if hp.Gaps[i].Title == "Credential Validation" {
			cv = &hp.Gaps[i]
		}
	}
	if cv == nil || cv.OS != "Windows" || cv.Affects != "Failed Logons" || strings.Join(cv.IDs, " · ") != "WN25-AU-000005 · WN11-AU-000005" ||
		cv.OneFix != "One GPO on the OU fixes all 10." || !cv.FixDot {
		t.Fatalf("Credential Validation: %+v", cv)
	}

	var b bytes.Buffer
	if err := r.WriteHTML(&b, nil); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	for _, want := range []string{"without it the report misses: Failed Logons", "WN25-AU-000005 · WN11-AU-000005", "10 systems",
		`<a class="mono" href="#health/SRV-DC02">SRV-DC02</a>`, "<b>One GPO on the OU fixes all 10.</b>", "16 more settings, each on 1–8 systems",
		"Show all 24 ↓", `data-hpane="logs"`, `aria-controls="hp-scap"`} {
		if !strings.Contains(h, want) {
			t.Errorf("Audit health lacks %q", want)
		}
	}
	view := h[strings.Index(h, `data-view="health"`):]
	view = view[:strings.Index(view, `<section class="view"`)]
	for _, gone := range []string{"Logs cleared", "No data received", "POA&amp;M", `class="jump"`} {
		if strings.Contains(view, gone) {
			t.Errorf("Audit health still has %q", gone)
		}
	}
}

// UI-R1 Original logs (design 09): four cards, one table grouped and
// problems first, and the assessor's three steps, also in README.txt.
func TestUIR1OriginalLogs(t *testing.T) {
	r, _ := demo30(t)
	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	lp := r.logsPage()
	var cards []string
	for _, c := range lp.Cards {
		cards = append(cards, c.Label+": "+c.Value+" · "+c.Note)
	}
	want := "Original logs in this report: 28 / 30 · 2 systems sent nothing (see Systems)\n" +
		"Complete: 24 · every collection exported, nothing missing\n" +
		"With a gap: 4 · 1 log cleared · 3 PowerShell overwrites\n" +
		"Checked: ✓ · all 84 files in 28 zips match their SHA-256 · "
	if got := strings.Join(cards, "\n"); !strings.HasPrefix(got, want) {
		t.Errorf("cards:\n%s", got)
	}
	if lp.AllN != 30 || lp.GapsN != 6 || len(lp.Table) != 2 || lp.Table[0].Title != "Servers" || lp.Table[1].Title != "Workstations" {
		t.Fatalf("table: %d, %d, %+v", lp.AllN, lp.GapsN, lp.Table)
	}
	srv := lp.Table[0].Items
	if srv[0].Chip != "Gap" || srv[0].Host != "SRV-APP02" || !strings.HasPrefix(srv[0].Brief, "PowerShell log overwrote 337 events") ||
		srv[1].Host != "SRV-DC02" || srv[1].Brief != "Security log cleared 14:22; nothing lost" || srv[2].Chip != "Complete" || srv[2].Inside != "3 .evtx · 3 pieces" {
		t.Errorf("servers: %+v / %+v / %+v", srv[0], srv[1], srv[2])
	}
	ws := lp.Table[1].Items
	if ws[0].Chip != "Missing" || !strings.HasPrefix(ws[0].Brief, "nothing received since") || ws[2].Chip != "Gap" {
		t.Errorf("workstations: %+v / %+v", ws[0], ws[2])
	}

	steps := []string{"sha256sum -c manifest.sha256", "blackbox verify", "Event Viewer", "ausearch -if", "archive.json lists every file with its hash, and any gap with its reason"}
	readme, err := os.ReadFile(filepath.Join(dir, "README.txt"))
	if err != nil {
		t.Fatal(err)
	}
	page, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	for _, s := range append(steps, "These are the systems' own log files, unchanged, so they can be checked without Blackbox") {
		if !strings.Contains(string(readme), s) {
			t.Errorf("README.txt lacks %q", s)
		}
	}
	text := strings.NewReplacer("<code>", "", "</code>", "", "&#39;", "'", "&lt;", "<", "&gt;", ">").Replace(string(page))
	for _, s := range append(steps, "Giving these to an assessor", "Gaps and missing 6", `data-lfilter="gaps"`) {
		if !strings.Contains(text, s) {
			t.Errorf("Original logs lacks %q", s)
		}
	}
}

// RET1 and AR7 stay visible on Original logs: the warnings at the top,
// and a set-aside archive as a line of its own.
func TestUIR1LogsKeepWarnings(t *testing.T) {
	r, _ := demo30(t)
	r.LeftOut = []LeftOutLogs{{Host: "ubu-ws-07", From: r.WindowStart, To: r.WindowEnd, Reason: "hash mismatch", SetAside: "aside/ubu-ws-07.zip"}}
	r.Overdue = []OverdueLogs{{Host: "WS-ENG-06", From: r.WindowStart, To: r.WindowEnd, Archives: 3, Days: 40, Dir: "/var/lib/blackbox/archive", RetentionDays: 30}}
	lp := r.logsPage()
	all := strings.Join(lp.Failing, "\n")
	if !strings.Contains(all, "were never put in a report") || !strings.Contains(all, "set aside in aside/ubu-ws-07.zip") {
		t.Errorf("warnings: %s", all)
	}
	found := false
	for _, a := range lp.Archives {
		if a.Host == "ubu-ws-07" && a.Chip == "Set aside" {
			found = true
		}
	}
	if !found || lp.Cards[0].Level != "bad" || !strings.Contains(lp.Cards[0].Note, "1 set aside") {
		t.Errorf("set aside: %v %+v", found, lp.Cards[0])
	}
}
