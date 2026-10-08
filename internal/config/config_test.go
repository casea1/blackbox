package config

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLoadTemplateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blackbox.conf")
	text := Render("Lab 3", "daily", DefaultReportAt, "", time.Hour) + "exclude_users = svc_backup, svc_scan  # noisy\n"
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.SiteName != "Lab 3" || c.ReportEvery != "daily" || len(c.ExcludeUsers) != 2 || c.ExcludeUsers[1] != "svc_scan" {
		t.Errorf("loaded wrong values: %+v", c)
	}
}

func TestLoadErrors(t *testing.T) {
	for _, bad := range []string{"report_every = hourly\n", "nonsense\n", "unknown_key = 1\n", "classification = SECRET\n"} {
		p := filepath.Join(t.TempDir(), "c.conf")
		os.WriteFile(p, []byte(bad), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	if c, err := Load(filepath.Join(t.TempDir(), "missing.conf")); err != nil || c.ReportEvery != "weekly" {
		t.Errorf("missing file should give defaults: %v %v", c, err)
	}
}

func absDir() string {
	if runtime.GOOS == "windows" {
		return `D:\AuditReports`
	}
	return "/srv/audit-reports"
}

func TestReportDir(t *testing.T) {
	c := Default()
	if c.ReportsDir() != filepath.Join(c.DataDir, "reports") {
		t.Errorf("default reports dir = %s", c.ReportsDir())
	}
	c.ReportDir = absDir()
	if c.ReportsDir() != absDir() {
		t.Errorf("custom reports dir = %s", c.ReportsDir())
	}
	p := filepath.Join(t.TempDir(), "c.conf")
	os.WriteFile(p, []byte("report_dir = reports\n"), 0o600)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "full path") {
		t.Errorf("relative report_dir accepted: %v", err)
	}
}

func TestSetValuesKeepsCommentsAndLineEndings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blackbox.conf")
	orig := strings.ReplaceAll(Render("Lab 3", "weekly", DefaultReportAt, "", time.Hour), "\n", "\r\n")
	os.WriteFile(p, []byte(orig), 0o600)

	if err := SetValue(p, "report_dir", absDir()); err != nil {
		t.Fatal(err)
	}
	if err := SetValues(p, [][2]string{{"collect_every", "30m"}, {"site_name", "Lab 4"}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	text := string(b)
	if strings.Count(text, "\n") != strings.Count(text, "\r\n") {
		t.Error("Windows line endings were not kept")
	}
	if !strings.Contains(text, "# How often a report is produced") {
		t.Error("comments were lost")
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ReportDir != absDir() || c.CollectEvery != 30*time.Minute || c.SiteName != "Lab 4" || c.ReportEvery != "weekly" {
		t.Errorf("settings after SetValues: %+v", c)
	}
	if strings.Count(text, "report_dir =") != 1 {
		t.Error("report_dir written more than once")
	}

	// Invalid values are refused and the file is left as it was.
	if err := SetValue(p, "report_every", "hourly"); err == nil {
		t.Error("invalid report_every accepted")
	}
	if err := SetValue(p, "data_dir", "/tmp"); err == nil {
		t.Error("data_dir should not be settable")
	}
	if b2, _ := os.ReadFile(p); string(b2) != text {
		t.Error("file changed by a refused SetValue")
	}
}

func TestSetValueCreatesMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "blackbox.conf")
	if err := SetValue(p, "site_name", "New Site"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.SiteName != "New Site" {
		t.Errorf("got %+v, %v", c, err)
	}
}

func TestLANSettings(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blackbox.conf")
	// A config written by an older version, without the LAN settings.
	old := "site_name = Lab\nreport_every = weekly\n"
	os.WriteFile(p, []byte(old), 0o640)
	share := "//COLLECTOR/BlackboxInbox"
	if runtime.GOOS == "windows" {
		share = `\\COLLECTOR\BlackboxInbox`
	}
	if err := SetValues(p, [][2]string{{"send_to", share}, {"share_user", "bbsend"}}); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.SendTo != share || c.ShareUser != "bbsend" || c.Role() != "sender" || c.MakesReports() {
		t.Errorf("got %+v, role %s", c, c.Role())
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "# LAN:") || strings.Count(string(b), "# LAN:") != 1 {
		t.Errorf("LAN explanation should be added once:\n%s", b)
	}
	if err := SetValue(p, "send_to", "relative/folder"); err == nil {
		t.Error("a relative send_to was accepted")
	}
	inbox := "/srv/inbox"
	if runtime.GOOS == "windows" {
		inbox = `C:\BlackboxInbox`
	}
	// A computer sends to a collector or is one, never both.
	if err := SetValue(p, "inbox", inbox); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("setting inbox on a sender: got %v, want a clear refusal", err)
	}
	if err := SetValues(p, [][2]string{{"send_to", ""}, {"share_user", ""}, {"inbox", inbox}}); err != nil {
		t.Fatal(err)
	}
	c, _ = Load(p)
	if c.Role() != "collector" || !c.MakesReports() {
		t.Errorf("role %s, want collector", c.Role())
	}
	for _, s := range []string{`\\server\share`, "//server/share", `\\server\share\sub`} {
		if !IsShare(s) {
			t.Errorf("IsShare(%q) = false", s)
		}
	}
	for _, s := range []string{`\\server`, "//", "/srv/x"} {
		if IsShare(s) {
			t.Errorf("IsShare(%q) = true", s)
		}
	}
}

// R3: every setting reads back exactly as it was set, including values
// with " #" in them (which would otherwise start a comment).
func TestEverySettingRoundTrips(t *testing.T) {
	abs := func(p string) string {
		if runtime.GOOS == "windows" {
			return `D:\` + p
		}
		return "/srv/" + p
	}
	cases := []struct {
		key, value string
		got        func(*Config) string
	}{
		{"site_name", "HOME-LAB #2", func(c *Config) string { return c.SiteName }},
		{"site_name", `Lab "3"`, func(c *Config) string { return c.SiteName }},
		{"report_every", "monthly", func(c *Config) string { return c.ReportEvery }},
		{"report_at", "Friday 12:00", func(c *Config) string { return c.ReportAt.String() }},
		{"report_dir", abs("Audit #1"), func(c *Config) string { return c.ReportDir }},
		{"archive_dir", abs("Logs #1"), func(c *Config) string { return c.ArchiveDir }},
		{"retention_days", "90", func(c *Config) string { return strconv.Itoa(c.RetentionDays) }},
		{"exclude_users", "svc_backup, CORP\\svc_scan", func(c *Config) string { return strings.Join(c.ExcludeUsers, ", ") }},
		{"exclude_processes", "scan.exe", func(c *Config) string { return strings.Join(c.ExcludeProcesses, ", ") }},
		{"working_hours", "Mon-Fri 06:00-18:00", func(c *Config) string { return c.WorkingHours.Text }},
		{"people_aliases", "jlee=j.lee,jlee2; mchen=m.chen", func(c *Config) string { return FormatPeopleAliases(c.PeopleAliases) }},
		{"send_to", abs("inbox #2"), func(c *Config) string { return c.SendTo }},
		{"inbox", abs("inbox"), func(c *Config) string { return c.Inbox }},
		{"share_user", "bbsend", func(c *Config) string { return c.ShareUser }},
		{"scap_results", abs("SCC #1"), func(c *Config) string { return c.ScapResults }},
		{"scap_max_age_days", "45", func(c *Config) string { return strconv.Itoa(c.ScapMaxAgeDays) }},
		{"keep_sent_days", "30", func(c *Config) string { return strconv.Itoa(c.KeepSentDays) }},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.key] = true
		p := filepath.Join(t.TempDir(), "blackbox.conf")
		if err := SetValue(p, tc.key, tc.value); err != nil {
			t.Errorf("%s = %q: %v", tc.key, tc.value, err)
			continue
		}
		c, err := Load(p)
		if err != nil {
			t.Errorf("%s = %q: load: %v", tc.key, tc.value, err)
			continue
		}
		if got := tc.got(c); got != tc.value {
			t.Errorf("%s: set %q, read back %q", tc.key, tc.value, got)
		}
	}
	for _, k := range Settable {
		if !seen[k] {
			t.Errorf("no round-trip case for %s", k)
		}
	}
	if err := SetValue(filepath.Join(t.TempDir(), "c"), "site_name", `A "b" #2`); err == nil {
		t.Error("a value with both a quote and \" #\" should be refused")
	}
}

// §6: SCAP results are read from the data folder by default, from a
// chosen folder, or not at all.
func TestScapDir(t *testing.T) {
	c := Default()
	if c.ScapDir() != filepath.Join(c.DataDir, "scap") || c.ScapMaxAgeDays != 30 {
		t.Errorf("default: %q %d", c.ScapDir(), c.ScapMaxAgeDays)
	}
	c.ScapResults = "none"
	if c.ScapDir() != "" {
		t.Errorf("none: %q", c.ScapDir())
	}
}

// The original logs wait in the data folder unless archive_dir names
// another one, e.g. on a larger volume.
func TestArchivesDir(t *testing.T) {
	abs := func(p string) string {
		if runtime.GOOS == "windows" {
			return `D:\` + p
		}
		return "/srv/" + p
	}
	c := Default()
	if c.ArchivesDir() != filepath.Join(c.DataDir, "archives") {
		t.Errorf("default: %s", c.ArchivesDir())
	}
	c.ArchiveDir = abs("Logs")
	if c.ArchivesDir() != abs("Logs") {
		t.Errorf("set: %s", c.ArchivesDir())
	}
	c.ArchiveDir = "relative"
	if err := c.Validate(); err == nil {
		t.Error("a relative archive_dir was accepted")
	}
}

// UI2: sending through a VirtualBox shared folder is what marks a VM.
func TestIsVirtualBoxShare(t *testing.T) {
	for p, want := range map[string]bool{
		"/media/sf_blackbox":           true,
		`\\VBOXSVR\blackbox`:           true,
		`\\vboxsrv\share\in`:           true,
		`\\WIN11-COL\BlackboxInbox`:    false,
		"/mnt/blackbox":                false,
		"sftp://collector/blackbox/in": false,
	} {
		if got := IsVirtualBoxShare(p); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
}

// CONF1b: an upgrade gives the settings file this version's comments and
// keeps every value; the earlier file is kept as .old.
func TestRefreshKeepsValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blackbox.conf")
	old := "# Blackbox configuration\r\n\r\n# How often a report is produced.\r\n# Events are collected every hour regardless.\r\nreport_every = daily\r\nsite_name = \"Lab 3\"\r\nreport_at = 06:00\r\n" +
		"collect_every = 15m\r\nretention_days = 400\r\nexclude_users = svc_backup, svc_scan\r\nworking_hours = Mon-Fri 06:00-18:00\r\n"
	os.WriteFile(path, []byte(old), 0o640)
	before, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := Refresh(path, "0.21.0")
	if err != nil || kept != path+".old" {
		t.Fatalf("refresh: %q %v", kept, err)
	}
	after, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("settings changed:\n%+v\n%+v", before, after)
	}
	b, _ := os.ReadFile(path)
	text := string(b)
	if strings.Contains(text, "every hour regardless") || !strings.Contains(text, "whatever the report schedule") || !strings.Contains(text, "\r\n") ||
		!strings.Contains(text, `site_name = "Lab 3"`) || !strings.Contains(text, "retention_days = 400") {
		t.Errorf("refreshed file:\n%s", text)
	}
	if b, _ := os.ReadFile(path + ".old"); string(b) != old {
		t.Error("the earlier file was not kept")
	}
	if kept, err := Refresh(path, "0.21.0"); kept != "" || err != nil {
		t.Errorf("second refresh: %q %v", kept, err)
	}
}

// SEC3c: a later refresh never overwrites the .old kept by the first one
// (the file as the person last edited it); it keeps its own copy under
// the version doing the refresh, and a number if that is taken too.
func TestRefreshKeepsFirstOld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blackbox.conf")
	stale := "# Events are collected every hour regardless.\nreport_every = daily\n"
	os.WriteFile(path, []byte(stale), 0o640)
	if kept, err := Refresh(path, "0.21.0"); err != nil || kept != path+".old" {
		t.Fatalf("first: %q %v", kept, err)
	}
	for i, want := range []string{path + ".old.0.23.0", path + ".old.0.23.0.2"} {
		second := stale + "# mine " + strconv.Itoa(i) + "\n"
		os.WriteFile(path, []byte(second), 0o640)
		kept, err := Refresh(path, "0.23.0")
		if err != nil || kept != want {
			t.Fatalf("refresh %d: %q %v", i, kept, err)
		}
		if b, _ := os.ReadFile(kept); string(b) != second {
			t.Errorf("refresh %d kept %q", i, b)
		}
	}
	if b, _ := os.ReadFile(path + ".old"); string(b) != stale {
		t.Errorf("the first .old was overwritten: %q", b)
	}
	// A version is only ever part of a file name.
	if got := keepName(path, `..\x/y`); got != path+".old.xy" {
		t.Errorf("unsafe version: %q", got)
	}
}

// UX10: config show leaves the weekday out when reports are not weekly.
func TestReportAtShow(t *testing.T) {
	at, _ := ParseReportAt("Wednesday 00:00")
	if at.Show("daily") != "00:00" || at.Show("monthly") != "00:00" || at.Show("weekly") != "Wednesday 00:00" {
		t.Errorf("show: %q %q %q", at.Show("daily"), at.Show("monthly"), at.Show("weekly"))
	}
}
