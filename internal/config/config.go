// Package config loads blackbox.conf, a plain "key = value" file.
//
// A flat format keeps Blackbox free of third-party parsing libraries and
// is easy to edit in Notepad or vi. Lines starting with # are comments;
// lists are comma-separated.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Config holds all settings. Zero values are replaced by defaults.
type Config struct {
	SiteName         string
	ReportEvery      string   // daily | weekly | monthly
	ReportAt         ReportAt // when a report period ends
	RetentionDays    int      // 0 = keep forever
	ExcludeUsers     []string // accounts to leave out (case-insensitive)
	ExcludeProcesses []string // program names/paths to leave out
	DataDir          string   // state and collected events
	ReportDir        string   // where reports go ("" = DataDir/reports)
	ArchiveDir       string   // where original logs wait for the next report ("" = DataDir/archives)
	CollectEvery     time.Duration
	WorkingHours     WorkingHours // when administrator activity is expected

	// LAN. SendTo is the collector's inbox this system sends its data to
	// (a folder, or a share: \\server\share on Windows, //server/share on
	// Linux). Inbox is the folder this system, as a collector, receives
	// other systems' data in. A computer does one or the other.
	SendTo    string
	Inbox     string
	ShareUser string // account for the SendTo share, when one is needed
	// KeepSentDays is how long a sender keeps batches after delivering
	// them, so "blackbox send --resend" can fill a gap the collector
	// reports (L11). 0 = not kept.
	KeepSentDays int

	// SCAP scan results to show with the report (docs/design.md 13a):
	// ScapResults is the folder to read ("" = scap in the data folder,
	// "none" = off), ScapMaxAgeDays how old a scan may be before it is
	// pointed out as stale.
	ScapResults    string
	ScapMaxAgeDays int

	Path string // file the config was loaded from ("" if defaults)
}

// Default returns the built-in defaults.
func Default() *Config {
	return &Config{
		ReportEvery:    "weekly",
		ReportAt:       DefaultReportAt,
		DataDir:        DefaultDataDir(),
		CollectEvery:   15 * time.Minute, // C6: an hour lets a busy STIG-audited Security log roll over
		ScapMaxAgeDays: 30,
		KeepSentDays:   14,
	}
}

// ScapDir is the folder SCAP results are read from, or "" when that is
// turned off.
func (c *Config) ScapDir() string {
	switch strings.ToLower(strings.TrimSpace(c.ScapResults)) {
	case "none", "off":
		return ""
	case "":
		return filepath.Join(c.DataDir, "scap")
	}
	return c.ScapResults
}

// ReportsDir is the folder reports are written to.
func (c *Config) ReportsDir() string {
	if c.ReportDir != "" {
		return c.ReportDir
	}
	return filepath.Join(c.DataDir, "reports")
}

// IsVirtualBoxShare says whether a send_to folder is a VirtualBox shared
// folder (/media/sf_… on Linux, \\VBOXSVR\… on Windows): the sender is a
// virtual machine on the collector's PC.
func IsVirtualBoxShare(p string) bool {
	lo := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	return strings.HasPrefix(lo, "/media/sf_") || strings.HasPrefix(lo, "//vboxsvr/") || strings.HasPrefix(lo, "//vboxsrv/")
}

// ArchivesDir is where the original logs (see package archive) wait until
// the next scheduled report moves them into its folder: this computer's
// and, on a collector, every sender's.
func (c *Config) ArchivesDir() string {
	if c.ArchiveDir != "" {
		return c.ArchiveDir
	}
	return filepath.Join(c.DataDir, "archives")
}

// DefaultDataDir is where state and collected events live (and reports,
// unless report_dir is set).
func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "Blackbox")
	}
	return "/var/lib/blackbox"
}

// DefaultPath is where the config file is looked for.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(DefaultDataDir(), "blackbox.conf")
	}
	return "/etc/blackbox/blackbox.conf"
}

// Load reads path. A missing file yields defaults (no error).
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c, err := parse(f, path)
	if err != nil {
		return nil, err
	}
	c.Path = path
	return c, nil
}

func parse(r io.Reader, path string) (*Config, error) {
	c := Default()
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, n)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = unquote(strings.TrimSpace(v))
		if err := c.set(k, v); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

// unquote reads a value: "a value in quotes" is taken as it is (it may
// contain " #"); otherwise a trailing " # comment" is removed.
func unquote(v string) string {
	if strings.HasPrefix(v, `"`) {
		if j := strings.Index(v[1:], `"`); j >= 0 {
			return v[1 : 1+j]
		}
	}
	return strings.TrimSpace(stripComment(v))
}

// quote writes a value so that it reads back the same: in quotes when it
// contains " #" (which would otherwise start a comment) or starts with a
// quote.
func quote(v string) (string, error) {
	if !strings.Contains(v, " #") && !strings.HasPrefix(v, `"`) {
		return v, nil
	}
	if strings.Contains(v, `"`) {
		return "", fmt.Errorf("a value can't contain both \" #\" and a quote mark: %s", v)
	}
	return `"` + v + `"`, nil
}

// stripComment removes a trailing " # comment" (a # preceded by space).
func stripComment(v string) string {
	if i := strings.Index(v, " #"); i >= 0 {
		return v[:i]
	}
	return v
}

func (c *Config) set(k, v string) error {
	switch k {
	case "site_name":
		c.SiteName = v
	case "report_every":
		if v != "" {
			c.ReportEvery = strings.ToLower(v)
		}
	case "report_at":
		if v != "" {
			r, err := ParseReportAt(v)
			if err != nil {
				return err
			}
			c.ReportAt = r
		}
	case "retention_days":
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("retention_days must be 0 or a positive number")
		}
		c.RetentionDays = n
	case "exclude_users":
		c.ExcludeUsers = list(v)
	case "exclude_processes":
		c.ExcludeProcesses = list(v)
	case "working_hours":
		w, err := ParseWorkingHours(v)
		if err != nil {
			return err
		}
		c.WorkingHours = w
	case "data_dir":
		if v != "" {
			c.DataDir = v
		}
	case "report_dir":
		c.ReportDir = v
	case "archive_dir":
		c.ArchiveDir = v
	case "scap_results":
		c.ScapResults = v
	case "scap_max_age_days":
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("scap_max_age_days must be a positive number of days")
		}
		c.ScapMaxAgeDays = n
	case "keep_sent_days":
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("keep_sent_days must be 0 or a positive number of days")
		}
		c.KeepSentDays = n
	case "send_to":
		c.SendTo = v
	case "inbox":
		c.Inbox = v
	case "share_user":
		c.ShareUser = v
	case "collect_every":
		if v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d < 5*time.Minute {
				return fmt.Errorf("collect_every must be a duration of at least 5m, e.g. 1h or 30m")
			}
			c.CollectEvery = d
		}
	default:
		return fmt.Errorf("unknown setting %q", k)
	}
	return nil
}

// Validate checks values that can be wrong.
func (c *Config) Validate() error {
	switch c.ReportEvery {
	case "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("report_every must be daily, weekly or monthly (got %q)", c.ReportEvery)
	}
	if c.ReportDir != "" && !IsAbs(c.ReportDir) {
		return fmt.Errorf("report_dir must be a full path, e.g. %s (got %q)", exampleDir(), c.ReportDir)
	}
	if c.ArchiveDir != "" && !IsAbs(c.ArchiveDir) {
		return fmt.Errorf("archive_dir must be a full path, e.g. %s (got %q)", exampleDir(), c.ArchiveDir)
	}
	if c.Inbox != "" && !IsAbs(c.Inbox) {
		return fmt.Errorf("inbox must be a full path, e.g. %s (got %q)", exampleInbox(), c.Inbox)
	}
	if c.SendTo != "" && !IsAbs(c.SendTo) && !IsShare(c.SendTo) {
		return fmt.Errorf("send_to must be a full path or a network share, e.g. %s (got %q)", exampleShare(), c.SendTo)
	}
	if c.SendTo != "" && c.Inbox != "" {
		return fmt.Errorf("send_to and inbox are both set: a computer either sends to a collector (send_to) or is the collector (inbox), not both")
	}
	return nil
}

// Role describes what this system does with its data.
func (c *Config) Role() string {
	switch {
	case c.SendTo != "":
		return "sender"
	case c.Inbox != "":
		return "collector"
	}
	return "standalone"
}

// MakesReports reports whether this system produces its own reports. A
// system that sends to a collector does not: its events appear in the
// collector's reports instead.
func (c *Config) MakesReports() bool { return c.SendTo == "" }

// IsShare reports whether p names a network share: \\server\share, or
// //server/share (the form Linux uses).
func IsShare(p string) bool {
	return (strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//")) && len(strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })) >= 2
}

func exampleInbox() string {
	if runtime.GOOS == "windows" {
		return `C:\BlackboxInbox`
	}
	return "/srv/blackbox-inbox"
}

func exampleShare() string {
	if runtime.GOOS == "windows" {
		return `\\COLLECTOR\BlackboxInbox`
	}
	return "//COLLECTOR/BlackboxInbox or /media/sf_BlackboxInbox"
}

// IsAbs reports whether p is a full path. On Windows that includes UNC
// paths (\\server\share\folder).
func IsAbs(p string) bool {
	return filepath.IsAbs(p) || (runtime.GOOS == "windows" && strings.HasPrefix(p, `\\`))
}

func exampleDir() string {
	if runtime.GOOS == "windows" {
		return `D:\AuditReports`
	}
	return "/srv/audit-reports"
}

// RawValues reads the settings in the file as written (unquoted, comments
// removed), for recording what a change replaced. Settings not in the
// file are "", and so is everything when the file does not exist.
func RawValues(path string) map[string]string {
	out := map[string]string{}
	for _, k := range append([]string{"collect_every"}, Settable...) {
		out[k] = ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(l)
		k, v, found := strings.Cut(t, "=")
		if !found || strings.HasPrefix(t, "#") {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, known := out[k]; known {
			out[k] = unquote(strings.TrimSpace(v))
		}
	}
	return out
}

// Settable lists the settings `blackbox config set` may change.
var Settable = []string{"site_name", "report_every", "report_at", "report_dir", "archive_dir", "retention_days", "exclude_users", "exclude_processes", "working_hours", "send_to", "inbox", "share_user", "keep_sent_days", "scap_results", "scap_max_age_days"}

// SetValue changes one user-settable setting in the config file (see
// Settable), keeping its comments and line endings.
func SetValue(path, key, value string) error {
	key = strings.ToLower(strings.TrimSpace(key))
	ok := false
	for _, k := range Settable {
		ok = ok || k == key
	}
	if !ok {
		return fmt.Errorf("%q cannot be set; settable: %s", key, strings.Join(Settable, ", "))
	}
	return SetValues(path, [][2]string{{key, value}})
}

// SetValues changes settings in the config file, keeping its comments and
// line endings. The result is validated before it is saved, so a bad value
// never leaves a broken file behind. A missing file is created from the
// template first.
func SetValues(path string, kv [][2]string) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		b = []byte(Render("", "weekly", DefaultReportAt, "", time.Hour))
		if runtime.GOOS == "windows" {
			b = []byte(strings.ReplaceAll(string(b), "\n", "\r\n"))
		}
	} else if err != nil {
		return err
	}
	text := string(b)
	nl := "\n"
	if strings.Contains(text, "\r\n") {
		nl = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for _, p := range kv {
		key, value := strings.ToLower(strings.TrimSpace(p[0])), strings.TrimSpace(p[1])
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s: value must be a single line", key)
		}
		written, err := quote(value)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		newLine := key + " = " + written
		replaced := false
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if k, _, found := strings.Cut(t, "="); found && !strings.HasPrefix(t, "#") && strings.ToLower(strings.TrimSpace(k)) == key {
				lines[i] = newLine
				replaced = true
				break
			}
		}
		if !replaced {
			add := []string{newLine}
			if intro, ok := keyIntro[key]; ok && !strings.Contains(strings.Join(lines, "\n"), intro[0]) {
				add = append(append([]string{""}, intro...), newLine)
			}
			if n := len(lines); n > 0 && lines[n-1] == "" {
				lines = append(append(lines[:n-1], add...), "")
			} else {
				lines = append(lines, add...)
			}
		}
	}
	out := strings.Join(lines, nl)
	if _, err := parse(strings.NewReader(out), path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(out), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func list(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// keyIntro is the explanation added above a setting when it is added to a
// config file written by an older version.
var keyIntro = func() map[string][]string {
	block := func(start string) []string {
		var out []string
		for _, l := range strings.Split(Template, "\n") {
			if strings.HasPrefix(l, start) || (len(out) > 0 && strings.HasPrefix(l, "#")) {
				out = append(out, l)
			} else if len(out) > 0 {
				break
			}
		}
		return out
	}
	lan := block("# LAN:")
	return map[string][]string{"send_to": lan, "inbox": lan, "share_user": lan, "report_at": block("# When each report period"),
		"archive_dir": block("# Folder where the original logs")}
}()

// Template is the commented config written by `blackbox install`.
const Template = `# Blackbox configuration
# Lines starting with # are comments. Lists are comma-separated.
# Changes take effect at the next scheduled run.

# Name shown at the top of every report.
site_name = {{SITE}}

# How often a report is produced: daily, weekly or monthly.
# Events are collected every collect_every (15 minutes by default),
# whatever the report schedule. A log that fills faster than that can
# still overwrite events before they are collected: blackbox check gives
# the log sizes, and blackbox status says when it happens.
report_every = {{REPORT_EVERY}}

# When each report period ends and the report is produced. Weekly: a day
# and time; "Wednesday 00:00" covers each week up to Tuesday night, so a
# fresh report is ready on Wednesday morning. Daily and monthly: a time
# (monthly periods end on the 1st). A report run by hand
# ("blackbox report") is a manual report and does not move this.
report_at = {{REPORT_AT}}

# Folder where reports are written. Leave blank for the default:
#   {{DEFAULT_REPORTS}}
# The folder may be one you have locked down; Blackbox only needs to be able
# to write to it. To move reports later, run (as administrator/root):
#   blackbox config set report_dir <folder>
# which checks the folder first (and on Linux updates the service sandbox).
# Existing reports stay where they are.
report_dir = {{REPORT_DIR}}

# Folder where the original logs (Windows .evtx, Linux audit and system
# logs) of this computer and, on a collector, of every sender wait until
# the next scheduled report moves them into its folder. Allow a few MB a
# day per computer. Leave blank for the archives folder in the data folder.
# To move it later, run (as administrator/root):
#   blackbox config set archive_dir <folder>
archive_dir =

# How often events are collected (the scheduled task/timer). To change it,
# run: blackbox config set collect_every 15m (or the installer again).
collect_every = {{COLLECT_EVERY}}

# LAN: sending to, or collecting from, other computers. See docs/lan.md.
#
# send_to: the collector's inbox this computer sends its events to. When
# set, this computer does not produce its own reports; its events appear
# in the collector's reports. Examples:
#   Windows:  \\COLLECTOR\BlackboxInbox
#   Linux:    //COLLECTOR/BlackboxInbox     (an SMB share)
#             /media/sf_BlackboxInbox        (a VirtualBox shared folder)
# share_user: the account used for an SMB share, if one is needed.
#
# inbox: makes this computer a collector. Other computers send their events
# into this folder, and this computer's reports cover all of them.
#
# Run the installer again to change these; it sets up the share and checks
# the folder.
send_to = {{SEND_TO}}
share_user = {{SHARE_USER}}
inbox = {{INBOX}}

# Days a sender keeps batches after delivering them, so they can be sent
# again with "blackbox send --resend FROM-TO" if the collector reports a
# gap. 0 = delete them once delivered.
keep_sent_days = 14

# Days to keep reports and collected events. 0 = keep forever.
retention_days = 0

# Accounts and programs to leave out of reports (for known noisy service
# accounts or tools). Example:
#   exclude_users = svc_backup, svc_scanner
#   exclude_processes = C:\Tools\Scanner\scan.exe
exclude_users =
exclude_processes =

# Working hours: administrator activity outside them is pointed out in the
# report's Detections. Leave empty to turn this off. Examples:
#   working_hours = Mon-Fri 06:00-18:00
#   working_hours = Daily 07:00-19:00
working_hours =

# SCAP scan results (DISA SCC or OpenSCAP XCCDF/ARF files) to show each
# computer's STIG compliance in the report. Blackbox only reads them; it
# never runs a scan. Blank reads the "scap" folder in the data folder;
# point it at SCC's results folder instead, or "none" to turn this off.
# A scan older than scap_max_age_days is pointed out as stale.
scap_results =
scap_max_age_days = 30

`

// Render fills in Template.
func Render(site, reportEvery string, reportAt ReportAt, reportDir string, collectEvery time.Duration) string {
	if collectEvery == 0 {
		collectEvery = time.Hour
	}
	if q, err := quote(site); err == nil {
		site = q
	}
	return strings.NewReplacer("{{SITE}}", site, "{{REPORT_EVERY}}", reportEvery, "{{REPORT_AT}}", reportAt.String(),
		"{{REPORT_DIR}}", reportDir, "{{DEFAULT_REPORTS}}", filepath.Join(DefaultDataDir(), "reports"),
		"{{COLLECT_EVERY}}", FormatDuration(collectEvery),
		"{{SEND_TO}}", "", "{{SHARE_USER}}", "", "{{INBOX}}", "").Replace(Template)
}

// FormatDuration writes 1h, 30m or 2h (not Go's 1h0m0s).
func FormatDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
