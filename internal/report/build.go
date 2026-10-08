// Package report turns translated events and collection records into a
// self-contained HTML report plus CSV/JSON exports and a SHA-256 manifest.
package report

import (
	"fmt"
	"github.com/casea1/blackbox/internal/archive"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/rollover"
	"github.com/casea1/blackbox/internal/scap"
	"github.com/casea1/blackbox/internal/store"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxRowsPerSection keeps the HTML file a manageable size; every event
// is always in events.zip (events.csv).
const maxRowsPerSection = 5000

// Options describe the report being built.
type Options struct {
	Site         string
	WindowStart  time.Time // zero = from the beginning of collected data
	WindowEnd    time.Time
	Generated    time.Time
	Version      string
	Source       string // e.g. "Live collection" or "Exported file sec.xml"
	Location     *time.Location
	InReportsDir bool // report sits in the reports folder next to the list of all reports

	// Interim marks a report run by hand between scheduled reports. It
	// covers the time since the last scheduled report and does not move
	// the schedule; the next scheduled report covers that time again.
	Interim bool
	// Range describes a report for a period chosen by hand (blackbox
	// report --from): where its events came from. Set with Interim.
	Range string
	// History is the summaries of earlier scheduled reports, oldest first
	// (up to eleven), for twelve-week trends.
	History []Summary

	// Period is how often reports are made ("weekly"), shown as "Weekly
	// report". Empty for a report from exported files.
	Period string

	ExcludeUsers     []string
	ExcludeProcesses []string

	// KnownDevices lists removable devices seen in earlier reports; new
	// ones are flagged. Nil disables the check.
	KnownDevices map[string]time.Time

	// Context is events from the day before the period, already reported,
	// so a detection that started then can be completed now.
	Context []*event.Event

	// Baseline is what has been seen before (first logons, administrator
	// use, logon addresses), and BaselineHosts the computers whose normal
	// activity has been learned. Nil Baseline turns first-time detection off.
	Baseline      map[string]time.Time
	BaselineHosts map[string]time.Time

	// WorkingHours: administrator activity outside them is detected.
	WorkingHours config.WorkingHours

	// PeopleAliases merges differently spelled accounts into one person on
	// the People page: other spelling → name shown, lower case
	// (config people_aliases).
	PeopleAliases map[string]string

	// Archives are the original logs for this period, one zip per
	// computer, stored in the report folder. ArchivesKept says logs are
	// archived, so a computer without them is pointed out.
	Archives     []ArchiveRef
	ArchivesKept bool
	// Waiting, on a manual report, is what of the original logs waits for
	// the next scheduled report (UI5).
	Waiting *WaitingLogs
	// OwnRuns are Blackbox's runs covering every event in the report, for
	// telling its own activity from a person's (AR2c); nil: the runs.
	OwnRuns []*store.Run
	// PackFailing is set while this computer's exported original logs
	// cannot be packed into an archive (AR5).
	PackFailing *PackFailing
	// LeftOut are daily archives of original logs that failed their
	// check and were set aside instead of going into a scheduled report
	// (AR7): this one's, or, on a manual report, recent ones.
	LeftOut []LeftOutLogs

	// CheckSets are the latest audit settings check of each computer.
	CheckSets []CheckSet

	// LAN: the computers this data folder knows about, whether this is a
	// collector, and problems noticed receiving from other computers.
	Systems   []SystemInfo
	Collector bool
	// ClockBack are the times the clock was found to have been moved back
	// since the last scheduled report (T3).
	ClockBack []ClockJump
	// MissingReports are earlier scheduled reports deleted, moved or
	// changed since they were written (the report ledger).
	MissingReports []MissingReport
	LANWarnings    []string
	// Removed are earlier reports deleted under retention_days, with their
	// original logs, since the last scheduled report (A9).
	Removed       []string
	RetentionDays int
	// Overdue are original logs in no report whose period ended more than
	// retention_days ago: kept, never pruned, and pointed out (RET1).
	Overdue []OverdueLogs

	// SCAP scan results to show (docs/design.md 13a): the latest and
	// previous scan of each computer and benchmark. ScapEnabled shows the
	// table even when no scan was found.
	Scap           []*scap.Scan
	ScapEnabled    bool
	ScapMaxAgeDays int
}

// ClockJump is the clock found to have been moved back on a computer: a
// stored time (Was) that was in the future when it was Noticed.
type ClockJump struct {
	Host         string
	Noticed, Was time.Time
}

// ArchiveRef is one computer's original logs for the period: a zip that
// Write moves from Path into the report folder as Name.
type ArchiveRef struct {
	Host     string
	From, To time.Time
	Name     string // file name in the report folder, e.g. logs-WS-07.zip
	Path     string // where the zip is before the report is written
	Bytes    uint64
	SHA256   string
	Gaps     []archive.Gap      // parts a full log had overwritten before it was saved
	Logs     []archive.LogCover // what each log actually covers (AR2)
	Notes    []string           // what the archives say, e.g. after a clock change (AR1)
	Changed  []archive.FileInfo // exports changed after they were made (AR6)
}

// Row is one event in a section table.
type Row struct {
	*event.Event
	ID    string
	Flags []string
}

// Section is one category of the report.
type Section struct {
	Info      event.CategoryInfo
	Rows      []*Row
	Total     int
	Truncated int
	BySev     map[string]int // by severity
	Logons    []LogonSummary // Logon Activity only
}

// LogonSummary is one person's logons in the period.
type LogonSummary struct {
	User    string
	Host    string
	ByType  map[string]int
	Types   string
	Count   int
	Sources string
	First   time.Time
	Last    time.Time
}

// Finding is a pattern across several events.
type Finding struct {
	Severity event.Severity
	Category event.Category
	Host     string
	Time     time.Time
	Title    string
	Detail   string
	RowID    string   // first related row, for linking
	RowIDs   []string // every related row
	// Check is set for a finding Blackbox's own check made, not an event
	// (UI21): what it checked, e.g. "Blackbox's own check of the saved
	// original logs when it bundled them for this report". Facts are
	// what it found, for the Involved panel.
	Check string
	Facts []KV
}

// AttentionGroup summarises medium-severity events by kind.
type AttentionGroup struct {
	Category event.Category
	Label    string
	Count    int
	RowID    string
}

// UserRow is the per-person view.
type UserRow struct {
	User   string
	Counts map[event.Category]int
	High   int
	Total  int
}

// ChannelHealth summarises collection of one log on one host.
type ChannelHealth struct {
	Host        string
	Channel     string
	Runs        int
	Read        int
	Kept        int
	Lost        uint64
	Resets      int
	LastError   string
	Unavailable string
	History     time.Duration // how far back the log reached at the last run
	MaxSize     uint64
}

// VolumeRow is one busy event ID (Windows) or record type (Linux).
type VolumeRow struct {
	Channel string
	EventID int
	Type    string
	Name    string
	Count   int
	Percent float64
}

// GapItem is one period where events were lost.
type GapItem struct {
	Host, Channel string
	Lost          uint64
	From, To      time.Time
	Reset         bool
	Note          string // when the number lost is not known
	// Held is how far back the full log reached when the loss was found,
	// MaxSize its size, and Every how often the system collects (LOG1).
	Held    time.Duration
	MaxSize uint64
	Every   time.Duration
}

// Loss is the gap as a rollover.Loss, for its name and advice.
func (g GapItem) Loss() rollover.Loss {
	return rollover.Loss{Host: g.Host, Channel: g.Channel, Lost: g.Lost, Held: g.Held, MaxSize: g.MaxSize, Every: g.Every}
}

// Health describes whether the report is complete.
type Health struct {
	Runs         int
	FirstRun     time.Time
	LastRun      time.Time
	LongestPause time.Duration
	Channels     []ChannelHealth
	Gaps         []GapItem
	Volume       []VolumeRow
	TotalRead    int
	TotalKept    int
	Warnings     []string
	ChecksPass   int
	ChecksFail   int
	ChecksWarn   int
	LogClears    int
	AuditOff     []string // periods auditing was switched off
	// Blocked are gaps in collection while a run held the lock (LOCK1).
	Blocked []BlockedItem
}

// BlockedItem is a gap in collection on Host: scheduled runs from From
// were refused until To because the run with PID held the lock.
type BlockedItem struct {
	Host     string
	From, To time.Time
	Since    time.Time // when that run took the lock
	PID      int
	Refused  int
}

// Report is everything the template needs.
type Report struct {
	weeksCache []trendWeek // see weeks()
	seenCache  seenSet     // see seenNow()
	seenHist   *[]seenSet  // see seenHistory()

	Options
	Hosts      []string
	FirstEvent time.Time
	LastEvent  time.Time
	Sections   []*Section
	Findings   []Finding
	HighRows   []*Row
	Medium     []AttentionGroup
	Users      []UserRow
	Health     Health
	Events     []*event.Event // final list (after exclusions and de-duplication)
	Excluded   int
	// ExcludedBy counts the events left out per excluded account or
	// program, and ExcludedOn the systems they came from.
	ExcludedBy map[string]int
	ExcludedOn map[string]bool
	Duplicates int
	// Folded are records shown inside another row (UX1): console hosts
	// in the program that started them, and identical records as one
	// row with "×N".
	Folded     int
	Late       int
	NewDevices map[string]time.Time
	Learned    map[string]time.Time // baseline items seen in this period
	Learning   []string             // computers whose normal activity is being learned
	NoArchive  []string             // computers with no log archive for this period
	BySev      map[string]int       // by severity
	SystemRows []SystemRow          // Systems page
	// Retired are the systems retired during this period (ROLE1b): on the
	// Systems page, marked, and in no count or health check.
	Retired []SystemRow
	Silent  []SystemRow // computers with no collection in this period

	rows []*Row // one per event, in the order of Events

	archiveState map[string]archiveState // set by Write
	dataSums     map[string]string       // data file → SHA-256 of its payload
	scapTable    []ScapRow
	evPages      []string // event index → the event page listing it (see evRef)
}

// Build assembles a report from events (already filtered to the period)
// and the collection runs in the period.
func Build(events []*event.Event, runs []*store.Run, opt Options) *Report {
	if opt.Location == nil {
		opt.Location = time.Local
	}
	r := &Report{Options: opt, NewDevices: map[string]time.Time{}, Learned: map[string]time.Time{}, BySev: map[string]int{}}

	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	formerNames(events, opt.Systems)
	formerRuns(runs, opt.Systems)
	events = r.exclude(events)
	events = sshAttempts(events)
	events = sshdLines(events)
	unknownNames(events)
	events = mergeAdminLogons(events)
	events = sshLogonPairs(events)
	events = sshSources(events)
	events = refusedDeletes(events)
	events = r.dedupe(events)
	events = foldClearCommands(events)
	events = foldPolicyCommands(events)
	own := runs
	if opt.OwnRuns != nil {
		own = opt.OwnRuns
	}
	events = selfChanges(events, own)
	events = installerWrites(events)
	events = exportWrites(events, own)
	events = r.appPackageRules(events)
	events = r.defenderState(events)
	events = defenderUpdates(events)
	events = r.windowsSetup(events)
	attributeDevices(events)
	auditStoppedBy(events)
	shutdownStops(events)
	events = r.foldConsoleHosts(events)
	events = r.foldRepeats(events)

	rows := make([]*Row, len(events))
	hosts := map[string]bool{}
	for i, e := range events {
		rows[i] = &Row{Event: e, ID: "r" + strconv.Itoa(i+1)}
		hosts[e.Host] = true
		r.BySev[string(e.Severity)]++
		if e.Late {
			r.Late++
			rows[i].Flags = append(rows[i].Flags, "Late")
		}
		if e.Repeat > 1 {
			rows[i].Flags = append(rows[i].Flags, fmt.Sprintf("×%d", e.Repeat))
		}
	}
	r.Events = events
	r.rows = rows
	for h := range hosts {
		r.Hosts = append(r.Hosts, h)
	}
	sort.Strings(r.Hosts)
	if len(events) > 0 {
		r.FirstEvent, r.LastEvent = events[0].Time, events[len(events)-1].Time
	}

	r.flagNewDevices(rows)
	r.buildSections(rows)
	r.findPatterns(rows)
	r.detect(rows, r.withContext(rows))
	r.buildAttention(rows)
	r.buildUsers(events)
	r.buildHealth(runs, events)
	r.clockFindings()
	r.buildSystems(runs, events)
	r.scapTable = r.scapRows()
	r.checkArchives()
	r.highDetections(rows)
	for _, s := range r.Silent {
		r.Health.Warnings = append(r.Health.Warnings, s.Name+": "+s.StatusMsg)
	}
	return r
}

// PackFailing is packing the original logs failing on Host since Since.
type PackFailing struct {
	Host   string
	Since  time.Time
	Reason string
}

// Text is the failure in one sentence.
func (f *PackFailing) Text(stamp func(time.Time) string) string {
	return fmt.Sprintf("%s: the original logs have not been archived since %s: %s. The exports are kept and packing is tried again at every run; the logs missing from this report's archive are in a later one once it works.",
		f.Host, stamp(f.Since), strings.TrimRight(f.Reason, ". "))
}

// LeftOutLogs is a daily archive of Host's original logs set aside
// because it failed its check, so its logs are not in Report (empty: this
// report) (AR7).
type LeftOutLogs struct {
	Report   string
	Host     string
	From, To time.Time
	Reason   string
	SetAside string
}

// Text is the archive left out in one sentence.
func (l LeftOutLogs) Text(stamp func(time.Time) string) string {
	in := "this report"
	if l.Report != "" {
		in = "the scheduled report " + l.Report
	}
	return fmt.Sprintf("%s: the original logs for %s to %s are not in %s: their archive failed its check (%s). It was set aside in %s. The events are in the report; the original copy of them is only in that file.",
		l.Host, stamp(l.From), stamp(l.To), in, strings.TrimRight(l.Reason, ". "), l.SetAside)
}

// OverdueLogs is Host's original logs from From to To, in Archives
// daily archives in no report, the oldest waiting Days days in Dir, more
// than RetentionDays (RET1).
type OverdueLogs struct {
	Host          string
	From, To      time.Time
	Archives      int
	Days          int
	Dir           string
	RetentionDays int
}

// Text is the overdue logs in one sentence.
func (o OverdueLogs) Text(stamp func(time.Time) string) string {
	return fmt.Sprintf("%s: original logs from %s to %s have waited %d days and were never put in a report (%s in %s). "+
		"retention_days = %d does not remove them: they may be the only copy of those logs.",
		o.Host, stamp(o.From), stamp(o.To), o.Days, plural(o.Archives, "daily archive"), o.Dir, o.RetentionDays)
}

// leftOutHosts are the computers with original logs left out (AR7).
func (r *Report) leftOutHosts() []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range r.LeftOut {
		if k := strings.ToLower(l.Host); !seen[k] {
			seen[k] = true
			out = append(out, l.Host)
		}
	}
	return out
}

// checkArchives notes the computers in this report with no archive of
// their original logs for the period.
func (r *Report) checkArchives() {
	if f := r.PackFailing; f != nil {
		r.Health.Warnings = append(r.Health.Warnings, "ORIGINAL LOGS NOT ARCHIVED: "+f.Text(r.stamp))
	}
	for _, l := range r.LeftOut {
		r.Health.Warnings = append(r.Health.Warnings, "ORIGINAL LOGS NOT IN REPORT: "+l.Text(r.stamp))
	}
	for _, o := range r.Overdue {
		r.Health.Warnings = append(r.Health.Warnings, "ORIGINAL LOGS NEVER REPORTED: "+o.Text(r.stamp))
	}
	if !r.ArchivesKept {
		return
	}
	have := map[string]bool{}
	for _, a := range r.Archives {
		have[strings.ToLower(a.Host)] = true
	}
	for _, h := range r.leftOutHosts() {
		have[strings.ToLower(archiveName(h))] = true // said above
	}
	for _, h := range r.Hosts {
		if !have[strings.ToLower(archiveName(h))] && !r.retired(h) {
			r.NoArchive = append(r.NoArchive, h)
		}
	}
	if len(r.NoArchive) > 0 {
		r.Health.Warnings = append(r.Health.Warnings, "No archive of the original logs for this period from: "+strings.Join(r.NoArchive, ", ")+". See Original logs.")
	}
	for _, a := range r.Archives {
		for _, f := range a.Changed {
			// Found by Blackbox's own check when it bundled the logs for
			// this report, not by an event (UI21): timed when it was
			// found, which is after the period.
			at := r.Generated
			if at.IsZero() {
				at = a.To
			}
			r.Findings = append(r.Findings, Finding{Severity: event.SevHigh, Category: event.CatIntegrity, Host: a.Host, Time: at,
				Title: "Saved original log changed before it was archived",
				Detail: fmt.Sprintf("Blackbox's own check, when it bundled %s's original logs for this report, found that the export of the %s log (%s) no longer matched the SHA-256 taken when it was exported: it was changed while it waited to be archived. "+
					"It is in %s as it was found; its archive.json says which file. Compare it with the events in this report, and find who could write to the Blackbox data folder.",
					a.Host, f.Source, f.Name, a.Name),
				Check: "Blackbox's own check of the saved original logs when it bundled them for this report",
				Facts: []KV{{Label: "Log", Value: f.Source}, {Label: "File", Value: f.Name + " in " + a.Name}}})
		}
		for _, g := range a.Gaps {
			if g.Reason != "" {
				r.Health.Warnings = append(r.Health.Warnings, fmt.Sprintf("%s: the original logs are incomplete: %s. Its events for that time are only in this report, not in %s.",
					a.Host, g.Reason, a.Name))
				continue
			}
			span := "from " + r.stamp(g.From) + " to " + r.stamp(g.To)
			if r.stamp(g.From) == r.stamp(g.To) {
				span = "at about " + r.stamp(g.To)
			}
			recs := ""
			if g.Records != "" {
				recs = " (" + g.Records + ")"
			}
			r.Health.Warnings = append(r.Health.Warnings, fmt.Sprintf("%s: the original logs are incomplete: %s had already overwritten its events%s %s when they were saved. Make the log larger (blackbox check gives the size).",
				a.Host, g.Source, recs, span))
		}
	}
}

// archiveName is how a host appears in archive file names.
var archiveUnsafe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

func archiveName(h string) string {
	h = strings.Trim(archiveUnsafe.ReplaceAllString(h, "-"), "-")
	if h == "" {
		return "unknown"
	}
	return h
}

// ---------------------------------------------------------------- filters

func (r *Report) flagNewDevices(rows []*Row) {
	if r.KnownDevices == nil {
		return
	}
	for _, row := range rows {
		if row.Action != "usb_connected" {
			continue
		}
		key := deviceKey(row.Event)
		if key == "" {
			continue
		}
		if _, seen := r.KnownDevices[key]; seen {
			continue
		}
		if _, seen := r.NewDevices[key]; !seen {
			r.NewDevices[key] = row.Time
			row.Flags = append(row.Flags, "New device")
			if row.Severity.Rank() < event.SevHigh.Rank() {
				row.Severity = event.SevHigh
			}
		}
	}
}

func deviceKey(e *event.Event) string {
	if strings.HasPrefix(e.DedupeKey, "usb|") {
		return e.Host + "|" + strings.TrimPrefix(e.DedupeKey, "usb|")
	}
	return ""
}

// ---------------------------------------------------------------- sections

func (r *Report) buildSections(rows []*Row) {
	by := map[event.Category]*Section{}
	for _, ci := range event.Categories {
		s := &Section{Info: ci, BySev: map[string]int{}}
		by[ci.ID] = s
		r.Sections = append(r.Sections, s)
	}
	for _, row := range rows {
		s := by[row.Category]
		if s == nil {
			continue
		}
		s.Total++
		s.BySev[string(row.Severity)]++
		if len(s.Rows) < maxRowsPerSection {
			s.Rows = append(s.Rows, row)
		} else {
			s.Truncated++
		}
	}
	by[event.CatLogon].Logons = summarizeLogons(rows)
}

func summarizeLogons(rows []*Row) []LogonSummary {
	idx := map[string]*LogonSummary{}
	sources := map[string]map[string]bool{}
	for _, row := range rows {
		if row.Action != "logon" {
			continue
		}
		k := row.Host + "|" + row.User
		s := idx[k]
		if s == nil {
			s = &LogonSummary{User: row.User, Host: row.Host, ByType: map[string]int{}, First: row.Time}
			idx[k] = s
			sources[k] = map[string]bool{}
		}
		s.Count++
		s.Last = row.Time
		for _, d := range row.Details {
			if d.Label == "Logon type" {
				s.ByType[d.Value]++
			}
		}
		if row.SourceIP != "" {
			sources[k][row.SourceIP] = true
		}
	}
	var out []LogonSummary
	for k, s := range idx {
		s.Types = joinCounts(s.ByType)
		var src []string
		for ip := range sources[k] {
			src = append(src, ip)
		}
		sort.Strings(src)
		s.Sources = strings.Join(src, ", ")
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].User < out[j].User
	})
	return out
}

func joinCounts(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var parts []string
	for _, x := range l {
		parts = append(parts, fmt.Sprintf("%s ×%d", x.k, x.v))
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------- patterns

// withContext returns the rows of the period preceded by the context
// events (filtered and merged the same way, with no row ID).
func (r *Report) withContext(rows []*Row) []*Row {
	if len(r.Context) == 0 {
		return rows
	}
	ctx := append([]*event.Event(nil), r.Context...)
	sort.SliceStable(ctx, func(i, j int) bool { return ctx[i].Time.Before(ctx[j].Time) })
	excluded, dups := r.Excluded, r.Duplicates
	ctx = r.dedupe(r.exclude(ctx))
	r.Excluded, r.Duplicates = excluded, dups
	all := make([]*Row, 0, len(ctx)+len(rows))
	for _, e := range ctx {
		all = append(all, &Row{Event: e})
	}
	all = append(all, rows...)
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	return all
}

// ---------------------------------------------------------------- attention

// actionLabels are singular/plural descriptions for the "Also review" list.
var actionLabels = map[string][2]string{
	"usb_connected":           {"removable device connected", "removable devices connected"},
	"virtual_disk_mounted":    {"virtual disk (ISO/VHD) mounted", "virtual disks (ISO/VHD) mounted"},
	"removable_write":         {"file written to removable media", "files written to removable media"},
	"removable_delete":        {"file deleted from removable media", "files deleted from removable media"},
	"removable_execute":       {"program run from removable media", "programs run from removable media"},
	"removable_access_denied": {"blocked removable media access attempt", "blocked removable media access attempts"},
	"usb_blocked":             {"USB device blocked by USBGuard", "USB devices blocked by USBGuard"},
	"account_locked":          {"account lockout", "account lockouts"},
	"account_created":         {"user account created", "user accounts created"},
	"account_enabled":         {"user account enabled", "user accounts enabled"},
	"account_disabled":        {"user account disabled", "user accounts disabled"},
	"account_deleted":         {"user account deleted", "user accounts deleted"},
	"account_renamed":         {"user account renamed", "user accounts renamed"},
	"password_reset":          {"password reset by an administrator", "passwords reset by an administrator"},
	"group_member_added":      {"group membership added", "group memberships added"},
	"group_member_removed":    {"group membership removed", "group memberships removed"},
	"group_deleted":           {"group deleted", "groups deleted"},
	"explicit_credentials":    {"use of another account's credentials", "uses of another account's credentials"},
	"service_installed":       {"service installed", "services installed"},
	"scheduled_task_created":  {"scheduled task created", "scheduled tasks created"},
	"time_changed":            {"system time change", "system time changes"},
	"audit_policy_changed":    {"audit policy change", "audit policy changes"},
	"malware_action":          {"anti-malware action", "anti-malware actions"},
	"eventlog_error":          {"event log error", "event log errors"},
	"sudo_denied":             {"refused sudo command", "refused sudo commands"},
	refusedRemove:             {"refused attempt to delete Blackbox's files", "refused attempts to delete Blackbox's files"},
	unconfirmedRemove:         {"delete command on Blackbox's files (whether it worked isn't recorded)", "delete commands on Blackbox's files (whether they worked isn't recorded)"},
	"removable_mounted":       {"removable disk opened (mounted)", "removable disks opened (mounted)"},
	"module_loaded":           {"kernel module loaded", "kernel modules loaded"},
	"module_unloaded":         {"kernel module unloaded", "kernel modules unloaded"},
	"promiscuous_mode":        {"network capture (promiscuous mode) started", "network captures (promiscuous mode) started"},
	"audit_rule_added":        {"audit rule added", "audit rules added"},
	"audit_config_changed":    {"audit configuration change", "audit configuration changes"},
	"powershell_suspicious":   {"PowerShell script flagged as suspicious", "PowerShell scripts flagged as suspicious"},
	"hidden_powershell":       {"PowerShell run hidden and around the script policy", "PowerShell runs hidden and around the script policy"},
	"powershell_tamper":       {"PowerShell script that can clear logs or weaken auditing", "PowerShell scripts that can clear logs or weaken auditing"},
	"powershell_av_tamper":    {"PowerShell script that weakens Microsoft Defender", "PowerShell scripts that weaken Microsoft Defender"},
	"powershell_download":     {"PowerShell script that downloads and runs code", "PowerShell scripts that download and run code"},
	"powershell_credential":   {"password-stealing tool run in PowerShell", "password-stealing tools run in PowerShell"},
	"powershell_amsi_bypass":  {"PowerShell attempt to switch off script scanning (AMSI)", "PowerShell attempts to switch off script scanning (AMSI)"},
}

func (r *Report) buildAttention(rows []*Row) {
	groups := map[string]*AttentionGroup{}
	var order []string
	for _, row := range rows {
		switch row.Severity {
		case event.SevHigh:
			r.HighRows = append(r.HighRows, row)
		case event.SevMedium:
			g := groups[row.Action]
			if g == nil {
				g = &AttentionGroup{Category: row.Category, RowID: row.ID}
				groups[row.Action] = g
				order = append(order, row.Action)
			}
			g.Count++
		}
	}
	for _, a := range order {
		g := groups[a]
		l, ok := actionLabels[a]
		if !ok {
			l = [2]string{strings.ReplaceAll(a, "_", " "), strings.ReplaceAll(a, "_", " ")}
		}
		g.Label = l[1]
		if g.Count == 1 {
			g.Label = l[0]
		}
		r.Medium = append(r.Medium, *g)
	}
	sort.SliceStable(r.Medium, func(i, j int) bool {
		return catIndex(r.Medium[i].Category) < catIndex(r.Medium[j].Category)
	})
}

func catIndex(c event.Category) int {
	for i, ci := range event.Categories {
		if ci.ID == c {
			return i
		}
	}
	return len(event.Categories)
}

// ---------------------------------------------------------------- users

func (r *Report) buildUsers(events []*event.Event) {
	idx := map[string]*UserRow{}
	for _, e := range events {
		if e.User == "" || e.Action == "logoff" {
			continue
		}
		u := idx[e.User]
		if u == nil {
			u = &UserRow{User: e.User, Counts: map[event.Category]int{}}
			idx[e.User] = u
		}
		u.Counts[e.Category]++
		u.Total++
		if e.Severity == event.SevHigh {
			u.High++
		}
	}
	for _, u := range idx {
		r.Users = append(r.Users, *u)
	}
	sort.Slice(r.Users, func(i, j int) bool {
		a, b := r.Users[i], r.Users[j]
		if a.High != b.High {
			return a.High > b.High
		}
		if a.Total != b.Total {
			return a.Total > b.Total
		}
		return a.User < b.User
	})
}

// ---------------------------------------------------------------- health

// ---------------------------------------------------------------- formatting

func (r *Report) clock(t time.Time) string { return t.In(r.Location).Format("15:04:05") }

// span is "between 18:17:02 and 18:19:40", or "at 18:17:02" when both are
// the same second (U1).
func (r *Report) span(a, b time.Time) string {
	if r.clock(a) == r.clock(b) {
		return "at " + r.clock(a)
	}
	return "between " + r.clock(a) + " and " + r.clock(b)
}

func (r *Report) stamp(t time.Time) string {
	if t.IsZero() {
		return "an unknown time"
	}
	return t.In(r.Location).Format("2006-01-02 15:04")
}

func roughDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	case d >= 2*time.Hour:
		return fmt.Sprintf("%.0f hours", d.Hours())
	case d >= time.Hour:
		return "1 hour"
	case d < time.Minute:
		return "less than a minute" // not "0 minutes" (U15)
	}
	if m := int(d.Round(time.Minute) / time.Minute); m > 1 {
		return fmt.Sprintf("%d minutes", m)
	}
	return "1 minute"
}

func commas[T ~int | ~uint64](n T) string {
	s := strconv.FormatUint(uint64(n), 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// clockFindings reports the clock having been moved back (T3): times in
// reports and logs are wrong around it, and moving the clock is a way to
// try to hide activity. Nothing collected is lost: reports follow the
// order events were collected in.
func (r *Report) clockFindings() {
	for _, j := range r.ClockBack {
		back := j.Was.Sub(j.Noticed)
		f := Finding{Severity: event.SevHigh, Category: event.CatIntegrity, Host: j.Host, Time: j.Noticed,
			Title: "The clock was moved back",
			Detail: fmt.Sprintf("On %s, the last collection was recorded at %s, about %s ahead of the clock at %s: the clock was moved back. "+
				"Event times around the change may be wrong. Every event collected is still in a report: reports follow the order events were collected in.",
				j.Host, r.stamp(j.Was), roughDuration(back), r.stamp(j.Noticed))}
		r.Findings = append(r.Findings, f)
		r.Health.Warnings = append(r.Health.Warnings, fmt.Sprintf("%s: the clock was moved back by about %s (noticed %s). Check the time source (Windows Time, chrony or timesyncd).",
			j.Host, roughDuration(back), r.stamp(j.Noticed)))
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.Time.Before(b.Time)
	})
}
