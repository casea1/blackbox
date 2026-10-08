package install

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/config"
)

// The questions, choices and checks below are shared by the console setup
// (wizard.go) and the setup window, so the two always ask the same thing
// and accept the same answers.

// Question texts.
const (
	QRole       = "How will this computer's audit events be reviewed?"
	QSite       = "Site or system name, shown at the top of each report"
	QEvery      = "How often should a report be produced?"
	QAtWeekly   = "Which day and time should each weekly report be ready?"
	QAt         = "At what time should each report be ready?"
	QReportDir  = "Where should reports be saved?"
	QArchiveDir = "Where should the original logs wait for the next report?"
	QInbox      = "Which folder should other computers deliver their events to (this computer's inbox)?"
	QInboxReach = "How will the other computers reach this inbox?"
	QSendTo     = "Where is the collector's inbox?"
	QInterval   = "How often should events be collected from the logs?"
	QTray       = "Show Blackbox's status in the notification area (system tray) for administrators?"
	QScap       = "Where are this computer's SCAP scan results (SCC or OpenSCAP) saved?"
	QQuickVerb  = "upgrade"

	NoteAtWeekly = "The week ends then. \"Wednesday 00:00\" covers the week up to Tuesday night,\nso auditors have a fresh report on Wednesday morning."
	NoteReport   = "Use a folder you have locked down if you like; Blackbox only needs to write to it."
	NoteArchive  = "The raw logs (.evtx, audit logs) of this computer and every sender are kept here until each scheduled report moves them into its folder. Allow a few MB a day per computer; choose a larger drive for many computers."
	NoteInbox    = "Blackbox imports what arrives there every time it collects."
	NoteScap     = "Optional. Blackbox reads the latest scan of each benchmark in this folder and its subfolders (SCC's Sessions folder works as it is) for the report's STIG compliance; a sender sends its latest scans to the collector. It never runs a scan. Type none to turn this off."
	NoteKeep     = "Use it anyway? The data waits here until the collector can be reached."
)

// Choice is one option of a multiple-choice question.
type Choice struct {
	Label, Detail string
}

// Roles in the order they are offered, with their descriptions.
var (
	Roles       = []string{RoleStandalone, RoleSender, RoleCollector}
	RoleChoices = []Choice{
		{"On this computer", "it produces its own reports"},
		{"Send to a collector", "for a virtual machine, or a workstation on a LAN"},
		{"This is the collector", "its reports cover it and every computer that sends to it"},
	}
)

// Report frequencies in the order they are offered.
var (
	Everies      = []string{"daily", "weekly", "monthly"}
	EveryChoices = []string{"Daily", "Weekly", "Monthly (each period ends on the 1st)"}
)

// Intervals lists the collection intervals offered, with cur added when
// it is none of them, and their labels.
func Intervals(cur time.Duration) ([]time.Duration, []Choice) {
	ints := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour}
	labels := []Choice{{"Every 15 minutes", "recommended: a STIG-audited Security log can fill within an hour"}, {"Every 30 minutes", ""},
		{"Every hour", "only for quiet systems with a large Security log"}}
	if indexOf(ints, cur) < 0 && cur > 0 {
		ints = append(ints, cur)
		t := EveryText(cur)
		labels = append(labels, Choice{strings.ToUpper(t[:1]) + t[1:], "current setting"})
	}
	return ints, labels
}

// WithDefaults fills in the settings a first install starts with.
func WithDefaults(a Answers) Answers {
	if a.ReportEvery == "" {
		a.ReportEvery = "weekly"
	}
	if a.ReportAt == (config.ReportAt{}) {
		a.ReportAt = config.DefaultReportAt
	}
	if a.CollectEvery == 0 {
		// 15 minutes (C6): with the STIG's File System auditing, Windows
		// Update can overwrite a 20 MB Security log within an hour.
		a.CollectEvery = 15 * time.Minute
	}
	if a.Role == "" {
		a.Role = RoleOf(a.SendTo, a.Inbox)
	}
	return a
}

// ForRole clears the settings the chosen role does not use.
func ForRole(a Answers) Answers {
	if a.Role == RoleSender || a.Role == RoleStandalone {
		a.Inbox, a.ShareInbox, a.InboxWriters, a.ShareWriters = "", false, nil, nil
	}
	if a.Role == RoleStandalone || a.Role == RoleCollector {
		a.SendTo, a.ShareUser, a.SharePassword = "", "", ""
	}
	if a.Role == RoleSender {
		a.Tray = false // the status icon belongs where the reports are
	}
	return a
}

// FolderCheck is the outcome of checking a folder answer.
type FolderCheck int

const (
	FolderOK       FolderCheck = iota // exists and can be written to
	FolderMissing                     // does not exist yet: offer to create it
	FolderBad                         // unusable; the error says why
	FolderNoAccess                    // exists, but the person running setup can't write to it
)

// CheckFolder checks a report or inbox folder. dirExists and dirWritable
// are the file system (replaceable in tests).
func CheckFolder(dir string, dirExists func(string) (bool, error), dirWritable func(string) error) (FolderCheck, error) {
	exists, err := dirExists(dir)
	if err != nil {
		return FolderBad, err
	}
	if !exists {
		return FolderMissing, nil
	}
	if err := dirWritable(dir); err != nil {
		// A local folder open only to some people (such as an auditors'
		// group): Blackbox's scheduled runs, not the person running setup,
		// write the reports, so SYSTEM can be given access instead.
		if CanGrantSystem && !config.IsShare(dir) {
			return FolderNoAccess, err
		}
		return FolderBad, fmt.Errorf("Blackbox cannot write to that folder (%v).\nChoose another folder, or give administrators write access and try again", err)
	}
	return FolderOK, nil
}

// GrantSystemQuestion asks before giving SYSTEM access to a folder the
// person running setup can't write to.
func GrantSystemQuestion(dir string) string {
	return "You can't write to " + dir + " yourself. Blackbox's scheduled runs write the reports as SYSTEM.\n" +
		"Give SYSTEM Modify access to this folder? No one else's access changes, and administrators get none."
}

// ReportDirError says what is wrong with a typed report folder, or nil.
func ReportDirError(s string) error {
	if !config.IsAbs(s) {
		return fmt.Errorf("Please enter a full path, for example %s", exampleFolder())
	}
	return nil
}

// InboxError says what is wrong with a typed inbox folder, or nil.
func InboxError(s, example string) error {
	if !config.IsAbs(s) || config.IsShare(s) {
		return fmt.Errorf("Please enter a full path to a folder on this computer, for example %s", example)
	}
	return nil
}

// SendToAnswer checks a typed collector inbox and writes it the way this
// system does (Linux writes shares as //server/share).
func SendToAnswer(s string, windows bool) (string, error) {
	if s == "" {
		return "", fmt.Errorf("Please enter the collector's inbox.")
	}
	if !config.IsAbs(s) && !config.IsShare(s) {
		return "", fmt.Errorf("Please enter a full path or a share name.")
	}
	if !windows && strings.HasPrefix(s, `\\`) {
		s = strings.ReplaceAll(s, `\`, "/")
	}
	return s, nil
}

// SendToExample is the hint shown with QSendTo.
func SendToExample(windows bool) string {
	if windows {
		return fmt.Sprintf("Enter the collector's shared folder, for example \\\\COLLECTOR\\%s", ShareName)
	}
	return fmt.Sprintf("A VirtualBox shared folder (for example /media/sf_%s), or\na Windows share on the network (for example //COLLECTOR/%s).", ShareName, ShareName)
}

// SummaryLine is one line of the summary shown before installing.
type SummaryLine struct{ Label, Value string }

// Summary lists the chosen settings.
func Summary(a Answers, defaultReports string, windows bool) []SummaryLine {
	l := []SummaryLine{{"This computer", roleText(a.Role)}}
	if a.Role == RoleStandalone || a.Role == RoleCollector {
		dir := a.ReportDir
		if dir == "" {
			dir = defaultReports
		}
		l = append(l, SummaryLine{"Site name", orNone(a.Site)},
			SummaryLine{"Reports", a.ReportAt.Describe(a.ReportEvery)},
			SummaryLine{"Saved in", dir})
		logs := a.ArchiveDir
		if logs == "" {
			logs = DefaultArchiveDir()
		}
		l = append(l, SummaryLine{"Original logs", logs})
	}
	if a.Inbox != "" {
		extra := ""
		if a.ShareInbox {
			extra = " (shared on the network as " + ShareName + ")"
		}
		l = append(l, SummaryLine{"Receives in", a.Inbox + extra})
		if w := append(append([]string{}, a.InboxWriters...), a.ShareWriters...); len(w) > 0 {
			l = append(l, SummaryLine{"Can deliver", strings.Join(w, ", ")})
		}
		newOnes := "taken at their first signed delivery"
		if a.HoldNewSenders {
			newOnes = "held until: blackbox senders approve NAME"
		}
		l = append(l, SummaryLine{"New computers", newOnes})
	}
	if a.SendTo != "" {
		l = append(l, SummaryLine{"Sends to", a.SendTo})
		if a.ShareUser != "" {
			l = append(l, SummaryLine{"Share account", a.ShareUser})
		}
	}
	l = append(l, SummaryLine{"Collect events", EveryText(a.CollectEvery)})
	scap := a.ScapResults
	switch {
	case scap == "":
		scap = DefaultScapDir()
	case strings.EqualFold(scap, "none"):
		scap = "not read"
	}
	l = append(l, SummaryLine{"SCAP results", scap})
	if windows && a.Role != RoleSender {
		l = append(l, SummaryLine{"Status icon", map[bool]string{true: "shown to administrators", false: "not shown"}[a.Tray]})
	}
	return l
}

// DefaultScapDir is where SCAP results are read when scap_results is not
// set: the scap folder in the data folder.
func DefaultScapDir() string { return filepath.Join(config.DefaultDataDir(), "scap") }

// SplitList splits a comma-separated list of names.
func SplitList(s string) []string {
	var out []string
	for _, u := range strings.Split(s, ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// DefaultArchiveDir is where the original logs wait when archive_dir is
// not set: the archives folder in the data folder.
func DefaultArchiveDir() string { return filepath.Join(config.DefaultDataDir(), "archives") }
