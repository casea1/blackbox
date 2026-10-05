package install

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/brand"
	"github.com/casea1/blackbox/internal/config"
)

// Roles a computer can have.
const (
	RoleStandalone = "standalone" // reports on itself
	RoleSender     = "sender"     // sends to a collector
	RoleCollector  = "collector"  // reports on itself and the computers that send to it
)

// Answers are the settings chosen during setup.
type Answers struct {
	Role         string
	Site         string
	ReportEvery  string          // daily | weekly | monthly
	ReportAt     config.ReportAt // when each report period ends
	ReportDir    string          // "" = the default reports folder
	ArchiveDir   string          // "" = the archives folder in the data folder
	CollectEvery time.Duration   // how often the schedule runs

	SendTo        string // collector inbox (sender)
	ShareUser     string // account for the SendTo share
	SharePassword string // entered during setup; stored encrypted, never in the config file

	Inbox        string   // this collector's inbox (collector)
	ShareInbox   bool     // Windows: share the inbox on the network
	InboxWriters []string // Windows: local accounts allowed to deliver (e.g. the user who runs VirtualBox)
	ShareWriters []string // Windows: accounts allowed to deliver over the network share (S11)

	Tray bool // Windows collector or standalone: the status icon for administrators
}

// RoleOf infers the role from settings.
func RoleOf(sendTo, inbox string) string {
	switch {
	case sendTo != "":
		return RoleSender
	case inbox != "":
		return RoleCollector
	}
	return RoleStandalone
}

// ErrCancelled means the person chose not to go ahead.
var ErrCancelled = errors.New("setup cancelled; nothing was changed")

// wizard asks setup questions on a console.
type wizard struct {
	in  *bufio.Reader
	out io.Writer
	n   int // question number

	// Replaceable for tests.
	dirExists    func(string) (bool, error)
	dirWritable  func(string) error
	password     func(prompt string) (string, error)
	findInboxes  func() []string                     // collector inboxes this computer can already see
	tryInbox     func(sendTo, user, pw string) error // can the collector's inbox be reached?
	defaultInbox string                              // suggested inbox folder for a collector
	isWindows    bool
	virtualBox   func() bool // is VirtualBox installed here? (S12)
}

// Wizard asks the setup questions, offering cur as the defaults (the
// current settings on a re-install), checks each answer as it is given,
// and asks for confirmation. defaultReports is the folder used when
// ReportDir is empty.
func Wizard(in io.Reader, out io.Writer, cur Answers, defaultReports string, reinstall bool) (Answers, error) {
	w := newWizard(in, out)
	return w.run(cur, defaultReports, reinstall)
}

func newWizard(in io.Reader, out io.Writer) *wizard {
	br, ok := in.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(in)
	}
	w := &wizard{in: br, out: out, dirExists: dirExists, dirWritable: CheckWritable,
		findInboxes: FindInboxes, tryInbox: TryInbox, defaultInbox: DefaultInbox(), isWindows: isWindows,
		virtualBox: VirtualBoxInstalled}
	w.password = func(prompt string) (string, error) {
		w.printf("%s", prompt)
		pw, err := readPassword(br)
		w.printf("\n")
		return pw, err
	}
	return w
}

func dirExists(p string) (bool, error) {
	fi, err := os.Stat(p)
	switch {
	case os.IsNotExist(err):
		return false, nil
	case err != nil:
		return false, err
	case !fi.IsDir():
		return false, fmt.Errorf("%s is a file, not a folder", p)
	}
	return true, nil
}

func (w *wizard) printf(format string, a ...any) { fmt.Fprintf(w.out, format, a...) }

// question prints the next numbered question.
func (w *wizard) question(text string) {
	w.n++
	w.printf("\n%d. %s\n", w.n, text)
}

// line reads one answer; io.EOF (no more input) cancels setup.
func (w *wizard) line() (string, error) {
	s, err := w.in.ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		if errors.Is(err, io.EOF) {
			return "", ErrCancelled
		}
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// ask shows a prompt with a default and returns the answer (or the
// default for Enter).
func (w *wizard) ask(def string) (string, error) {
	w.printf("   [%s]: ", orNone(def))
	s, err := w.line()
	if err != nil {
		return "", err
	}
	if s == "" {
		return def, nil
	}
	return strings.Trim(s, `"`), nil
}

// yes asks a yes/no question.
func (w *wizard) yes(prompt string, def bool) (bool, error) {
	hint := "(Y/n)"
	if !def {
		hint = "(y/N)"
	}
	for {
		w.printf("   %s %s: ", prompt, hint)
		s, err := w.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
	}
}

func (w *wizard) run(cur Answers, defaultReports string, reinstall bool) (Answers, error) {
	a := WithDefaults(cur)
	title := brand.Name + " setup"
	if reinstall {
		title = brand.Name + " setup (already installed: your current settings are shown as the defaults)"
	}
	w.printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))
	w.printf("Press Enter to keep the value in [brackets].\n")

	var err error
	if a.Role, err = w.askRole(a.Role); err != nil {
		return a, err
	}
	tray := a.Tray
	a = ForRole(a)

	if a.Role == RoleStandalone || a.Role == RoleCollector {
		if err := w.askReports(&a, defaultReports); err != nil {
			return a, err
		}
		if err := w.askArchiveDir(&a); err != nil {
			return a, err
		}
	}
	if a.Role == RoleCollector {
		if err := w.askInbox(&a); err != nil {
			return a, err
		}
	}
	if a.Role == RoleSender {
		if err := w.askSendTo(&a); err != nil {
			return a, err
		}
	}
	if err := w.askInterval(&a); err != nil {
		return a, err
	}
	if w.isWindows && a.Role != RoleSender {
		w.question(QTray)
		if a.Tray, err = w.yes("Show it?", tray); err != nil {
			return a, err
		}
	}

	// Summary.
	w.printf("\nSummary\n")
	for _, l := range Summary(a, defaultReports, w.isWindows) {
		w.printf("   %-18s%s\n", l.Label+":", l.Value)
	}
	verb := "Install"
	if reinstall {
		verb = "Apply"
	}
	w.printf("\n")
	ok, err := w.yes(verb+" these settings?", true)
	if err != nil {
		return a, err
	}
	if !ok {
		return a, ErrCancelled
	}
	return a, nil
}

func roleText(r string) string {
	switch r {
	case RoleSender:
		return "sends its events to a collector"
	case RoleCollector:
		return "collector: reports on itself and the computers that send to it"
	}
	return "standalone: reports on itself"
}

func (w *wizard) askRole(cur string) (string, error) {
	w.question(QRole)
	i, err := w.choose(choiceLabels(RoleChoices, 28), indexOf(Roles, cur))
	if err != nil {
		return "", err
	}
	return Roles[i], nil
}

func (w *wizard) askReports(a *Answers, defaultReports string) error {
	w.question(QSite)
	if a.Site != "" {
		w.printf("   (type - to clear it)\n")
	}
	s, err := w.ask(a.Site)
	if err != nil {
		return err
	}
	if s == "-" {
		s = ""
	}
	a.Site = s

	w.question(QEvery)
	i, err := w.choose(EveryChoices, indexOf(Everies, a.ReportEvery))
	if err != nil {
		return err
	}
	a.ReportEvery = Everies[i]

	if a.ReportEvery == "weekly" {
		w.question(QAtWeekly)
		w.note(NoteAtWeekly)
	} else {
		w.question(QAt)
	}
	for {
		def := a.ReportAt.String()
		if a.ReportEvery != "weekly" {
			def = a.ReportAt.Clock()
		}
		v, err := w.ask(def)
		if err != nil {
			return err
		}
		r, perr := config.ParseReportAt(v)
		if perr == nil {
			if a.ReportEvery != "weekly" {
				r.Day = a.ReportAt.Day
			}
			a.ReportAt = r
			break
		}
		w.printf("   %v\n", perr)
	}

	w.question(QReportDir)
	w.note(NoteReport)
	for {
		show := a.ReportDir
		if show == "" {
			show = defaultReports
		}
		s, err := w.ask(show)
		if err != nil {
			return err
		}
		if s == defaultReports {
			a.ReportDir = ""
			return nil
		}
		if err := ReportDirError(s); err != nil {
			w.note(err.Error())
			continue
		}
		ok, err := w.checkFolder(s, "Create it (administrators only)?")
		if err != nil {
			return err
		}
		if ok {
			a.ReportDir = s
			return nil
		}
	}
}

// askArchiveDir asks where the original logs wait for the next report.
func (w *wizard) askArchiveDir(a *Answers) error {
	w.question(QArchiveDir)
	w.note(NoteArchive)
	def := DefaultArchiveDir()
	for {
		show := a.ArchiveDir
		if show == "" {
			show = def
		}
		s, err := w.ask(show)
		if err != nil {
			return err
		}
		if s == def {
			a.ArchiveDir = ""
			return nil
		}
		if err := ReportDirError(s); err != nil {
			w.note(err.Error())
			continue
		}
		ok, err := w.checkFolder(s, "Create it (administrators only)?")
		if err != nil {
			return err
		}
		if ok {
			a.ArchiveDir = s
			return nil
		}
	}
}

func (w *wizard) askInbox(a *Answers) error {
	w.question(QInbox)
	w.note(NoteInbox)
	for {
		def := a.Inbox
		if def == "" {
			def = w.defaultInbox
		}
		s, err := w.ask(def)
		if err != nil {
			return err
		}
		if err := InboxError(s, w.defaultInbox); err != nil {
			w.note(err.Error())
			continue
		}
		ok, err := w.checkFolder(s, "Create it?")
		if err != nil {
			return err
		}
		if ok {
			a.Inbox = s
			break
		}
	}
	if !w.isWindows {
		return nil
	}

	w.question(QInboxReach)
	w.printf("   A virtual machine on this PC reaches it through a VirtualBox shared folder.\n")
	w.printf("   Other computers on the network reach it through a Windows share.\n")
	// Suggested only where VirtualBox is installed (S12).
	vbox := w.virtualBox != nil && w.virtualBox()
	vm, err := w.yes("Will virtual machines on this PC send to it (VirtualBox shared folder)?", len(a.InboxWriters) > 0 || (vbox && !a.ShareInbox))
	if err != nil {
		return err
	}
	a.InboxWriters = nil
	if vm {
		w.printf("   VirtualBox writes into the shared folder as the Windows account that runs it.\n")
		w.printf("   Windows account that runs VirtualBox (several: separate with commas)\n")
		def := ""
		if vbox {
			def = os.Getenv("USERNAME")
		}
		s, err := w.ask(def)
		if err != nil {
			return err
		}
		a.InboxWriters = SplitList(s)
	}
	a.ShareInbox, err = w.yes("Share it on the network so other computers can send to it?", a.ShareInbox)
	if err != nil || !a.ShareInbox {
		a.ShareWriters = nil
		return err
	}
	w.printf("   %s\n", NoteShareWriters)
	s, err := w.ask(strings.Join(a.ShareWriters, ", "))
	if err != nil {
		return err
	}
	a.ShareWriters = SplitList(s)
	return nil
}

// NoteShareWriters explains the accounts that may deliver over the share
// (S11): they are added to the Blackbox Senders group.
const NoteShareWriters = "Accounts the other computers deliver as (for example bbsend, or CORP\\svc-bbsend; several: separate with commas). They are added to the \"" + SendersGroup + "\" group; you can add more to it later."

func (w *wizard) askSendTo(a *Answers) error {
	w.question(QSendTo)
	found := w.findInboxes()
	w.note(SendToExample(w.isWindows))
	for _, f := range found {
		w.printf("   Found a collector inbox at %s\n", f)
	}
	def := a.SendTo
	if def == "" && len(found) > 0 {
		def = found[0]
	}
	user, pw := a.ShareUser, a.SharePassword
	for {
		s, err := w.ask(def)
		if err != nil {
			return err
		}
		s, err = SendToAnswer(s, w.isWindows)
		if err != nil {
			w.note(err.Error())
			continue
		}
		def = s // offered again if this attempt does not work
		if config.IsShare(s) {
			w.printf("   Account on the collector to connect with")
			if w.isWindows {
				w.printf(" (leave blank to use this computer's domain account)")
			}
			w.printf("\n")
			newUser, err := w.ask(user)
			if err != nil {
				return err
			}
			if newUser == "-" {
				newUser = ""
			}
			if newUser != "" && (pw == "" || newUser != user) {
				if pw, err = w.password("   Password for " + newUser + ": "); err != nil {
					return err
				}
			}
			user = newUser
		} else {
			user, pw = "", ""
		}
		w.printf("   Checking %s ... ", s)
		if err := w.tryInbox(s, user, pw); err != nil {
			w.printf("not reachable.\n   %v\n", err)
			keep, err := w.yes(NoteKeep, false)
			if err != nil {
				return err
			}
			if !keep {
				pw = "" // ask for the password again
				continue
			}
		} else {
			w.printf("OK, it is a Blackbox inbox.\n")
		}
		a.SendTo, a.ShareUser, a.SharePassword = s, user, pw
		return nil
	}
}

func (w *wizard) askInterval(a *Answers) error {
	w.question(QInterval)
	ints, choices := Intervals(a.CollectEvery)
	i, err := w.choose(choiceLabels(choices, 18), indexOf(ints, a.CollectEvery))
	if err != nil {
		return err
	}
	a.CollectEvery = ints[i]
	return nil
}

// checkFolder reports whether a folder is usable, offering to create it if
// it does not exist.
func (w *wizard) checkFolder(dir, create string) (bool, error) {
	switch c, err := CheckFolder(dir, w.dirExists, w.dirWritable); c {
	case FolderOK:
		return true, nil
	case FolderBad:
		w.note(err.Error() + ".")
		return false, nil
	}
	w.printf("   That folder does not exist yet.\n")
	return w.yes(create, true)
}

// note prints indented text under a question.
func (w *wizard) note(text string) {
	for _, l := range strings.Split(text, "\n") {
		w.printf("   %s\n", l)
	}
}

// choiceLabels lays choices out for the console: "Label   (detail)".
func choiceLabels(c []Choice, width int) []string {
	out := make([]string, len(c))
	for i, x := range c {
		out[i] = x.Label
		if x.Detail != "" {
			out[i] = fmt.Sprintf("%-*s(%s)", width, x.Label, x.Detail)
		}
	}
	return out
}

// choose shows numbered options and returns the index picked.
func (w *wizard) choose(labels []string, def int) (int, error) {
	if def < 0 {
		def = 0
	}
	for i, l := range labels {
		w.printf("     %d) %s\n", i+1, l)
	}
	for {
		w.printf("   Choose 1-%d [%d]: ", len(labels), def+1)
		s, err := w.line()
		if err != nil {
			return 0, err
		}
		if s == "" {
			return def, nil
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(labels) {
			return n - 1, nil
		}
		w.printf("   Please enter a number from 1 to %d.\n", len(labels))
	}
}

func indexOf[T comparable](list []T, v T) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func exampleFolder() string {
	if strings.HasPrefix(config.DefaultDataDir(), "/") {
		return "/srv/audit-reports"
	}
	return `D:\AuditReports`
}

// IsTerminal reports whether f is an interactive console, so setup can ask
// questions (and skips them when run from a script or deployment tool).
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// EveryText describes an interval: "every hour", "every 30 minutes".
func EveryText(d time.Duration) string {
	switch {
	case d == time.Hour:
		return "every hour"
	case d%time.Hour == 0:
		return fmt.Sprintf("every %d hours", int(d.Hours()))
	}
	return fmt.Sprintf("every %d minutes", int(d.Minutes()))
}
