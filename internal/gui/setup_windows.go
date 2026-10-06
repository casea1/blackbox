//go:build windows

package gui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/install"
	"github.com/casea1/blackbox/internal/setup"
)

// The setup window (SETUP-SPEC.md, "Setup window"): the console setup's
// questions on pages, then the install with its progress.

const (
	winW, winH = 640, 480
	headerH    = 72
	barY       = 420
	bodyX      = 32
	bodyY      = 92
	bodyW      = 576
)

// Messages from the install goroutine to the window.
const (
	msgLog  = wmApp + 1
	msgDone = wmApp + 2
	msgTest = wmApp + 3
)

type setupWin struct {
	*window
	version        string
	a              install.Answers
	tray           bool
	defaultReports string
	reinstall      bool
	installed      string // version already installed, if any
	page           page

	back, next, cancel uintptr
	openRep, openDir   uintptr

	// Controls of the current page.
	c      map[string]uintptr
	radios []uintptr
	ints   []time.Duration

	// Sender: the connection test.
	testing  bool
	tested   string // what was tested and worked: sendTo|user|pw
	testErr  error
	onTested func()

	// Installing.
	mu      sync.Mutex
	lines   []string
	running bool
	done    bool
	res     setup.Result
	err     error
}

// Setup opens the setup window. It asks for administrator rights first if
// it does not have them. With selftest it builds every page for every
// role, then closes (for CI).
func Setup(version string, selftest bool) error {
	initUI()
	hideOwnConsole()
	if !install.IsAdmin() && !selftest {
		return elevate("setup")
	}
	a, defReports, reinstall, err := setup.Current()
	if err != nil {
		messageBox(0, err.Error(), "Blackbox setup", mbOK|mbIconError)
		return err
	}
	s := &setupWin{version: version, a: install.WithDefaults(a), tray: a.Tray, defaultReports: defReports,
		reinstall: reinstall, installed: install.InstalledVersion(), c: map[string]uintptr{}}
	s.window = newWindow("Blackbox setup", winW, winH, 0)
	s.onPaint = s.paint
	s.onClose = s.confirmClose
	s.onDestroy = quit
	s.onApp = s.app
	s.onDPI = func() { s.save(); s.rebuild() }

	s.makeButtons()
	s.handlers[idOK] = func(uint16) { s.goNext() }
	s.handlers[idCancel] = func(uint16) { post(s.hwnd, wmClose, 0, 0) }
	s.build()
	if selftest {
		return s.selftest()
	}
	s.window.show()
	loop()
	return s.err
}

// selftest builds each page for each role, without showing the window.
func (s *setupWin) selftest() error {
	defer s.close()
	for _, role := range install.Roles {
		s.a.Role = role
		for _, p := range pagesFor(role) {
			s.page = p
			s.build()
			if p != pWelcome && p != pInstall && len(s.window.page) == 0 {
				return fmt.Errorf("setup window: page %d for %s has no controls", p, role)
			}
			s.save()
		}
	}
	if d := newFolderDialog(); d == nil {
		return errors.New("setup window: the folder picker could not be created")
	} else {
		d.release()
	}
	return nil
}

func (s *setupWin) makeButtons() {
	y := barY + 16
	s.back = s.button("< Back", 340, y, 96, true, func() {
		if !s.testing {
			s.save()
			s.page = step(s.a.Role, s.page, -1)
			s.build()
		}
	})
	s.next = s.control("BUTTON", "Next >", wsTabStop|bsDefPushButton, 0, 440, y, 96, 28, true)
	s.on(s.next, func(code uint16) {
		if code == bnClicked {
			s.goNext()
		}
	})
	s.cancel = s.button("Cancel", 544, y, 80, true, func() { post(s.hwnd, wmClose, 0, 0) })
	s.openRep = s.button("Open report", 16, y, 110, true, func() { openReport(s.hwnd, s.res.Report, s.res.ReportsDir) })
	s.openDir = s.button("Open reports folder", 134, y, 150, true, func() { openFolder(s.hwnd, s.res.ReportsDir) })
	show(s.openRep, false)
	show(s.openDir, false)
}

// rebuild re-creates the bottom buttons and the page in the new size,
// after the window moves to a screen with a different scaling.
func (s *setupWin) rebuild() {
	for _, b := range []uintptr{s.back, s.next, s.cancel, s.openRep, s.openDir} {
		pDestroyWindow.Call(b)
	}
	s.makeButtons()
	s.build()
}

func (s *setupWin) header() (title, sub string) {
	switch s.page {
	case pWelcome:
		return "Welcome to Blackbox setup", "Audit log collection and reporting"
	case pRole:
		return "This computer", install.QRole
	case pReports:
		return "Reports", "What reports are called, how often they are produced and where they are saved"
	case pArchive:
		return "Original logs", "Where the raw logs wait for the next report"
	case pInbox:
		return "Inbox", "Where the other computers deliver their events"
	case pSendTo:
		return "Collector", "Where this computer sends its events"
	case pCollect:
		return "Collection", install.QInterval
	case pScap:
		return "SCAP results", "Where this computer's SCC or OpenSCAP scan results are saved"
	case pSummary:
		if s.installed != "" {
			return "Ready to apply", "Check the settings, then click Apply."
		}
		return "Ready to install", "Check the settings, then click Install."
	}
	switch {
	case s.running:
		return "Installing", "This can take a few minutes the first time: the whole event log is read."
	case s.err != nil:
		return "Setup could not finish", "Nothing after the step that failed was changed. The details are below."
	}
	return "Blackbox is ready", "Setup has finished."
}

func (s *setupWin) paint(hdc uintptr, _ rect) {
	title, sub := s.header()
	pDrawIconEx.Call(hdc, uintptr(s.s(24)), uintptr(s.s(16)), appIcon, uintptr(s.s(40)), uintptr(s.s(40)), 0, 0, diNormal)
	s.text(hdc, title, s.fonts.title, colText, 80, 12, 540, 28, dtSingleLine|dtEndEllipsis)
	s.text(hdc, sub, s.fonts.normal, colNote, 80, 42, 540, 20, dtSingleLine|dtEndEllipsis)
	s.fill(hdc, lineBrush, 0, headerH, winW, 1)
	s.fill(hdc, barBrush, 0, barY, winW, winH-barY)
	s.fill(hdc, lineBrush, 0, barY, winW, 1)
}

// build creates the current page's controls and sets the buttons.
func (s *setupWin) build() {
	s.clear()
	s.c = map[string]uintptr{}
	s.radios = nil
	x, y, w := bodyX, bodyY, bodyW
	setText(s.next, "Next >")
	enable(s.back, s.page != pWelcome && s.page != pInstall)
	show(s.back, s.page != pInstall)
	enable(s.next, true)
	enable(s.cancel, true)

	switch s.page {
	case pWelcome:
		s.label(welcomeText(s.installed, s.version), x, y, w, 100)
		s.note("Program folder: "+filepath.Dir(install.ProgramPath())+"\nSettings and collected events: "+config.DefaultDataDir(), x, y+130, w, 40)
		if quickUpgrade(s.installed, s.version) {
			// One click: the settings as they are (shown under the button).
			s.c["quick"] = s.control("BUTTON", "Upgrade now, keep current settings", wsTabStop|bsDefPushButton, 0, x, y+184, 290, 32, false)
			s.on(s.c["quick"], func(code uint16) {
				if code == bnClicked {
					s.page = pInstall
					s.start()
					s.build()
				}
			})
			var cur []string
			for _, l := range install.Summary(s.final(), s.defaultReports, true) {
				cur = append(cur, l.Label+": "+l.Value)
			}
			s.note(strings.Join(cur, " · "), x, y+224, w, 60)
		}
	case pRole:
		var ch []choiceText
		for _, c := range install.RoleChoices {
			ch = append(ch, choiceText{c.Label, c.Detail})
		}
		s.radios = s.radios_(ch, indexOf(install.Roles, s.a.Role), x, y, w)
	case pReports:
		s.label(install.QSite, x, y, w, 20)
		s.c["site"] = s.edit(s.a.Site, x, y+22, w, false)
		y += 60
		s.label(install.QEvery, x, y, w, 20)
		s.c["every"] = s.combo(install.EveryChoices, indexOf(install.Everies, s.a.ReportEvery), x, y+22, 300, false)
		s.on(s.c["every"], func(code uint16) {
			if code == cbnSelChange {
				s.save()
				s.build()
			}
		})
		y += 60
		if s.a.ReportEvery == "weekly" {
			s.label(install.QAtWeekly, x, y, w, 20)
			var days []string
			for d := time.Monday; d <= time.Saturday; d++ {
				days = append(days, d.String())
			}
			days = append(days, time.Sunday.String())
			s.c["day"] = s.combo(days, (int(s.a.ReportAt.Day)+6)%7, x, y+22, 160, false)
			s.c["at"] = s.edit(s.a.ReportAt.Clock(), x+170, y+22, 80, false)
			s.note(strings.ReplaceAll(install.NoteAtWeekly, "\n", " "), x, y+52, w, 34)
			y += 96
		} else {
			s.label(install.QAt, x, y, w, 20)
			s.c["at"] = s.edit(s.a.ReportAt.Clock(), x, y+22, 80, false)
			y += 60
		}
		s.label(install.QReportDir, x, y, w, 20)
		dir := s.a.ReportDir
		if dir == "" {
			dir = s.defaultReports
		}
		s.c["dir"] = s.edit(dir, x, y+22, w-100, false)
		s.button("Browse…", x+w-92, y+20, 92, false, func() { s.browse("dir", "Where should reports be saved?") })
		s.note(install.NoteReport, x, y+52, w, 20)
	case pArchive:
		s.label(install.QArchiveDir, x, y, w, 20)
		dir := s.a.ArchiveDir
		if dir == "" {
			dir = install.DefaultArchiveDir()
		}
		s.c["logs"] = s.edit(dir, x, y+22, w-100, false)
		s.button("Browse…", x+w-92, y+20, 92, false, func() { s.browse("logs", install.QArchiveDir) })
		s.note(install.NoteArchive, x, y+52, w, 60)
	case pInbox:
		s.label(install.QInbox, x, y, w, 20)
		s.note(install.NoteInbox, x, y+20, w, 20)
		inbox := s.a.Inbox
		if inbox == "" {
			inbox = install.DefaultInbox()
		}
		s.c["inbox"] = s.edit(inbox, x, y+44, w-100, false)
		s.button("Browse…", x+w-92, y+42, 92, false, func() { s.browse("inbox", "Which folder should other computers deliver to?") })
		y += 92
		s.label(install.QInboxReach, x, y, w, 20)
		// Suggested only where VirtualBox is installed (S12).
		vbox := install.VirtualBoxInstalled()
		s.c["vm"] = s.check("Virtual machines on this PC send to it (VirtualBox shared folder)", len(s.a.InboxWriters) > 0 || (vbox && !s.a.ShareInbox), x, y+24, w)
		s.note("Windows account(s) that run VirtualBox; it writes into the shared folder as that account (separate several with commas)", x+20, y+50, w-20, 34)
		writers := strings.Join(s.a.InboxWriters, ", ")
		if writers == "" && vbox {
			writers = os.Getenv("USERNAME")
		}
		s.c["writers"] = s.edit(writers, x+20, y+86, w-20, false)
		s.on(s.c["vm"], func(uint16) { enable(s.c["writers"], checked(s.c["vm"])) })
		enable(s.c["writers"], checked(s.c["vm"]))
		s.c["share"] = s.check("Share it on the network as "+install.ShareName+", so other computers can send to it", s.a.ShareInbox, x, y+122, w)
		// The accounts other computers deliver as (S11).
		s.note(install.NoteShareWriters, x+20, y+148, w-20, 34)
		s.c["swriters"] = s.edit(strings.Join(s.a.ShareWriters, ", "), x+20, y+184, w-20, false)
		s.on(s.c["share"], func(uint16) { enable(s.c["swriters"], checked(s.c["share"])) })
		enable(s.c["swriters"], checked(s.c["share"]))
	case pSendTo:
		s.label(install.QSendTo, x, y, w, 20)
		s.note(strings.ReplaceAll(install.SendToExample(true), "\n", " "), x, y+20, w, 20)
		found := install.FindInboxes()
		cur := s.a.SendTo
		if cur == "" && len(found) > 0 {
			cur = found[0]
		}
		s.c["sendto"] = s.combo(found, -1, x, y+44, w, true)
		setText(s.c["sendto"], cur)
		y += 84
		s.label("Account on the collector to connect with (leave blank to use this computer's domain account)", x, y, w, 20)
		s.c["user"] = s.edit(s.a.ShareUser, x, y+22, 280, false)
		y += 58
		s.label("Password", x, y, w, 20)
		s.c["pw"] = s.edit(s.a.SharePassword, x, y+22, 280, true)
		if s.reinstall && s.a.ShareUser != "" && s.a.SharePassword == "" {
			send(s.c["pw"], emSetCueBanner, 1, ptr("leave blank to keep the saved password"))
		}
		y += 58
		s.c["test"] = s.button("Test connection", x, y, 140, false, func() { s.save(); s.test(nil) })
		s.c["result"] = s.label("", x+152, y+5, w-152, 40)
	case pCollect:
		ints, choices := install.Intervals(s.a.CollectEvery)
		s.ints = ints
		var ch []choiceText
		for _, c := range choices {
			ch = append(ch, choiceText{c.Label, c.Detail})
		}
		s.radios = s.radios_(ch, indexOf(ints, s.a.CollectEvery), x, y, w)
		if s.a.Role != install.RoleSender {
			s.c["tray"] = s.check("Show Blackbox's status in the notification area for administrators", s.tray, x, y+200, w)
			s.note("An icon by the clock: collecting on schedule, something to look at, or stopped. Only members of Administrators see it.", x+20, y+224, w-20, 34)
		}
	case pScap:
		s.label(install.QScap, x, y, w, 20)
		dir := s.a.ScapResults
		if dir == "" {
			dir = install.DefaultScapDir()
		}
		s.c["scap"] = s.edit(dir, x, y+22, w-100, false)
		s.button("Browse…", x+w-92, y+20, 92, false, func() { s.browse("scap", install.QScap) })
		s.note(install.NoteScap, x, y+52, w, 76)
	case pSummary:
		a := s.final()
		for _, l := range install.Summary(a, s.defaultReports, true) {
			h := 20 // rows must not overlap, or the later one hides the text
			if len(l.Value) > 70 {
				h = 38
			}
			s.boldLabel(l.Label, x, y, 130, 20)
			s.label(l.Value, x+140, y, w-140, h)
			y += h + 8
		}
		setText(s.next, applyVerb(s.installed))
	case pInstall:
		s.c["status"] = s.label("", x, y, w, 20)
		s.c["bar"] = s.control("msctls_progress32", "", pbsMarquee, 0, x, y+24, w, 6, false)
		send(s.c["bar"], pbmSetMarquee, 1, 30)
		s.c["log"] = s.control("EDIT", "", wsVScroll|esMultiline|esReadOnly|esAutoVScroll|wsTabStop, wsExClientEdge, x, y+40, w, 268, false)
		send(s.c["log"], wmSetFont, s.fonts.mono, 1)
		send(s.c["log"], emSetLimitText, 0, 0)
		s.mu.Lock()
		text := strings.Join(s.lines, "\r\n")
		s.mu.Unlock()
		setText(s.c["log"], text)
		s.installButtons()
	}
	pInvalidateRect.Call(s.hwnd, 0, 1)
}

func (s *setupWin) radios_(ch []choiceText, sel, x, y, w int) []uintptr {
	if sel < 0 {
		sel = 0
	}
	return s.window.radios(ch, sel, x, y, w)
}

func indexOf[T comparable](list []T, v T) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}

// final is the answers as they will be installed.
func (s *setupWin) final() install.Answers {
	a := s.a
	a.Tray = s.tray
	return install.ForRole(a)
}

// save reads the current page's controls into the answers, without
// checking them (Back keeps what was typed).
func (s *setupWin) save() {
	get := func(k string) string { return strings.TrimSpace(getText(s.c[k])) }
	switch s.page {
	case pRole:
		if len(s.radios) > 0 {
			s.a.Role = install.Roles[selected(s.radios)]
		}
	case pReports:
		s.a.Site = get("site")
		if i := comboIndex(s.c["every"]); i >= 0 {
			s.a.ReportEvery = install.Everies[i]
		}
		if c, ok := s.c["day"]; ok {
			if i := comboIndex(c); i >= 0 {
				s.a.ReportAt.Day = time.Weekday((i + 1) % 7)
			}
		}
		if r, err := config.ParseReportAt(get("at")); err == nil {
			r.Day = s.a.ReportAt.Day
			s.a.ReportAt = r
		}
		if d := get("dir"); d == s.defaultReports {
			s.a.ReportDir = ""
		} else {
			s.a.ReportDir = strings.Trim(d, `"`)
		}
	case pArchive:
		if d := strings.Trim(get("logs"), `"`); d == install.DefaultArchiveDir() {
			s.a.ArchiveDir = ""
		} else {
			s.a.ArchiveDir = d
		}
	case pInbox:
		s.a.Inbox = strings.Trim(get("inbox"), `"`)
		s.a.InboxWriters = nil
		if checked(s.c["vm"]) {
			s.a.InboxWriters = install.SplitList(get("writers"))
		}
		s.a.ShareInbox = checked(s.c["share"])
		s.a.ShareWriters = nil
		if s.a.ShareInbox {
			s.a.ShareWriters = install.SplitList(get("swriters"))
		}
	case pSendTo:
		s.a.SendTo = strings.Trim(get("sendto"), `"`)
		s.a.ShareUser = get("user")
		s.a.SharePassword = getText(s.c["pw"])
	case pScap:
		switch d := strings.Trim(get("scap"), `"`); {
		case d == install.DefaultScapDir():
			s.a.ScapResults = ""
		case strings.EqualFold(d, "none"):
			s.a.ScapResults = "none"
		default:
			s.a.ScapResults = d
		}
	case pCollect:
		if len(s.radios) > 0 {
			s.a.CollectEvery = s.ints[selected(s.radios)]
		}
		if c, ok := s.c["tray"]; ok {
			s.tray = checked(c)
		}
	}
}

// goNext checks the page and moves on (or installs, or finishes).
func (s *setupWin) goNext() {
	if s.testing || s.running {
		return
	}
	if s.page == pInstall {
		if s.done {
			s.close()
		}
		return
	}
	s.save()
	if !s.check_() {
		return
	}
	if s.page == pSendTo && s.tested != s.a.SendTo+"|"+s.a.ShareUser+"|"+s.a.SharePassword {
		s.test(func() {
			if s.testErr == nil || messageBox(s.hwnd, fmt.Sprintf("%s could not be reached:\n%v\n\n%s", s.a.SendTo, s.testErr, install.NoteKeep),
				"Blackbox setup", mbYesNo|mbIconWarning) == idYes {
				s.tested = s.a.SendTo + "|" + s.a.ShareUser + "|" + s.a.SharePassword
				s.advance()
			}
		})
		return
	}
	s.advance()
}

func (s *setupWin) advance() {
	if s.page == pSummary {
		s.page = pInstall
		s.start()
		s.build()
		return
	}
	s.page = step(s.a.Role, s.page, 1)
	s.build()
}

// check_ applies the console setup's checks to the current page.
func (s *setupWin) check_() bool {
	warn := func(ctrl, text string) bool {
		messageBox(s.hwnd, text, "Blackbox setup", mbOK|mbIconWarning)
		if c, ok := s.c[ctrl]; ok {
			pSetFocus.Call(c)
		}
		return false
	}
	switch s.page {
	case pReports:
		v := strings.TrimSpace(getText(s.c["at"]))
		if _, ok := s.c["day"]; ok {
			v = s.a.ReportAt.Day.String() + " " + v
		}
		if _, err := config.ParseReportAt(v); err != nil {
			return warn("at", "Please enter the time as hours and minutes, for example 00:00 or 06:30.")
		}
		// An empty box is not "the default": a full path is required, as
		// the console asks.
		if strings.TrimSpace(getText(s.c["dir"])) == "" {
			return warn("dir", install.ReportDirError("").Error())
		}
		if s.a.ReportDir != "" {
			if err := install.ReportDirError(s.a.ReportDir); err != nil {
				return warn("dir", err.Error())
			}
			if !s.folderOK(s.a.ReportDir, "That folder does not exist yet. Create it (administrators only)?") {
				pSetFocus.Call(s.c["dir"])
				return false
			}
		}
	case pArchive:
		if strings.TrimSpace(getText(s.c["logs"])) == "" {
			return warn("logs", install.ReportDirError("").Error())
		}
		if s.a.ArchiveDir != "" {
			if err := install.ReportDirError(s.a.ArchiveDir); err != nil {
				return warn("logs", err.Error())
			}
			if !s.folderOK(s.a.ArchiveDir, "That folder does not exist yet. Create it (administrators only)?") {
				pSetFocus.Call(s.c["logs"])
				return false
			}
		}
	case pInbox:
		if err := install.InboxError(s.a.Inbox, install.DefaultInbox()); err != nil {
			return warn("inbox", err.Error())
		}
		if !s.folderOK(s.a.Inbox, "That folder does not exist yet. Create it?") {
			pSetFocus.Call(s.c["inbox"])
			return false
		}
		if checked(s.c["vm"]) && len(s.a.InboxWriters) == 0 {
			return warn("writers", "Enter the Windows account that runs VirtualBox, or untick the box.")
		}
		if s.a.ShareInbox && len(s.a.ShareWriters) == 0 && !s.reinstall {
			return warn("swriters", "Enter the account other computers deliver as (for example bbsend), or untick sharing.")
		}
	case pScap:
		if strings.TrimSpace(getText(s.c["scap"])) == "" {
			return warn("scap", install.ReportDirError("").Error()+" Type none to turn SCAP results off.")
		}
		if d := s.a.ScapResults; d != "" && d != "none" {
			if err := install.ReportDirError(d); err != nil {
				return warn("scap", err.Error())
			}
			if ok, err := dirExists(d); err != nil {
				return warn("scap", err.Error())
			} else if !ok && messageBox(s.hwnd, d+" does not exist yet. Use it anyway? Blackbox reads it once scans are saved there.", "Blackbox setup", mbYesNo|mbIconQuestion) != idYes {
				pSetFocus.Call(s.c["scap"])
				return false
			}
		}
	case pSendTo:
		v, err := install.SendToAnswer(s.a.SendTo, true)
		if err != nil {
			return warn("sendto", err.Error())
		}
		s.a.SendTo = v
	}
	return true
}

// folderOK checks a folder answer; a missing one is offered for creation
// (it is created during the install).
func (s *setupWin) folderOK(dir, create string) bool {
	switch c, err := install.CheckFolder(dir, dirExists, install.CheckWritable); c {
	case install.FolderOK:
		return true
	case install.FolderBad:
		messageBox(s.hwnd, err.Error()+".", "Blackbox setup", mbOK|mbIconWarning)
		return false
	}
	return messageBox(s.hwnd, create, "Blackbox setup", mbYesNo|mbIconQuestion) == idYes
}

func folderExists(p string) bool {
	ok, _ := dirExists(p)
	return ok
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

func (s *setupWin) browse(key, title string) {
	start := strings.TrimSpace(getText(s.c[key]))
	for start != "" {
		if ok, _ := dirExists(start); ok {
			break
		}
		parent := filepath.Dir(start)
		if parent == start {
			start = ""
			break
		}
		start = parent
	}
	if p := pickFolder(s.hwnd, title, start); p != "" {
		setText(s.c[key], p)
	}
}

// test tries the collector's inbox in the background, then calls then.
func (s *setupWin) test(then func()) {
	sendTo, err := install.SendToAnswer(s.a.SendTo, true)
	if err != nil {
		setText(s.c["result"], err.Error())
		return
	}
	s.testing = true
	s.onTested = then
	setText(s.c["result"], "Checking "+sendTo+" …")
	for _, b := range []uintptr{s.back, s.next, s.c["test"]} {
		enable(b, false)
	}
	user, pw := s.a.ShareUser, s.a.SharePassword
	go func() {
		s.testErr = install.TryInbox(sendTo, user, pw)
		post(s.hwnd, msgTest, 0, 0)
	}()
}

// start runs the install in the background.
func (s *setupWin) start() {
	s.running = true
	a := s.final()
	logf := func(format string, args ...any) {
		s.mu.Lock()
		s.lines = append(s.lines, fmt.Sprintf(format, args...))
		s.mu.Unlock()
		post(s.hwnd, msgLog, 0, 0)
	}
	go func() {
		res, err := setup.Run(setup.Options{Answers: a, Version: s.version, Reinstall: s.reinstall, StartTray: true, Logf: logf})
		s.mu.Lock()
		s.res, s.err = res, err
		s.mu.Unlock()
		post(s.hwnd, msgDone, 0, 0)
	}()
}

func (s *setupWin) app(m uint32, _, _ uintptr) {
	switch m {
	case msgLog:
		s.mu.Lock()
		text := strings.Join(s.lines, "\r\n")
		s.mu.Unlock()
		if l, ok := s.c["log"]; ok {
			setText(l, text)
			n := len(text) + 1
			send(l, emSetSel, uintptr(n), uintptr(n))
			send(l, 0x00B7, 0, 0) // EM_SCROLLCARET
		}
	case msgDone:
		s.running, s.done = false, true
		if s.err != nil {
			s.mu.Lock()
			s.lines = append(s.lines, "", "Setup could not finish: "+s.err.Error())
			s.mu.Unlock()
		}
		s.build()
		s.app(msgLog, 0, 0)
	case msgTest:
		s.testing = false
		enable(s.back, true)
		enable(s.next, true)
		if b, ok := s.c["test"]; ok {
			enable(b, true)
		}
		if s.testErr != nil {
			setText(s.c["result"], "Not reachable: "+s.testErr.Error())
		} else {
			setText(s.c["result"], "OK, it is a Blackbox inbox.")
			s.tested = s.a.SendTo + "|" + s.a.ShareUser + "|" + s.a.SharePassword
		}
		if then := s.onTested; then != nil {
			s.onTested = nil
			then()
		}
	}
}

// installButtons sets the bottom bar for the install page.
func (s *setupWin) installButtons() {
	status := "Installing…"
	switch {
	case s.running:
	case s.err != nil:
		status = "Setup could not finish."
	default:
		status = "Done."
	}
	setText(s.c["status"], status)
	show(s.c["bar"], s.running)
	setText(s.next, finishLabel(s.done && s.err != nil))
	enable(s.next, s.done)
	enable(s.cancel, false) // as in any wizard: Finish, with Cancel greyed out
	show(s.openRep, s.done && s.err == nil && s.res.Report != "")
	show(s.openDir, s.done && s.err == nil && s.res.ReportsDir != "" && folderExists(s.res.ReportsDir))
}

func (s *setupWin) confirmClose() bool {
	switch {
	case s.running:
		messageBox(s.hwnd, "Setup is still working. Please wait for it to finish.", "Blackbox setup", mbOK|mbIconInfo)
		return false
	case !confirmCancel(s.page, s.running, s.done):
		return true
	}
	return messageBox(s.hwnd, "Cancel Blackbox setup? Nothing has been changed.", "Blackbox setup", mbYesNo|mbIconQuestion) == idYes
}
