//go:build windows

package gui

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/casea1/blackbox/internal/app"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/hidden"
	"github.com/casea1/blackbox/internal/install"
)

// The status icon (SETUP-SPEC.md, "Tray").

const (
	msgTray     = wmApp + 10 // from the notification area
	msgHealth   = wmApp + 11 // a fresh status is ready
	msgQuit     = wmApp + 12 // uninstall, or the icon was turned off
	msgReport   = wmApp + 13 // a manual report finished
	timerPoll   = 1
	timerAdd    = 2
	timerExit   = 3
	timerNotify = 4 // the next queued notification
	noticeGap   = 7000
	pollEvery   = time.Minute
	trayIconID  = 1
	nimAdd      = 0
	nimModify   = 1
	nimDelete   = 2
	nimSetVer   = 4
	nifMessage  = 0x01
	nifIcon     = 0x02
	nifTip      = 0x04
	nifInfo     = 0x10
	nifShowTip  = 0x80
	niifInfo    = 0x1
	niifWarning = 0x2
)

// Menu commands.
const (
	cmdOpen = iota + 1
	cmdAll
	cmdInterim
	cmdCollect
	cmdStatus
	cmdSettings
	cmdClose
)

type tray struct {
	*window
	version    string
	icons      map[trayState]uintptr
	added      bool
	taskbar    uint32 // "TaskbarCreated": Explorer restarted
	exeTime    time.Time
	relaunch   bool
	mu         sync.Mutex
	lastHealth app.Health
	healthErr  error
	view       trayView
	memory     trayMemory
	clickOpen  string // report to open when the last notification is clicked
	queue      noticeQueue
	making     bool
	made       string
	madeErr    error
	// reading is set while a status read runs; readHealth is how the
	// status is read (a test replaces it).
	reading    bool
	readHealth func() (app.Health, error)
}

// Tray runs the status icon until it is closed. It runs only for an
// administrator with full rights (the logon task starts it that way), one
// per person. With selftest it builds the icon and menu and returns.
func Tray(version string, selftest bool) error {
	initUI()
	hideOwnConsole()
	if !install.IsAdmin() && !selftest {
		return nil // only administrators see it
	}
	mutex, _, err := pCreateMutexW.Call(0, 0, ptr(`Local\BlackboxTray`))
	if errors.Is(err, syscall.Errno(183)) { // ERROR_ALREADY_EXISTS: already running for this person
		return nil
	}
	if mutex != 0 {
		defer syscall.CloseHandle(syscall.Handle(mutex))
	}
	install.RemoveOld()

	t := &tray{version: version, icons: map[trayState]uintptr{}, memory: loadMemory()}
	for _, s := range []trayState{stateOK, stateLook, stateStopped, stateUnknown} {
		t.icons[s] = hicon(trayImage(iconSize(), s))
	}
	if fi, err := os.Stat(install.WindowedPath()); err == nil {
		t.exeTime = fi.ModTime()
	}
	t.window = newWindow("Blackbox status", 0, 0, 0)
	consumeStartupShow(t.hwnd) // the menu's windows open on the first click
	r, _, _ := pRegisterWindowMessageW.Call(ptr("TaskbarCreated"))
	t.taskbar = uint32(r)
	t.onApp = t.app
	t.onTimer = t.timer
	t.onDestroy = func() { t.remove(); quit() }
	t.other = func(m uint32, wp, lp uintptr) (uintptr, bool) {
		if m == t.taskbar && m != 0 {
			t.added = false
			t.add()
			return 0, true
		}
		return 0, false
	}
	t.view = trayView{State: stateUnknown, Tip: "Blackbox", Status: "Reading status…"}
	if selftest {
		menu := t.menu()
		pDestroyMenu.Call(menu)
		t.close()
		return nil
	}
	t.watchQuit()
	t.add()
	t.refresh()
	pSetTimer.Call(t.hwnd, timerPoll, uintptr(pollEvery/time.Millisecond), 0)
	loop()
	if t.relaunch {
		if mutex != 0 {
			syscall.CloseHandle(syscall.Handle(mutex))
			mutex = 0
		}
		install.StartTray()
	}
	return nil
}

func iconSize() int {
	r, _, _ := pGetSystemMetrics.Call(49) // SM_CXSMICON
	if r == 0 {
		return 16
	}
	return int(r)
}

// watchQuit closes the icon when setup or uninstall asks every icon to go.
func (t *tray) watchQuit() {
	ev, _, _ := pCreateEventW.Call(0, 1, 0, ptr(install.TrayQuitEvent))
	if ev == 0 {
		return
	}
	go func() {
		pWaitForSingleObject.Call(ev, 0xFFFFFFFF)
		post(t.hwnd, msgQuit, 0, 0)
	}()
}

func (t *tray) data() notifyIconData {
	d := notifyIconData{Wnd: t.hwnd, ID: trayIconID, CallbackMessage: msgTray}
	d.Size = uint32(unsafe.Sizeof(d))
	return d
}

// add puts the icon in the notification area, retrying until Explorer is
// ready (at logon it may not be yet).
func (t *tray) add() {
	if t.added {
		return
	}
	d := t.data()
	d.Flags = nifMessage | nifIcon | nifTip | nifShowTip
	d.Icon = t.icons[t.view.State]
	copy(d.Tip[:127], syscall.StringToUTF16(t.view.Tip))
	if r, _, _ := pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&d))); r == 0 {
		pSetTimer.Call(t.hwnd, timerAdd, 5000, 0)
		return
	}
	d.Version = 4 // NOTIFYICON_VERSION_4
	pShellNotifyIconW.Call(nimSetVer, uintptr(unsafe.Pointer(&d)))
	t.added = true
	pKillTimer.Call(t.hwnd, timerAdd)
}

func (t *tray) remove() {
	d := t.data()
	pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&d)))
	t.added = false
}

func (t *tray) update() {
	if !t.added {
		t.add()
		return
	}
	d := t.data()
	d.Flags = nifIcon | nifTip | nifShowTip
	d.Icon = t.icons[t.view.State]
	copy(d.Tip[:127], syscall.StringToUTF16(t.view.Tip))
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&d)))
}

// notify shows a notification by the clock, or queues it behind the one
// showing.
func (t *tray) notify(n notice) {
	if t.queue.add(n) {
		t.show(n)
		pSetTimer.Call(t.hwnd, timerNotify, noticeGap, 0)
	}
}

func (t *tray) show(n notice) {
	d := t.data()
	d.Flags = nifInfo
	copy(d.InfoTitle[:63], syscall.StringToUTF16(n.Title))
	text := n.Text
	if len(text) > 250 {
		text = text[:247] + "..."
	}
	copy(d.Info[:255], syscall.StringToUTF16(text))
	d.InfoFlags = niifInfo
	if n.Warn {
		d.InfoFlags = niifWarning
	}
	t.clickOpen = n.Open
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&d)))
}

func (t *tray) newApp() (*app.App, error) {
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return nil, err
	}
	return &app.App{Cfg: cfg, Version: t.version}, nil
}

// health reads the status as "blackbox status" does. On a collector with
// a week of runs and checks this takes seconds (8 on the Server 2025 VM,
// TRAY2), so it is only ever read in the background.
func (t *tray) health() (app.Health, error) {
	if t.readHealth != nil {
		return t.readHealth()
	}
	a, err := t.newApp()
	if err != nil {
		return app.Health{}, err
	}
	return a.Health()
}

// refresh reads the status in the background, unless a read is already
// running; the icon and the next menu show it when it is done.
func (t *tray) refresh() {
	t.mu.Lock()
	if t.reading {
		t.mu.Unlock()
		return
	}
	t.reading = true
	t.mu.Unlock()
	go func() {
		h, err := t.health()
		t.mu.Lock()
		t.lastHealth, t.healthErr, t.reading = h, err, false
		t.mu.Unlock()
		post(t.hwnd, msgHealth, 0, 0)
	}()
}

func (t *tray) timer(id uintptr) {
	switch id {
	case timerPoll:
		// A new version installed: hand over to it.
		if fi, err := os.Stat(install.WindowedPath()); err == nil && !t.exeTime.IsZero() && !fi.ModTime().Equal(t.exeTime) {
			t.relaunch = true
			t.close()
			return
		}
		t.refresh()
	case timerAdd:
		t.add()
	case timerExit:
		t.close()
	case timerNotify:
		if n, ok := t.queue.next(); ok {
			t.show(n)
		} else {
			pKillTimer.Call(t.hwnd, timerNotify)
		}
	}
}

func (t *tray) app(m uint32, wp, lp uintptr) {
	switch m {
	case msgHealth:
		t.mu.Lock()
		h, err := t.lastHealth, t.healthErr
		t.mu.Unlock()
		t.view = classify(h, err, time.Now())
		t.update()
		if err == nil {
			var list []notice
			list, t.memory = notices(t.memory, h, t.view, t.version, time.Now())
			saveMemory(t.memory)
			for _, n := range list {
				t.notify(n) // queued: each is shown in turn
			}
		}
	case msgTray:
		switch uint32(loword(lp)) {
		case ninSelect, ninKeySelect, wmContextMenu: // left click, keyboard, right click
			t.showMenu()
		case ninBalloonUserClick:
			if t.clickOpen != "" {
				openReport(t.hwnd, t.clickOpen, t.view.Reports)
			}
		}
	case msgQuit:
		t.close()
	case msgReport:
		t.making = false
		t.mu.Lock()
		made, err := t.made, t.madeErr
		t.mu.Unlock()
		if err != nil {
			messageBox(0, "The manual report could not be made:\n"+err.Error(), "Blackbox", mbOK|mbIconError)
			return
		}
		t.notify(notice{Title: "Blackbox", Text: "Manual report ready. Click to open it.", Open: made})
		t.refresh()
	}
}

// menu builds the right-click menu.
func (t *tray) menu() uintptr {
	m, _, _ := pCreatePopupMenu.Call()
	add := func(flags uintptr, id int, text string) {
		pAppendMenuW.Call(m, flags, uintptr(id), ptr(strings.ReplaceAll(text, "&", "&&")))
	}
	add(mfString|mfGrayed, 0, t.view.Status)
	for _, it := range t.view.Items {
		add(mfString|mfGrayed, 0, it)
	}
	add(mfSeparator, 0, "")
	open := uintptr(mfString)
	if t.view.Report == "" {
		open |= mfGrayed
	}
	add(open, cmdOpen, "Open latest report")
	all := uintptr(mfString)
	if t.view.Reports == "" {
		all |= mfGrayed
	}
	add(all, cmdAll, "Open all reports")
	add(mfSeparator, 0, "")
	interim := uintptr(mfString)
	if t.view.Reports == "" || t.making {
		interim |= mfGrayed
	}
	add(interim, cmdInterim, "Make a manual report…")
	add(mfString, cmdCollect, "Collect now")
	add(mfString, cmdStatus, "Status details…")
	add(mfString, cmdSettings, "Change settings…")
	add(mfSeparator, 0, "")
	add(mfString, cmdClose, "Close this icon")
	pSetMenuDefaultItem.Call(m, cmdOpen, 0)
	return m
}

// openMenu builds the menu at once with the status last read (at most a
// minute old), and starts a fresh read: its result updates the icon and
// the next menu (TRAY2). Reading it first held the menu back for seconds,
// so a second click seemed needed.
func (t *tray) openMenu() uintptr {
	t.refresh()
	return t.menu()
}

func (t *tray) showMenu() {
	m := t.openMenu()
	defer pDestroyMenu.Call(m)
	var p point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	pSetForegroundWindow.Call(t.hwnd)
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmRightButton|tpmReturnCmd|tpmBottomAlign, uintptr(p.X), uintptr(p.Y), 0, t.hwnd, 0)
	post(t.hwnd, wmNull, 0, 0)
	switch int(cmd) {
	case cmdOpen:
		openReport(t.hwnd, t.view.Report, t.view.Reports)
	case cmdAll:
		openReport(t.hwnd, filepath.Join(t.view.Reports, "index.html"), t.view.Reports)
	case cmdInterim:
		t.interimDialog()
	case cmdCollect:
		if out, err := hidden.Command("schtasks.exe", "/Run", "/TN", install.TaskName).CombinedOutput(); err != nil {
			messageBox(0, "Collection could not be started:\n"+strings.TrimSpace(string(out)), "Blackbox", mbOK|mbIconError)
		} else {
			t.notify(notice{Title: "Blackbox", Text: "Collecting now. The status updates when it finishes."})
		}
	case cmdStatus:
		t.statusWindow()
	case cmdSettings:
		cmd := exec.Command(install.WindowedPath(), "setup")
		if err := cmd.Start(); err != nil {
			messageBox(0, err.Error(), "Blackbox", mbOK|mbIconError)
		}
	case cmdClose:
		t.notify(notice{Title: "Blackbox", Text: "Blackbox keeps collecting. The icon comes back at your next logon."})
		pSetTimer.Call(t.hwnd, timerExit, 4000, 0)
	}
}

// interimDialog (a manual report) asks which period, then makes the report in the background.
func (t *tray) interimDialog() {
	d := newWindow("Make a manual report", 380, 250, 0)
	d.onPaint = func(hdc uintptr, _ rect) {
		d.fill(hdc, barBrush, 0, 190, 380, 60)
		d.fill(hdc, lineBrush, 0, 190, 380, 1)
	}
	d.label("Report on which period? The schedule is not changed.", 20, 16, 340, 20)
	rs := d.radios([]choiceText{{"Since the last report", ""}, {"The last 7 days", ""}, {"The last 30 days", ""}, {"The last 90 days", ""}}, 0, 24, 46, 320)
	makeIt := func() {
		days := []int{0, 7, 30, 90}[selected(rs)]
		d.close()
		t.making = true
		go func() {
			a, err := t.newApp()
			dir := ""
			if err == nil {
				if days == 0 {
					dir, err = a.ReportNow(false)
				} else {
					now := time.Now()
					dir, err = a.ReportRange(now.AddDate(0, 0, -days), now)
				}
			}
			t.mu.Lock()
			t.made, t.madeErr = filepath.Join(dir, "report.html"), err
			t.mu.Unlock()
			post(t.hwnd, msgReport, 0, 0)
		}()
	}
	ok := d.control("BUTTON", "Make report", wsTabStop|bsDefPushButton, 0, 168, 206, 110, 28, false)
	d.on(ok, func(code uint16) {
		if code == bnClicked {
			makeIt()
		}
	})
	d.button("Cancel", 286, 206, 80, false, func() { d.close() })
	d.handlers[idOK] = func(uint16) { makeIt() }
	d.handlers[idCancel] = func(uint16) { d.close() }
	d.show()
}

// statusWindow shows the text of "blackbox status".
func (t *tray) statusWindow() {
	var buf bytes.Buffer
	if a, err := t.newApp(); err != nil {
		buf.WriteString(err.Error())
	} else if err := a.Status(&buf); err != nil {
		buf.WriteString(err.Error())
	}
	d := newWindow("Blackbox status", 720, 480, 0)
	e := d.control("EDIT", strings.ReplaceAll(buf.String(), "\n", "\r\n"), wsVScroll|wsHScroll|esMultiline|esReadOnly|esAutoVScroll|esAutoHScroll|wsTabStop,
		wsExClientEdge, 12, 12, 696, 412, false)
	send(e, wmSetFont, d.fonts.mono, 1)
	d.button("Close", 628, 438, 80, false, func() { d.close() })
	d.handlers[idCancel] = func(uint16) { d.close() }
	d.handlers[idOK] = func(uint16) { d.close() }
	d.show()
}

// The memory of what was notified lives in HKCU\Software\Blackbox.
var (
	pRegCreateKeyExW = advapi32.NewProc("RegCreateKeyExW")
	pRegSetValueExW  = advapi32.NewProc("RegSetValueExW")
)

const regKey = `Software\Blackbox`

func loadMemory() trayMemory {
	var m trayMemory
	var k syscall.Handle
	if syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, wstr(regKey), 0, syscall.KEY_READ, &k) != nil {
		return m
	}
	defer syscall.RegCloseKey(k)
	var typ, n uint32
	if syscall.RegQueryValueEx(k, wstr("TrayNotified"), nil, &typ, nil, &n) != nil || n == 0 {
		return m
	}
	buf := make([]uint16, n/2+1)
	if syscall.RegQueryValueEx(k, wstr("TrayNotified"), nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n) != nil {
		return m
	}
	json.Unmarshal([]byte(syscall.UTF16ToString(buf)), &m)
	return m
}

func saveMemory(m trayMemory) {
	b, _ := json.Marshal(m)
	var k syscall.Handle
	if r, _, _ := pRegCreateKeyExW.Call(uintptr(syscall.HKEY_CURRENT_USER), ptr(regKey), 0, 0, 0, syscall.KEY_WRITE, 0,
		uintptr(unsafe.Pointer(&k)), 0); r != 0 {
		return
	}
	defer syscall.RegCloseKey(k)
	v := syscall.StringToUTF16(string(b))
	pRegSetValueExW.Call(uintptr(k), ptr("TrayNotified"), 0, syscall.REG_SZ, uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)*2))
}
