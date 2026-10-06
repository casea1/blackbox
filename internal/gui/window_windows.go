//go:build windows

package gui

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/casea1/blackbox/internal/brand"
)

// window is a top-level window: the setup window, a small dialog, or the
// status icon's hidden window. Sizes are given in units of 1/96 inch and
// scaled to the screen's DPI.
type window struct {
	hwnd  uintptr
	dpi   int
	fonts fonts

	nextID   uint16
	handlers map[uint16]func(code uint16)
	notes    map[uint16]bool // controls (by ID) drawn in grey
	page     []uintptr       // controls of the current page, destroyed together

	onPaint   func(hdc uintptr, r rect)
	onClose   func() bool // false keeps the window open
	onDestroy func()
	onApp     func(m uint32, w, l uintptr)
	onTimer   func(id uintptr)
	onDPI     func()
	other     func(m uint32, w, l uintptr) (uintptr, bool) // anything else
}

type fonts struct{ normal, bold, title, mono uintptr }

var (
	windows    = map[uintptr]*window{}
	classOnce  sync.Once
	className  = "BlackboxWindow"
	wndProcPtr uintptr
	white      uintptr
	barBrush   uintptr
	lineBrush  uintptr
	appIcon    uintptr
	appIconSm  uintptr
)

// Colours (as COLORREF).
var (
	colText = rgb(0x0B, 0x16, 0x30)
	colNote = rgb(0x5A, 0x67, 0x85)
	colBar  = rgb(0xF4, 0xF6, 0xFA)
	colLine = rgb(0xE3, 0xE7, 0xEF)
)

// initUI prepares the process for windows: per-monitor DPI (if the
// manifest did not already), the current controls, and the window class.
// It locks the calling goroutine to its thread: Windows delivers a
// window's messages to the thread that created it.
func initUI() {
	runtime.LockOSThread()
	classOnce.Do(func() {
		pSetDpiAwarenessContext.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
		icc := initCommonControlsEx{Size: 8, ICC: 0x0000FFFF}
		pInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
		pCoInitializeEx.Call(0, 0x2|0x4) // apartment threaded, no OLE1 DDE
		white, _, _ = pCreateSolidBrush.Call(rgb(255, 255, 255))
		barBrush, _, _ = pCreateSolidBrush.Call(colBar)
		lineBrush, _, _ = pCreateSolidBrush.Call(colLine)
		appIcon = hicon(brand.Logo(48))
		appIconSm = hicon(brand.Logo(16))
		wndProcPtr = syscall.NewCallback(wndProc)
		cursor, _, _ := pLoadCursorW.Call(0, idcArrow)
		wc := wndClassEx{Size: uint32(unsafe.Sizeof(wndClassEx{})), WndProc: wndProcPtr, Instance: moduleHandle(),
			Icon: appIcon, IconSm: appIconSm, Cursor: cursor, ClassName: wstr(className)}
		pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	})
}

func systemDPI() int {
	if pGetDpiForSystem.Find() == nil {
		d, _, _ := pGetDpiForSystem.Call()
		if d > 0 {
			return int(d)
		}
	}
	return 96
}

// newWindow creates a fixed-size top-level window with a client area of
// w×h (unscaled), centred on the screen. A hidden window (for the status
// icon) is created with w = h = 0.
func newWindow(title string, w, h int, owner uintptr) *window {
	win := &window{dpi: systemDPI(), nextID: 100, handlers: map[uint16]func(uint16){}, notes: map[uint16]bool{}}
	style := uintptr(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsClipChildren)
	ex := uintptr(wsExControlParent)
	x, y, cw, ch := uintptr(0), uintptr(0), uintptr(0), uintptr(0)
	if w > 0 {
		r := win.outer(w, h, style, ex)
		cw, ch = uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top)
		sw, _, _ := pGetSystemMetrics.Call(smCxScreen)
		sh, _, _ := pGetSystemMetrics.Call(smCyScreen)
		x, y = (sw-cw)/2, (sh-ch)/2
		if int(sw) < int(cw) {
			x = 0
		}
		if int(sh) < int(ch) {
			y = 0
		}
	}
	hwnd, _, _ := pCreateWindowExW.Call(ex, ptr(className), ptr(title), style, x, y, cw, ch, owner, 0, moduleHandle(), 0)
	win.hwnd = hwnd
	windows[hwnd] = win
	if d := dpiOf(hwnd); d != win.dpi && w > 0 {
		win.dpi = d // on another monitor than the main one
		r := win.outer(w, h, style, ex)
		pSetWindowPos.Call(hwnd, 0, 0, 0, uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), 0x0002|swpNoZOrder) // SWP_NOMOVE
	}
	win.makeFonts()
	return win
}

func dpiOf(hwnd uintptr) int {
	if pGetDpiForWindow.Find() == nil {
		d, _, _ := pGetDpiForWindow.Call(hwnd)
		if d > 0 {
			return int(d)
		}
	}
	return 96
}

// outer is the window size for a client area of w×h.
func (win *window) outer(w, h int, style, ex uintptr) rect {
	r := rect{0, 0, win.s(w), win.s(h)}
	if pAdjustWindowRectExDpi.Find() == nil {
		pAdjustWindowRectExDpi.Call(uintptr(unsafe.Pointer(&r)), style, 0, ex, uintptr(win.dpi))
	} else {
		pAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&r)), style, 0, ex)
	}
	return r
}

// s scales a length for the window's DPI.
func (win *window) s(v int) int32 { return int32(v * win.dpi / 96) }

func (win *window) makeFonts() {
	for _, f := range []uintptr{win.fonts.normal, win.fonts.bold, win.fonts.title, win.fonts.mono} {
		if f != 0 {
			pDeleteObject.Call(f)
		}
	}
	win.fonts = fonts{
		normal: makeFont("Segoe UI", 9, 400, win.dpi),
		bold:   makeFont("Segoe UI", 9, 600, win.dpi),
		title:  makeFont("Segoe UI", 13, 600, win.dpi),
		mono:   makeFont("Consolas", 9, 400, win.dpi),
	}
}

func makeFont(face string, points, weight, dpi int) uintptr {
	lf := logFont{Height: -int32(points * dpi / 72), Weight: int32(weight), CharSet: 1, Quality: 5}
	copy(lf.FaceName[:31], syscall.StringToUTF16(face))
	f, _, _ := pCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
	return f
}

// control adds a child control at (x, y) with size w×h, unscaled. Page
// controls are destroyed by clear(); fixed ones (the bottom buttons) are
// not.
func (win *window) control(class, text string, style, ex uint32, x, y, w, h int, fixed bool) uintptr {
	id := win.nextID
	win.nextID++
	// Each input starts its own group, so arrow keys move only within a
	// set of options. Text (the grey lines under options) and the 2nd and
	// later option buttons of a set don't, or the set would be split and
	// two options could be ticked at once.
	if class != "STATIC" && (class != "BUTTON" || style&0xF != bsAutoRadio) {
		style |= wsGroup
	}
	hwnd, _, _ := pCreateWindowExW.Call(uintptr(ex), ptr(class), ptr(text), uintptr(wsChild|wsVisible|style),
		uintptr(win.s(x)), uintptr(win.s(y)), uintptr(win.s(w)), uintptr(win.s(h)), win.hwnd, uintptr(id), moduleHandle(), 0)
	send(hwnd, wmSetFont, win.fonts.normal, 1)
	if !fixed {
		win.page = append(win.page, hwnd)
	}
	return hwnd
}

// id returns a control's ID, for handlers.
func ctrlID(hwnd uintptr) uint16 {
	r, _, _ := user32.NewProc("GetDlgCtrlID").Call(hwnd)
	return uint16(r)
}

func (win *window) on(ctrl uintptr, fn func(code uint16)) { win.handlers[ctrlID(ctrl)] = fn }

// label is static text; note is grey static text.
func (win *window) label(text string, x, y, w, h int) uintptr {
	return win.control("STATIC", text, ssLeft|ssNoPrefix, 0, x, y, w, h, false)
}

func (win *window) note(text string, x, y, w, h int) uintptr {
	// Marked before it exists: a control may be drawn while it is created.
	win.notes[win.nextID] = true
	return win.label(text, x, y, w, h)
}

func (win *window) boldLabel(text string, x, y, w, h int) uintptr {
	l := win.label(text, x, y, w, h)
	send(l, wmSetFont, win.fonts.bold, 1)
	return l
}

func (win *window) edit(text string, x, y, w int, password bool) uintptr {
	style := uint32(wsTabStop | esAutoHScroll)
	if password {
		style |= esPassword
	}
	return win.control("EDIT", text, style, wsExClientEdge, x, y, w, 24, false)
}

func (win *window) button(text string, x, y, w int, fixed bool, fn func()) uintptr {
	b := win.control("BUTTON", text, wsTabStop|bsPushButton, 0, x, y, w, 28, fixed)
	win.on(b, func(code uint16) {
		if code == bnClicked {
			fn()
		}
	})
	return b
}

func (win *window) check(text string, on bool, x, y, w int) uintptr {
	c := win.control("BUTTON", text, wsTabStop|bsAutoCheckBox, 0, x, y, w, 22, false)
	setChecked(c, on)
	return c
}

// radios adds a group of option buttons, each with grey detail text under
// it, and returns them.
func (win *window) radios(choices []choiceText, sel, x, y, w int) []uintptr {
	var out []uintptr
	for i, c := range choices {
		style := uint32(bsAutoRadio)
		if i == 0 {
			style |= wsGroup | wsTabStop
		}
		r := win.control("BUTTON", c.label, style, 0, x, y, w, 22, false)
		setChecked(r, i == sel)
		out = append(out, r)
		y += 24
		if c.detail != "" {
			win.note(c.detail, x+20, y-2, w-20, 18)
			y += 22
		}
		y += 4
	}
	return out
}

type choiceText struct{ label, detail string }

func selected(rs []uintptr) int {
	for i, r := range rs {
		if checked(r) {
			return i
		}
	}
	return 0
}

// combo is a drop-down list (editable when free is set).
func (win *window) combo(items []string, sel, x, y, w int, free bool) uintptr {
	style := uint32(wsTabStop | wsVScroll | cbsDropDownList)
	if free {
		style = wsTabStop | wsVScroll | cbsDropDown | 0x40 // CBS_AUTOHSCROLL
	}
	c := win.control("COMBOBOX", "", style, 0, x, y, w, 200, false)
	for _, it := range items {
		send(c, cbAddString, 0, ptr(it))
	}
	if sel >= 0 {
		send(c, cbSetCurSel, uintptr(sel), 0)
	}
	return c
}

func comboIndex(c uintptr) int { return int(int32(send(c, cbGetCurSel, 0, 0))) }

// clear removes the current page's controls.
func (win *window) clear() {
	for _, c := range win.page {
		delete(win.notes, ctrlID(c))
		delete(win.handlers, ctrlID(c))
		pDestroyWindow.Call(c)
	}
	win.page = nil
	pInvalidateRect.Call(win.hwnd, 0, 1)
}

func (win *window) show() {
	pShowWindow.Call(win.hwnd, swShowNormal)
	// A process's first ShowWindow can take the show mode the process was
	// started with (STARTUPINFO) instead of the one asked for: the icon,
	// started by its task, would then create its first dialog hidden and
	// leave it behind (TRAY1). Show it again if it is not visible.
	if v, _, _ := pIsWindowVisible.Call(win.hwnd); v == 0 {
		pShowWindow.Call(win.hwnd, swShow)
	}
	pUpdateWindow.Call(win.hwnd)
	pSetForegroundWindow.Call(win.hwnd)
}

func (win *window) close() { pDestroyWindow.Call(win.hwnd) }

// consumeStartupShow makes the process's first ShowWindow call on a window
// that stays hidden anyway, so the show mode the process was started with
// (a task's hidden window) does not fall on the first dialog (TRAY1).
func consumeStartupShow(hwnd uintptr) { pShowWindow.Call(hwnd, swHide) }

// fill paints a rectangle given in unscaled units.
func (win *window) fill(hdc uintptr, brush uintptr, x, y, w, h int) {
	r := rect{win.s(x), win.s(y), win.s(x + w), win.s(y + h)}
	pFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), brush)
}

// text draws text in a box given in unscaled units.
func (win *window) text(hdc uintptr, s string, font, color uintptr, x, y, w, h int, flags uintptr) {
	old, _, _ := pSelectObject.Call(hdc, font)
	pSetBkMode.Call(hdc, transparent)
	pSetTextColor.Call(hdc, color)
	r := rect{win.s(x), win.s(y), win.s(x + w), win.s(y + h)}
	pDrawTextW.Call(hdc, ptr(s), ^uintptr(0), uintptr(unsafe.Pointer(&r)), flags|dtNoPrefix)
	pSelectObject.Call(hdc, old)
}

func wndProc(hwnd uintptr, m uint32, wp, lp uintptr) uintptr {
	win := windows[hwnd]
	if win == nil {
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(m), wp, lp)
		return r
	}
	switch m {
	case wmCommand:
		if fn := win.handlers[loword(wp)]; fn != nil {
			fn(hiword(wp))
			return 0
		}
	case wmCtlColorStatic, wmCtlColorBtn:
		pSetBkColor.Call(wp, rgb(255, 255, 255))
		if win.notes[ctrlID(lp)] {
			pSetTextColor.Call(wp, colNote)
		} else {
			pSetTextColor.Call(wp, colText)
		}
		return white
	case wmPaint:
		var ps paintStruct
		hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		var r rect
		pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
		pFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), white)
		if win.onPaint != nil {
			win.onPaint(hdc, r)
		}
		pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0
	case wmClose:
		if win.onClose != nil && !win.onClose() {
			return 0
		}
		pDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		delete(windows, hwnd)
		if win.onDestroy != nil {
			win.onDestroy()
		}
		return 0
	case wmTimer:
		if win.onTimer != nil {
			win.onTimer(wp)
			return 0
		}
	case wmDpiChanged:
		var r rect
		pRtlMoveMemory.Call(uintptr(unsafe.Pointer(&r)), lp, unsafe.Sizeof(r))
		win.dpi = int(loword(wp))
		win.makeFonts()
		pSetWindowPos.Call(hwnd, 0, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), swpNoZOrder|swpNoActivate)
		if win.onDPI != nil {
			win.onDPI()
		}
		pInvalidateRect.Call(hwnd, 0, 1)
		return 0
	}
	if m >= wmApp && m < wmApp+0x100 && win.onApp != nil {
		win.onApp(m, wp, lp)
		return 0
	}
	if win.other != nil {
		if r, ok := win.other(m, wp, lp); ok {
			return r
		}
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(m), wp, lp)
	return r
}

// loop runs until PostQuitMessage. Tab and Enter move between and press
// controls as in any dialog.
func loop() {
	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		root, _, _ := pGetAncestor.Call(m.Hwnd, 2) // GA_ROOT
		if w := windows[root]; w != nil && w.page != nil {
			if d, _, _ := pIsDialogMessageW.Call(root, uintptr(unsafe.Pointer(&m))); d != 0 {
				continue
			}
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func quit() { pPostQuitMessage.Call(0) }

// waitCursor shows the hourglass until the returned function is called.
func waitCursor() func() {
	c, _, _ := pLoadCursorW.Call(0, idcWait)
	old, _, _ := pSetCursor.Call(c)
	return func() { pSetCursor.Call(old) }
}
