# Blackbox 0.10.0 on Windows: review against `docs/redesign/SETUP-SPEC.md`

Tested 2 Oct 2026 on DSK1 (Windows 11 Pro 26200), at the local console with one 3440×1440 monitor, at 100% and 150% scale. There are also a few shots at 200% from an earlier RDP session.

The test used the release file `Blackbox-Setup-0.10.0.exe` (SHA256 `955ed102…399b`, which matches `SHA256SUMS`). Source was checked at HEAD `ead2e1b`. There is no `v0.10.0` tag in the repo yet.

All screenshots are in [`shots/`](shots/).

## Differences from the spec

### Bugs and real gaps

| # | Spec | What happens | Evidence |
|---|---|---|---|
| 1 | **Open reports folder** opens the reports folder. | After a reinstall that keeps settings, no report is made, so `C:\ProgramData\Blackbox\reports` doesn't exist yet. The button then opens Explorer at **Documents**. | [100-09-openfolder-goes-to-Documents](shots/100-09-openfolder-goes-to-Documents.png), [100-08b-installing-done](shots/100-08b-installing-done.png) |
| 2 | Folder-access question: **No** "opens the folder in Explorer instead". | It does open Explorer, but the person's account can't read the folder. Explorer shows "Location is not available – Access is denied" with only **OK**; there is no Continue button. So **No** is a dead end. | [100-folder-access-No](shots/100-folder-access-No-%2332770.png) |
| 3 | Cancel before the Installing page asks "Cancel Blackbox setup? Nothing has been changed." | On **Welcome**, Cancel and X close at once without asking (`internal/gui/setup_windows.go:652`). Page 2 onwards do ask. | [page 2 prompt](shots/page2-cancel-dialog-200.png) |
| 4 | Button is **Install** on a first install, **Apply** when already installed. | After an uninstall (settings are kept), a fresh install shows **Apply** and "Ready to apply". The choice depends on `blackbox.conf` existing, not on the program being installed (`internal/setup/setup.go:173`). | [100-07-summary](shots/100-07-summary.png) |
| 5 | Welcome, upgrade: "Blackbox <installed version> is installed. This will upgrade it to <version>." | Shown for the same version too: "0.10.0 is installed. This will upgrade it to 0.10.0." This also appears from the tray's **Change settings…** and the Programs and Features **Modify** button, where nothing is being upgraded. | [100-01b](shots/100-01b-welcome-modify-from-tray.png), [150-01](shots/150-01-welcome-upgrade.png) |
| 6 | "a full path is required" | An empty reports-folder box is accepted without a word and replaced by the default `C:\ProgramData\Blackbox\reports`. | (seen live; Reports page shows the default afterwards) |
| 7 | The tray restarts after an upgrade and shows "Blackbox updated to <version>". | The restart works. The notification is **not verified**. With the same version (0.10.0 → 0.10.0) the code doesn't notify, which is correct. To test it, I set the tray's remembered version in HKCU to 0.9.3 and restarted the tray. No notification appeared, and the tray never wrote its memory again: the key's last-write time stayed at the tray's start time through 3+ one-minute polls. This needs checking with a real version bump. | [150-updated-toast-4](shots/150-updated-toast-4.png) |
| 8 | Interim report: "a notification says it's ready and **Open report** opens it" | The notification says "Interim report ready. Click to open it." There is no **Open report** button, and the notification disappears after about 5 seconds. | [100-tray-interim-toast](shots/100-tray-interim-toast.png) |
| 9 | On failure: the error with **Close**. | The code labels the button **Finish** on failure (`setup_windows.go:640`). Not triggered live. | code |
| 10 | Folder-access question with Yes/No. | It has a third button, **Cancel**, which does nothing, plus two extra lines explaining Yes and No. | [100-folder-access-question](shots/100-folder-access-question.png) |
| 11 | Standalone ("reports on this computer only") | After switching this PC from collector to standalone, the old Linux sender `claude-code` still appears. It's in the tray ("2 settings to fix on claude-code"), in Status details, and the interim report is named `…_2-systems_interim`. Close to the spec, but worth a look. | [100-tray-menu](shots/100-tray-menu.png), [100-tray-status-details](shots/100-tray-status-details.png) |

### Wording and minor points

- **Welcome text** adds an extra paragraph, plus grey "Program folder / Settings and collected events" lines. These go beyond the spec's one sentence. See [100-01](shots/100-01-welcome-firstinstall.png).
- **Collector unreachable** wording: "Use it anyway (the data waits here until the collector can be reached)?". The spec has "Use it anyway? The data waits here…". The error text comes first. See [100-05d](shots/100-05d-use-anyway-dlg.png).
- **Tray status line** says "next report 9 Oct". The spec's example shows a weekday and time ("next report Wed 00:00").
- **Open latest report** is greyed out when there's no report in the folder. The spec doesn't mention a disabled state. See [100-tray-menu](shots/100-tray-menu.png).
- **Font:** Segoe UI is hard-coded rather than the system font (`internal/gui/window_windows.go:155`). It looks right on Windows 11.
- **Logo:** the header and tray use the GE Aerospace "GE" monogram (`internal/brand/logo.png`). The spec says "the Blackbox logo". I didn't change the design; please confirm this is intended.
- **Interim-report window** shows a greyed maximise box. See [150-tray-interim-window](shots/150-tray-interim-window.png).
- **"UAC declined" message** ends with a full stop and is also shown for any failure to start elevated.
- **Rollback** after a failed upgrade looks only for `<file>.old`. If `.old1` or `.old2` had to be used, the wrong file could be restored (`internal/install/program_windows.go:64-103`). Not triggered live.
- **Uninstall CI** never checks that uninstall itself removes the **Blackbox Status** task.

## What matches the spec

**Release and files**
- The release has the one setup file and no Windows zip.
- The setup file is windowed, and `blackbox.exe` is console.
- The installed `blackboxw.exe` is byte-identical to the setup file.

**Starting setup**
- `blackbox.exe` with no arguments at a real `cmd` prompt prints the usage.
- Started from Explorer or a pipe, it opens the setup window.

**UAC**
- Setup started non-elevated asks UAC.
- Declining shows "Blackbox setup needs administrator rights." and exits. See [uac-declined-100](shots/uac-declined-100.png).
- Approving opens the window elevated.

**Window**
- Real Win32 controls with visual styles.
- The client area is 640×480 at 100%, and the window measures 656×519 at 100% and 982×776 at 150%.
- It can't be resized, the layout scales cleanly at 100%, 150% and 200%, and nothing clips.
- White header band and Back / Next / Cancel.

**Page order** for each role, the three role descriptions, defaults carried over from the current settings, and Daily hiding the day picker.

**Reports-page checks**
- A relative path is refused. See [100-chk-relative](shots/100-chk-relative.png).
- A bad time is refused. See [100-chk-badtime](shots/100-chk-badtime.png).
- A missing folder is offered for creation "(administrators only)" with Yes/No; No leaves it uncreated. See [100-chk-create-folder](shots/100-chk-create-folder.png).
- An unwritable folder is refused with the reason. See [100-chk-unwritable](shots/100-chk-unwritable.png).

**Inbox page**
- The VirtualBox box with its accounts field.
- The share box.

**Collector page**
- The combo box with the account field.
- A masked password box (`ES_PASSWORD`).
- **Test connection** shows its result on the page.
- **Next** asks the "use it anyway" question.

**Collection page** has the three intervals and the tray box, ticked by default.

**Installing page**
- The marquee progress bar and the log.
- No report and no schedule change when settings already exist.
- **Open reports folder** and **Finish**; **Cancel** is greyed while it runs.

**Upgrade with the tray running**
- No locked files: `blackbox.exe.old` and `blackboxw.exe.old` were created and the new files put in place.
- The tray restarted itself on the new program and deleted the `.old` files.

**Programs and Features**
- **Modify** (`ModifyPath = blackboxw.exe setup`) opens the setup window. See [150-modify-from-programs](shots/150-modify-from-programs.png).

**Tray**
- **Blackbox Status** logon task: it started the tray at console logon, elevated, in the person's own session.
- One tray per person: starting it twice more didn't add an icon.
- Left-click opens the same menu.
- Amber dot when there are things to look at; the tooltip matches the spec.
- Menu items, order, separators and bold default are as specified. See [100](shots/100-tray-menu.png), [150](shots/150-tray-menu.png) and [200](shots/tray-menu-200.png).
- **Open latest report:** asks the folder-access question when the account can't read the folder. **Yes** grants only `DSK1\Austin:(OI)(CI)(RX)` on the reports folder (the data folder is untouched) and opens the report in a **non-elevated** Chrome. **Cancel** changes nothing.
- **Open all reports** opens the index.
- **Make an interim report…:** four choices, the default is "Since the last report", and the report is made in about 4 seconds. See [100-tray-interim-window](shots/100-tray-interim-window.png).
- **Collect now** runs the task and shows a notification. See [100-tray-collectnow](shots/100-tray-collectnow-corner.png).
- **Status details…** shows the same text as `blackbox status`.
- **Change settings…** opens setup elevated with no UAC prompt.
- **Close this icon** ends the tray, collection carries on, and the notification is correct. See [100-tray-close-toast](shots/100-tray-close-toast.png).

**Uninstall** (with the tray running, using the registry `UninstallString`) removed:
- both tasks;
- the running tray;
- `C:\Program Files\Blackbox`, including `blackboxw.exe` and the `.old` files;
- the Programs and Features entry.

It kept `C:\ProgramData\Blackbox`, the reports and `HKCU\Software\Blackbox`.

The first uninstall, while the PC was still a collector, also removed the `BlackboxInbox` share and the "Blackbox Senders" group. It kept `C:\BlackboxInbox`.

## State of the PC now

- **Blackbox is uninstalled.** The settings in `C:\ProgramData\Blackbox\blackbox.conf` are kept, but are now **standalone** with the default reports folder; before the test this PC was a collector with `report_dir = C:\IT\Blackbox` and `inbox = C:\BlackboxInbox`. The old reports in `C:\IT\Blackbox` and the `C:\BlackboxInbox` folder are untouched. The `BlackboxInbox` share is gone. The new `C:\ProgramData\Blackbox\reports` holds one interim report, and its ACL is back to administrators and SYSTEM only.
- **The Linux sender** (`claude-code`) can't deliver here until this PC is set up as a collector again.
- **Display scale** was set back to 100%.
- **`HKCU\Software\Blackbox`** has its original value back.
- **Test folders** I created were removed.
- **No audit policy or other system settings were changed.**
