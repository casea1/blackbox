# Windows setup and tray: locked design

Agreed with the product owner on 2 Oct 2026. It follows the same rules as `SPEC.md`: **build to this document**. Don't add, drop or rearrange a page, menu item or behaviour without asking first.

## Decisions

| Question | Decision |
|---|---|
| What is carried to a new PC or for an upgrade | **One file:** `Blackbox-Setup-<version>.exe`. No zip to extract and no `.cmd` to run. |
| Built with | **Go only, standard library.** The window and the tray are plain Windows controls drawn through the Windows API. No C#, no Inno Setup, no second codebase. |
| Which computers get the tray | **Collector or standalone computers only.** It is never installed on a sender. |
| Who sees the tray | **Members of the local Administrators group only.** |
| Code signing | **Optional.** No application control (AppLocker/WDAC) blocks unsigned programs where Blackbox runs. When a certificate is set in the release workflow's secrets, the release signs the setup file and the console program it carries (A10, 3 Oct 2026); without one it is unsigned. |
| Linux | **Unchanged:** `sudo ./install.sh` or `sudo ./blackbox install`, with no window. |

## Files

The release publishes `Blackbox-Setup-<version>.exe` in place of the Windows zip, alongside the Linux tarballs and `SHA256SUMS`.

The setup file is `blackbox.exe` with its Windows subsystem set to "windowed", so double-clicking it opens no console. A release's setup file also carries the console `blackbox.exe` (signed, when the release is), which it installs unchanged; it installs itself as `blackboxw.exe` (A10). Setup installs two copies of the same program:

| File | Kind | Used for |
|---|---|---|
| `C:\Program Files\Blackbox\blackbox.exe` | console | Command line and the scheduled collection task. Unchanged. |
| `C:\Program Files\Blackbox\blackboxw.exe` | windowed | The setup window and the tray, so neither opens a console. |

`blackbox.exe` double-clicked in Explorer also opens the setup window, with its console hidden. Typed at a prompt with no command, it prints the usage as today.

- **Scripted installs** still work: `Blackbox-Setup-<version>.exe install --yes …` (use `start /wait` from cmd), or the installed `blackbox.exe install …`.
- **New commands:** `blackbox setup` opens the setup window; `blackbox tray` runs the tray.
- **The console setup** (`blackbox install` at a prompt) asks the same questions as the window, including the new tray question, and keeps working exactly as before.
- **The flag** `--tray=false` leaves the tray out of a scripted install.

## Setup window

Standard Windows controls with the Windows visual style and the system font. The layout follows the screen's DPI.

- **Size:** about 640 × 480 at 100% scale. It cannot be resized.
- **Header band:** white, with the logo (the GE Aerospace monogram for now, as in the reports), a page title and one line of explanation.
- **Bottom bar:** **Back**, **Next**, **Cancel**.

If setup isn't running with administrator rights, it asks Windows for them (the UAC prompt) and restarts itself elevated. If the prompt is declined, it says "Blackbox setup needs administrator rights" and exits.

The pages ask exactly the console setup's questions, in the same order, with the same defaults and checks. The checks are shared code, so the two can't drift apart.

1. **Welcome.**
   - First install: "Blackbox <version> will be installed on this computer."
   - Upgrade: "Blackbox <installed version> is installed. This will upgrade it to <version>. Your current settings are kept and shown on the next pages."
   - Same version already installed (from **Change settings…** or **Modify**): "Blackbox <version> is installed. Change any settings on the next pages, then click Apply."
   - A first install also says in a short paragraph what Blackbox does, and lists the program and data folders in grey (owner decision, 3 Oct 2026).
2. **This computer.** How will this computer's audit events be reviewed? Three radio buttons, each with the console setup's description:
   - on this computer;
   - send to a collector;
   - this is the collector.
3. **Reports** (standalone and collector only).
   - Site or system name.
   - How often: Daily / Weekly / Monthly.
   - When each report is ready: a day (weekly only) and a time.
   - Where reports are saved: a folder with a **Browse…** button.

   The same checks as the console run on **Next**:
   - a full path is required;
   - a folder that doesn't exist yet is offered for creation (Yes/No), restricted to administrators;
   - a folder Blackbox can't write to is refused, with the reason.
4. **Inbox** (collector only).
   - The inbox folder, with **Browse…**.
   - Windows: ☐ Virtual machines on this PC send to it (VirtualBox shared folder), and the Windows account(s) that run VirtualBox.
   - ☐ Share it on the network as `BlackboxInbox`.
5. **Collector** (sender only).
   - The collector's inbox, with any inbox already found offered in the list.
   - The account on the collector, and its password (hidden as typed).
   - A **Test connection** button that shows the result on the page.

   On **Next** the connection is tested. If the collector can't be reached, setup asks the console's question: "Use it anyway? The data waits here until the collector can be reached."
6. **Collection.** How often events are collected:
   - every hour (recommended);
   - every 30 minutes;
   - every 15 minutes;
   - the current setting, if it is none of these.

   On a collector or standalone computer this page also has ☑ **Show Blackbox's status in the notification area for administrators** (on by default).
7. **Summary.** The console's summary lines, and an **Install** button (**Apply** when already installed).
8. **Installing.**
   - A progress bar and a read-only box showing the same lines the console prints: the install steps, the audit-settings check, then the first report or first send. This keeps the existing rule that an upgrade doesn't produce a report or move the schedule.
   - When finished: "Done" with **Open report** (when one was made), **Open reports folder** (collector or standalone) and **Finish**.
   - On failure: the error in plain words, with **Close**.

**Cancel** before the Installing page changes nothing. It asks "Cancel Blackbox setup? Nothing has been changed."

## Upgrades

- **No locked files.** Setup renames the running program files out of the way (`blackbox.exe.old`) and puts the new ones in place. Windows allows a running program to be renamed, so neither a scheduled collection in progress nor the tray blocks an upgrade. Old files are deleted at the next start.
- **Safety check.** After copying, setup runs the installed `blackbox.exe version`. If it doesn't answer with the new version, setup puts the previous files back and says the upgrade was undone.
- **Programs and Features.** The entry gets a **Modify** button that opens the setup window, to change settings later. **Uninstall** works as today.

## Tray

- **Starting it.** A scheduled task, **Blackbox Status**, starts `blackboxw.exe tray` when any member of Administrators logs on, with highest privileges. There is no UAC prompt, because the task was registered by an administrator. It runs in that person's session, so only administrators get it. A task can start a program with a hidden show mode, which Windows applies to the program's first `ShowWindow`; the icon spends it on its own hidden window when it starts, and each dialog shows itself again if it is still hidden, so every menu item opens on the first click (TRAY1).
- **Why elevated.** Blackbox's data folder is readable only by administrators with full rights, and the tray needs it for **Collect now** and **Make an interim report**.
- **One per person.** Only one tray runs per logged-on person. Closing it doesn't affect collection; it comes back at the next logon.
- **Where it's installed.**
  - Only when the role is collector or standalone and the box on the Collection page is ticked.
  - Changing the role to sender, unticking the box, or uninstalling removes the task and ends any running trays.
- **After an upgrade.** The tray notices the new program, restarts itself and shows "Blackbox updated to <version>".

### What it shows

The tray reads the same status as `blackbox status` directly, once a minute.

| Icon | Means |
|---|---|
| Logo, green dot | Collecting on schedule; nothing needs attention |
| Logo, amber dot | Something to look at: audit settings to fix, antivirus definitions out of date (Defender, or ClamAV on Linux), events lost because a log filled up before it was collected, files set aside in the inbox, or a sender that has gone quiet |
| Logo, red dot | Collection has stopped (no run for twice the interval plus 15 minutes), the last run failed, or the last collection found auditing off on a system (owner request, 3 Oct 2026, L3) |
| Logo, grey | Status can't be read |

The tooltip gives the state in a few words, e.g. "Blackbox: collecting · last 14:05".

### Menu (right-click; left-click opens the same menu)

- Status line, not clickable: "Collecting every hour · last 14:05 · next report Wed 00:00", or what is wrong.
- When there is something to look at, one line per item, not clickable: e.g. "Audit settings: 2 to fix on WS-13", "WS-09 has not sent since 29 Sep".
- **Open latest report** (bold: the default; greyed out when there is no report yet).
- **Open all reports** (the reports `index.html`).
- **Make an interim report…** opens a small window. Choices:
  - since the last report (default);
  - last 7 days;
  - last 30 days;
  - last 90 days.

  **Make report** produces it in the background, then a notification says it's ready; clicking the notification opens it (owner decision, 3 Oct 2026: Windows notifications from the tray have no buttons).
- **Collect now:** runs the scheduled task now.
- **Status details…** opens a window with the text of `blackbox status`.
- **Change settings…** opens the setup window.
- **Close this icon:** the notification says it comes back at the next logon.

### Notifications

Each is shown once per occurrence, remembered per person in `HKCU\Software\Blackbox`:

- a scheduled report is ready ("Weekly report ready: 2 detections, 1 high");
- collection has stopped, or the last run failed;
- auditing is off on a system (auditd stopped, or kernel auditing off);
- a sender has gone quiet (collector);
- audit settings went from matching the STIG to not matching;
- events were lost because a log filled up before it was collected (once per report period);
- Blackbox was updated.

Several found together are shown one after another, not on top of each other.

### Opening reports

- **Browser rights.** Reports are opened in the person's normal browser without administrator rights, handed over through Explorer.
- **Folder access.** The default reports folder is readable only by administrators with full rights, like the data folder. If the person's own account can't read the report, the tray asks: "Your account can't open reports in <folder> without administrator rights. Give <account> read access to this folder? (This is what Explorer's Continue button does.)"
  - **Yes** grants read access to that one account.
  - **No** changes nothing (owner decision, 3 Oct 2026: Explorer can't open a folder the account can't read, so offering it was a dead end).
  - **Nothing is changed without asking.**

## Uninstall

Uninstalling also removes:
- the **Blackbox Status** task;
- `blackboxw.exe`;
- any `.old` files.

It also ends running trays. Reports, settings and collected data are kept, as today.

## Testing

- **Unit tests (all platforms):**
  - switching the program between console and windowed (byte-exact against `debug/pe`);
  - the tray's icon state and notification rules from canned status;
  - the logon task definition;
  - the page order for each role;
  - the shared answer checks, used by both the console and the window.
- **Windows CI:**
  - build the setup file and confirm it is windowed;
  - a scripted install with the tray creates `blackboxw.exe` and the **Blackbox Status** task, and uninstall removes them;
  - `blackbox setup --selftest` creates and destroys every page of the window off screen.
