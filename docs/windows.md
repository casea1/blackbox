# Windows guide

Supports Windows 11 and Windows Server 2025.

No other software is needed. Blackbox is a single self-contained program:
there is no .NET, Go or other runtime to install.

## Install

1. Download `Blackbox-Setup-<version>.exe` from
   [Releases](https://github.com/casea1/blackbox/releases/latest) and copy
   that one file to the system.
2. Double-click it and approve the administrator prompt.
3. Answer the questions in the setup window. Each page shows a default you
   can keep by clicking **Next**. For a single computer the pages are:

| Page | Asks |
|---|---|
| This computer | How will this computer's audit events be reviewed? On this computer, send to a collector, or this is the collector |
| Reports | Site name; daily, weekly or monthly; when each report is ready (default Wednesday 00:00); where reports are saved, with **Browse…** |
| Collection | How often events are collected (every 15 minutes is recommended), and whether to show the status icon to administrators |
| Ready to install | A summary of your answers, and **Install** |

The last page shows each step as it happens: the install, the audit
settings check, then the first report. When it is done, **Open report**
opens it.

The window asks exactly the same questions as `blackbox install` at a
command prompt, which still works and is what scripts use:

```
blackbox-<version>-windows-amd64.exe install --yes --site "Lab 3" --report-dir D:\AuditReports
```

**At a command prompt or over SSH, use `blackbox-<version>-windows-amd64.exe`**
(also on the release page): the same program as the setup file, without
the window. The setup file is a windowed program, so cmd.exe does not wait
for it and takes your answers itself ("'y' is not recognized…"). From an
elevated prompt:

```
blackbox-<version>-windows-amd64.exe install
```

asks the same questions as the window, and upgrades an installed Blackbox
the same way.

A run with `--yes` keeps the earlier answers you don't repeat. Giving only `--inbox` (or only `--send-to`) replaces the computer's earlier role: a former sender given `--inbox` becomes a collector.

For a PC with Linux VMs, or a LAN, see [Several computers](lan.md): the
other choices ask where the inbox is, or where to send.

Each answer is checked as you give it. A report folder must be a full path
that Blackbox can write to:

- **If the folder already exists,** its permissions are left exactly as
  they are.
- **If it exists but you can't write to it** (a local folder open only to
  a group such as auditors, with no access for Administrators), setup
  offers to give SYSTEM Modify access to it. The scheduled task runs as
  SYSTEM and writes the reports; no one else's access changes, and
  administrators still get none. Unattended installs do this without
  asking. The first report is then written by the scheduled task, not by
  setup.
- **If it doesn't exist,** Blackbox offers to create it, restricted to
  Administrators and SYSTEM.

Setup then:

- copies `blackbox.exe` (the command-line program) and `blackboxw.exe`
  (the same program for the setup window and the status icon, which opens
  no console) to `C:\Program Files\Blackbox\`
- creates `C:\ProgramData\Blackbox\`, readable only by Administrators and
  SYSTEM, which holds the settings, reports and collected events
- registers the scheduled task **Blackbox Audit Collection**, which runs as
  SYSTEM every 15 minutes (by default) and at startup, and catches up
  after the system has been off. Its repeating trigger starts in 2000, so
  its runs follow the clock even if the clock is corrected after install.
  Windows runs it once straight away when it is registered, so the first
  collection (and, on a collector or standalone computer, the first
  report) comes within a minute of installing
- adds **Blackbox** to Settings → Apps (and Programs and Features), with
  its version, so it can be inventoried and uninstalled like any other
  program
- on a collector or standalone computer, registers **Blackbox Status**,
  which shows the [status icon](#status-icon) to administrators
- checks the audit settings against the DISA STIG (Windows 11 or Windows
  Server 2025, whichever the computer is) and lists what is missing (it
  changes nothing)
- collects events and produces the first report. The first run reads the
  whole Security log, so it can take a few minutes.

## Changing settings later

Open **Settings → Apps**, find **Blackbox** and choose **Modify**, or pick
**Change settings…** on the status icon. The setup window opens with your
current settings filled in, so change only what you need.

**To upgrade,** double-click the newer `Blackbox-Setup-<version>.exe`. It
says which version is installed and lists your current settings; click
**Upgrade now, keep current settings** to upgrade in one click, or **Next**
to go through them. It doesn't move the report schedule. A collection running at that moment, or an open
status icon, doesn't block it. Setup then checks the new program starts,
and puts the previous one back if it doesn't. Installing or upgrading
(also `blackbox install --yes`) starts a collection straight away, as on
Linux.

To change a single setting from a script, use `blackbox config`:

```
blackbox config                                   (show the current settings)
blackbox config set report_dir D:\AuditReports    (checks the folder first)
blackbox config set report_every daily
```

New reports go to the new folder. Existing reports are not moved.

### Unattended installs (SCCM, Intune, GPO scripts)

Options skip the questions. Any setting not given keeps its current value,
or the default on a first install:

```
blackbox.exe install --yes --site "Lab 3" --report-dir D:\AuditReports
```

| Option | Meaning |
|---|---|
| `--yes` | Don't ask questions |
| `--site` | Name shown at the top of reports (`-` clears it) |
| `--report-every` | `daily`, `weekly` or `monthly` |
| `--report-dir` | Folder for reports (`default` for the standard location) |
| `--collect-every` | `1h`, `30m` or `15m` |
| `--no-first-report` | Skip the first report; it comes at the next scheduled run |

**Report folder on a network share:** the scheduled task runs as SYSTEM,
which reaches network shares as the computer account (`DOMAIN\COMPUTER$`).
Grant that account write access to the share and folder. On a workgroup
system with no domain, use a local folder.

## Console output

`blackbox` writes its messages in plain ASCII when its output is
redirected to a file or another program (`>`, `Out-File`,
`Start-Process -RedirectStandardOutput`), so Windows PowerShell 5.1 doesn't
turn dashes into `ΓÇö` in what you paste into a ticket. In a console window
it shows them as they are. Run it from an administrator prompt: its
settings and data are readable by Administrators only, and it says so if
it is refused.

## Status icon

On a collector or standalone computer, members of **Administrators** see a
Blackbox icon by the clock when they log on. It is started by the
scheduled task **Blackbox Status**, with full rights, so there is no UAC
prompt. Untick the box on the Collection page of setup to turn it off.

The icon is the Blackbox logo. Its menu's status line and the notifications
say how things are.

Click it for the menu:
- the status line: "Collecting every 15 minutes · last 14:05 · next report Wed 00:00", or what is wrong (what needs fixing on each system is in the report and `blackbox status`);
- **Open latest report** and **Open all reports**;
- **Make a manual report…**, for a chosen period (the schedule doesn't change);
- **Collect now**, with a notification when the run has finished;
- **Status details…**, the same as `blackbox status`;
- **Change settings…**;
- **Close this icon**.

When something needs looking at, the icon's tooltip ends "something to
look at: see Status details"; **Status details…** says what.

It shows a notification when a scheduled report is ready, when collection
stops, when a computer stops sending, when audit settings stop matching
the STIG, and after an upgrade. Each is shown once.

Reports open in your normal browser without administrator rights. The
default reports folder is readable only by administrators with full
rights. If your account can't open it, the icon asks before giving your
account read access to that folder. This is the same as Explorer's
**Continue** button. For a reports folder you chose, nothing is offered: the icon says your
account can't open it, and its access stays as whoever set it up decided.

## Where things are

| | |
|---|---|
| Program | `C:\Program Files\Blackbox\blackbox.exe` |
| Settings | `C:\ProgramData\Blackbox\blackbox.conf` ([reference](configuration.md)) |
| Reports | `C:\ProgramData\Blackbox\reports\` by default, or the folder you chose (open `index.html`) |
| Log of each run | `C:\ProgramData\Blackbox\blackbox.log` |
| Lock held by a run | `C:\ProgramData\Blackbox\blackbox.lock` (released when the run ends, even if it is ended in Task Manager; see [One run at a time](configuration.md#one-run-at-a-time)) |

## What Blackbox reads

| Event log | Used for |
|---|---|
| Security | Logons, failed logons, lockouts, admin logons, elevated programs, account and group changes, audit policy changes, log cleared, removable storage file access; audit events dropped (4612), LSA packages (4611/4614/4622), user rights (4704/4705), domain, Kerberos and trust policy (4739, 4713, 4706/4707/4716), weakened boot settings (4826), auditing settings on objects (4907), firewall rules, settings and service (4946–4950, 5024/5025/5030), code integrity (5038/6281), shares (5140, refused 5145), security registry keys (4657), permissions (4670), SID history (4765/4766), lock and unlock (4800/4801), files with auditing set (File System 4656/4663: refused access, writes and deletes). Every other Security event is listed as "Security event <ID>" on Other security, or counted when too frequent (see below). |
| System | Services installed, startup and shutdown, other logs cleared |
| OpenSSH/Operational | Only sshd's "Accepted … from <address>" line, to give an SSH logon its source address (when the OpenSSH server is installed) |
| Application | Software installed and removed (Windows Installer 1033/1034, 11707/11724) |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | Who changed a firewall rule or setting (2003, 2004/2097, 2006, 2033); merged with the Security log's firewall events |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational and RemoteConnectionManager/Operational | Remote Desktop sign-ins (21, 1149), disconnects and reconnects (24, 25), with the client address; merged with the Security log's |
| Microsoft-Windows-PrintService/Operational | Documents printed (307). Off by default; `check` shows it as optional |
| Microsoft-Windows-Partition/Diagnostic | USB storage make, model, serial and size (on by default) |
| Microsoft-Windows-Kernel-PnP/Configuration | First-time USB device setup |
| Microsoft-Windows-DriverFrameworks-UserMode/Operational | Extra USB detail (optional, off by default) |
| Microsoft-Windows-Windows Defender/Operational | Malware detections, protection turned off, settings changed and exclusions added (5007), changes blocked by Tamper Protection (5013) |
| Microsoft-Windows-PowerShell/Operational | Suspicious PowerShell scripts: clearing logs or weakening auditing, turning off Defender, downloading and running code, password-stealing tools, malware-scanning (AMSI) bypasses |

PowerShell records every script it runs (event 4104, Script Block
Logging), which on a managed computer is thousands a day. Blackbox reports
only the suspicious ones: those matching the list above (High), and those
PowerShell itself flags as suspicious (Medium), with the script's name or
path and the word that got it flagged. Commands Windows generates for its
own modules (for example Defender's `MSFT_MpScan`, which PowerShell flags
because of words like "Scan") are not reported. The rest are counted but
not listed, and stay in the original log saved with each report. A large
script is recorded in several parts; matching parts of one script are
shown as one row. Windows PowerShell 5.1 is read; PowerShell 7 writes to a
separate log that Blackbox does not read yet.

**Other Security-log events.** Nothing the audit policy records is
silently dropped. A Security event Blackbox has no translation for is a
row on Other security ("Security event 5376 (Credential Manager
credentials backed up) by jsmith"). The frequent ones (Filtering Platform
connections 5156–5158, handle events 4658/4690, privileged service calls
4673/4674, group membership 4627, Kerberos tickets 4768/4769 and similar)
are counted, not listed: Audit health lists every such ID with its count
and where to find it, and the original logs are in each report's archive.
In each system's settings on Audit health, an audit subcategory whose
events Blackbox only counts or lists untranslated says so (for example
Sensitive Privilege Use, Handle Manipulation).

**Watching Blackbox itself (AU-9).** Changes to Blackbox are reported
High: `blackbox config set` for `exclude_users`, `exclude_processes`,
`retention_days`, `report_dir`, `send_to` or `inbox` (other settings
Medium), `blackbox uninstall`, `schtasks` or PowerShell disabling or
deleting the **Blackbox Audit Collection** task (4699/4701), and edits to
`C:\ProgramData\Blackbox` by anything other than Blackbox. Creating or
updating its task (an install or upgrade) is Medium. Edits to the folder
are only recorded if it has an auditing entry, which Blackbox does not
set itself (it never changes audit settings). To add one, as an
administrator (`blackbox.exe check` shows whether it is there, and Audit
health lists it as "Blackbox's own folder audited"):

```powershell
$acl = Get-Acl C:\ProgramData\Blackbox -Audit
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone",
  "Write,Delete,ChangePermissions,TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Success,Failure")
$acl.AddAuditRule($rule)
Set-Acl C:\ProgramData\Blackbox $acl
```

This needs File System auditing (success and failure). The Server 2025
STIG requires it (WN25-AU-000581/582); the Windows 11 STIG no longer
does (see Audit settings below), so on Windows 11 `blackbox check` asks
for it as Blackbox's advice.

Two kinds of writes to that folder are Blackbox's own and are not rows:
the original-log pieces each collection exports (`archive-pieces\000001\Security.evtx`
and so on), which `wevtutil` writes through the Event Log service
(`svchost.exe`) in the name of whoever ran Blackbox, when a Blackbox run
on that computer covers their time; and the installer's writes when
Blackbox recorded that install or upgrade. The commands the installer
runs (its Uninstall entry, the inbox share and its permissions, the
scheduled task) are listed on that install or upgrade row instead of as
rows of their own. Anything else changing or deleting files there is
still High.

Blackbox also **records its own changes** (A15): when `blackbox config
set`, setup or an upgrade actually writes a setting, it adds a row of its
own saying who (the account that ran it), which setting, and the value before and after,
High for `exclude_users`, `exclude_processes`, `retention_days`,
`report_dir`, `send_to`, `inbox` and `scap_results` (others Medium). It
writes the same record to the Application log, source **Blackbox**, event ID 100, so a copy exists outside its own folder.
A scheduled report found missing or changed afterwards ("REPORT MISSING",
"REPORT CHANGED") is written there too, once per report, as a warning
with event ID 101 (LEDGER4). An administrator's decision about a
sender's signing key on a collector (`blackbox senders approve`, `rekey`
or `forget`) is written there as event ID 102, with who did it and why
(DESIGN1).
Installing, upgrading and removing Blackbox are recorded the same way. A
`config set` command line with no matching record (refused, answered
"no", failed, or the value was already set) is shown as "tried to change
… (not applied)".
This is how a `config set` is reported on Windows: the command line
alone needs Process Creation auditing with command lines, which a fresh
server does not have.

A command that deletes Blackbox's files (`del`, `Remove-Item`, `rd` of
something under `C:\ProgramData\Blackbox`) is High, "deleted Blackbox's
files", when a record shows it worked. When the File System audit records of the same process (4656 or
4663, audit failure, the same process ID as the command's 4688) show the
delete refused, and none shows a file deleted, the row says "tried to
delete Blackbox's files (refused)", Medium, with the refused files in its
details, and it is not counted as a removal (DET1). This needs failure
auditing on the folder, as above. With no File System record of the
delete at all (the folder has no auditing entry), the row is "ran del on
Blackbox's files", Medium, whether it worked isn't recorded, unless a
file it names is gone at the next Blackbox run (DET1b).

Script Block Logging must be turned on by Group Policy: Administrative
Templates > Windows Components > Windows PowerShell > Turn on PowerShell
Script Block Logging (STIG WN11-CC-000326 on Windows 11, WN25-CC-000460 on
Server 2025; `blackbox.exe check` shows whether it is on). Without it,
only the scripts PowerShell flags itself are recorded.

## Audit settings

A report can only show what Windows records. To compare the system with
the STIG, run:

```
blackbox.exe check
```

Blackbox picks the STIG from the kind of Windows:

| Computer | Compared with |
|---|---|
| Windows 11 (workstations) | Windows 11 STIG V2R11 (5 October 2026) |
| Windows Server (any version) | Windows Server 2025 STIG V1R1 |

Each setting shows its STIG rule ID (for example `WN11-AU-000505`). Each
item that falls short is listed with the report section it affects and the
exact command or Group Policy setting that fixes it. Blackbox never changes
settings itself. The report's **Audit health** view shows the same check,
and which STIG it used.

What is checked:

- **Advanced audit policy**: every subcategory the STIG requires, with
  success and/or failure exactly as the STIG says, including Registry
  (success and failure) and Process Creation failures (Windows 11).
  Server 2025 also requires File System and Handle Manipulation (success
  and failure).
- **Blackbox's advice on Windows 11: File System (success and failure)
  and Handle Manipulation success.** The Windows 11 STIG had these
  (WN11-AU-000582, 000581 and 000584) up to V2R7, but V2R8 (10 July 2026)
  and V2R11 (5 October 2026) do not; Handle Manipulation failure
  (WN11-AU-000583) is still a rule. Blackbox still asks for them, marked
  "Blackbox's advice" rather than a STIG ID: File System success is what
  records changes to Blackbox's own folder, and Server 2025 requires
  them. They are not counted in "Systems matching STIG". Checked on
  8 October 2026 against the stigaview.com copy of the DISA Windows 11
  STIG releases (V2R7, V2R8 and V2R11 rule lists); the DISA library at
  cyber.mil could not be read by script that day, so check your own copy
  of the current release.
- **Security log size**:
  - Windows 11 (WN11-AU-000505, V2R8 to V2R11): it must hold at least a week of
    events, and the STIG's check fails a maximum size below
    **5,120,000 KB** (about 5 GB; earlier releases said 1,024,000 KB).
    Blackbox fails it below that size. The 20 MB default is far too small
    with File System auditing: one Windows Update run
    overwrote it many times within an hour in testing (94,565 events
    lost).
  - Windows Server 2025 (WN25-CC-000280): at least 196,608 KB.
- **System and Application log sizes**: at least 32,768 KB.
- **The other logs Blackbox reads** (not STIG rules; a shortfall is a
  warning, LOG1):
  - the **PowerShell log** (Microsoft-Windows-PowerShell/Operational):
    at least 1 GB, or enough for a week at its rate (up to 2 GB). Once
    a collection has seen a log turn over, `check` gives the size
    `blackbox status` gives, from that rate. Windows
    gives it 15 MB. With script block logging (WN11-CC-000326), and
    Windows' own logging of "suspicious" script blocks, each event is
    often 30 KB or more, so 15 MB holds a few hundred: any administrator
    session or management script (SCCM, Intune, Ansible, WinRM, SSH) can
    turn it over in minutes, faster than any collection interval. On the
    Windows 11 test VM it held 9 minutes and lost 447 events between two
    collections 15 minutes apart; the Server 2025 VM's was full at 556
    records;
  - the others (Defender, Firewall, Remote Desktop, Print, USB) only when
    they hold less than a week.

  `blackbox status` gives the same capped size when one of these logs
  loses events. Group Policy has no setting for these logs under Event Log Service.
  `blackbox check` gives the command, for example (as administrator):

  ```
  wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1073741824
  ```

  To set it on many computers, use a Group Policy Preferences registry
  item: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational`,
  value `MaxSize` (REG_DWORD, bytes), which is what `wevtutil sl /ms:`
  sets.
- **Command line in process creation events.** Without it, elevated
  programs are listed by name only.
- **Audit: Force audit policy subcategory settings.** Without it, the
  advanced audit policy can be ignored.
- **PowerShell script block logging**, and on Windows 11 **PowerShell
  transcription**.
- **Windows Time** running and synchronising (from the domain, or an NTP
  server), so event times from different computers line up (AU-8). This
  is a basic check and Blackbox's advice, not a STIG rule.
- **USB logs** (Partition/Diagnostic and Kernel-PnP/Configuration),
  which the report needs for device details, and the **PowerShell log**
  (on by default; shown for information, never as a failure). These are
  not STIG rules: Blackbox's advice.
- **Defender**: real-time protection on and definitions under 30 days
  old. Blackbox's advice, not STIG rules.

Every check without a STIG ID is Blackbox's advice. The report words it
"Blackbox recommends", not "the STIG requires", leaves it out of
"Systems matching STIG" and counts it on its own ("Blackbox's advice").

On a server, Other Logon/Logoff Events auditing is not a STIG rule, but
the report needs it for Remote Desktop sessions. It is listed as
recommended, not as a failure.

File System, Handle Manipulation and Registry auditing record far more
events where files and keys have auditing (SACLs) set. That is why the STIG
asks for a much larger Security log. Blackbox reads these events but
reports only what matters, so the report itself does not grow much.

## Reporting on exported logs

Export events on any Windows machine, then produce a report on any OS:

```
wevtutil qe Security /f:xml /c:20000 > security.xml
wevtutil qe System /f:xml /c:5000 > system.xml
blackbox report --xml security.xml --xml system.xml
```

On Windows, saved `.evtx` files work too: `blackbox report --evtx Security.evtx`.

## Uninstall

Use **Settings → Apps → Blackbox → Uninstall**, or run
`"C:\Program Files\Blackbox\blackbox.exe" uninstall` as an administrator.
This removes the scheduled tasks, the status icon, the program and the
Apps entry. Reports, settings and collected events are kept.
