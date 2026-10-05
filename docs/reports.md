# Reports

## Collection and report periods

Blackbox **collects** every 15 minutes (by default) and **reports** on the schedule you
choose:

- **Collecting:** each run copies only the security-relevant events out of
  the logs and remembers where it stopped. Events are captured before a
  busy log overwrites them, and the copy stays small.
- **Reporting:**
  - The first report is produced at install time. Installing again (to
    upgrade or change settings) does not produce one, so the schedule is
    kept.
  - After that, each report ends at the time set by `report_at` (default
    `Wednesday 00:00`: a weekly report covers the week up to Tuesday night,
    ready for Wednesday morning). Daily reports end at that time each day,
    monthly ones on the 1st.
  - Each report starts where the previous one ended, so every event
    appears in exactly one report.
  - Events that happened earlier but were collected late, for example
    because the system was off, go into the next report marked **Late**.

To produce a report now, run `blackbox report`. This is an **interim**
report: it covers the time since the last scheduled report, is marked
*Interim* in the report and on the list of reports, and does not change the
schedule. The next scheduled report still covers its whole period. Interim
reports do not include the original logs; those go with the scheduled
report.

**A report for any period.** `blackbox report` run by hand asks which
period to cover: press Enter for the time since the last report, type a
number of days (`30`), a start date (`2026-09-01`), or a start and end date
(`2026-09-01 2026-09-15`). The same as options:

```
blackbox report --days 30
blackbox report --from 2026-09-01
blackbox report --from 2026-09-01 --to 2026-09-15
```

The events come from Blackbox's own copy, which reaches back to the oldest
events in each log when it was installed and is kept for
`retention_days` (for good by default). For any time before that copy
starts, Blackbox reads this computer's event logs (or Linux logs) as far
back as they still go. The report says what it covers and where the
earliest available event is. It is saved with `_range` in its folder name,
listed as Interim, and does not change the schedule. On a collector it
covers every system's collected events; only the collector's own logs can
be read further back.

With exported log files (`--xml`, `--evtx`, `--audit`, `--syslog`), the
same options keep only the events in that period:
`blackbox report --audit audit.log --from 2026-09-01 --to 2026-09-15`.

If you change `report_at`, the next report ends at the new time and
covers the time since the last report (so it may be shorter or longer
than usual once).

## Severities

| Severity | Meaning | Examples |
|---|---|---|
| **High** | Review now | Log cleared, auditing stopped, user added to an admin group, audit tampering command, malware detected, USB device never seen before, USB network adapter |
| **Medium** | Review | Account created or deleted, password reset, USB storage connected, file written to USB, service installed, time changed, refused sudo command |
| **Low** | Routine but relevant | Single failed logon, sudo command, admin logon |
| **Info** | Context | Logons, logoffs, startup and shutdown |

Only High and Medium are flagged in the report: the event tables show
the severity for those and a dash for the rest. Every event is still
listed, whatever its severity.

## Detections

Detections are patterns across several events: steps that are ordinary on
their own but worth a look together, and things done for the first time.
They are worked out from events Blackbox already collects, so they add
nothing to what computers collect, store or send. They are also listed in
each report's `summary.json`.

| Detection | Severity | When |
|---|---|---|
| Possible password guessing | High | 5 or more failed logons for one account on one computer within 15 minutes |
| One source tried several accounts | High | Failures for 3 or more accounts from one address within 15 minutes |
| Same account failing on several computers | High | Failed logons for one account on 3 or more computers within 30 minutes (a collector sees every computer) |
| Possible covering of tracks | High | An account created, someone added to a privileged group, or sudo rules changed, then within 24 hours on the same computer a log cleared or altered, auditing stopped, an audit rule added, removed or refused, auditing on an object changed, anti-malware turned off or an exclusion added, the firewall stopped, or Blackbox stopped, removed or its exclusions or retention changed, by a person |
| Account created and deleted within a day | High | The same account created and deleted on one computer within 24 hours |
| Auditing was switched off | High | The audit service stopped by a person, with how long it stayed off |
| Successful logon after failures | Medium | 3 or more failures, then a success, within 30 minutes |
| New USB device, then administrator activity | Medium | Administrator rights used within 30 minutes of a USB device never seen before |
| Administrator activity outside working hours | Medium | Needs `working_hours` in the [settings](configuration.md); one detection per person, computer and day |
| First logon to this computer | Medium | A person logs on (at the computer, by Remote Desktop or SSH) to a computer they have not logged on to before |
| First use of administrator rights | Medium | A person uses administrator rights on a computer for the first time |
| First logon from this address | Medium | A logon to a computer from a network address not seen before |

**Across reports.** Each report also looks at the day before its period,
so a pattern that starts at the end of one report and finishes in the
next is still detected. It is reported once, in the report where it
finishes.

**First times.** Blackbox remembers who has logged on to each computer,
who has used administrator rights on it, and the addresses logons came
from. A computer's first report only learns this, and says so, so that
installing Blackbox does not flag everyone. Something not seen for a year
counts as new again. Service and computer accounts, and SYSTEM, are left
out.

**One row per action.** Windows and Linux often record one action more
than once (a failed logon as 4625 and 4776; a service install as 7045 and
4697; a USB stick in up to four logs). These are merged into one row, the
most informative, and a service is shown with both of its names. Two
records of the *same* kind are two actions: five failed logons in one
second are five rows, so fast password guessing is detected. Removing a
deleted account from its primary group ("None" or "Domain Users") is not
shown as a separate change.

**Linux sign-ins and restarts.** One SSH sign-in or sign-out is one row,
even when it is recorded twice (two audit login records, or the same
line read from two logs). The audit service stopping during a planned
restart or shutdown (`reboot`, `shutdown`, `systemctl poweroff`, or a
shutdown record within minutes) is shown as routine, not as auditing
being switched off. When `systemctl stop auditd` (or `service auditd
stop`, `pkill auditd`) was run just before, the stop is shown as done by
the person who ran it: systemd sends the signal, so auditd's own record
names no one.

**Refused audit changes (Linux).** With the rules locked (`-e 2`, as the
STIG requires) the kernel refuses `auditctl -e 0`, `-D` and rule changes,
and records the refusal. Those rows say "tried to turn off auditing;
refused because the audit rules are locked … Auditing stayed on" (High
for turning auditing off, Medium for rule changes). They are never shown
as auditing being off.

**SSH failed logons (Linux).** OpenSSH 9.8 and later split the server
into `sshd`, `sshd-session` and `sshd-auth`; they are all treated as
`sshd`, so one attempt is one row. For a name that doesn't exist, sshd
records only "(invalid user)": the name tried is taken from the password
check of the same attempt, and every try says "the user name does not
exist", not "wrong password". Attempts from the computer itself (`::1`,
`127.0.0.1`) are shown as from `localhost`, so several accounts tried
from it is still detected.

**Login scripts (Linux).** At each SSH sign-in, `pam_motd` runs the login
message scripts in `/etc/update-motd.d` as root, and a root login shell
(`sudo -i`, `su -`) runs `/etc/profile.d` and the `.bashrc` scripts.
Each is one Info row ("The login message scripts ran as root when jsmith
logged on"), not a "ran as root" row per command. Only commands run as
root in that session before it starts (login message), or the usual
profile commands (`locale-check`, `id`, `dircolors` and so on) in the
first 3 seconds of a root shell, are folded in; anything else the person
runs is listed as usual. A change to the scripts themselves is a file
change, reported when the audit rules watch those folders.

**Mounts (Linux).** A disk mounted from the command line (`/dev/…`,
`UUID=`, `LABEL=`) is removable media (Medium). Memory and system
filesystems (`tmpfs`, `proc`, `overlay` …), bind and move mounts and
remounts are not; network shares (`nfs`, `cifs`, `sshfs`) are Low,
"mounted a network share".

**Auditing off at collection (Linux).** Each collection checks that the
audit service is running (`systemctl is-active auditd`) and that kernel
auditing is on (`auditctl -s`). If not, the computer is red: "Auditing
off" on Systems, an "Auditing is off" card on Audit health, a line in
`blackbox status` (also in a collector's list of systems) and a red
status icon with a notification.

**Computer accounts.** An account whose name ends in `$` is treated as a
computer account, and its routine activity is left out, only when it is
this computer's own account or comes from a domain. A local account named
like one (for example `helper$`) is always shown.

**Windows' own housekeeping.** The firewall rules Windows registers for
its built-in apps and services (app packages such as `@{Microsoft.…}`,
WinDefend's rules), changed by the Windows Firewall service (by name or by
its SID) or SYSTEM, are one Info row per computer and day with the counts;
rules changed by people keep their own rows. A firewall rule with no name
is shown by its rule ID. Defender's own bookkeeping in its settings
(signature and scan state, 5007 events) is one Info row per computer and
day; changes to exclusions, real-time protection, any `Disable…` switch,
tamper protection and Defender policy keep their own rows.
`DisableBmNetworkSensor` turned on outside Policies is Low, with a note.
Windows setup's own activity (the `defaultuser0` account the out-of-box
setup uses, and events recorded under the setup PC name `MINWINPC`) is one
Info "Windows setup" row per computer and day, and is never paired with
other changes as covering tracks. Blackbox's own writes to its data folder
and the programs Blackbox starts (`wevtutil`, `auditpol` and so on) are
left out. Deleting a report is one High row per report, not one per file.
Logon rights given or taken away (4717/4718) are a Medium sentence when a
person did it, and left out when Windows grants them itself. A 5038 (a
system file whose signature doesn't match) on a Microsoft Defender
platform file stays High, with a note: Windows often logs this while
Defender updates its platform, and the row says how to tell. PowerShell module code that
Windows generates (CDXML modules such as the firewall's
`Get-NetFirewallRule`, in every part of a long script) is not flagged.
OpenSSH for Windows' per-connection account `VIRTUAL USERS\sshd_<pid>` is
not a person. An account "renamed" to its own name and a new account
joining its default primary group (None) during Windows setup are left
out. Events recorded under a computer's name from before setup renamed
it are shown on that computer, with a "Recorded under its former name"
detail. On Linux, the temporary account files `groupadd` and the other
account tools write (`/etc/group+` and so on) and Blackbox's own writes
in its data folder are not rows of their own; the account change is.

**Hidden PowerShell.** PowerShell started with two or more of a hidden
window, a bypassed execution policy, no prompts (`-NonInteractive`) and an
encoded command is flagged Medium, whatever the script does: that is how
scripts are run unseen. A command that clears logs or changes auditing is
High however it is written, including with the program's path in quotes.

**Process starts.** Programs started with administrator rights are
listed. Programs a standard user starts are not, to keep reports
readable; their logons and anything they change still are.

**Nothing dropped silently.** A Windows Security-log event Blackbox has
no translation for is listed on Other security as "Security event <ID>";
the very frequent ones are counted instead. Audit health lists them all
with their counts, and marks the audit subcategories whose events are
only counted. On Linux, a record of any keyed audit rule Blackbox has no
translation for (your site's own rules included) is an Info row naming
the rule. See the [Windows](windows.md#what-blackbox-reads) and
[Linux](linux.md#set-up-auditd) guides.

**When the clock is wrong.** Each report covers what was collected since
the previous one, in the order it was collected, so changing the clock
can't keep an event out of every report. A period never starts after it
ends. When the clock was moved back (a recorded collection time is now in
the future, or Windows logged the time being set back, event 4616),
the report has the High detection **The clock was moved back**,
`blackbox status` says so and exits with code 4, and on Windows the
collection task is registered again so its next run follows the corrected
clock. Events recorded while the clock was ahead are shown in the next
report, not held back until the clock catches up.

**Exclusions.** `exclude_users` and `exclude_processes` leave out routine
activity only. Failed logons against an excluded account, changes to it,
log clears and audit changes by it, and anything of Medium severity or
above are always shown. An entry with a domain (`CORP\svc_backup`)
matches that account only; one without matches the local account. The
Overview and Audit health say how many events were left out, and by whom.

## Original logs

Reports show what Blackbox found in the logs. The original logs are kept
too, for an assessor or an investigation, because the report's own event
lists and `events.zip` hold only the security-relevant events, translated.

Each report's folder holds the original logs it was made from, unaltered:
one zip per computer, `logs-COMPUTER.zip`, covering the report's period.

| Computer | What is in the zip | Open it with |
|---|---|---|
| Windows | `Security.evtx`, `System.evtx`, and the USB, Defender, device and PowerShell (`Microsoft-Windows-PowerShell-Operational.evtx`, every script block, not only the ones reported) logs, as `.evtx` files | Event Viewer (Open Saved Log), or `Get-WinEvent -Path` |
| Linux | `audit.log`: the audit records, in their original format | `ausearch -if audit.log`, or `aureport -if audit.log` |
| Linux | `syslog`/`messages` and `auth.log`/`secure`: the lines for the period (or `journal.log` from the systemd journal when there are no log files) | Any text editor |

Inside, there is a folder for each day, named for the time it covers (in
UTC), with that day's logs and an `archive.json` listing each file's
SHA-256. The zip's own SHA-256 is in the report's `manifest.sha256`, so
`blackbox verify` checks it with the rest of the report.

**How it works.** Once a day each computer saves its logs since the last
save, so nothing rolls over before the report is made. The first save
reaches back a week. When a report is made, the computer saves its logs up
to the end of the period, then the saved days go into the report's folder.
It works the same on a standalone computer and on a collector.

A computer that sends to a collector delivers its daily saves with its
events. The collector checks every file against its hash when it arrives;
a damaged or altered zip is set aside in the inbox's `rejected` folder. A
day's logs go into the report whose period its save ends in, so a
computer that was off catches up in the next report.

The **Original logs** page lists each computer's zip with its size and
SHA-256, checked against the hash recorded when the zip was made, and
shows what is inside each one. A computer with no logs for the period is
listed first, as Missing.
They are also listed in `summary.json`. The zips are removed with their
reports after `retention_days`.

Expect a few MB a day per Windows computer (much less for Linux),
compressed. It depends on how busy the Security log is.

## STIG compliance (SCAP)

An assessor asks two things: is what the STIG audits reviewed, and is the
system configured to the STIG? The report answers the second from the
SCAP scans you already run, DISA SCC on Windows or OpenSCAP on Linux.
Blackbox **reads** their results; it never runs a scan, and never changes
a setting.

**Where results come from.** Put the result files (SCC's
`*_XCCDF-Results_*.xml`, or OpenSCAP's `--results` or `--results-arf`
files) in the `scap` folder in Blackbox's data folder, or set
`scap_results` to the folder your scanner writes to (subfolders are
searched, so SCC's `Sessions\<date>\Results\SCAP\XML` layout works).
A sender sends its own results to the collector with its events, once
each. The files are copied, never moved or changed.

**What the report shows.** Once any scan is found (or `scap_results` is
set), Audit health has a **STIG compliance (SCAP)** table: for each
computer and benchmark, the version and profile, when it was scanned,
the score, pass and fail counts, open CAT I, II and III findings, and
what changed since the previous scan (newly open, fixed, score). A scan
older than `scap_max_age_days` (30 by default) is marked **Stale**, and a
computer in the report with no scan says **No scan found**.

- CAT comes from each rule's severity: high is CAT I, medium CAT II, low
  CAT III. Open means `fail` or `error`, as STIG Viewer and SCC count
  them.
- **Overview:** open CAT I findings are a red line in the checklist;
  computers with no scan, or a stale one, are amber.
- **Open rules:** each open CAT I, II or III count in the table opens
  that computer's open rules on Audit health, CAT I first, then by STIG
  ID, with each rule's title, Vuln ID and rule ID. Each computer's
  settings list also has a **STIG compliance (SCAP)** line (score and open
  counts; a gap when CAT I findings are open) linking to the same list.
- **Systems:** each computer's header adds "SCAP 94% · 1 CAT I".
- **Report folder:** each result shown is copied into `scap/` and listed
  in `manifest.sha256`, so the report proves which scan it showed.
  `scap-open-rules.csv` lists every open rule (computer, benchmark, CAT,
  Vuln ID, STIG ID, rule ID, title, scan time) for a POA&M; the Export
  menu offers it. `summary.json` has each computer's score and open
  findings.

## Is the audit trail complete?

The Overview flags a report as incomplete when:

- events were overwritten before collection, for example because the
  system was off longer than the log could hold
- a log was cleared
- auditing was switched off
- a Linux log was rotated away before it was read, or the kernel dropped
  audit records

The **Audit health** page shows every system against every STIG audit
check (logon, account management, policy change, privilege use, process
creation, removable storage, PowerShell logging, log size, reporting, logs
intact), the gaps with how to fix them, and each system's own settings
table. Blackbox only reports audit settings; it never changes them.
"How to fix" gives the Group Policy location and setting for each gap
(for example Computer Configuration > Policies > Windows Settings >
Security Settings > Advanced Audit Policy Configuration > Audit Policies >
Object Access > Audit Removable Storage).

The **Antivirus** column shows Microsoft Defender on each Windows system:
the security intelligence (definitions) version, the date that version was
created, and whether real-time protection is on. Definitions created more
than 30 days ago, or protection turned off, show as a gap. The Systems page
lists the version and its date for each system. It is read once a day with
`Get-MpComputerStatus`.

On Linux the same column shows **ClamAV**: the daily database version and
when it was built (from `clamscan --version`), and whether its scanner
service (`clamav-daemon`, or `clamd@scan` on Alma) is running. Definitions
built more than 30 days ago, or no definitions loaded, show as a gap, just
as for Defender; the service not running is a warning (ClamAV then only
scans when asked). A system without ClamAV says so and is not counted as
a gap. Blackbox only reads this; it never updates definitions or starts
the service.

## Output files

Every report is a folder containing:

| File | |
|---|---|
| `report.html` | The report. Open it in any browser; it works offline |
| `data/` | The events the report's pages list, compressed, one file per page and day. `report.html` reads them only when a page needs them; keep them next to it |
| `logs-COMPUTER.zip` | The original logs, one per computer (see above) |
| `events.zip` | Every event as `events.csv`, for Excel. Double-click to open. A field that starts with `=`, `+`, `-` or `@` gets a `'` in front, so Excel shows it as text and never runs it as a formula |
| `summary.json` | Counts and period, used by the report list |
| `manifest.sha256` | SHA-256 hash of each file |

To confirm a report has not been altered, run
`blackbox verify <report folder>`, or `sha256sum -c manifest.sha256`.
The report also checks each data file as it loads it: if one was changed,
**Verified** at the top of every page turns red.

`blackbox verify` also fails if a file the manifest lists is missing, if a
file was added to the folder afterwards, or if the manifest no longer
lists a file the report needs: `report.html`, `summary.json`,
`events.zip`, or any data file `report.html` loads. Each problem is one
line.

**What this proves, and what it doesn't.** The manifest is not signed, so
it finds accidental damage, a copy that went wrong, and careless edits.
Someone who edits a file and also rewrites its hash in the manifest is not
caught. For that, keep the reports where only administrators can change
them (the default report folder is), or copy each report to write-once
storage when it is made.

**Large networks.** A report lists up to 2,000,000 events. Above that,
routine Info events (mostly logons) are counted and charted but not
listed, and the event pages say so; every High, Medium and Low event, and
every event a detection points to, is always listed. All of them are in
the original logs. Tables draw only the rows on screen, so a page with
hundreds of thousands of events still scrolls smoothly.

The folder of reports has an `index.html`: detections per week over the
last twelve reports, and each report with its week, systems, events,
detections and whether its audit trail is complete.
