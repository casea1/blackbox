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

**Report folders** are named for the end of the period and the site name
set in setup, for example `2026-10-05_0000_Lab-3-LAN`. Without a site
name, a report on one computer is named after it, and a collector's
report after the collector. A manual report's folder ends in `_manual`
(`_interim` before 0.15), and a report for a chosen period in `_range`.

To produce a report now, run `blackbox report`. This is a **manual**
report: it covers the time since the last scheduled report, is marked
*Manual* in the report and on the list of reports, and does not change the
schedule. The next scheduled report still covers its whole period. A
manual report shows everything collected so far, even an event stamped
a little after the moment it was made (as happens just after the clock
is corrected). Manual reports do not include the original logs; those
go with the scheduled report. A manual report's **Original logs** page
says where they wait (`archive_dir`), the period and size so far, from
how many systems, and when the scheduled report that holds them is due.

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
listed as Manual, and does not change the schedule. On a collector it
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

The report uses two words for what needs a person: **Detections**, to
investigate, and **Health**, to fix. Every High event is in a detection:
one that no detection rule below took is a detection of its own, one per
kind of event on each system ("Log cleared on WS-07", with every such
event listed in it). `summary.json`'s `high` counts High detections.

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
| Possible covering of tracks | High | An account created, someone added to a privileged group, or sudo rules changed, then within 24 hours on the same computer a log cleared or altered, auditing stopped, an audit rule added, removed or refused, auditing on an object changed, anti-malware turned off or an exclusion added, the firewall stopped, or Blackbox stopped, removed or its exclusions or retention changed, by a person. Blackbox's own installer (`Blackbox-Setup-<version>.exe`) writing its data folder is not a step when Blackbox recorded that install or upgrade on the same computer, nor is the Event Log service writing the original-log pieces during a Blackbox run; those writes are not rows either |
| Account created and deleted within a day | High | The same account created and deleted on one computer within 24 hours |
| Auditing was switched off | High | The audit service stopped by a person, with how long it stayed off |
| Successful logon after failures | Medium | 3 or more failures, then a success, within 30 minutes |
| New USB device, then administrator activity | Medium | Administrator rights used within 30 minutes of a USB device never seen before |
| The clock was moved back (or forward) by a person | High back, Medium forward | A person (not the Windows Time service) set the clock by more than 5 minutes (Windows event 4616). Changes of under a second, which each `Set-Date` also logs, are not rows |
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

**Repeats are one row.** The console host Windows starts for every
console program run with administrator rights (`conhost.exe 0xffffffff
-ForceV1`) is not a row of its own: the program that started it says
"Also started: N console windows" in its details. One started by a
program that is not a row (sshd, for each command in an SSH session) is
counted with that person's logon on that computer, or left out. Windows
records each SSH sign-in as two logons (4624) at the same second, not
always linked to each other: they are one row, with the second logon ID
in its details ("Also logon ID"), so Logon activity counts sign-ins. One
log clear is one row too: the command that cleared it (`wevtutil cl`,
`Clear-EventLog`) is folded into the log's own record of the clear when
they match (same computer and person, the command names that log, within
a minute), its command line under "Cleared with". Identical records (the
same system, person, action and text within a minute) are one row marked
**×N**, with the time of each in its details ("Recorded: 7 times: …").
Failed logons are never folded: each is an attempt. Every count in the
report (the sidebar, the tiles, People, Trends) counts rows.

**Blackbox's own writes.** The Event Log service writing the original-log
pieces during a Blackbox run is not a row, also in a manual report made
right after a run that made a scheduled report: the report looks at
Blackbox's runs from an hour before its earliest event.

**Audit integrity kinds.** Each row has its kind: Log cleared, Audit
policy changed, Logging stopped (the event log or audit service stopping,
a full log, dropped records), Blackbox (its install, upgrade, settings and
files), Firewall, Clock, Startup and shutdown, or Other. The **Logging
stopped** tile counts only stops of Medium severity or above: the event
log service stopping as Windows shuts down, or auditd as a restart ends,
is not counted.

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
off" on Systems, an "Auditing is off" row in Audit health's Gaps table, a line in
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
platform file is Medium "during a Microsoft Defender update" when
Defender's own log records an update (2000/2014) on that computer within
15 minutes, to that platform version (the folder the file is in); the
update is in its details. Otherwise it stays High, with a note: Windows
often logs this while Defender updates its platform, and the row says how
to tell. Defender's updates are not rows. PowerShell module code that
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

**How it works.** At every collection, each computer exports its logs
written since the last export, while the logs still hold them: with
`wevtutil epl` on Windows, and by copying the new lines on Linux. A log
the collection read nothing new from is left out of that export. Once a
day the exports are packed into one archive: the `.evtx` files of each
export are kept as they are (named after the export's start time, to
the second, e.g. `Security_20261005-041503Z.evtx`, when there is more
than one; two exports started in the same second get `-2`, `-3` …), and the
text logs are joined in order into one file. The first export reaches
back a week. So a log that rolls over within the day (one Windows Update
run can fill a 20 MB Security log in an hour) loses only what it
overwrote between two collections.

`archive.json` records, for each log, the part of the period it actually
covers (`logs[].from`, the oldest record present) and the events
Blackbox knows it overwrote before they could be exported
(`logs[].overwritten`, from the collection's record numbers). The
Original logs page shows the same, e.g. "Covers from 5 Oct 04:08; 94,565
events were overwritten before they could be exported". If a full log
had already overwritten part of the period since the last export, that
part is recorded as missing: the page shows "Missing <from> – <to>:
overwritten before it was saved" for that log, Audit health has a
warning, `summary.json` lists it under the archive's `gaps` (and the
coverage under `logs`), and `blackbox status` says **LOGS INCOMPLETE**
for 14 days and exits with code 4. For another log, such as the
PowerShell log, the line is "Logs incomplete" and does not change the
exit code. Each log has one line, however many times it overwrote
itself: how many times since when, the latest part, and the same advice
as its "Events lost" line. The fix is a larger log (`blackbox check`
gives the size, from the same rate as `status`), or, on a system that
collects less often than every 15 minutes and whose log holds more than
that, collecting more often.

A log cleared since it last had a record exported is not an overwrite:
the clear is its own High row. The part it leaves out is labelled with
who cleared it and when, also when the log stayed empty until a later
collection: the Original logs page says "Cleared by claude at …: its
events from before then are not in this archive", `archive.json` has
`cleared` on that gap, and `blackbox status` has a "Log cleared:" line
with no size advice and no exit code 4.

**Exports lost or changed before packing.** Each export's files are
hashed when they are written (`piece.json`). When they are packed, a file
that has been deleted or can't be read is left out and the rest are still
packed: `archive.json` records it under `gaps` with its log, its period
and the reason (e.g. "Application.evtx, exported for … was missing when
the logs were packed"), and the Original logs page, Audit health and
`blackbox status` (**LOGS INCOMPLETE**) say so. Its events are still in
the reports; only the original copy of that part is gone. A file whose
hash no longer matches is packed as it was found, marked `changed` in
`archive.json`, and the report has a High detection, "Saved original
log changed before it was archived". On Linux, `blackbox check
--audit-rules` also watches `/var/lib/blackbox/archive-pieces/` for
writes by anything but Blackbox, a root script included.

If packing fails altogether (the archive folder can't be written, for
example), the exports are kept and packing is tried again at every run.
Until it works, `blackbox status` says **ORIGINAL LOGS NOT ARCHIVED
since <time>: <reason>** and exits with code 4, the status icon notifies
once, and reports say so on Original logs and in Audit health.

**An archive that fails its check.** Every daily archive is checked
against the hashes in its `archive.json` before it goes into a
scheduled report. One that fails (damaged, or changed after it was
written) is left out of that report and the others still go in: it is
moved to a `set-aside` folder next to it (e.g.
`archives\WIN11\set-aside\WIN11_…zip`) and not tried again. For 14 days
`blackbox status` says **ORIGINAL LOGS NOT IN REPORT <report>: <the
computer>'s logs for <from> to <to>: <reason>** with where the file is,
and exits with code 4; the status icon notifies once. The report says so
on the Overview ("Original logs not in this report", never "Original
logs archived"), on Original logs and in Audit health, and a manual
report made afterwards says so too. The events are in the report; the
original copy of that period is only in the file set aside. Archives
written before 0.21 could hold two `.evtx` files under one name (two
exports started in the same minute); they are still read, in order, and
rewritten with the second one renamed (`…-2.evtx`, contents and hashes
unchanged, noted in `archive.json`) when they are bundled.

**After the clock is moved back.** Exports follow on from the end of the
last one. If the clock was ahead and is then corrected, what is written
afterwards is stamped before that end. Blackbox notices, starts the next
export at the first record written since the last one, so nothing is
skipped, and notes it in `archive.json` and on the Original logs page.
Records stamped in the overlap may then be in two consecutive exports.

Until then, the exports and the archives (this computer's and, on a
collector, those senders delivered) wait in the `archives` folder in the
data folder, or in `archive_dir` if set (setup asks for it: choose a
larger volume for many computers). When a **scheduled** report is made,
the computer packs its exports so far, then all the archives waiting go
into the report's folder and are removed from there. A manual report
(`blackbox report`) leaves them waiting for the scheduled one. It works
the same on a standalone computer and on a collector.

A computer that sends to a collector delivers its daily archives with its
events. The collector checks every file against its hash when it arrives;
a damaged or altered zip is set aside in the inbox's `rejected` folder. A
day's logs go into the report whose period its save ends in, so a
computer that was off catches up in the next report.

The **Original logs** page lists each computer's zip with its size and
SHA-256, checked against the hash recorded when the zip was made, and
shows what is inside each one. A computer with no logs for the period is
listed first, as Missing.
They are also listed in `summary.json`.

**Retention.** The zips live only in the report folders. Under
`retention_days`, a report folder is deleted with everything in it,
including its original logs, so set `retention_days` no lower than how
long the original logs must be kept (a year is usual, AU-11), or copy
the report folders elsewhere first.

Expect a few MB a day per Windows computer (much less for Linux),
compressed. It depends on how busy the Security log is.

**Deleting a report folder.** What is lost depends on the folder:

- **A scheduled report** holds the only copy of its period's original
  logs (they were moved out of `archive_dir` into it), its hashes
  (`manifest.sha256`), and its day-by-day counts for Trends
  (`summary.json`). The collected events stay in the data folder (kept
  for good unless `retention_days` is set), so `blackbox report` can make
  a report for that period again, but without the original logs, and as
  a manual report that Trends do not count. Trends show a gap for its
  weeks. Blackbox keeps a record of every scheduled report it made (its
  folder, period and the hash of its manifest), so a scheduled report
  that is deleted, moved or changed afterwards is pointed out until
  someone says why: `blackbox status` says "REPORT MISSING" (or
  "CHANGED") and exits 4, the status icon notifies once, the next report
  has "Earlier reports missing or changed" on the Overview and in Audit
  health's gaps, and All reports lists it as "Missing: deleted or moved".
  Every run checks that each file the manifest lists is there, at the
  size it was written with; once a day every file is hashed again. A
  file deleted or changed is named, e.g. "REPORT CHANGED: … logs-WS-07.zip
  is missing". Reports recorded by 0.19 have no file list: it is taken
  from their manifest, so a file moved out of one is noticed at once too.
  `blackbox reports` lists them, and exits 4 like `status` when one is
  missing or changed; when one was moved or
  removed on purpose, `blackbox reports accept NAME "why"` records who,
  when and why (a row in the next report and a copy in the system log)
  and stops pointing it out. All reports keeps its row, muted: "Accepted
  as moved by <who> on <date>: <why>". Removal under `retention_days` is expected and not
  pointed out. The record starts with the first scheduled report made by
  0.19.
- **A manual report** holds nothing that is not kept elsewhere: its
  original logs still wait in `archive_dir` for the scheduled report,
  which also covers the same time. Only that snapshot of the report is
  gone.

All reports (`index.html`) is rebuilt at every collection, so a deleted
report drops off it within one collection interval.

**Keeping them safe.** An administrator on the computer can always delete
files there, so the protection is a copy elsewhere and the record above.
Back up the whole data folder (`C:\ProgramData\Blackbox`, or
`/var/lib/blackbox` and `report_dir`) after each scheduled report (reports
are ready at `report_at`, Wednesday 00:00 by default), to storage the
computer's own administrators can't delete from. The data folder also
holds the collected events and `archive_dir`, the current period's
original logs, which are in no report yet. Keeping `archive_dir` on
another disk of the same computer does not protect it.

On Windows, deleting a report under `C:\ProgramData\Blackbox` is a High
row in the next report when that folder has an
auditing entry (see [windows.md](windows.md)): "deleted the report …"
when its folder went, or the files by name when only some did ("deleted
logs-WIN11-TEST.zip from the report …"). A `report_dir` elsewhere needs
its own. On Linux, Blackbox's audit rules watch `/var/lib/blackbox`;
a `report_dir` elsewhere is not watched unless you add a rule for it.

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
computer's operating-system STIG (Windows, Ubuntu, RHEL, Alma and so
on), the version and profile, when it was scanned, the score, pass and
fail counts, open CAT I, II and III findings, and what changed since the
previous scan (newly open, fixed, score), open CAT I first. Other
benchmarks scanned on the same computers (Edge, Firefox, Defender, …)
are under **Other benchmarks** below it, one click away; a computer with
no operating-system scan shows its other scans in the main table. A scan
older than `scap_max_age_days` (30 by default) is marked **Stale**, and
the computers with no scan are named in one **No scan found** line. The
open-rules CSV still lists every benchmark.

**Where the score is.** Besides the table: the bar at the top of Audit
health ("lowest score 40% · 1 open CAT I"); each system's own Audit
health view, as **SCAP score** next to its checks (on a one-computer
report, that view is the whole of Audit health); and each system's
health list on the Systems page (**STIG compliance (SCAP)**, or **Open
CAT I findings (SCAP)** when it has them). Each uses the system's
operating-system scan.

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

## Inventory

The **Inventory** page (under Audit) lists what each system is, read with
its daily settings check by Blackbox 0.13 or later:

- **The system:** make and model, serial number (from the BIOS on Windows,
  DMI on Linux), BIOS version, operating system, processor and memory, and
  its domain.
- **Drives:** each physical disk's model, serial number, size (as its maker
  labels it) and type (NVMe, SATA, USB; SSD, HDD, removable).
- **Accounts:** local accounts and, on Windows, every domain account with a
  profile on the computer: whether it is an administrator, enabled or
  disabled, and its last logon. Only the **last four digits of each SID**
  are kept (on Linux, the UID). On Linux an account whose password is
  locked is shown as such but stays enabled, since it can still log on
  with a key or through sudo; one whose shell refuses logons, or that has
  expired, is disabled. Nothing about passwords is read or kept.

The page has three tabs, each with a filter box:

- **Systems**: one row per system (make, model and serial, operating
  system, processor and memory, how many drives and accounts, how many
  administrators). Click a row, or press Enter on it, to open that
  system's drives (with serial numbers) and accounts right under it;
  several can be open at once, and **Expand all** opens every one. A link
  to `#inventory/WS-07` opens that system.
- **Drives**: every drive on every system, with its serial number.
- **Accounts**: every account on every system, with **Administrators** and
  **Enabled** filters, so all administrator accounts on the network are in
  one list. Click an account to search its events.

The four tiles at the top open their tab (Administrators opens Accounts
filtered to administrators). **Export > Inventory as CSV** saves every
system, drive and account, one per line. Systems with no inventory yet
are named under the table with the reason: it has sent nothing since a
given time, it runs a Blackbox from before 0.13, or it has sent no
settings check yet.

How it is read: on Windows, one PowerShell query of CIM
(`Win32_ComputerSystem`, `Win32_BIOS`, `Win32_DiskDrive`,
`Get-PhysicalDisk`) and the local accounts (`Get-LocalUser`,
`Get-LocalGroupMember`, `Win32_UserProfile`); on Linux, `/sys/class/dmi`,
`/sys/block` (with `udevadm` for a drive's serial number), `/etc/passwd`,
`/etc/group` and the lock and expiry fields of `/etc/shadow`. A sender's
inventory reaches the collector with its settings check.

## Is the audit trail complete?

The Overview flags a report as incomplete when:

- events were overwritten before collection, for example because the
  system was off longer than the log could hold. The log is named ("PowerShell
  log on WIN11-TEST: 447 events overwritten"). Losses from the audit
  record (the Security log, the Linux audit log) are **Events lost to log
  rollover** (red); other logs' losses, such as the PowerShell log's, are
  **Other logs overwrote events** (amber), on their own line. The advice
  depends on the rate: a log that turned over in less time than there is
  between collections is too small for its volume, and collecting more
  often would not help, so the size it needs is given; collecting every 15
  minutes is suggested only to a system that collects less often. The
  size given is capped at 2 GB, the same as `blackbox check` gives. The
  original logs exported at each collection hold what each log had at that
  moment: events written and overwritten between two collections are in no
  export
- a log was cleared. The log is named: "Security log cleared" for event
  1102, "PowerShell log cleared" for a System 104 naming that log. The
  records a clear removed are not also counted as lost to rollover, and
  no size advice is given for them
- auditing was switched off
- a Linux log was rotated away before it was read, or the kernel dropped
  audit records

**A computer that sent nothing.** A system with no collection in the
period is **Silent**, with the time it last sent. A virtual machine is
treated more gently, because it sends only while it is on: one that was
off for part of the period is fine, and one that sent nothing all period
is **Worth a look: nothing received since** that time. Blackbox calls a
system a virtual machine only when it says so itself, which a sender does
when it sends through a VirtualBox shared folder (`/media/sf_…` or
`\\VBOXSVR\…`); data relayed through another computer does not make it
one. A VM that sends over the network shows as a workstation.

The **Audit health** page shows every system against every STIG audit
check (logon, account management, policy change, privilege use, process
creation, removable storage, PowerShell logging, log size, reporting, logs
intact), the gaps with how to fix them, and each system's own settings
table. Blackbox only reports audit settings; it never changes them.
The grid takes the page's full width, with short headings (hover one for
its full name) and the System column always in view; on a narrow screen
it scrolls sideways and says **more →** until its last column is in view.
Systems that match on every check are folded under **Show the N systems
that match on every check**, so the sections below stay in reach; a bar
at the top of the page links to each section (the grid, Gaps, Antivirus,
STIG compliance, other Security-log events) with what needs attention.
In the **Antivirus** table, systems with current definitions are folded
the same way. The gaps follow below the grid as a table, one row per gap (its STIG ID, the systems and the result; a gap systems share under different STIGs lists each one's IDs with its OS, e.g. "WN25-AU-000070, WN25-AU-000080 (Windows Server 2025) · WN11-AU-000010, WN11-AU-000005 (Windows 11)", and the CSV gives each system its own); click a gap for what it means and how to fix it. **Log size and space settings** counts the
systems whose logs are smaller than the STIG asks, or, on Linux, whose
auditd space and disk actions differ from it.
"How to fix" gives the Group Policy location and setting for each gap
(for example Computer Configuration > Policies > Windows Settings >
Security Settings > Advanced Audit Policy Configuration > Audit Policies >
Object Access > Audit Removable Storage).

The **Antivirus** column shows Microsoft Defender on each Windows system:
the security intelligence (definitions) version, the date that version was
created, and whether real-time protection is on. Definitions created more
than 30 days ago, or protection turned off, show as a gap. It is read once
a day with `Get-MpComputerStatus`.

**Where to find the definitions date.** Audit health has an **Antivirus**
table (linked from the bar at the top), one row per system, out-of-date ones first: the antivirus, the
date its definitions were made, how old they are, the version, real-time
protection (or the ClamAV service), and the result. The Overview's
checklist has an **Antivirus definitions** line with the oldest date and
any system that is out of date; each system's health list on the Systems
page has its own date. All three link to the table (`#health/@av`).

On Linux the same column shows **ClamAV**: the daily database version and
when it was built (from `clamscan --version`), and whether its scanner
service (`clamav-daemon`, or `clamd@scan` on Alma) is running. Definitions
built more than 30 days ago, or no definitions loaded, show as a gap, just
as for Defender; the service not running is a warning (ClamAV then only
scans when asked). A system without ClamAV says so and is not counted as
a gap. Blackbox only reads this; it never updates definitions or starts
the service.

## Reading a report

The sidebar has the pages most used: **Overview**, **Detections**,
**Search**, **Systems**, **People**, **Audit health**, **Original logs**
and **All reports**. The pages for each kind of event (Privileged
activity, USB & removable, …) are under **Events by kind**, closed until
one is opened; a kind with no events is left out. **Inventory** and
**Trends** are under **More**. Search has the same kinds as chips, with
their counts, and a timeline with times of day for a short period.

- **Overview.** Four headline numbers for this report (systems
  reporting, detections, events, and systems whose audit settings match
  the STIG), the activity counters that are not zero (the rest are named
  in one line), **Health** with each problem once and a line for what is
  fine, and **Detections**. The trends below it, which count every
  report by calendar week, appear once there are two full weeks.
- **Each fact once.** The Systems page gives a system's audit settings
  to fix as a count that links to Audit health, which lists them. A
  system that sent nothing says so once.
- **Columns that say nothing are hidden.** Severity when no row is High
  or Medium; a Kind, Session or From that is the same on every row. With
  a Person column, the summary leaves out the person's name (the event's
  panel keeps it).
- **Short and empty periods.** A page with no events is one line. A
  period of a day or less is charted by hour, and "Above normal" is shown
  only when there are at least three days with events to compare. "Not
  enough history" is said once, and trend tiles appear once there is
  history.
- **A manual report** says so in a banner on the Overview, and in a
  "Manual" chip by the title on every other page.
- **SSH logons on Windows** show the address they came from: the 4624
  Windows writes for an OpenSSH sign-in has none, so Blackbox reads the
  OpenSSH server's log (`OpenSSH/Operational`) and joins sshd's
  "Accepted … from <address>" line to the logon.
- **Privileged actions** count people's actions, as Trends' "by person"
  table does; actions by service accounts are listed but not counted.

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

The folder of reports has an `index.html`, **All reports**: detections per
calendar week (manual reports not included, and nothing drawn until 2
full weeks), and each report with its period, systems, events,
detections and whether its audit trail is complete. A period of one whole
day is one date ("5 Oct 2026"); one that starts or ends during a day shows
the times ("5 Oct 00:00 – 06:44"). Numbers have thousands separators
everywhere ("95,229 events lost"). The
newest is marked **Latest**; click a row to open it. In a report, the
**All reports** button at the top of every page (and in the menu) opens
it. The date range next to it only shows the report's period.

**Trends.** Each scheduled report keeps its counts day by day in
`summary.json` (`days`), and later reports add them up by **calendar
week**, Monday to Sunday, whatever period each report covered: two
reports in one week make one week, and a report that spans two weeks is
split between them.

- Only **complete weeks** count: weeks fully covered by scheduled reports.
  Manual reports are never part of the history. The first report, which
  reads back through the logs from before Blackbox was installed, only
  fills partial weeks, which are labelled "(part)" in the tables and left
  out of charts and averages.
- The week the report ends in is shown **so far** ("190 so far this
  week, 2.5 of 7 days") and compared with the same part of an average
  week, not with a whole one.
- With fewer than **2 complete weeks**, every trend says "Not enough
  history yet: trends start after 2 full weeks" instead of drawing a
  point or two.
- Charts are labelled with the weeks' dates, and say how many weeks they
  show (up to 13).

The Overview's **What changed** panel lists the biggest moves: a
network-wide count (failed logons, privileged actions, …) up or down by
25% or more on the average week, a system with more detections than
usual, and a person with more privileged actions than usual or with
privileged actions for the first time. The Trends page charts the
network's counts and has detections per system and privileged actions per
person, by week. On the People page, each person's **Over time** panel
compares this week's privileged actions, after-hours actions, logons,
failed logons and detections with their own average week. The list of
reports has **Detections per week** by the same calendar weeks, without
manual reports, from 2 complete weeks on.

Reports made before 0.16 did not keep counts by day. A report from then
whose whole period lies in one calendar week (a daily report) still
counts; one that spans two weeks (a weekly report ending mid-week) can't
be split and is left out, except for its detections, which carry their
times.

**Clicking through.** The boxes at the top of each event page filter the
table below them: for example **Accounts locked out** shows only the
lockouts, **New devices** only the devices seen for the first time, and the
first box shows everything again. Boxes about another page open it. On a
person's page, each hour of **When they were active** can be clicked: a
red hour shows only the detections in that hour; any other hour opens
Search with that person's events in that hour of the week.
