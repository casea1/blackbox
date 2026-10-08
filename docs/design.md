# Design

Open source audit log review tool for air-gapped Windows and Linux systems and
small air-gapped LANs (10–30 hosts, designed to scale further).

Blackbox reads Windows event logs and Linux audit logs, **translates events into
plain English**, groups them into the categories auditors actually review, and
produces a self-contained HTML report on a recurring schedule.

Status: **M1 (Windows single host) implemented.** Section 13 records the
decisions made so far.

---

## 1. Goals

1. **Readable output.** Every event is shown as a sentence a reviewer can
   understand without looking up event IDs or decoding hex codes.
   - Bad: `4625 | 0xC000006A | LogonType 10 | S-1-5-21-...-1104`
   - Good: `jsmith failed to log on to WS-07 via Remote Desktop from 10.1.1.20 — wrong password`
2. **Focus on what auditors review**, in priority order:
   1. Privileged events and privileged commands
   2. USB and removable media activity
   3. Failed logons and lockouts
   4. Other security-relevant events (account changes, audit policy changes,
      logs cleared, audit service stopped, time changes, new services, and so on)
3. **Simple installation and setup.** One file to copy across the air gap, one
   command to install, and a default configuration that works without editing.
4. **Meets DCSA / DISA STIG / RMF (NIST SP 800-53) audit review expectations**,
   including continuous coverage, integrity and retention.
5. **Easy to get approved.** Small codebase, few dependencies, no network
   listeners, read-only access to logs, reproducible builds and an SBOM.
6. **Ready for Splunk.** Normalized events are also written as JSON, so moving
   to Splunk later loses nothing.

### Non-goals (for now)

- Real-time alerting or SIEM features. That is Splunk's job later.
- An always-on web application with its own user accounts. We may add an
  optional viewer later, but static reports come first (see §6).

---

## 2. Target platforms

| Platform | Log sources |
|---|---|
| Windows 11 Enterprise | Security, System, Application, PowerShell/Operational, Partition/Diagnostic, DriverFrameworks-UserMode, Defender, Sysmon (if installed) |
| Windows Server 2025 | Same as above; also the log collector role once the LAN is on a domain (§7) |
| Ubuntu 22.04 / 24.04 / 26.04 | auditd (`/var/log/audit/audit.log*`), journald, `/var/log/auth.log`, AppArmor |
| AlmaLinux 8.10 | auditd, journald, `/var/log/secure`, SELinux AVC |

Everything ships as a single static binary for each OS (Go, cross-compiled),
with no runtime to install: no Python, .NET, Java or Node.

---

## 3. Architecture

```
 ┌──────────┐   ┌───────────┐   ┌──────────────┐   ┌──────────┐   ┌──────────────┐
 │ Collect  │ → │ Normalize │ → │ Classify +   │ → │ Report   │ → │ Seal +       │
 │ evtx /   │   │ common    │   │ Translate    │   │ HTML +   │   │ retain       │
 │ auditd / │   │ event     │   │ (YAML rules) │   │ JSON/CSV │   │ (SHA-256     │
 │ journald │   │ schema    │   │              │   │          │   │  manifest)   │
 └──────────┘   └───────────┘   └──────────────┘   └──────────┘   └──────────────┘
       ▲                                                                 │
       └──────────── bookmark (last record read) ◄──────────────────────┘
```

- **Collect**
  - Parse `.evtx` files directly. On a live system, use the Windows Event Log
    API so that archived and rolled-over logs are also read.
  - Parse raw auditd logs, grouping records into complete events by their
    serial number.
- **Normalize**
  - Put every event into one schema: time, host, OS, category, severity,
    actor (user and SID/UID), target, action, outcome, source IP, process,
    command line, raw event.
- **Classify and translate**
  - A built-in catalog (`internal/winevt/translate*.go`) maps each raw event
    to a category and a plain-English sentence. Many events need logic, not
    just a template: decoding failure codes, telling a real person from a
    service account, working out elevation. So the catalog is Go code with
    tests, which also makes it easier for a security reviewer to read.
    Site-specific tuning (excluded users and programs) goes in the config
    file.
- **Report**
  - One report folder per run: `report.html`, its compressed event data
    files, and `events.zip` (every event as CSV).
- **Seal**
  - A SHA-256 manifest covers every output file, and the retention policy
    decides how long outputs are kept.

### Decoding that makes events readable

- **Windows**
  - Logon types: 2 = at the console, 3 = over the network, 10 = Remote
    Desktop, and so on.
  - `Status`/`SubStatus` codes: `0xC000006A` = wrong password,
    `0xC0000064` = no such user, `0xC0000234` = account locked, and so on.
  - `%%` message tokens, for example `%%1937` = elevated token.
  - SIDs resolved to names; group names; UAC flag changes.
- **Linux**
  - Hex-encoded `proctitle` decoded to the actual command line.
  - EXECVE arguments rejoined into one command.
  - `auid`/`uid`/`euid` resolved to usernames, so "who really ran this" is
    clear through sudo and su.
  - Syscall numbers resolved to names.
  - STIG audit rule keys, such as `-k privileged`, `-k usb` or `-k identity`,
    used as classification hints.

---

## 4. Event coverage (initial rule set)

Each category is tagged with the NIST 800-53 controls it supports.

### 4.1 Privileged activity — AC-6(9), AU-2, AU-12

| Windows | Linux |
|---|---|
| 4672 special privileges assigned at logon | `USER_CMD` (sudo), with the full decoded command |
| 4688 process created with an elevated token (includes the command line when that auditing is enabled) | `su` / `USER_START` sessions as root |
| 4648 logon with explicit credentials (runas) | EXECVE where `euid=0` and `auid≠0` (a normal user acting as root) |
| 4673 / 4674 privileged service or object operations | STIG `privileged-*` keys (passwd, chage, usermod, mount, and so on) |
| 4104 PowerShell script block logging | Changes to sudoers, sudo config |

### 4.2 USB and removable media — MP-7, AC-19, AU-2

| Windows | Linux |
|---|---|
| Partition/Diagnostic 1006: device connected, with vendor, model, **serial number** and capacity (enabled by default on Windows 11) | Kernel "new USB device" messages with vendor, product and serial |
| 6416 new external device recognized (needs the "Audit PnP Activity" policy) | `usb-storage` / `uas` attach and detach |
| 4663 access to removable storage (needs the "Audit Removable Storage" policy) | `mount` / `umount` syscalls on removable devices |
| DriverFrameworks-UserMode 2003 / 2100 connect and disconnect | udev add/remove events (from journald) |

The report pairs each connect with its disconnect, links the device to the
logged-on user, and flags devices not seen before.

### 4.3 Failed logons and lockouts — AC-7, AU-2, IA-2

| Windows | Linux |
|---|---|
| 4625 failed logon, with the reason decoded | `USER_LOGIN` / `USER_AUTH` with `res=failed` |
| 4740 account locked out | faillock / pam_faillock lockouts |
| 4771 / 4776 Kerberos / NTLM failures (after the domain move) | sshd `Failed password` / `Invalid user` |
| 4767 account unlocked | sudo authentication failures |

The report also detects patterns: repeated failures for one account, one
source trying many accounts, and failures followed by a success.

### 4.4 Other security events

| Area | Windows | Linux | Controls |
|---|---|---|---|
| **Audit log cleared / audit stopped** | 1102, 104, 4719 (audit policy changed), 1100 (event log service shut down) | `DAEMON_END`, `CONFIG_CHANGE`, auditd rules changed, gaps in the log | AU-5, AU-9 |
| Account management | 4720 / 4722 / 4725 / 4726 / 4738 / 4781, group membership changes 4728 / 4732 / 4756 | `ADD_USER`, `DEL_USER`, `USER_MGMT`, `ADD_GROUP`, identity file changes | AC-2 |
| Successful logon / logoff | 4624 / 4634 / 4647 (summarized, not listed one by one) | `USER_LOGIN`, `USER_END` | AC-2, AU-2 |
| System time changed | 4616 | `adjtimex` / `settimeofday` / `clock_settime` | AU-8 |
| New services / scheduled tasks | 7045, 4697, 4698 | systemd unit changes, cron changes | CM-7, SI-4 |
| Malware / security software | Defender 1116 / 1117 / 5001 (real-time protection off) | — | SI-3 |
| Mandatory access control | — | SELinux AVC denials (Alma), AppArmor DENIED (Ubuntu) | AC-3 |
| System start / shutdown | 4608, 1074, 6005 / 6006 / 6008 | boot / shutdown records | AU-2 |

---

## 5. Audit health check: coverage is part of the report

A report is only as good as the auditing turned on underneath it. Every report
begins with an **audit health** panel:

- **Coverage window.** The time period this report covers, and any **gaps**
  since the previous report, detected from the bookmark (AU-6, AU-5).
- **Log cleared or audit stopped** during the period. Always shown at the top
  and never hidden.
- **Log rollover.** A warning when the Security log wrapped before it was read,
  which means events were lost. The panel suggests a larger log size.
- **Audit configuration check.** Compares the live configuration against what
  the STIGs require, and lists anything missing:
  - Windows: `auditpol` subcategories (Logon, Special Logon, Process Creation,
    PnP Activity, Removable Storage, Audit Policy Change, Security Group
    Management, and so on), plus command-line logging in 4688 events.
  - Linux: loaded auditd rules (`auditctl -l`) compared with the STIG rules
    for Ubuntu and RHEL/Alma.
  - For example: "USB auditing is **not** enabled on WS-04, so the USB section
    for this host is incomplete."

`blackbox check` runs the configuration check on its own. We also ship a
recommended baseline so hosts can be brought into compliance:

- an `auditpol` backup file for Windows
- an auditd rules file for Linux

The tool **never changes audit settings unless you explicitly ask it to**.

---

## 6. Report format

**Decision: one self-contained static HTML file per run.** All CSS and JS are
embedded in the file. It needs no server, runs no network calls, and works in
any browser on an air-gapped machine.

Why:

- No listening port, logins or TLS, so there is nothing new to add to the
  system's authorization package.
- Each report is a single, fixed piece of evidence: hashable, easy to archive
  and possible to burn to media.
- Sorting, filtering and expanding tables still work offline through the
  built-in JS.

### Layout

The page designs are locked in [redesign/SPEC.md](redesign/SPEC.md), with a
mockup of each in `redesign/mockups/`. In short: a sidebar switches
between the Overview, Systems, Detections, Search and People; one page per
kind of event (each with stat cards, a chart, a top-six list, what was
flagged, and every event of that kind); and Audit health, Trends and
Original logs. Each event opens a side panel with the original record.

Events are not inside `report.html`: they are in compressed data files
next to it, one per page and day, read only when a page needs them, so
the report opens fast on a network of thirty busy computers. Charts are
drawn when the report is written, as SVG, so they need no script and print
as they look.

### Review and sign-off

Not part of the report: ISSOs and ISSMs record their reviews on a separate
platform (see section 13).

### Other outputs, written on every run

- `events.zip`: every event as CSV
- `data/`: the event pages' compressed data files
- `manifest.sha256`
- `index.html`: links to every report, with its coverage window

An optional read-only viewer (`blackbox serve`) could come later if a live
dashboard is needed. Splunk may make that unnecessary.

---

## 7. Deployment models

### Phase 1: now (standalone hosts, VMs and workgroup LANs) ✅

**Model A: standalone.** Each host runs Blackbox on a schedule and writes its
own reports locally. This covers standalone air-gapped systems.

**Model A+: collector inbox** (built; see [lan.md](lan.md)).

- **Senders.** Each host keeps collecting locally and copies numbered,
  checksummed batches of its kept events into a collector's inbox folder
  after every collection. The inbox can be a VirtualBox shared folder (a VM
  on the collector PC) or a Windows share (the LAN).
- **Collector.** It imports the batches and produces one report covering
  every host, with a Systems page, per-system filtering and per-system
  audit settings.
- **Guarantees.**
  - Nothing listens on the network.
  - Hosts that are off catch up later.
  - Missing batches, damaged batches, silent hosts and clock skew are
    reported.
  - Delivery is exactly-once: an outbox, an atomic rename into the inbox,
    and import that is idempotent by sequence number, with write-ahead
    recovery.

This replaces the `blackbox merge` idea. Merging report folders by hand
could not detect a host that stopped sending, and it put the work on the
administrator.

### Phase 2: after the domain move (recommended target)

**Model B: central collector** on Windows Server 2025.

- **Windows hosts.** Two options:
  - Keep Model A+ as it is. In a domain, senders can use their computer
    accounts (`Domain Computers` in the Blackbox Senders group), so no
    password is stored anywhere.
  - Or use Windows Event Forwarding (WEF), where hosts push their raw
    events to the collector by **Group Policy**.
- **Linux hosts.** Model A+ over the share.
- **Blackbox** runs on the collector and produces one LAN-wide report.

Later, Splunk can read from the same collector: add a Splunk forwarder or
point it at the collector's event spool (`spool/events-*.jsonl` in the data
folder), which holds every normalized event as JSON lines.


---

## 8. Install and setup (simplicity is a priority)

**Target: from copying the file to the first report in under 5 minutes, with
no config editing.**

### Windows

```powershell
# Copy blackbox.exe onto the system, then in an elevated prompt:
.\blackbox.exe install
```

`install` does the following:

- Copies the binary into `C:\Program Files\Blackbox\`.
- Creates `C:\ProgramData\Blackbox\` for the config, reports and state. The
  folder is restricted to Administrators and SYSTEM.
- Writes a commented default `config.yaml`.
- Registers a scheduled task that runs as SYSTEM, weekly by default.
- Runs `blackbox check` and prints what auditing is missing.
- Produces the first report immediately so you can see it working.

An MSI package can come later for deployment through Group Policy.

### Linux

```bash
sudo ./blackbox install
```

`install` does the following:

- Installs the binary to `/usr/local/bin`.
- Creates `/etc/blackbox/config.yaml`, and `/var/lib/blackbox/` for reports
  and state, readable by root only.
- Creates a systemd service and timer, weekly by default.
- Runs the configuration check and produces the first report.

We will also build `.deb` (Ubuntu) and `.rpm` (Alma) packages for sites that
prefer package installs. Neither package has any dependencies.

### Everyday commands

```
blackbox run                  # generate a report now (the scheduler runs this)
blackbox check                # check the audit configuration against the STIG baseline
blackbox status               # role, last collection, what is waiting to be sent or imported
blackbox send                 # collect and send to the collector now (e.g. before a VM shuts down)
blackbox send --resend 214-219  # send kept batches again to fill a gap the collector reports
blackbox send --new-id        # a computer cloned from another: give it a sender ID of its own
blackbox systems              # the computers a collector reports on (remove NAME to retire one; rename OLD NEW)
blackbox inbox add NAME ACCOUNT  # a folder in the collector's inbox only ACCOUNT can write to
blackbox verify <report-dir>  # check the SHA-256 manifest
blackbox reports              # scheduled reports made here, and any missing or changed (accept NAME "why")
blackbox uninstall            # remove the task/timer; reports are kept
```

---

## 9. Security and approval considerations

- **Read-only.** Blackbox reads logs and never modifies or deletes them. The
  only exception is `blackbox install`, and applying the audit baseline, which
  only happens when explicitly requested.
- **No network access at all.** No listening ports and no outbound calls.
- **Least privilege.** Runs as SYSTEM or root only because reading the Security
  log and `audit.log` requires it. Outputs are restricted to Administrators or
  root.
- **Integrity.** A SHA-256 manifest for every run (AU-9). Signing reports with
  a site key is an optional later addition.
- **Retention.** A configurable retention period that defaults to **keep
  everything**. It never deletes anything automatically unless configured to.
  The period is the site's records schedule (NARA GRS or the DoD component's
  records schedule, set with the ISSM), not AU-11, and a legal hold overrides
  it. Reports are aged by their period end, not their folder's date, and
  original logs not yet in a report are never deleted: past the period they
  are pointed out instead (RET1).
- **Supply chain.**
  - Dependencies kept to a minimum and vendored into the repository, so the
    code builds fully offline.
  - Reproducible builds.
  - An SBOM (CycloneDX) and SHA-256 checksums published with every release.
- **FIPS.** Build with Go's FIPS 140-3 module (`GOFIPS140`) so hashing uses
  validated cryptography.

---

## 10. Configuration (default shown)

The config is a plain `key = value` file (`blackbox.conf`), not YAML, so no
third-party parser is needed. Lines starting with `#` are comments, and
lists are comma-separated.

```
site_name =
report_every = weekly              # daily | weekly | monthly
retention_days = 0                 # 0 = keep forever
exclude_users =                    # e.g. svc_backup, svc_scanner
exclude_processes =                # e.g. C:\Tools\Scanner\scan.exe
```

---

## 11. Roadmap

| Milestone | Scope |
|---|---|
| **M1: single Windows host** | evtx collection, normalization, translation for §4.1–4.3, HTML report, bookmark, manifest, `install` / `run` |
| **M2: Linux** ✅ | auditd, syslog and journald collection for Ubuntu 22.04/24.04 and Alma 8.10, the same report (see section 15) |
| **M3: audit health** | `check` against the STIG baselines, gap and rollover detection, audit-integrity section |
| **M4: LAN (Model A+)** ✅ | Collector inbox over VirtualBox shared folders and Windows shares, Systems page, per-system filters and checks, gap and silence detection |
| **M5: packaging** | MSI, .deb, .rpm, SBOM, reproducible release builds |
| **M6: domain / collector (Model B)** | WEF and forwarding guides, GPO templates, collector mode |
| Later | Optional `serve` viewer, report signing, Splunk ingestion notes |

---

## 12. Open questions (answered)

The answers are in section 13. The original questions were:

1. Report schedule: weekly for everyone, or does it vary by system?
2. Does anyone other than the ISSO and ISSM review reports, for example
   custodians?
3. Should `install` offer to apply the STIG audit baseline, or only report
   what is missing? Some sites need configuration changes to go through
   change control.
4. What classification banner text and colors should the defaults use?
5. Are there existing site templates or formats that the reports should match
   for ISSM or DCSA review?

---

## 13. Decisions

| Topic | Decision |
|---|---|
| Report schedule | Windows LAN hosts currently run PowerStrux daily because a noisy tool overwrites logs within a week. Blackbox separates **collection (hourly by default, `--collect-every`)** from **reporting (`report_every`: daily/weekly/monthly, default weekly)**. Hourly collection captures events before rollover, so weekly reports lose nothing. Linux reports are weekly. |
| Reviewers | ISSO/Auditor, then ISSM. Reviews are recorded on a separate platform and reports are not printed, so the report has **no signature or review section**, and `blackbox review` is dropped from the roadmap. |
| Audit baseline | **Report only.** `check` and the report's health panel show what is missing and the command that fixes it. Blackbox never changes settings. |
| Classification banner | Not needed, and removed. |
| Report layout | **`report.html` plus its data folder**, designed for a desktop and locked in [redesign/SPEC.md](redesign/SPEC.md) (October 2026): a glassy navy look with sharp edges, Public Sans and Source Code Pro, Lucide icons, and severity shown as colored text with a small square marker. |
| Report template | No existing template needs to be matched. |
| Config format | Plain `key = value`, not YAML. This keeps the module at zero third-party dependencies. |
| Report chain | Each report covers the time up to its period end and includes every event not already reported. Events collected late, for example from before a system was powered off, go into the next report marked *Late*. Every event appears in exactly one report (`app.SelectWindow`). |
| Log volume | Every report lists the busiest event IDs with their share of all events read. This identifies noisy tools and over-broad audit settings, the cause of fast rollover. |

## 13a. Design note: STIG compliance from SCAP scans (for owner approval)

*Written 3 Oct 2026 for the v0.10.1 findings (§6). Implemented as
described here; anything the owner changes is changed before release.*

**Why.** An assessor checks that the system is configured to the STIG,
not only that what the STIG audits is reviewed. Sites already scan with
DISA SCC (Windows) or OpenSCAP (Linux). Blackbox puts the latest result
next to the audit review, so the weekly report answers both questions.

**What Blackbox does, and does not do.**

- It **reads** scan results that already exist. It never bundles,
  installs or runs a scanner, never changes a setting and never
  remediates.
- Results are XCCDF 1.1 or 1.2 `TestResult` files (SCC's
  `*_XCCDF-Results_*.xml`, `oscap xccdf eval --results`) or ARF files
  (`--results-arf`), parsed with `encoding/xml`. Nothing else is needed.

**Where results come from.**

- `scap_results` (setting): a folder Blackbox searches, including
  subfolders (SCC writes `Sessions\<date>\Results\SCAP\XML`). Blank
  reads `scap` in the data folder; point it at SCC's or OpenSCAP's output
  folder instead, or `none` to turn the feature off. The table appears
  once SCAP is in use (a folder chosen, or any scan found), so sites that
  don't scan see nothing new.
- For each computer and benchmark, the newest result counts; the one
  before it gives the change since the previous scan.
- The computer is named by the result's `target` (or its `fqdn` /
  `host_name` facts), matched to systems as everywhere else.
- **Senders ship their results.** A sender delivers each new result file
  (gzip, once, by SHA-256) to the collector's inbox next to its batches,
  like its log archives. The collector keeps them under
  `scap-received\<computer>` in its data folder. Blackbox copies result
  files into a report; it never moves or changes the originals.

**What the report shows.**

- **Audit health:** a "STIG compliance (SCAP)" table, one row per
  computer: benchmark and version, profile, scan time, score, pass and
  fail counts, open CAT I / II / III, and the change since the previous
  scan (newly open, newly fixed, score up or down).
  - A result older than `scap_max_age_days` (default 30) is marked stale.
  - A computer with no result says "no scan found".
- **Systems:** each computer's header line adds "SCAP 94% · 1 CAT I"
  (the five facts stay as the locked design has them).
- **Overview:** open CAT I findings are a red line in the audit-trail
  checklist (with how many computers).
- **Report folder:** each result used is copied into `scap/` and listed
  in `manifest.sha256`, so the report proves which scan it showed.
  `scap-open-rules.csv` lists every open rule: computer, benchmark, CAT,
  Vuln ID, rule ID, title and the scan time. The Export menu offers it.
- CAT comes from the rule's severity: high is CAT I, medium CAT II, low
  CAT III. "Open" means `fail` or `error` (as STIG Viewer and SCC count
  them); `notchecked` and `notapplicable` are counted, not open.

**Later, only with owner approval: an opt-in scan (`scc_path`).** A
setting naming the installed SCC command line (`cscc.exe`) would let the
scheduled run start a scan before a report, read-only, with the site's
own SCC configuration. It would never install SCC, never change a
setting, and never run remediation. It is *not* implemented: running a
third-party scanner from a SYSTEM task needs its own security review.

## 13b. Proposals for the owner (v0.10.4 re-test)

*Written 5 Oct 2026. Decided 5 Oct 2026: L11 approved and implemented in
0.12.0 as below. `send --resend` is self-recorded like a setting change,
and kept copies have the outbox's protection. N2 not approved: setup and
`status` print the rule instead (see docs/lan.md).*

**L11: keep delivered batches so a sender can resend them.** Today a
sender deletes a batch from its outbox once it is copied into the inbox.
If the collector then loses inbox files before importing them, or its
data folder is restored from a backup, it reports a gap the sender can't
fill. The collector already accepts a late batch that fills a gap
(`inGap`, `fillGap`) and skips one it already has, so the change is on
the sender only:

- `keep_sent_days` (default 14): delivered batches move to `outbox/sent`
  instead of being deleted, and are removed after that many days.
  Delivered log archives and SCAP results are not kept (the archive is
  already on the collector, and the next scan replaces the results).
- `blackbox send --resend 214-219` copies those batches into the inbox
  again. The collector imports the ones in a gap and ignores the rest.
  The collector's gap warning names the batches and the command to run on
  the sender.
- Cost: about 14 days of compressed batches on each sender, typically a
  few MB. Retention still never deletes waiting (undelivered) data.

**N2: offer to allow file sharing through the firewall.** Setup and
`status` now say when Windows Firewall blocks SMB (TCP 445) in, but
Blackbox does not change it (decision 2: report, don't change settings).
An option for the owner: setup could offer, unticked by default, "Allow
file sharing from these addresses only", creating one inbound rule for
TCP 445 limited to the senders' addresses and the Private/Domain
profiles, and removing it on uninstall. Recommended only if sites ask.
Otherwise the documented command stays the way to do it.
**Not approved:** setup must not open the firewall. When SMB (or, for an
SFTP collector, the OpenSSH server on TCP 22) is blocked, setup and
`status` print the exact `New-NetFirewallRule` command for that one rule
and the Group Policy path to create it.

## 13c. Proposal for the owner: an off-box copy of the original logs (AR4)

*Written 5 Oct 2026 after the v0.12.1 re-test. Not implemented; for the
owner to decide.*

**The problem.** On a standalone computer or a collector, the original
logs (`logs-*.zip`), with each report's `manifest.sha256` and
`summary.json`, sit only in the report folders, on the same disk as
everything else. An administrator can delete them. The SACL (Windows) or
audit rule (Linux) on the folder records the deletion, but the evidence
itself is gone. AU-9(2) asks for audit records to be backed up onto a
different system or media, and AU-4(1) for them to be moved off the
system being audited. Reports and archives are also deleted with their
folder under `retention_days` (now documented in reports.md).

**Proposal: `archive_copy_to`, optional, off by default.**

- A folder path: a removable drive, a share with write-once permissions
  (the Blackbox account may create files but not change or delete them),
  or a second server's share. On Linux, an SMB or SFTP share mounted the
  way `send_to` already mounts it, with the same `soft` mount and
  `ExecStartPre` handling (L12).
- After each scheduled report, Blackbox copies that report's
  `logs-*.zip`, `manifest.sha256` and `summary.json` there, into a
  folder named like the report folder. It writes under a temporary name,
  checks each file's SHA-256 against the manifest, then renames, as it
  does for the inbox.
- It never deletes or overwrites anything there, and `retention_days`
  does not apply there: the copy is kept for as long as the site keeps it.
- A failed or incomplete copy is retried at every run. Until it succeeds,
  `status` says **ARCHIVE COPY FAILED: <report> could not be copied to
  <path> since <time>: <reason>** and exits with code 4, and the next
  report has an Audit health warning naming the report folders not yet
  copied.
- `blackbox verify <copy folder>` checks a copied folder the same way as
  a report folder (the manifest covers the zips and `summary.json`).
- Setup gets one optional field, "Also copy the original logs to", next
  to the reports folder; `config set archive_copy_to <path>` does the
  same.

**What it costs.** One more folder to set up per site, and the space of
the zips (a few MB a day per Windows computer). No new dependencies:
it is a file copy with the existing hashing.

**What it does not do.** It does not make the copy tamper-proof by
itself: that depends on the target (write-once permissions, a removable
drive kept elsewhere, or a server administered by someone else). It does
not copy `report.html` or the event data, which can be made again from
the original logs.

## 14. M1 implementation status

**Done:**

- Live collection from the Windows Event Log API
  - Logs read: Security, System, Partition/Diagnostic,
    Kernel-PnP/Configuration, DriverFrameworks-UserMode, Defender.
  - Collection is resumed from bookmarks.
  - Reports detect events lost to rollover and cleared logs.
- Translation of all events listed in section 4 for Windows.
  - Routine service and computer account noise is filtered out.
  - Duplicate records of the same activity from different logs are
    merged; one USB stick appears in up to four logs.
  - USB activity is attributed to the logged-on user.
  - Devices seen for the first time are flagged.
- Pattern findings: password guessing, one source trying several accounts,
  and a successful logon after failures.
- The HTML report (section 6), CSV, JSONL, `summary.json`, a SHA-256
  manifest, `verify`, and an index page listing all reports.
- `check`, which compares the audit policy, command-line auditing, forced
  subcategories, log sizes and USB logs against the Windows 11 or Windows Server 2025 STIG (see internal/check/stig.go).
- `install` / `uninstall` (scheduled task as SYSTEM, restricted data
  folder), and `report --xml` for exported logs on any OS.

**Verification:**

- Unit tests cover translation, patterns, the report chain, the store,
  config, checks and the task definition.
- CI runs the tests on Linux and Windows. It also runs `check`, `collect`,
  `report` and `verify` against the Windows runner's real event logs.

**Next:** M2 (Linux) — done, see section 15.

## 15. M2 implementation status (Linux)

**Done:**

- **auditd reader** (`internal/linuxlog`):
  - Parses `key=value` records, including hex-encoded values, the nested
    `msg='…'` part of user-space records, and ENRICHED name fields.
  - Groups multi-record kernel events by serial number until the EOE
    record.
- **Plain-English translation** of logons, failed logons, lockouts
  (pam_faillock), sudo (commands, refusals, root shells), su, setuid
  programs, commands inside root shells, account and group changes,
  password changes, and edits to sudoers and `/etc/passwd` made outside the
  account tools.
  - Also: auditd start/stop, audit rule changes, auditing disabled, time
    changes, kernel modules, promiscuous mode, AppArmor/SELinux denials,
    and SELinux switched to permissive.
  - Activity with no logged-in user behind it is left out, except changes
    to sudoers, the account database and log files, which are reported
    whoever makes them.
- **USB from kernel messages:** make, model, serial and capacity; USB
  network adapters (tethered phones, Wi-Fi dongles); and who mounted each
  device (udisks).
- **Syslog formats:** traditional (Ubuntu 22.04, Alma), RFC 3339 (Ubuntu
  24.04) and journalctl output.
  - The journal is used when there are no syslog files.
  - auth.log/secure is used only when auditd is missing, so nothing is
    reported twice.
- **Bookmarks for text logs:** inode, byte offset, and a fingerprint of the
  file's first bytes. Blackbox follows rotation (Ubuntu `.1` and Alma
  date-suffixed names) and detects truncation. It reports data rotated
  away before collection, and audit records the kernel dropped (the
  `auditctl -s` lost counter).
- **Report additions:**
  - a finding for how long auditing was off
  - removable devices attributed to whoever mounted them, otherwise to
    whoever was logged on at the console (never a remote session)
  - auditd record types in the busiest-events table
- **`check` on Linux:**
  - auditd running
  - loaded rules against the needed set (accounts, sudoers, setuid
    programs, root commands, modules, mounts, time, audit configuration)
  - rules locked (`-e 2`)
  - backlog size
  - `log_format`
  - `audit=1` at boot
  - a persistent system log
  - `check --audit-rules` prints a recommended rules file.
- **`install` on Linux:** a systemd timer plus a sandboxed oneshot service
  (`PrivateNetwork`, `ProtectSystem=strict`, writes only to
  `/var/lib/blackbox`).

**Verification:**

- Unit tests with a synthetic Ubuntu day (`testdata/linux`), covering
  Ubuntu and Alma auth-log lines, syslog timestamp formats, and rotation,
  truncation and lost-rotation handling.
- The `linux-live` CI job installs auditd with the recommended rules on a
  real Ubuntu machine, makes account and sudoers changes, then collects,
  reports and checks that the report contains them.

**Not yet:**

- A real AlmaLinux run. Unit tests cover its log formats, but it has not
  been run on a live Alma system.
- dnf and dpkg software install history.
- Files copied to USB on Linux. That needs auditd watches on mount points,
  which the STIG does not require.
