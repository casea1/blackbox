# Blackbox

<img src="internal/brand/logo.png" alt="GE Aerospace" width="72" align="right">

**Plain-English audit log reports for air-gapped Windows and Linux systems.**

Blackbox reads your Windows event logs and Linux audit logs every 15 minutes. On
a daily, weekly or monthly schedule it turns them into a single HTML report
an auditor can actually read. No server, no database, no dependencies,
and nothing listening on the network. One PC, a PC with Linux VMs, or a
whole air-gapped LAN can be covered by one report.

**[⬇ Download the latest release](https://github.com/casea1/blackbox/releases/latest)** · [Windows guide](docs/windows.md) · [Linux guide](docs/linux.md) · [Security review notes](docs/security.md)

![Blackbox report overview](docs/images/overview.png)

## Why Blackbox

- **Readable.** Events come out as sentences, not raw event IDs:
  - `4625 0xC000006A LogonType 3` becomes "Failed logon for administrator
    over the network from 10.1.1.99 — wrong password."
- **Focused.** Events are grouped the way auditors review them:
  privileged activity, USB, failed logons, account changes, and audit
  integrity. Each category is tagged with the NIST SP 800-53 controls it
  supports.
- **Nothing lost.** Logs are read every 15 minutes, so busy systems can't
  overwrite events before they're collected. The report says when events
  were lost, a log was cleared, or auditing was switched off.
- **Flags what matters.** Blackbox detects password guessing, new USB
  devices, users added to admin groups, audit tampering and more, and
  lists them first.
- **Easy to approve.** It's one small program with no third-party code. It
  only reads logs and never writes to them. It opens no ports and never
  listens on the network; on a LAN it only copies files to a shared folder.
  Every report is SHA-256 hashed so tampering can be detected.

## Supported systems

| | |
|---|---|
| Windows | Windows 11, Windows Server 2025 |
| Linux | Ubuntu 22.04 and 24.04, AlmaLinux 8.10 (auditd recommended, as the STIG requires) |

## Install

Nothing else needs to be installed first: no Go, no .NET, no runtime of any
kind.

**Windows:** download `Blackbox-Setup-<version>.exe` from
[Releases](https://github.com/casea1/blackbox/releases/latest), double-click
it, and answer the questions in the setup window. The same file upgrades
an installed Blackbox.

**Linux:**

```sh
tar xzf blackbox-<version>-linux-amd64.tar.gz
cd blackbox-<version>-linux-amd64
sudo ./install.sh
```

Setup asks a few questions, each with a default you can accept by pressing
Enter. First it asks how this computer's events will be reviewed: on this
computer, or by a collector (see [Several computers](#several-computers)).
For a single computer it then asks:

- a site name
- how often to produce reports
- where to save them (any folder, including one you have locked down)
- how often to collect events

It then schedules collection, checks your audit settings against the DISA
STIG (it never changes them), and produces the first report. Run
`blackbox status` as an administrator at any time to check it is working. On
Windows, administrators also get a status icon by the clock that shows
whether collection is on schedule and what needs looking at.

**To change settings later**, such as moving reports to another folder,
run the installer again. It shows your current settings as the defaults.
On Windows, Blackbox appears in **Settings → Apps**, where it can be
uninstalled like any other program.

## Several computers

A Linux VM on a Windows PC, or a whole air-gapped LAN, can be reviewed in
one report. One computer, the **collector**, produces the reports. The
others send their events to its inbox folder every 15 minutes:

- a VM uses a VirtualBox shared folder
- LAN computers use an ordinary Windows share

Nothing listens on the network, and a computer that is off catches up when
it is back on. The report's **Systems** page shows every computer and
flags any that stopped sending.

Set up the collector first: run the installer and choose **This is the
collector**. Then run it on each other computer and choose **Send to a
collector**. The [LAN guide](docs/lan.md) walks through each setup.

![Systems page of a combined report](docs/images/lan-systems.png)

## Reports

Reports are written to `C:\ProgramData\Blackbox\reports\` on Windows and
`/var/lib/blackbox/reports/` on Linux, or to the folder you chose during
setup. Open `index.html` there for the list of all reports. Each report is a
folder; open its `report.html` in any browser (it works offline, from a
local folder or a file share). Its pages:

| Page | Shows |
|---|---|
| **Overview** | Stat cards with twelve-week trends, important events, every system's health (antivirus definitions included), the latest detections, and **What changed**: the biggest moves against earlier reports, across the network, each system and each person |
| **Systems** | Every computer (servers, workstations, VMs), problems first: its collection this period, health, activity against a typical system, its detections |
| **Detections** | Each detection explained: why it was flagged, what happened in order, who was involved, and the exact events |
| **Search** | "Show [events] by [person] on [systems] during [days] containing [text]", plus eight common searches |
| **People** | Every account that did something, grouped Needs a look / Administrators / Service accounts / Users, with when they were active (click an hour for its events or detections) and their activity over time |
| **Event pages** | Privileged activity, USB & removable, Failed logons, Accounts & groups, Audit integrity, PowerShell, Other security and Logon activity: stat cards, events per day, top six, what was flagged, and every event of that kind, filterable, with the full original event one click away |
| **Audit health** | Every system against every STIG audit check, the antivirus on each (Defender or ClamAV) with its definitions date, the gaps and where to fix them in Group Policy, and each system's settings (Blackbox only reports these; it never changes them) |
| **Inventory** | Each system's make, model and serial number, its drives with their serial numbers, and its user accounts (last four digits of the SID), as a page and a CSV |
| **Trends** | This week against the last twelve, detections per system by week, and privileged actions per person by week |
| **Original logs** | The raw logs the report was made from, one zip per system, with hashes |

Export prints a one-page summary (or saves it as PDF), or saves the
detections, every event, or the audit health check as CSV. **Verified**
shows the report's hash checks; a changed file turns it red.

**Detections** point out patterns across events, the kind a SIEM
correlates: password guessing and spraying across computers, access set up
and then the logs cleared, accounts created and deleted within a day,
administrator activity outside working hours, a new USB device followed by
admin activity, and the first time a person logs on to a computer, uses
administrator rights on it, or logs on from a new address. They use only
the events already collected, so they add no storage or network traffic.
[All detections →](docs/reports.md#detections)

**Original logs** are kept as well. Each report's folder holds the logs it
was made from, unaltered: Windows `.evtx` files and the Linux audit and
system logs, one zip per computer, with a SHA-256 for every file. This works
on a standalone computer and on a collector. [More →](docs/reports.md#original-logs)

Each report also comes with `events.zip` (every event as a spreadsheet for
Excel) and a `manifest.sha256`. [More about reports →](docs/reports.md)

## Try it without installing

Blackbox can build a report from log files copied off any system, on any
OS:

```sh
blackbox report --xml security.xml                                  # Windows (wevtutil export)
blackbox report --audit audit.log --syslog syslog                   # Linux
blackbox report --xml testdata/sample-events.xml                    # built-in Windows sample
blackbox report --audit testdata/linux/ubuntu-audit.log \
                --syslog testdata/linux/ubuntu-syslog               # built-in Ubuntu sample
```

## Documentation

- [Several computers (VMs and LANs)](docs/lan.md): collector, senders, day-to-day use
- [Windows guide](docs/windows.md): install, audit settings, what is read
- [Linux guide](docs/linux.md): install, auditd setup, what is read
- [Reports](docs/reports.md): report periods, severities, detections, output files
- [Configuration](docs/configuration.md): `blackbox.conf` settings
- [Security review notes](docs/security.md): what Blackbox does and doesn't do
- [Development](docs/development.md): building, testing, releasing
- [Design](docs/design.md): architecture and roadmap

## Building from source

Blackbox needs Go 1.24 or later and has no other dependencies:

```sh
go test ./...
VERSION=0.2.0 scripts/build.sh    # packages in dist/
```

## Verifying a release

Each release has a `SHA256SUMS` file. After copying the downloads to the
air-gapped system, check them:

```sh
sha256sum -c SHA256SUMS            # Linux
```

```powershell
Get-FileHash Blackbox-Setup-<version>.exe -Algorithm SHA256   # Windows: compare with SHA256SUMS
```

When a release also has `SHA256SUMS.asc`, the checksums are signed: check
the signature on a connected machine with the project's release key,
before copying anything across:

```sh
gpg --import blackbox-release-key.asc     # the key published below
gpg --verify SHA256SUMS.asc SHA256SUMS
```

**Release key:** not published yet. Releases are signed once the
maintainer adds the key to the repository's secrets; its fingerprint
and public key will be listed here, so it can be checked against a copy
from a second source.

When the release is code-signed, `Blackbox-Setup-<version>.exe` and the
`blackbox.exe` and `blackboxw.exe` it installs carry an Authenticode
signature (Properties > Digital Signatures). `blackbox-<version>.spdx.json`
is the software bill of materials (SPDX 2.3): Blackbox and the Go
standard library, nothing else.

## License

Copyright 2026 Austin Case. Licensed under the [Apache License, Version 2.0](LICENSE).

Reports embed the [Public Sans](https://github.com/uswds/public-sans) and
[Source Code Pro](https://github.com/adobe-fonts/source-code-pro) fonts, so
they look the same on every computer without installing anything. Both are
licensed under the SIL Open Font License 1.1
([Public Sans](internal/brand/fonts/PublicSans-OFL.txt),
[Source Code Pro](internal/brand/fonts/SourceCodePro-OFL.txt)). The icons
are from [Lucide](https://lucide.dev) ([ISC license](internal/report/icons/LICENSE)).
