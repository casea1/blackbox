# Linux guide

Supports Ubuntu 22.04, 24.04 and 26.04, and AlmaLinux 8.10.

On **Ubuntu 26.04** Blackbox handles what changes there:

- OpenSSH 10's `sshd-session` and `sshd-auth`, which record no logon
  (`USER_LOGIN`) in the audit log for an SSH sign-in. Blackbox takes the
  sign-in from the session start (`USER_START`) instead, and the method
  from `auth.log` (see [SSH logons](#ssh-logons)). `blackbox check` warns
  when sshd records sessions but no logons.
- The GNU tools renamed `gnurm`, `gnucp` and so on (shown by their usual
  names).
- sudo-rs, which writes no audit record of the commands it runs
  (`blackbox check` flags it, and Blackbox reads sudo's journal lines
  instead, with or without a terminal). A sudo-rs command refused because
  the person is not in sudoers is logged nowhere.

No other software is needed. Blackbox is a single self-contained program:
there is no Go or other runtime to install.

## Install

```sh
tar xzf blackbox-<version>-linux-amd64.tar.gz     # or linux-arm64
cd blackbox-<version>-linux-amd64
sudo ./install.sh
```

Setup asks how this computer's events will be reviewed, then only what
that needs. Each question has a default you can accept by pressing Enter:

- **On this computer:**
  - a site name
  - the report schedule (daily, weekly or monthly)
  - the report folder (any full path; an existing folder's permissions
    are left as they are)
  - how often to collect events
- **Send to a collector** (a VM, or a workstation on a LAN):
  - the collector's inbox. A VirtualBox shared folder is found
    automatically; for a Windows share, setup asks for an account.
  - how often to collect events

  See [Several computers](lan.md).

Each answer is checked as you give it. See the
[Windows guide](windows.md#install) for what the questions look like.

Setup then:

- copies `blackbox` to `/usr/local/bin/`
- creates `/var/lib/blackbox/` (root only) for reports and collected
  events, and `/etc/blackbox/blackbox.conf`
- installs and starts `blackbox.timer`, which runs every 15 minutes (by default) and catches
  up after the system has been off. The service it runs is sandboxed:
  - no network access
  - a read-only view of the system
  - it can write only to `/var/lib/blackbox`, the report folder and, on a
    LAN, the folders it sends to and receives in
- checks the audit configuration and produces the first report

## Changing settings later

Run `blackbox` commands with `sudo`: its settings and data are readable by
root only, and a command run without it says so ("run it with sudo").

**Run `sudo ./install.sh` again.** It shows the current settings as the
defaults. Or change one setting:

```sh
sudo blackbox config                                  # show the current settings
sudo blackbox config set report_dir /srv/audit-reports
```

Moving the report folder also updates the service sandbox, so the
scheduled job is allowed to write there. New reports go to the new folder;
existing reports are not moved.

A report folder on NFS or CIFS works if the system mounts it (through
`/etc/fstab` or autofs). Blackbox itself has no network access.

**Unattended installs** (Ansible, scripts) use the same options as on
Windows:

```sh
sudo ./install.sh --yes --site "Lab 3" --report-dir /srv/audit-reports
```

The options are `--yes`, `--site`, `--report-every`, `--report-dir`,
`--collect-every` (which must divide an hour or a day evenly, e.g. `15m`,
`30m`, `1h`) and `--no-first-report`.

## Set up auditd

auditd records logons, sudo, account changes and audit integrity. The STIG
requires it, but **Ubuntu does not install it by default**. Without it,
Blackbox falls back to `auth.log`/`secure`, which records less.

Blackbox includes a rules file that covers everything the report needs:

```sh
sudo apt install auditd                 # Ubuntu (AlmaLinux: sudo dnf install audit)
sudo blackbox check --audit-rules | sudo tee /etc/audit/rules.d/zz-blackbox.rules
sudo augenrules --load
sudo blackbox check                     # lists anything still missing
```

Review the rules against your site's STIG checklist before using them. The
last rule (`-e 2`) locks the rules until the next reboot, as the STIG
requires.

What the rules record, beyond logons and sudo (each is a report row):

| Rules (key) | In the report |
|---|---|
| `perm_access` (EACCES and EPERM) | A person refused access to a file (Medium) |
| `perm_mod` (chmod, chown, setxattr) | Permission and owner changes: setuid or setgid set High, files under `/etc`, `/usr`, `/var/log` and other system folders Medium, the rest Low; `setcap` High |
| `delete` | Files deleted or renamed by a person (Low; system folders Medium), one row per folder |
| `logon_config` | Changes to PAM and `/etc/security` (High), `sshd_config` and the login message scripts (Medium) |
| `scheduled_jobs`, `systemd_units` | Cron jobs and systemd services or timers created or changed (Medium) |
| `blackbox` | Changes to Blackbox's settings, data, program or timer by anything other than Blackbox (High) |
| `privileged-*`, `modules`, `perm_chng` | The STIG's privileged programs, `kmod`, `setfacl`, `chacl` |
| `session`, `logins` | utmp, wtmp, btmp, lastlog and faillock |

Files written by the package manager (`dpkg`, `rpm`, `dnf`, `apt`) are
not listed: the `sudo apt …` command that ran it is. Any other keyed rule,
including your site's own, is still a row: "jsmith: the audit rule
"my_rule" recorded openat on /srv/plan.txt".

Files and folders are watched with `-a always,exit -F path=` (or `dir=`)
rules, not `-w`, as the current STIGs write them. `--missing` treats the
two as the same rule, so a baseline loaded with `-w` is not duplicated.

**Watching Blackbox itself (AU-9).** Besides the `blackbox` rules above,
commands that change Blackbox are reported High whoever runs them:
`blackbox config set` for `exclude_users`, `exclude_processes`,
`retention_days`, `report_dir`, `send_to` or `inbox` (other settings
Medium), `systemctl stop`, `disable` or `mask` of `blackbox.timer`,
`blackbox uninstall`, and deleting Blackbox's files.

Blackbox also **records its own changes** (A15): when `blackbox config
set`, setup or an upgrade actually writes a setting, it adds a row of its
own saying who (the user who ran sudo, or the login user), which setting, and the value before and after,
High for `exclude_users`, `exclude_processes`, `retention_days`,
`report_dir`, `send_to`, `inbox` and `scap_results` (others Medium). It
writes the same record to syslog/the journal with the ident `blackbox` (`journalctl -t blackbox`), so a copy exists outside its own folder. So does an administrator's decision about a sender's signing key on a collector (`blackbox senders approve`, `rekey` or `forget`, with who and why).
A scheduled report found missing or changed afterwards ("REPORT MISSING",
"REPORT CHANGED") is written there too, once per report, as a warning
(LEDGER4).
Installing, upgrading and removing Blackbox are recorded the same way. A
`config set` command line with no matching record (refused, answered
"no", failed, or the value was already set) is shown as "tried to change
… (not applied)".

**A refused delete is not a removal** (DET1). A command that deletes
Blackbox's files (`rm` of something under `/etc/blackbox`,
`/var/lib/blackbox` or `/usr/local/bin/blackbox`) is High, "deleted
Blackbox's files", when a record shows it worked. When the audit records of that program
(or of the one sudo started for it) show the kernel refusing the delete
(`success=no` with a non-zero `exit=`, such as `-13`, permission denied)
and none shows a file deleted, the row says "tried to delete Blackbox's
files (refused)", Medium, with each refused file under "Refused" in its
details; the refused-access rows of the same delete are folded into it.
It is not counted as a removal: no "Blackbox's files removed" detection,
and not a step of "Possible covering of tracks". A delete with no
record of the delete at all, only `sudo`'s and `rm`'s `execve` (a CIFS
share, or no watch rules), is "ran rm on Blackbox's files", Medium,
whether it worked isn't recorded, unless a file it names is gone at the
next Blackbox run (DET1b; see [Reports](reports.md)). Any failed change to a
file under Blackbox's folders is recorded for this, whatever the error;
elsewhere only a refusal (EACCES or EPERM) is a row.

**Changes with no one logged on.** Configuration management (Ansible or
Salt run through `systemd-run`) has no login session, so its changes name
no one. Changes to PAM, `/etc/security`, the SSH server settings,
`/etc/audit` and systemd units made that way are shown at Low ("… were
changed with no one logged on"). The tool's own log says who started it.
Software updates are left out: their sudo command is the record. A
program writing its own log that the STIG watches (sudo's
`/var/log/sudo.log`, the logon records) is not a row of its own.

**On a STIG-hardened system** (for example, one built with Ubuntu's USG
or an Ansible STIG role), most of these rules are already loaded under
other key names. Install only the ones that are missing, so nothing is
recorded twice:

```sh
sudo blackbox check --audit-rules --missing | sudo install -m 0600 /dev/stdin /etc/audit/rules.d/zz-blackbox.rules
sudo augenrules --load
```

`--missing` compares against the rules actually loaded (`auditctl -l`),
ignores key names, and leaves out watches on files that do not exist. If
the loaded rules are locked (`-e 2`), the new ones take effect at the next
reboot, and `blackbox check` says so.

The file is named `zz-blackbox.rules` so it sorts after a STIG baseline's
own files (`augenrules` reads `rules.d` in `ls -v` order). Where a rule is
in both, the STIG's key is the one recorded, which `ausearch -k` and other
tools expect. Earlier versions used `99-blackbox.rules`: `--missing` reads
it as Blackbox's own and tells you to remove it when you save the new
file, since `auditctl` stops loading at a duplicate rule. On a merged-/usr
system, `/sbin/modprobe` and `/usr/sbin/modprobe` are one file, and
`--missing` treats rules on either as the same.

> **Rules only in `/etc/audit/audit.rules`.** `augenrules` rebuilds
> `audit.rules` from `rules.d`. Rules that a tool wrote to `audit.rules`
> without a matching `rules.d` file would be dropped at the next
> `augenrules --load` or reboot. (Upstream SCAP Security Guide writes both
> files, so this is rare.) `--missing` lists exactly those rules, if any;
> save just those as `/etc/audit/rules.d/50-existing.rules` (mode 0600)
> before adding Blackbox's file. Don't copy all of `audit.rules`: the rules
> already in `rules.d` would then be loaded twice, and `auditctl` stops at
> the first duplicate.

`blackbox check` also looks for:

- `audit=1` and `audit_backlog_limit=8192` on the kernel command line.
  If they are in GRUB's settings but the running kernel doesn't have
  them yet, it says "takes effect at the next boot".
- the ENRICHED log format, which records names instead of user ID numbers
- a large enough audit backlog
- what auditd does as its disk fills (`auditd.conf`): `space_left_action`
  must tell someone (email, exec or syslog), `admin_space_left_action`
  single or halt, and `disk_full_action` and `disk_error_action` halt,
  single or syslog (SUSPEND or IGNORE stop recording without anyone
  knowing); `action_mail_acct` set
- the audit log readable only by root (log 0600 or 0640, folder 0750;
  the STIGs ask for log 0600, so this is Blackbox's advice)
- time synchronisation: a basic check that chrony or systemd-timesyncd
  is running (AU-8). It does not check the STIG's time rules
  (UBTU-24-600160 and 600180: comparing with an authoritative source
  every 24 hours and correcting a drift over one second), and the
  Ubuntu STIG forbids systemd-timesyncd (UBTU-24-100010)
- sudo-rs, which records no audit events of sudo commands, and does not
  log a refused command anywhere
- ClamAV, when installed: definitions built within the last 30 days, and
  its scanner service running (as Defender is checked on Windows). A
  scanner running in a container counts as running; a masked `clamd`
  unit (turned off on purpose) is shown for information, without
  advice to enable it. On a FIPS host, a note says ClamAV's engine is not
  FIPS 140 validated
- a system log that survives reboots

### STIG rule IDs

`blackbox check` and Audit health show each check's STIG rule ID where
the STIG for the system's distribution has one. The STIG is picked from
`/etc/os-release`:

| System | Compared with |
|---|---|
| Ubuntu 24.04 | Ubuntu 24.04 LTS STIG V1R5 (UBTU-24) |
| Ubuntu 22.04 | Ubuntu 22.04 LTS STIG V2R10 (UBTU-22) |
| AlmaLinux 9 | AlmaLinux OS 9 STIG V1R8 (ALMA-09) |
| RHEL 9 | RHEL 9 STIG V2R10 (RHEL-09) |
| AlmaLinux 8, RHEL 8 | RHEL 8 STIG V2R9 (RHEL-08; DISA has no AlmaLinux 8 STIG, so sites apply RHEL 8's) |
| anything else | no STIG: every check is Blackbox's advice |

The IDs were checked against the stigaview.com copy of each DISA release
on 8 October 2026 (the DISA library at cyber.mil could not be read by
script that day). A cited ID means the check covers the main part of
that rule; your SCAP scan is the full test.

| Check | Ubuntu 24.04 (UBTU-24-) | Ubuntu 22.04 (UBTU-22-) | AlmaLinux 9 (ALMA-09-) | RHEL 9 (RHEL-09-) | RHEL 8, AlmaLinux 8 (RHEL-08-) |
|---|---|---|---|---|---|
| auditd running | advice (100400 only asks for the package) | advice (653010 only asks for the package) | 054910 | 653015 | 030181 |
| Watch /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow | 200280, 200290, 200300, 200310 | 654145, 654130, 654150, 654135 | 005410, 005080, 005960, 005190 | 654240, 654225, 654245, 654230 | 030150, 030170, 030130, 030160 |
| Watch /etc/sudoers and /etc/sudoers.d | 900510, 900520 | 654220, 654225 | 004970, 006070 | 654215, 654220 | 030171, 030172 |
| Programs run with raised privileges (execve) | 200580 | 654230 | 007280 | 654010 | 030000 |
| Kernel module loading | 900340 | 654175 | 046660 | 654080 | 030360 |
| Filesystem mounts | 900090 | 654065 | 047650 | 654180 | 030300 |
| Unsuccessful file access | 900160 | 654165 | 048090 | 654070 | 030420 |
| chmod, chown, setxattr | 900150, 900140, 900130 | 654155, 654160, 654180 | 048530, 048640, 051390 | 654015, 654020, 654025 | 030490, 030480, 030200 |
| utmp, wtmp, btmp watched | 900600, 900590, 900610 | 654205, 654200, 654195 | advice | advice | advice |
| kmod, setfacl, chacl | 900740, 900230, 900240 | 654055, 654085, 654015 | 049300, 050180, 048200 | 654105, 654040, 654035 | 030580, 030330, 030570 |
| Rules locked (`-e 2`) | 909000 | 654240 | 057110 | 654275 | 030121 |
| `audit=1` at boot | 102010 | 212015 | 047980 | 212055 | 030601 |
| `audit_backlog_limit` at boot | advice | advice | 051830 | 653120 | 030602 |
| `log_format = ENRICHED` | advice | advice | 046880 | 653100 | 030063 |
| `space_left_action` | 900960 | 653040 | 053590 | 653040 | 030731 |
| `admin_space_left_action` | advice | advice | 053370 | 653050 | advice |
| `disk_full_action` | advice | 653030 | 054140 | 653025 | 030060 |
| `disk_error_action` | advice | advice | 054030 | 653020 | 030040 |
| `action_mail_acct` | 900980 | 653025 | 053810 | 653070 | 030020 |

Everything else (commands run as root, time changes, `/etc/audit` and
`/etc/blackbox` watched, the kernel audit backlog, audit log
permissions, time synchronisation, sudo-rs, a persistent system log) is
Blackbox's advice on every distribution. The report words it "Blackbox
recommends", not "the STIG requires", leaves it out of "Systems matching
STIG", and counts it on its own as "Blackbox's advice".

## Where things are

| | |
|---|---|
| Program | `/usr/local/bin/blackbox` |
| Settings | `/etc/blackbox/blackbox.conf` ([reference](configuration.md)) |
| Reports | `/var/lib/blackbox/reports/` by default, or the folder you chose (open `index.html`) |
| Schedule | `systemctl list-timers blackbox.timer` |
| Log of each run | `journalctl -u blackbox.service` |
| Lock held by a run | `/var/lib/blackbox/blackbox.lock` (released when the run ends, even if it is killed; see [One run at a time](configuration.md#one-run-at-a-time)) |

## What Blackbox reads

| Log | Used for |
|---|---|
| `/var/log/audit/audit.log` | Logons, failed logons and lockouts, sudo and su, root shells, account and group changes, sudoers and `/etc/passwd` edits, auditd stopped, audit rules changed, time changes, kernel modules, AppArmor/SELinux |
| `/var/log/syslog` (Ubuntu), `/var/log/messages` (Alma), or the systemd journal | USB devices from kernel messages (make, model, serial, size, USB network adapters), and who mounted them (udisks) |
| `/var/log/auth.log` (Ubuntu), `/var/log/secure` (Alma) | With auditd: sshd's sign-in lines (see [SSH logons](#ssh-logons)), and sudo-rs's commands. Without auditd: logons, sudo, su and account changes |

Each file is read from where the last run stopped. Blackbox follows log
rotation, and the report says if anything was rotated away, or dropped by
the kernel, before it could be read.

### SSH logons

Each SSH sign-in is one Logons row, with the account, the source address
and, when sshd's lines are there, the method (`password` or `publickey`)
and the key's type and fingerprint. The row is built from whichever of
these the system writes, all within a few seconds of each other:

- the audit log's logon record (`USER_LOGIN`), written by sshd on Ubuntu
  22.04 and 24.04 and AlmaLinux
- the audit log's session start (`USER_START`, `terminal=ssh`), the only
  audit record of a sign-in on Ubuntu 26.04
- sshd's `Accepted publickey for claude from 192.168.1.11 port 50522 ssh2:
  ED25519 SHA256:…` line in `auth.log`/`secure` or the journal

Each failed try is one Failed Logons row, from the audit log's password
check (`USER_AUTH`) and failed logon (`USER_LOGIN`), joined to sshd's
`Failed password …`, `Failed publickey …` or `… for invalid user …` line,
which says whether a password or a key was refused and whether the name
exists. A connection closed while signing in with no `Failed` line (how a
refused key shows at sshd's usual log level) is a failed try too. A
connection from an unknown name that tried nothing (`Invalid user` alone)
is not.

## Reporting on copied logs

Copy the logs off the system, then produce a report on any OS. Rotated
copies and `.gz` files work too:

```sh
blackbox report --audit audit.log --audit audit.log.1 --syslog syslog --passwd passwd
```

`--passwd` is optional. It turns user ID numbers into names when the audit
log is not in ENRICHED format. Give `auth.log` (or `secure`) with
`--syslog` as well to see how each SSH sign-in was made. Use `--host NAME` if the logs don't include
the host name.

## Uninstall

```sh
sudo ./uninstall.sh          # or: sudo blackbox uninstall
```

This removes the timer. Reports and collected events stay in
`/var/lib/blackbox/`.
