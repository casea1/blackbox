# Blackbox 0.10.1: test plan (Windows collector + Ubuntu sender)

Machines are Umbrel VMs on an isolated private network (no port forwards):

| VM | OS | Role | Address |
|---|---|---|---|
| windows-11 | Windows 11 25H2 | Collector, inbox shared as `\\<WIN>\BlackboxInbox` | 10.203.0.2 |
| ubuntu-server | Ubuntu 26.04 LTS (not on the supported list) | Sender over SMB (cifs) | 10.203.0.3 |

All driving is through the VM consoles (keyboard, mouse, screenshots). Times in the activity log are UTC.

## 1. Install and setup
- [ ] Windows: setup window, "This is the collector", share on network, `bbsend` in Blackbox Senders
- [ ] Ubuntu: auditd + recommended rules, `blackbox check`
- [ ] Ubuntu: `install.sh`, "Send to a collector", `//10.203.0.2/BlackboxInbox` (and by name)
- [ ] First delivery arrives; collector `status` lists both systems; Systems page shows both

## 2. 0.10.1 fixes, re-checked
- [ ] C1 lost events show in `status` and the tray (amber)
- [ ] C3 refused sender: status says "no batch since …" after two hours; uninstall keeps the group
- [ ] C4 one Linux sign-in = one row (ssh to localhost inside the VM)
- [ ] C5 audit settings re-checked after restart; Audit health shows when checked
- [ ] C6 planned reboot of the sender is Info, not High
- [ ] D1 fast guessing (5 in 1 s) detected; one source, several accounts
- [ ] D2 `$` accounts keep their 4624/4672
- [ ] D3 exclusions: attacks on an excluded account still detected or disclosed
- [ ] D4 hidden / bypass / encoded PowerShell flagged
- [ ] R1 CSV formula prefix in every CSV
- [ ] R3 `#` in a setting round-trips
- [ ] R5 summary.json PowerShell key
- [ ] R6 verify fails on added files / manifest missing report.html
- [ ] R7 short interim report doesn't call the sender silent
- [ ] Setup window S1–S10 (spot checks)

## 3. Collector/sender behaviour
- [ ] Collector off: sender queues, catches up, nothing lost
- [ ] Share down / marker missing: never mistaken for inbox
- [ ] Batch deleted from inbox: gap reported
- [ ] Batch altered: set aside in `inbox\rejected`, gap reported
- [ ] Same batch delivered twice: counted once
- [ ] Sender clock ahead: reported
- [ ] Clean shutdown delivers last events (`blackbox-shutdown.service`); hard power-off doesn't
- [ ] `blackbox systems remove`

## 4. Linux detections (sender)
- [ ] sudo / su / root shell; failed sudo
- [ ] useradd, add to sudo group, userdel (created-then-deleted)
- [ ] sudoers and /etc/passwd edits
- [ ] password guessing over ssh; spraying across accounts
- [ ] auditctl rule change; auditd stop
- [ ] time change; kernel module load
- [ ] log rotation / audit.log rotated away

## 5. Windows detections (collector)
- [ ] failed logons, guessing, admin group add/remove, account create/delete
- [ ] scheduled task, service install
- [ ] PowerShell (encoded, IEX)
- [ ] `$` account; exclusions

## 6. Reports
- [ ] Overview, Systems, Detections, Search, People, event pages, Audit health, Trends, Original logs
- [ ] Linux original logs zip in collector's report
- [ ] Exports (CSV, print); `blackbox verify`; tamper → red

## 7. ISSO / ISSM review (AU, AC, CM, SI controls)
Live, on the VMs, as an ISSO would check before relying on the tool for the weekly review:
- [ ] AC-2 account lifecycle, both OSes: create, enable/disable, password reset by admin, rename, lockout/unlock, delete; added to/removed from each privileged group (Administrators, Remote Desktop Users, Backup Operators; sudo, adm, wheel-like)
- [ ] AC-7 lockout after N failures (Windows `net accounts /lockoutthreshold`, Linux pam_faillock)
- [ ] AC-6(9) privileged functions: runas/4648, sudo -i, su, pkexec; failed sudo by non-sudoer
- [ ] AU-5 audit failure: Security log full/overwrite, auditd stopped, `auditctl -e 0` (locked), audit events dropped
- [ ] AU-6 everything the STIG makes us collect is visible somewhere (A1–A3 live)
- [ ] AU-8 time change by an admin (4616, Linux time-change)
- [ ] AU-9 protection of audit info: clear logs (1102/104), delete /var/log files, edit Blackbox config/exclusions, disable Blackbox task/timer, delete Blackbox bookmarks; does the report say who did it?
- [ ] AU-11 retention: `retention_days` behaviour, original-log archives kept
- [ ] CM-5/CM-11 changes: service install, scheduled task, software install (MSI), firewall off, Defender RTP off / exclusion added
- [ ] SI-3 Defender detection (EICAR test string)
- [ ] Off-hours admin activity with `working_hours` set
- [ ] People page as an account review; Search as an investigation tool (by person, system, time, text)
- [ ] Report usable as review evidence: period covered, systems covered, gaps stated, hashes verify
