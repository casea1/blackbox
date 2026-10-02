# Blackbox 0.10.0: testing the tool as a collector (DSK1 + claude-code)

Tested 2 Oct 2026, 13:45–15:10, on DSK1 (Windows 11, collector) with claude-code (Linux sender, version 0.9.2, delivering over the `\\DSK1\BlackboxInbox` share from 192.168.1.11).

Every test action is timestamped in [test-activity.log](test-activity.log). Reports made during testing are in `C:\IT\Blackbox\2026-10-02_1358_*`, `…_1400_*` and `…_1403_*`.

"Confirmed" means seen live. "Code only" means taken from the source, not reproduced here.

## Data collection

| # | Finding | Status |
|---|---|---|
| C1 | **Events are being lost every hour, and only the report says so.** The Security log is 20 MB and fills in about **41 minutes**. Most of the volume is noise: 4673 from MSI's `LEDKeeper2.exe`, and 4656/4658/4690 from Handle Manipulation auditing, which the STIG doesn't require. Collection runs every 60 minutes. `blackbox.log` shows, for example, "Security: 17925 events were overwritten before they could be collected", and the PowerShell log lost 892 and then 1,200. The report shows it ("151,106 events were overwritten"), but **`blackbox status`, the tray icon and tray notifications never mention it**. An admin watching the tray sees an amber icon for audit settings only. **Suggestion:** treat ongoing loss as amber or red in status and tray, and suggest collecting every 15 minutes or point to the noisiest event IDs and processes. | Confirmed |
| C2 | **Bookmarks are correct.** Counting the Security log by record ID showed no gaps and no double reads between runs. Manual `blackbox report` runs also collect and move the bookmark forward, as designed. | Confirmed OK |
| C3 | **A sender can silently stop delivering.** After the reinstall, claude-code's SMB session still carried the old "Blackbox Senders" group, which had been deleted and re-created with a new SID. Its 14:05 delivery was refused (SMB event 1006, Access Denied). Nothing on the collector reported it: `status` still showed claude-code as fine. The installer does say "takes effect at that account's next sign-in", but a Linux CIFS mount never signs in again on its own. Fixed by closing the SMB session on DSK1 (see the end of this file). **Suggestion:** have uninstall keep the group, or have install reuse its SID; and have the collector's status show "no batch since X" earlier than the quiet threshold. | Confirmed |
| C4 | **Linux sign-ins are counted two or three times.** Before auditd was installed, every SSH logon and logoff from `auth.log` appears **3 times** with the same second, user and IP: 83 logon rows, only 36 unique. Probably sshd, pam_unix and systemd-logind each produce a row. With auditd, each logon still appears **twice** (records 298 and 299). This inflates Logon activity, People and the trends. | Confirmed (cause not checked on the Linux box) |
| C5 | **Stale audit settings for the sender.** Audit health says claude-code's auditd is "inactive" and `audit=1` is "Missing". Yet the same report has auditd records from claude-code after its 11:31 reboot, and its sudo history shows `update-grub` just before. The tray's "2 settings to fix on claude-code" comes from this. | Confirmed in the report data; the Linux side was not checked (no SSH) |
| C6 | **Planned reboot raises a High.** `sudo reboot` on Linux gives a High "auditd was stopped by root – events are not recorded while it is stopped". A clean shutdown shouldn't count as audit tampering. | Confirmed |
| C7 | **The command-line install doesn't start the tray.** After `install --yes`, no tray runs until the next logon; the window install starts one straight away. | Confirmed |

## Detections and filtering

| # | Finding | Status |
|---|---|---|
| D1 | **Fast password guessing goes undetected.** 5 wrong passwords for Administrator within 1 second were merged into **1 row**, with no detection. The same attempt with 6 tries 3 seconds apart gave High "Possible password guessing". Failed logons are merged within a 2-second window before detection runs (`internal/report/build.go:363`, key `authfail|<user>`), and real guessing tools are fast. 13 failures for 9 accounts within 1 second also gave no "one source tried several accounts". | Confirmed |
| D2 | **Accounts ending in `$` leave no logon trace.** `bbhid$` was created, added to Administrators, signed in over the network, then removed. Windows logged the 4624 (type 3) and 4672 (admin rights). **The report has neither.** It shows only the account changes and a 4648 row. Machine-account filtering drops anything ending in `$` (`translate.go:1208`). | Confirmed |
| D3 | **Exclusions hide attacks on the excluded account.** With `exclude_users = bbtest`, 12 failed logons, 6 against `bbtest` and 6 against **`OTHERDOMAIN\bbtest`**, produced **0 rows and 0 detections**, though both bursts meet the guessing threshold. The report never says anything was excluded. Exclusions are applied to the target account and before detection, and the short name matches any domain. | Confirmed |
| D4 | **Hidden, policy-bypassing PowerShell isn't flagged.** `powershell -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand …` is collected and helpfully decoded, but filed as a plain "ran with administrator rights". `IEX (New-Object Net.WebClient).DownloadString(…)` *is* flagged. | Confirmed |
| D5 | Working correctly: created-then-deleted account (High); Administrators add and remove (4732/4733); scheduled task create and delete (4698/4699); service install (7045 and 4697); failed logons with reason and sub-status. | Confirmed OK |
| D6 | One service install shows as **two rows**: 7045 under its display name "Blackbox Test Service" and 4697 under its service name "BBTestSvc". It reads like two different services. | Confirmed (minor) |
| D7 | Removing a user also gives "removed bbtest from the group **None**" (4729, the default primary group). This is noise. | Confirmed (minor) |
| D8 | Only **elevated** process starts (4688) are kept, so anything run by a non-admin account isn't in the report at all. This may be intended, but it isn't stated in the report. | Code and live (all 4688 rows are elevated) |
| D9 | Could not test without changing audit policy or clearing logs, which I agreed not to do: "covering of tracks" only fires on log clears (`detect.go:46`); `wevtutil cl` isn't matched when PowerShell quotes the program path; 4719 with Subject=SYSTEM is downgraded. | Code only |

## Reports, exports and configuration

| # | Finding | Status |
|---|---|---|
| R1 | **CSV injection.** A failed logon with username `=HYPERLINK("http://example.invalid","bb")` ends up in `events.csv` (inside `events.zip`; it's the report's "All events as CSV") as `"=HYPERLINK(…)"` in the `user` and `target` columns. Excel runs it as a formula. Anyone who can attempt a logon can put this into an auditor's spreadsheet. **Fix:** prefix fields starting with `= + - @` with `'`. | Confirmed |
| R2 | **HTML escaping is fine.** A username of `<img src=x onerror=alert(1)>` shows as plain text in Failed logons, People and Search, with no injected element and no script run. | Confirmed OK |
| R3 | **`#` in a setting cuts it short without warning.** `blackbox config set site_name "HOME-LAB #2"` says "Saved site_name = HOME-LAB #2", but reads back and reports as `HOME-LAB`, because ` #` starts a comment (`config.go:128`). | Confirmed |
| R4 | `config set` says changes take effect "at the next scheduled run", but `blackbox report` used them immediately. | Confirmed (minor) |
| R5 | **`summary.json` has no PowerShell category.** PowerShell events are counted under `other_security`, so it says other_security=3 while the HTML says Other security 0, PowerShell 3. | Confirmed (minor) |
| R6 | **`blackbox verify` checks only the files listed in an unsigned manifest.** Editing `summary.json` and updating its hash, or deleting `events.zip` and its line, should still verify. My live test of this was blocked by the session's permission check. | Code only |
| R7 | **Short interim reports call senders "Silent".** A 1-minute report flags claude-code because it sends hourly. | Confirmed (minor) |
| R8 | Late or out-of-order batches are dropped and the gap is never cleared (`receive.go:192/241`). Linux account deletions show as "uid N" across runs. A sender whose clock ran ahead stays "fresh". | Code only (needs the sender) |

## Not tested

- **Anything run on claude-code:** I couldn't SSH in. 192.168.1.11 drops ping and port 22 from DSK1, and `claude-code` only resolves through Tailscale, which is stopped here.
- **Log clearing, audit-policy changes, Defender tampering:** these would change system settings.

## What I changed and put back

- **Blackbox:** reinstalled as a collector with the original settings: `C:\IT\Blackbox`, inbox `C:\BlackboxInbox` shared as `BlackboxInbox`, `Austin` in "Blackbox Senders", weekly on Friday at 12:00, collecting hourly.
- **Test objects:** `bbtest` and `bbhid$` (with their Administrators membership), `\BBTestTask` and `BBTestSvc` were created and deleted. None remain.
- **Settings:** `exclude_users` and `site_name` were changed for testing and put back.
- **SMB session:** I closed claude-code's stale session so its mount reconnects with the new group.
- **Files:**
  - New reports in `C:\IT\Blackbox`: `…_1358_…`, `…_1400_…`, `…_1403_…`.
  - One interim report in `C:\ProgramData\Blackbox\reports`, from the earlier standalone test.
  - A copy of one report in `E:\Claude\Blackbox-Testing\probe`.
  - A local preview server config in `E:\Claude\Blackbox-Testing\.claude\launch.json`.

  The test reports in `C:\IT\Blackbox` are in your report index. Say if you want them removed.
