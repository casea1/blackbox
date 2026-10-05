You're working on Blackbox (github.com/casea1/blackbox). Your second work list shipped as 0.11.0 (#38–#42). It was re-tested on 5 Oct 2026, partly live and partly offline:

- **Live:** a fresh Windows 11 Pro 25H2 VM on Proxmox, set up as **standalone**. Tests: silent install, daily reports, the first scheduled report, tampering, a missed schedule, and a real log rollover.
- **Offline:** the 0.11.0 binary run on recorded Ubuntu logs and on the Server 2025 collector's exported event logs.

Results are in `docs/testing/2026-10-02-v0.10.1/findings.md`, sections "v0.11.0 verification" and "Windows 11 Pro 25H2, standalone, live". If that folder isn't in your checkout, this prompt is enough.

Same review lens and owner decisions as before (`docs/design.md` §13): report only, no third-party dependencies, plain-English sentences, no sign-off section.

**Confirmed fixed in 0.11.0, don't regress:**
- *Offline:* U5 (one row per try, spray detection), O1 parsing (sudo-rs without TTY), W2, W3, W4.
- *Live on Windows 11:* W1 (one system, no former name), R10 (no signature lines), A5/A15 on Windows, the folder-SACL check and the time-service check.
- *Tamper detection, with the SACL that `check` recommends:* log cleared (1102), audit policy changed (4719), settings file edited directly, the collection task disabled (4701), and a report folder deleted. All are High.
- *Scheduling:* the boot trigger catches up a missed collection, and the scheduled daily report runs.

**Owner decisions on §13b:**
- **L11, keep delivered batches for resend: approved.** Build it as written in §13b. Also:
  - `blackbox send --resend` is self-recorded like a setting change.
  - The kept copies get the outbox's protection: root/SYSTEM only, and watched by the self-audit rules and the recommended SACL.
- **N2, setup opening the firewall: not approved.** Instead, when SMB is blocked, setup and `status` print the exact command and the Group Policy path. The command is one inbound rule for TCP 445, limited to the senders' addresses and the Private/Domain profiles. When the collector is used over SFTP, the message names port 22 and the OpenSSH server instead.

Same working rules: one PR per group, tests with every fix (real-record fixtures where given), gofmt, vet on Linux and Windows, docs in the same PR, IDs in commit messages.

## 1. Clock changes (do first; T3 is High)

The test VM's clock started 3 hours fast with Windows Time stopped (a Proxmox clock setting), which is common on air-gapped PCs with no time source. Correcting the clock exposed three problems.

- **T3 (High): after the clock is set back, events are lost from reports.**
  - The previous report's period ended at 23:00 by the fast clock. After the correction, an interim report at 20:09 covered **23:00 → 20:09**: `window_start` was after `window_end`. It showed 0 events, 0 detections and "0 logs cleared", and `status` exited 0.
  - The first scheduled daily report then covered 23:00 → 00:00 and included only events collected from 23:05 on.
  - So everything collected during the backwards period is in **no report**: the Security log clear, an audit policy change, the settings file edited, the task disabled and a report deleted. The events are in the spool, so collection was fine.
  - Anyone who can set the clock forward, let Blackbox run, and set it back can hide activity until the clock catches up.
  - Fix:
    1. Choose what goes into a report by **collection order** (what was collected since the previous report: a sequence number or collection run, not wall-clock time), so nothing collected is ever skipped.
    2. Never write a period whose start is after its end or after now.
    3. Flag "the clock was moved back" (4616 by anyone, or a stored collection or report time in the future) as a High item in Audit health and in `status`, with a non-zero exit code.
  - Add a test that moves the clock back between two runs.
- **T1: collection pauses after the clock is set back.**
  - The hourly trigger's `StartBoundary` was `2026-10-04T23:05`, set by the fast clock at install. After the correction, Task Scheduler's next run stayed at 23:05, so nothing was collected for 3 hours.
  - `status` said "Last collection: 23:00 (just now)", a time 3 hours in the future.
  - Fix: give the trigger a fixed start in the past (e.g. 2000-01-01 00:05), so repetitions follow the current clock. Have each run notice a last-run time in the future, re-register the trigger, and report it as part of T3.
- **C6: a STIG-audited Windows 11 loses events by default.**
  - With File System auditing on (as the STIG requires), one Windows Update servicing run (TiWorker.exe writing under `C:\Windows\UUS`) overwrote the default 20 MB Security log (about 23,000 records) many times over within the hourly interval: **94,565 events lost**. Blackbox detected this correctly ("Events lost … Collect more often (every 15 minutes), or make the log larger"). But:
    1. `check` rates a 20 MB Security log only INFO ("not enough history yet to tell"). Confirm WN11-AU-000505's minimum in the current Windows 11 STIG (1,024,000 KB as far as we know; the Server 2025 entry uses 196,608) and FAIL below it.
    2. Standalone and collector installs default to `collect_every = 1h`, the interval `status` itself calls too slow. Default to 15 minutes.
    3. `status` exits 0 with events lost; give it a non-zero exit code, like the 24-hour delivery warning.

## 2. Noise on a fresh Windows 11 (first report: 504 rows, about 350 of them noise)

- **A13b/c/d: firewall rules Windows registers for its app packages are still rows.** Key on the account that made the change, not the rule name. Changes made by the firewall service itself, `NT SERVICE\MpsSvc` (SID `S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052`), are Windows maintaining app-container rules; a person's change carries their own SID. That one rule covers all three cases:
  - (b) 24 Medium "A Windows Firewall rule was deleted: ." with an empty `RuleName` and a `RuleId` like `Microsoft.WindowsTerminal_8wekyb3d8bbwe_S-1-5-21-…_In_emptyRemoteName_Cellular`. When `RuleName` is empty, say the rule ID rather than "deleted: .".
  - (c) In exported logs (`--xml`, `--evtx` from another PC) the service appears only as that SID, so name matching fails.
  - (d) On Windows 11 the rule names are display names, not `@{…}`: 47 Low + 15 Medium rows like "added by NT SERVICE\mpssvc: Widgets Platform Runtime" / "deleted…: Usermode Font Driver Host", with `RuleId` such as `Microsoft.WidgetsPlatformRuntime_8wekyb3d8bbweS-1-5-21-…-Out-Allow-AllCapabilities` or `microsoft.windows.fontdrvhostS-1-5-18-In-Block`.

  Keep the one Info count per day. The WinDefend service-restriction rules changed by SYSTEM during Defender updates can be counted the same way.
- **A16: Defender 5007 floods the report with its own state.**
  - 240 Low rows in the first day, like "A Microsoft Defender setting was changed: HKLM\SOFTWARE\Microsoft\Windows Defender\WdConfigHash / IsServiceRunning / ServiceStartStates / Diagnostics\… / Features\EcsConfigs\… / SpyNet\LastMAPSFailureTimeString (every minute)".
  - Keep:
    - Exclusions (paths, processes, extensions);
    - Real-Time Protection and the other `Disable*` protections;
    - tamper protection;
    - `Policy Manager` / policy keys;
    - anything that turns protection off.
  - Count the rest (Defender's bookkeeping) as one Info row per day.
  - Check `NIS\Consumers\IPS\DisableBmNetworkSensor = 0x1` specifically. It was reported High "protection turned off" by "an unknown account" on a fresh install; it looks like Defender's own platform update.
- **A17: Windows setup (OOBE) reads as an attack.** The first report on a new PC has:
  - High "SYSTEM added defaultuser0 to the privileged group Administrators". That's OOBE's temporary account, which setup creates and deletes.
  - Medium rows for image-build events under the machine name `MINWINPC` (WDAGUtilityAccount created, "MINWINPC policy" 4739, IIS_IUSRS, built-in Administrator disabled).
  - A **High "Possible covering of tracks"** detection pairing the defaultuser0 change with the Defender change above an hour later.

  Fix:
  - Show the `defaultuser0` lifecycle and `MINWINPC` events as one Info "Windows setup" row.
  - Don't let covering-of-tracks pair with Defender changing its own settings, or with SYSTEM during setup.
- **T4 (minor), from the recommended folder SACL:**
  - Deleting one report folder gives 10 High rows (two 4663 per file); make it one row: "deleted the report <name>".
  - Blackbox's own writes to the folder object itself (`C:\ProgramData\Blackbox`, no trailing path) show as Low "claude changed C:\ProgramData\Blackbox (using blackbox.exe)" about 5 times per run. The self-filter only matches paths *under* the folder.
  - A hand-run `blackbox run` adds 26 Low rows for its own child processes (`wevtutil.exe gl <log>`, `conhost.exe`). Leave out processes whose parent is Blackbox.
  - 4717/4718 (system security access granted/removed, on every logon) read "Security event 4717 (no description)". Give them a sentence, or count them.
- **T2 (check, don't assume):** 5038 High "a system file whose signature doesn't match: …\Windows Defender\Platform\4.18.26080.4-0\DefenderSessionHelper.exe" during a Defender platform update. If this is a known false positive, say so in the row rather than dropping 5038 for Defender's folder.

## 3. SCAP

- **SC3 (owner request): make the open rules viewable in the report.** Today the STIG compliance table has only counts (Open CAT I 7, CAT II 133, CAT III 4), and they can't be clicked; the system page shows only "SCAP 63% · 7 CAT I". Fix:
  - Make each count open that system's open rules: CAT I first, then STIG ID (from SC1), title and rule ID.
  - Add a "STIG compliance (SCAP)" row to each system's Health list, linking to it.

## 4. Release (owner action, not yours)

A10 still needs the owner to add `WINDOWS_SIGN_PFX_BASE64`, `WINDOWS_SIGN_PASSWORD`, `RELEASE_GPG_KEY` and `RELEASE_GPG_PASSPHRASE`, and the variable `SIGN_TIMESTAMP_URL`. Add the public key and its fingerprint to the README's "Verifying a release" section once the key exists.

## Done means

- Everything above is fixed with tests. T3 and T1 each need a test that moves the clock back between runs.
- L11 is built, and N2's message is done.
- findings.md has a "Fixed in" column for the new rows.
- The version is bumped, with the IDs in the release notes.

Still to be re-tested live after this release (not by you):
- 0.11.0's Linux items: the sudo-rs journal path, auditd-stop attribution, the sshfs outage (L8), and the 24-hour warning;
- SMB delivery between two machines, and a dead SMB mount on a Linux sender;
- a Windows sender;
- the upgrade of an existing collector.

Report anything you couldn't verify, as you did last time.
