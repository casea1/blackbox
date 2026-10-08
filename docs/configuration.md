# Configuration

The settings file is `C:\ProgramData\Blackbox\blackbox.conf` on Windows
and `/etc/blackbox/blackbox.conf` on Linux. It is a plain `key = value`
file:

- lines starting with `#` are comments
- lists are comma-separated
- changes take effect at the next collection or report, including one you run now with `blackbox report`
- an upgrade rewrites the comments to the new version's, keeping every
  setting as it is (CONF1b); the file as it was, with any comments of
  your own, is kept next to it as `blackbox.conf.old`. A later upgrade
  never overwrites that file: it keeps its own copy as
  `blackbox.conf.old.<version>`, named after the version upgraded to (SEC3c)

| Setting | Default | Meaning |
|---|---|---|
| `site_name` | *(blank)* | Name shown at the top of reports |
| `report_every` | `weekly` | `daily`, `weekly` or `monthly` |
| `report_at` | `Wednesday 00:00` | When each report period ends and the report is produced. Weekly: a day and time; `Wednesday 00:00` covers each week up to Tuesday night, so a fresh report is ready on Wednesday morning. Daily and monthly: a time such as `06:00` (monthly periods end on the 1st) |
| `report_dir` | *(blank = default)* | Folder for reports. Any full path Blackbox can write to, including one you have locked down |
| `archive_dir` | *(blank = `archives` in the data folder)* | Folder where the original logs (this computer's and, on a collector, every sender's) wait until the next **scheduled** report moves them into its folder; with weekly reports that is up to a week of logs. Choose a larger volume for many computers, e.g. `D:\BlackboxLogs`. Setup asks for it. A new folder is created for administrators only; an existing one keeps its permissions. Archives already waiting where it was go into the next report from there |
| `collect_every` | `15m` | How often events are collected (15 minutes since 0.12: a STIG-audited Security log can fill within an hour). An upgrade keeps the old value, often `1h`; while events are being lost to rollover, `status` and the report give the command to change it (only when collecting more often would help: a log that turns over faster than collection needs to be larger, and they say by how much, LOG1). `blackbox config set collect_every 15m` changes it and the schedule (the scheduled task or `blackbox.timer`); it must divide an hour or a day evenly |
| `retention_days` | `0` | Days to keep reports and collected events; `0` keeps them forever. A report is removed once its period ended more than this many days ago (its period end, from the report ledger or its `summary.json`, not the folder's date; a folder with no readable period end is kept). A report folder holds the original logs (the daily archives) for its period, so they are deleted with it. Original logs not yet in a report (waiting in `archive_dir`, set aside, or delivered by a sender) are never deleted; once older than `retention_days`, `status` and the report point them out. Take the period from your site's records schedule (the NARA General Records Schedule or your DoD component's records schedule; ask your ISSM), not from AU-11, which leaves it to the organization, and do not set it while a legal hold covers these records. `config set` always asks you to type `yes` (or add `--yes` in a script). The next scheduled report lists the reports that were removed |
| `exclude_users` | *(none)* | Accounts whose routine activity is left out of reports, e.g. `svc_backup, CORP\svc_scanner`. Failed logons against them, changes to them and anything Medium or above are always shown (see [Exclusions](reports.md#detections)) |
| `exclude_processes` | *(none)* | Programs to leave out, by name or full path, e.g. `scan.exe` |
| `scap_results` | *(blank)* | SCAP scan results to show each computer's STIG compliance ([STIG compliance](reports.md#stig-compliance-scap)). Blank reads the `scap` folder in the data folder; set a folder (for example SCC's results folder) to read that instead, including its subfolders, or `none` to turn this off. Setup asks for it (the **SCAP results** page). Blackbox only reads results; it never runs a scan |
| `scap_max_age_days` | `30` | A scan older than this is marked stale |
| `keep_sent_days` | `14` | On a sender: days to keep batches after delivering them, so `blackbox send --resend FROM-TO` can fill a gap the collector reports. `0` deletes them once delivered, which ends resends: `blackbox config set` says so Kept batches are a few MB and only in the data folder |
| `working_hours` | *(blank)* | When administrator activity is expected, e.g. `Mon-Fri 06:00-18:00`, `Daily 07:00-19:00` or `Mon-Fri 22:00-06:00` (a night shift). Activity outside these hours is shown under [Detections](reports.md#detections). Blank turns the check off |
| `people_aliases` | *(blank)* | Account names spelled differently on different systems that are one person, shown as one row on the report's [People](reports.md#people) page, e.g. `jlee=j.lee,jlee2; mchen=m.chen` (`name=other,other`, groups separated by `;`). Names are matched without case and without a system or domain prefix. Accounts with the same name on several systems are always one row; this is only for other spellings. The merged spellings are marked in the person's "Accounts named" table |
| `data_dir` | platform default | Where reports and collected events are stored |
| `send_to` | *(blank)* | The collector's inbox this computer sends to: `\\COLLECTOR\BlackboxInbox` (Windows), `//COLLECTOR/BlackboxInbox` or `/media/sf_BlackboxInbox` (Linux). When set, this computer makes no reports of its own. See [lan.md](lan.md) |
| `share_user` | *(blank)* | Account on the collector for `send_to`. The password is never in this file: it is stored encrypted (Windows) or root-only (Linux) by the installer |
| `inbox` | *(blank)* | Makes this computer a collector that receives other computers' events in this folder |
| `new_senders` | `accept` | On a collector: what happens to a computer's first signed delivery. `accept` takes it and pins the computer to its key (`blackbox status` names it as a new sender); `hold` keeps its deliveries in `inbox/rejected/held` until `blackbox senders approve NAME`. Setup's checkbox **Accept new computers automatically** (ticked) is `accept`. See [How the inbox is protected](lan.md#how-the-inbox-is-protected) |
| `require_signed` | `no` | On a collector: `yes` refuses unsigned deliveries (senders before 0.24). With `no`, this release's default, they are taken from a computer that has never delivered signed, and `blackbox status` lists them to upgrade. The next release makes `yes` the default |

The easiest way to change settings is to run the installer again: it shows
the current values as defaults. To change one setting from a script:

```
blackbox config set report_dir D:\AuditReports
blackbox config set report_every daily
blackbox config set report_at "Thursday 06:00"
blackbox config set working_hours "Mon-Fri 06:00-18:00"
blackbox config set people_aliases "jlee=j.lee,jlee2"
```

`blackbox config set` checks the value before saving it:

- For `report_dir` and `archive_dir`, it also checks the folder is
  writable, and on Linux lets the service write there.
- For `send_to` and `inbox`, it sets up the share, mount or inbox folder.
  A new share password is read from `BLACKBOX_SHARE_PASSWORD`.
- `none` clears a LAN setting, `exclude_users`, `exclude_processes`,
  `working_hours` or `people_aliases` ("Cleared exclude_users.").
- `retention_days` (any value but 0) asks you to confirm by typing `yes`;
  in a script, add `--yes`. The prompt says what is deleted, that the
  period comes from the site's records schedule (ask your ISSM), not
  AU-11, and not to set it under a legal hold; below 365 days it also
  says the period is less than a year.

Run `blackbox config` to see the current settings, and `blackbox status` to
see whether everything is working.

## One run at a time

Each run (the scheduled collection, `send`, a manual report, `config set`)
takes `blackbox.lock` in the data folder, so two never work on the data at
once; one started while another runs waits for it (a scheduled run up to
10 minutes). Since 0.18 this is an operating-system lock (`flock` on Linux,
`LockFileEx` on Windows) held for the life of the run: a run that crashes,
is killed (`kill -9`, the out-of-memory killer, Task Manager) or loses power
leaves nothing behind, and the next run starts normally. The file also holds
the process ID and start time of the run holding it. (Before 0.18 a run that
died left the file, and collection stopped silently for up to two hours,
LOCK1.)

A run that hangs still holds the lock. When a scheduled run gives up waiting
for it:

- `blackbox status` says "Collection is blocked: a run has held the lock
  since <time> (PID n)", with the command to end it, and exits 4;
- the status icon turns red and says the same;
- the next run that collects records the gap, and the next report's Audit
  health shows "Collection was blocked" for that system, with the times
  (on the collector too, for a sender).
