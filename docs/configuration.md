# Configuration

The settings file is `C:\ProgramData\Blackbox\blackbox.conf` on Windows
and `/etc/blackbox/blackbox.conf` on Linux. It is a plain `key = value`
file:

- lines starting with `#` are comments
- lists are comma-separated
- changes take effect at the next collection or report, including one you run now with `blackbox report`

| Setting | Default | Meaning |
|---|---|---|
| `site_name` | *(blank)* | Name shown at the top of reports |
| `report_every` | `weekly` | `daily`, `weekly` or `monthly` |
| `report_at` | `Wednesday 00:00` | When each report period ends and the report is produced. Weekly: a day and time; `Wednesday 00:00` covers each week up to Tuesday night, so a fresh report is ready on Wednesday morning. Daily and monthly: a time such as `06:00` (monthly periods end on the 1st) |
| `report_dir` | *(blank = default)* | Folder for reports. Any full path Blackbox can write to, including one you have locked down |
| `collect_every` | `15m` | How often events are collected (15 minutes since 0.12: a STIG-audited Security log can fill within an hour). To change it, run the installer again, which updates the schedule |
| `retention_days` | `0` | Days to keep reports and collected events; `0` keeps them forever. A report folder holds the original logs (the daily archives) for its period, so they are deleted with it. Below 365 days, `config set` asks you to type `yes` (or add `--yes` in a script), since a year is the usual retention (AU-11). The next scheduled report lists the reports that were removed |
| `exclude_users` | *(none)* | Accounts whose routine activity is left out of reports, e.g. `svc_backup, CORP\svc_scanner`. Failed logons against them, changes to them and anything Medium or above are always shown (see [Exclusions](reports.md#detections)) |
| `exclude_processes` | *(none)* | Programs to leave out, by name or full path, e.g. `scan.exe` |
| `scap_results` | *(blank)* | SCAP scan results to show each computer's STIG compliance ([STIG compliance](reports.md#stig-compliance-scap)). Blank reads the `scap` folder in the data folder; set a folder (for example SCC's results folder) to read that instead, including its subfolders, or `none` to turn this off. Blackbox only reads results; it never runs a scan |
| `scap_max_age_days` | `30` | A scan older than this is marked stale |
| `working_hours` | *(blank)* | When administrator activity is expected, e.g. `Mon-Fri 06:00-18:00`, `Daily 07:00-19:00` or `Mon-Fri 22:00-06:00` (a night shift). Activity outside these hours is shown under [Detections](reports.md#detections). Blank turns the check off |
| `data_dir` | platform default | Where reports and collected events are stored |
| `send_to` | *(blank)* | The collector's inbox this computer sends to: `\\COLLECTOR\BlackboxInbox` (Windows), `//COLLECTOR/BlackboxInbox` or `/media/sf_BlackboxInbox` (Linux). When set, this computer makes no reports of its own. See [lan.md](lan.md) |
| `share_user` | *(blank)* | Account on the collector for `send_to`. The password is never in this file: it is stored encrypted (Windows) or root-only (Linux) by the installer |
| `inbox` | *(blank)* | Makes this computer a collector that receives other computers' events in this folder |

The easiest way to change settings is to run the installer again: it shows
the current values as defaults. To change one setting from a script:

```
blackbox config set report_dir D:\AuditReports
blackbox config set report_every daily
blackbox config set report_at "Thursday 06:00"
blackbox config set working_hours "Mon-Fri 06:00-18:00"
```

`blackbox config set` checks the value before saving it:

- For `report_dir`, it also checks the folder is writable, and on Linux lets
  the service write there.
- For `send_to` and `inbox`, it sets up the share, mount or inbox folder.
  A new share password is read from `BLACKBOX_SHARE_PASSWORD`.
- `none` clears a LAN setting, `exclude_users`, `exclude_processes` or
  `working_hours` ("Cleared exclude_users.").
- `retention_days` below 365 asks you to confirm by typing `yes`; in a
  script, add `--yes`.

Run `blackbox config` to see the current settings, and `blackbox status` to
see whether everything is working.
