# Report redesign: locked design

These choices were made with the product owner between 29 Sep and 1 Oct 2026, and approved one page at a time.
**Build to this document and the mockups in `mockups/`.** Don't change a layout, add a page, or drop a section during the build without asking first.
If something can't be built as shown, stop and ask.

The Windows setup window and status icon are designed in [`SETUP-SPEC.md`](SETUP-SPEC.md), under the same rules.

`source/` holds the Python scripts that generated the mockups. They are the reference for exact colors, spacing and chart construction.

## Visual style ("G2 Arctic")

| Item | Value |
|---|---|
| Background | Light blue-grey gradient (`#EEF3FB` → `#E3EAF6`) with soft blue radial glows |
| Sidebar | Dark navy glass (`rgba(0,24,80,.94)` → `rgba(0,18,60,.96)`); active item gets a `#5AA9FF` left bar |
| Panels | Frosted white glass: `rgba(255,255,255,.82)` → `.64`, 1px white border, faint navy outline, soft shadow, **square corners** |
| Accent | `#0B5FFF` (charts, links); dark navy `#0A2A7A` (numbers, primary buttons, selected chips) |
| Severity | High `#D12C2C`, Medium `#E08A00`, OK `#1A9A50`; severity is a small square plus a word, never a pill |
| Name | "Blackbox" with the GE Aerospace logo; the company name is not written out (changed 2 Oct 2026) |
| Fonts | Public Sans (text), Source Code Pro (times, IDs, hashes, numbers in tables) |
| Icons | Lucide (lucide-static 0.460.0), 1.6 stroke |
| Corners | Square everywhere: no rounded cards, pills or oval buttons |
| Colour rule | Colour only where something needs attention; healthy items are grey or plain |

## Navigation (sidebar, same on every page)

Overview · Systems · Detections · Search · People
**Events:** Privileged activity · USB & removable · Failed logons · Accounts & groups · Audit integrity · PowerShell · Other security · Logon activity (each shows its count)
**Audit:** Audit health · Trends · Original logs

The header on every page has the breadcrumb line, the page title, and three buttons:
- **date range**
- **Verified**
- **Export**

## Pages

| # | Page | Choice | Mockup |
|---|---|---|---|
| 1 | Overview, LAN | **M2 Split** | `01-overview-lan.png` |
| 1b | Overview, standalone (1 system ± VM) | M2 adapted: host + VM cards | `02-overview-standalone.png` |
| 2 | Systems | **S2 List + detail** | `03-systems.png` |
| 3 | Detections | **D2 List + investigation** | `04-detections.png` |
| 4 | Search | **Q2 Fill in the blanks** | `05-search.png` |
| 5 | People | **P1 List + profile** | `06-people.png` |
| 6 | Event pages (all 7) | **V1 Stacked** | `07a`–`07d` |
| 6b | Event row detail | Side panel | `07e-event-row-detail.png` |
| 7 | Audit health | **A1 Grid**, with **A3's per-system STIG table** opening on click | `08a`, `08b` |
| 8 | Trends | **T1 Small charts** | `09-trends.png` |
| 9 | Original logs | **O1 Table**, with **O3's per-system detail** opening on click | `10a`, `10b` |
| 10 | Reports index | List of all reports + 12-week chart | `11-reports-index.png` |
| 11 | Export menu | Dropdown | `12-export-menu.png` |
| 12 | Verified | Popover | `13-verified.png` |
| 13 | Clean week | Empty states | `14-clean-week.png` |
| 14 | Print / PDF | Plain printable summary | `15-print-pdf.png` |

### 1. Overview, LAN (M2)
1. Alert bar, shown only when something needs attention.
2. Four main stat cards with 12-week sparklines:
   - **Systems reporting** (n / total)
   - Detections
   - Events collected
   - Privileged actions
3. A row of six **important-event cards**, each with a count and who or where:
   - Logs cleared
   - New admins
   - Policy changes
   - Lockouts
   - After-hours admin
   - New USB devices

   Red or amber top edge when it needs a look; greyed when zero.
4. Left: **Systems** panel.
   - Health bar (OK / warnings / problems counts) and the six-line health checklist (Logs intact, Every system reporting, Reports on time, Audit settings match STIG, No events lost to rollover, Original logs archived), each with an "n/total" count and the failing system named in one line. A failing line is titled with what went wrong (Logs cleared, Not every system reporting, Events arrived late, Audit settings to fix, Events lost to log rollover, Original logs missing), never with the passing wording.
   - Below the checklist: the system map with tiles grouped Servers / Workstations / Virtual machines. Problem tiles are solid red and warning tiles amber; VMs have dashed borders.
5. Right: **Detections**. Cards grouped by day; each has a severity edge, title, one-line plain explanation, and system + time.
6. Bottom: **Trends · last 12 weeks** (three small charts):
   - High-severity events
   - Failed logons
   - Privileged actions

Rejected: a systems table with seven coloured day squares (too busy); separate placement of the high-severity line graph.

### 1b. Overview, standalone
Use this when a report has 1–3 systems.
- The system map is replaced by **one card per system** (host, and VM if any). Each card shows OS, role, events, detections, days collected and audit-settings status.
- Everything else is the same as M2.

### 2. Systems (S2)
**Left:** a list grouped Servers / Workstations / VMs, with problems first and a search box.

**Right, for the selected system:**
- **Header:** name, OS and role, and a status label.
- **Five facts:** Events, Detections, Collected, Audit settings, Last report.
- **Collection bar:** this week, with gaps and log clears marked in red.
- **Health checklist** for that system.
- **Activity vs. typical system:** bars, with a line at the network median.
- **That system's detections.**

### 3. Detections (D2)
**Left:** a list grouped by day, with All / High / Medium chips.

**Right:**
- **Title, system, time range, and severity.**
- **"Why this was flagged"** in plain words.
- **What happened:** an ordered sequence with times and event IDs; key steps are marked red.
- **Involved:** system, done by, affected account, source, device.
- **Related this week.**
- **Events table:** the exact raw events, naming the original-log zip they came from.

### 4. Search (Q2)
**Search sentence:** "Show [All events] by [person] on [Any system] during [This week] containing [any text]".

**Eight one-click common searches:**
- Everything one person did
- USB devices on servers
- Admin work after hours
- Failed logons by source
- Changes to admin groups
- Logs cleared or audit changed
- PowerShell that downloads
- Remote Desktop logons

**Results:**
- A result title, for example "47 events by admin_jd on 6 systems".
- Sort and Group by system controls, and Export CSV.
- A histogram of matches across the week.
- A results table: Time, System, Event, Person, Details, Severity.

**How it works:** search runs in the browser over events embedded in the report. That works air-gapped, but the report file grows by about 10–20 MB for 24 systems a week.

### 5. People (P1)
**Left:** a list grouped Needs a look / Administrators / Service accounts / Users, with initials avatars.

**Right:**
- **Header:** name, account type, domain account, first seen.
- **Five facts:** systems used, logons, admin actions, after hours, detections.
- **Notable actions**, as plain sentences.
- **When they were active:** a week heatmap with red cells where a detection happened.
- **Systems used**, as bars.

### 6. Event pages (V1)
Same layout on all seven event pages, top to bottom:
1. **Four stat cards**, chosen per page; a card gets a red or amber edge when it needs a look.
2. **Chart row:**
   - Left: per-day stacked bars by kind, with above-normal days outlined in red.
   - Right: a top-6 list, with flagged entries in red.
3. **Flagged this week:** three detection cards in a row, plus a line such as "n of N … are part of something unusual".
4. **All events.** This lists every event of the type, not only flagged ones:
   - **Filters:** text filter, then dropdowns (Severity, System, Person/Account, plus page-specific ones, then Day).
   - **Table:** non-flagged rows show "—" for severity.
   - **Below the table:** pager and Export CSV.
   - **Clicking a row** opens the event side panel (6b).

Per page:

| Page | Stat cards | Chart split | Top list | Table columns / extra filters |
|---|---|---|---|---|
| Failed logons | Failed logons (normal range), Password-guessing bursts, Accounts locked out, Sources | Bad password / Expired / Locked out | Sources | Time, System, Account, Source, Logon type, Reason, Severity |
| Privileged activity | Privileged actions, After hours, New admins, People | Admin logon / sudo or run-as-admin / Security settings | People | Time, System, Person, Kind, What they did, Severity |
| USB & removable | USB events, New devices, Files copied to USB, Systems | Connected or removed / Files copied / Blocked | Devices | Time, System, Person, Device, What happened, Severity |
| PowerShell | Scripts logged, Suspicious, Systems, Logging off | Routine / Warning / Suspicious | Systems | Time, System, Person, Script (first line, mono), Kind, Severity |
| Accounts & groups | (same pattern) | Created / Changed / Added to group / Disabled | Changed accounts | Who changed what, before → after |
| Audit integrity | (same pattern) | Log cleared / Audit policy changed / Logging stopped | Systems | What changed and by whom |
| Logon activity | (same pattern) | Console / Remote Desktop / SSH / Network | People | Who, from where, how, session length |

### 6b. Event row detail (side panel)
- **Header:** event type, event ID and log, a plain title, and severity with a link to its detection.
- **Field table:** time with milliseconds and zone, system, account, source, logon type, reason, process, record ID, and the original log (zip › file).
- **Raw event data**, in a dark code block.
- **One-click buttons:**
  - Everything from this source
  - This person's page
  - This system's page
  - Open detection
- **Events within 2 minutes either side** on the same system.

### 7. Audit health (A1 + A3)
**Four stat cards:** Systems matching STIG, Logs cleared, Events lost to rollover, Log size and space settings (log sizes, and on Linux auditd's space and disk actions).

The header line says Blackbox only reports and never changes settings.

**Grid (left):**
- Rows are systems, grouped; columns are the checks: Logon, Account mgmt, Policy change, Privilege use, Process creation, Removable storage, PowerShell logging, Log size, Reporting, Logs intact.
- Cells: faint green ✓, solid red ✕, amber !, grey n/a.

**Right:** Gaps cards. Each has:
- the title and STIG ID
- the plain explanation
- the systems affected, as tags
- a **How to fix** box with the exact GPO path or command

**Clicking a system or cell** opens the A3 table for that system:
- the STIG version it was compared against
- for each check: STIG ID, Required, On this system, and a Matches / Gap result

### 8. Trends (T1)
**Eight small charts:**
- Detections
- High-severity events
- Failed logons
- Privileged actions
- USB events
- After-hours admin
- Account changes
- Systems reporting

Each chart shows this week's value, its % vs. the 12-week average, 12 weekly bars, a dashed average line, and a red "this week" bar when the value is well above average.

**Below the charts:** a grid of detections per system by week, darker for more.

### 9. Original logs (O1 + O3)
**Four stat cards:** Archives, Total size, Hashes verified, Missing.

**Table, one row per system:** OS, logs inside, size, SHA-256 (short), and Verified or Missing. Missing systems come first.

**"How to use them" box:** the three steps, plus the report folder path.

**Clicking a system** opens the O3 detail:
- the zip's full SHA-256 and the hash-verified status
- **Inside the zip:** File, Log, Covers, Events, Size, Hash, Note (for example "Cleared 28 Sep · nothing lost")

### 10. Reports index (`index.html`)
**Top:** a 12-week detections chart.

**Table (newest first):** Week, Systems, Events, High, Medium, Audit trail (Complete, or the problem in red or amber), and an Open button. Filters: All / Incomplete. There is **no review column.**

### 11–14
**Export menu:**
- Print or save as PDF
- Detections as CSV
- All events as CSV
- Audit health as CSV
- Open the report folder

**Verified popover:** lists the hash checks, the continuity with the previous report, and which version and host wrote the report. It shows red if any file fails.

**Clean week:** everything is green or grey zeros. Detections says "Nothing unusual this week", and all events are still available.

**Print / PDF:**
- black and white, with the GE logo
- totals
- a detections table (Severity, Detection, System, When)
- the audit-trail checklist
- no ISSO / Date / ISSM lines: there is no review section (owner decision,
  design.md §13; removed in 0.11, R10)

## Behaviour rules agreed during design
- **VMs are on 25–75% of the week; that is normal.**
  - Show "VM on 41%" in neutral grey, and never flag a VM for being off.
  - Flag a VM only for real problems: a cleared log, missing settings, or an unsent report while it was on.
- **Event pages list every event of their type**, not just flagged ones, and are filterable by severity, person, system and the rest.
- **Size safeguard (approved 2 Oct 2026).** A report embeds at most about 2 million events. Above that, routine Info rows beyond the limit are counted and charted but not listed, and the page says so plainly and points to the archived original logs. High, Medium and Low events, and every event a detection refers to, are always listed.
- **Event data is split by page and compressed.** `report.html` opens without loading event data. Each event page and Search load their own data files from the report folder only when opened, and tables draw only the rows on screen.
- **Other security page (approved 2 Oct 2026).** Events that fit no other page (new services, scheduled tasks, Defender detections or Defender turned off, Linux kernel modules, SELinux/AppArmor denials) get an **Other security** event page with the same V1 layout, listed after PowerShell in the sidebar.
- **Export files (approved 2 Oct 2026).** `events.jsonl` is no longer written; `events.csv` is written zipped as `events.zip`. The data files and each page's CSV export cover the rest.
- **Schedule (v0.8.1).** Reports end at `report_at` (default Wednesday 00:00). Reports run by hand are *Interim* (labelled in the report and on the index) and don't move the schedule. The raw-log export stays daily.
- **No in-report review or sign-off.** Review happens in the ticketing system, so there is no Review page, no review column and no outcome fields.
- **Audit settings: report only; never change them.**
- **ADM-Toolkit logons and actions stay out of reports.**
- **Plain words everywhere:** say what happened, not just an event ID.

## Not in scope unless asked
- Linux STIG currency check.
- The "Late" events reordering fix.
