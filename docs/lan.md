# Several computers: VMs and LANs

One computer, the **collector**, produces reports that cover itself and
every computer that sends to it. The other computers keep collecting their
own logs every 15 minutes and copy what they collect into the collector's
**inbox**, a folder on the collector.

![A combined report's Systems page](images/lan-systems.png)

```
 Linux VM (VirtualBox) ──shared folder──┐
 Ubuntu PCs ────────────Windows share───┼──►  Collector: C:\BlackboxInbox  ──►  one report for all of them
 Windows PCs ───────────Windows share───┘
```

- **Nothing listens on the network.** Computers copy files into a folder,
  which can be a VirtualBox shared folder or an ordinary Windows share. No
  ports are opened, and it works with or without a domain.
- **A computer that is off or cut off loses nothing.** Its data waits on
  it and is sent when the collector can be reached. A VM that is only
  switched on for a few minutes catches up each time.
- **Gaps are reported.** Each delivery is numbered and checksummed. If one
  goes missing or is damaged, or a computer stops sending, the report says
  so. See [What the report shows](#what-the-report-shows).
- **Small.** Only the security events Blackbox keeps are sent, compressed,
  and only what is new. Expect tens of kilobytes per computer per hour.
  Once a day a computer also sends a zip of its original logs (exported
  at every collection, so a log that rolls over loses nothing), typically
  a few MB for Windows (see [Original logs](reports.md#original-logs)).

## Choosing a role

The installer's first question sets the role:

| Choose | For | Produces reports? |
|---|---|---|
| **On this computer** | A standalone computer | Yes, about itself |
| **Send to a collector** | A Linux VM, or a LAN workstation | No, its events appear in the collector's reports |
| **This is the collector** | The PC or server the ISSO reviews reports on | Yes, about itself and every sender |

A computer is one or the other: it sends to a collector, or it is one.

**Changing a computer's role or its collector.** Run setup again (or
`blackbox config set send_to …`). What happens to what it already has:

- **A sender moved to another collector.** Its next batch is marked as
  the first for the new collector, with the name of the previous one. The
  new collector starts counting from there, so the batches that went to
  the old collector are not reported missing; `blackbox status` on the
  new collector says "batches start at 281 here; earlier ones went to
  WIN-498EC8UMUEL". A batch made for the old collector but not delivered
  yet goes to the new one.
- **A collector (or standalone computer) that becomes a sender.** If it
  made a scheduled report since it last sent to a collector, then before
  its first send it makes a **final report**, in its reports folder with
  `_final` at the end of the folder name: everything it had collected and
  received and not yet reported, with every original log it held (its own
  and other computers'). Setup gives its path. If it made no scheduled
  report in that time (for example, it was standalone for a few hours),
  there is nothing to finalise: what it collected meanwhile is sent to
  the collector with its next batches, and setup says so. From then on it sends only
  its own new events. It never passes on what other computers sent it, so
  the new collector neither gets their events twice nor lists them as
  coming "via" this computer. Point the computers that sent to it at the
  new collector.
- **A collector that becomes standalone.** Nothing is lost: what other
  computers sent so far, with their original logs, is in its next report.
- **A renamed computer.** Each sender sends the names it had before with
  its data, so the collector files events under an old name under the
  computer's current one and does not list the old name as another system.

A computer is shown "via" another only while its data has only ever come
through that computer.

**Set up the collector first.** Senders check that the collector's inbox is
there before they use it.

## Scenario 1: one air-gapped PC with a Linux VM

The Windows PC is the collector. The VM sends through a VirtualBox shared
folder, so no networking is needed.

**On the Windows PC:**

1. Run `Blackbox-Setup-<version>.exe` and choose **This is the collector**.
2. Accept the inbox folder, `C:\BlackboxInbox`.
3. Answer **yes** to "Will virtual machines on this PC send to it?" and
   give the Windows account that runs VirtualBox. That account is added
   to the local group **Blackbox Senders**, which may write to the inbox.
   It takes effect the next time that account signs in.
4. Answer **no** to sharing it on the network.

**In VirtualBox**, with the VM powered off:

1. Open **Settings → Shared Folders** and add a folder.
2. Set **Folder Path** to `C:\BlackboxInbox`.
3. Set **Folder Name** to `BlackboxInbox`.
4. Tick **Auto-mount**. Leave **Read-only** unticked.

The VM needs the VirtualBox Guest Additions. They are on the Guest
Additions CD image that comes with VirtualBox, so no internet access is
needed.

**In the VM** (Ubuntu or AlmaLinux):

1. Run `sudo ./install.sh`.
2. Choose **Send to a collector**.
3. Setup finds `/media/sf_BlackboxInbox` and offers it as the default.
   Press Enter.

Done. The VM's events appear in the Windows PC's next report. Its
Systems page lists both computers. Because the VM sends through a VirtualBox shared
folder, it says it is a virtual machine and the report lists it as one
("Virtual machine on" the PC). Being off for part of the week is not a
problem; sending nothing all week is "Worth a look".

## Scenario 2: LAN workstations that host Linux VMs

Every computer sends straight to the LAN collector (scenario 3), VMs
included:

- **The workstation** is a sender, like any other LAN computer.
- **Its VM** is a sender too. It reaches the collector's inbox over the
  network: the Windows share, or an SFTP mount (see
  [Other ways to reach the inbox](#other-ways-to-reach-the-inbox)). The VM
  therefore needs a network adapter that can reach the collector, for
  example a bridged adapter.

Your script that powers the VMs on for the scheduled job keeps working. A
VM does not have to be on at a particular time:

- The Blackbox timer runs 5 minutes after boot and catches up any runs it
  missed while the VM was off.
- A Linux sender also sends when it shuts down cleanly (the
  `blackbox-shutdown.service` unit), so a VM powered off with an ACPI
  shutdown delivers its last events on the way down. A VM that is
  powered off hard does not; to be sure, run `sudo blackbox send` in the
  VM from your script before stopping it.

## Scenario 3: a LAN with a Windows collector

**On the collector** (a Windows PC or Windows Server):

1. Run `Blackbox-Setup-<version>.exe` and choose **This is the collector**.
2. Answer **yes** to "Share it on the network", and enter the account
   (or accounts) the other computers deliver as. Setup then:
   - shares `C:\BlackboxInbox` as `\\COLLECTOR\BlackboxInbox`, encrypted,
     with offline caching off (no copies of batches in client caches)
   - gives the local group **Blackbox Senders** permission to add files
     to it, and nothing else (see
     [How the inbox is protected](#how-the-inbox-is-protected)), and adds
     those accounts to it
   - checks that Windows Firewall lets file sharing in: any enabled
     inbound rule that allows TCP 445 counts, including **File and Printer
     Sharing (Restrictive) (SMB-In)**, which Windows 11 25H2 turns on when
     a share is created. Windows Server 2025
     ships **File and Printer Sharing (SMB-In)** turned off. Blackbox
     never changes the firewall, so setup and `blackbox status` print the
     one rule to add, both as a command and as a Group Policy path: inbound
     TCP 445, from the senders' addresses only, Domain and Private
     profiles:

     ```
     New-NetFirewallRule -DisplayName "Blackbox inbox - SMB from senders" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress 192.0.2.21,192.0.2.22 -Profile Domain,Private -Action Allow
     ```

     By Group Policy: Computer Configuration > Policies > Windows Settings
     > Security Settings > Windows Defender Firewall with Advanced Security
     > Inbound Rules > New Rule: Port, TCP 445, Allow, Domain and Private;
     then set the rule's Scope to the senders' addresses. When the
     collector also runs the OpenSSH server for SFTP senders and port 22 is
     closed, the same message names TCP 22 and the OpenSSH server.

Senders sign in to the share with an account on the collector. Choose how:

- **Workgroup (no domain):** create one local account for senders and add
  it to the group. Use a strong password, and follow your password policy.

  ```
  net user bbsend * /add
  net localgroup "Blackbox Senders" bbsend /add
  ```
- **Domain:** add `DOMAIN\Domain Computers` (or a group of the sending
  computers) to **Blackbox Senders**. Windows senders then need no
  password: they sign in as their computer account.

**On each Windows sender:**

1. Run `Blackbox-Setup-<version>.exe` and choose **Send to a collector**.
2. Enter `\\COLLECTOR\BlackboxInbox`.
3. Enter the account and its password. On a domain, leave the account
   blank.

The password is stored encrypted with Windows DPAPI in machine scope (so
the collection task, which runs as SYSTEM, can use it), in the data
folder, which only Administrators and SYSTEM can read. Machine scope means
any administrator on the sender can recover it, so use an account that is
only a member of **Blackbox Senders** (see
[security.md](security.md#lan-security)). Setup checks the share straight
away.

**On each Ubuntu or AlmaLinux sender:**

1. Install the SMB client if it is not already there. It is on your
   installation media:
   - Ubuntu: `sudo apt install cifs-utils`
   - AlmaLinux: `sudo dnf install cifs-utils`
2. Run `sudo ./install.sh` and choose **Send to a collector**.
3. Enter `//COLLECTOR/BlackboxInbox`, then the account and its password.

Setup stores the account in `/etc/blackbox/share.cred`, readable by root
only. It also creates a systemd mount unit that mounts the share for
Blackbox before each run. Files on the share are root-only and cannot be
run.

**FIPS mode (STIG-hardened Ubuntu Pro, AlmaLinux).** With
`/proc/sys/crypto/fips_enabled` set to 1, the kernel refuses the NTLM
sign-in that SMB shares use, so the mount fails. Setup detects this and
says so. Use an SFTP (sshfs) mount instead, which works in FIPS mode; see
[Other ways to reach the inbox](#other-ways-to-reach-the-inbox).

If the collector cannot be reached during setup, you can still continue.
The data waits on the sender until the collector can be reached.

## Other ways to reach the inbox

A sender needs only a folder it can write to that holds the collector's
inbox. Any way of mounting the inbox works:

- a VirtualBox shared folder
- an SMB share (set up by the installer)
- an SFTP mount
- an NFS mount

Blackbox checks for the collector's `BLACKBOX-INBOX.txt` marker before
every delivery, so a mount that is down is never mistaken for the inbox.
The data simply waits until the mount is back.

**SFTP (sshfs) from a Linux sender.**

1. On the Windows collector, turn on the **OpenSSH Server** optional
   feature. On an air-gapped system, install it from the Features on
   Demand media.
2. Give an account (the same one as for SMB is fine) access to the
   inbox through **Blackbox Senders** (on a Linux collector,
   **blackbox-senders**), and use key-based sign-in.
3. On the Linux sender, install `sshfs` from the installation media and
   mount the inbox at boot. For example, in `/etc/fstab`:

   ```
   bbsend@COLLECTOR:/C:/BlackboxInbox  /mnt/blackbox-inbox  fuse.sshfs  _netdev,nofail,reconnect,IdentityFile=/root/.ssh/blackbox,ServerAliveInterval=15  0 0
   ```

   `nofail` lets the computer start when the collector is down. You can
   add `x-systemd.automount` as well.

4. Run `sudo ./install.sh`, choose **Send to a collector**, and enter
   `/mnt/blackbox-inbox`.

For a folder like this, collection and delivery are separate (L8):

- `blackbox.service` collects and queues, and does not name the folder.
  A collector that is down, or a dead mount ("Transport endpoint is not
  connected"), never stops collection.
- `blackbox-send.service` delivers after each run. It first asks systemd
  to start the folder's mount unit (`systemctl start
  mnt-blackbox\x2dinbox.mount`, the unit systemd makes from the
  `/etc/fstab` line), so a mount that failed at boot, or dropped, is tried
  again at every run, as Blackbox does for an SMB share. systemd mounts it
  outside the service's sandbox, which has no network of its own, and the
  mount stays after the send. The folder needs its `/etc/fstab` line.
- If delivery fails, the data waits; see
  [When the collector can't be reached](#when-the-collector-cant-be-reached).

The installer and CI test VirtualBox shared folders, SMB shares, a
folder sender, and an sshfs mount that is down when the send runs (CI
mounts it again from the send service). An SFTP mount goes through the
same checks, but its setup is yours.

**FIPS mode.** SMB from Linux fails under FIPS (see above), so SFTP is
the route there:

- Use an ECDSA or RSA key. FIPS OpenSSH refuses ed25519:
  `ssh-keygen -t ecdsa -b 384 -f /root/.ssh/blackbox`.
- Pin the collector's host key by connecting once with `ssh`:
  `sudo ssh -i /root/.ssh/blackbox bbsend@COLLECTOR exit`, then answer
  "yes" after checking the fingerprint. `ssh-keyscan` aborts under FIPS.
- A later option for domain-joined senders is SMB with Kerberos
  (`sec=krb5`) and a machine keytab, which needs no NTLM.

## How the inbox is protected

The inbox is a trust boundary: whatever is in it goes into the
collector's reports as that computer's evidence. From 0.24 there is one
inbox, as before 0.23, and it is **drop-only**: senders can add files to
it, but can't list, read, change, rename or delete anything in it, their
own files included. Setup applies this on the collector, and so does the
upgrade; there is nothing to set up per computer, and senders may share
one delivery account.

- **Windows (NTFS, under the share):**
  - **Blackbox Senders** has *Create files / write data* and
    *Synchronize* on the inbox folder only. It has no *List folder*,
    *Read*, *Create folders*, *Delete* or *Change permissions*, and the
    files a sender creates inherit no entry for it.
  - **OWNER RIGHTS** has no rights on the files, so the account that
    created a file gets nothing from owning it (no reading or changing its
    permissions).
  - The handle that creates a file keeps the access it asked for, so a
    sender writes the file it just made, and nothing afterwards.
  - **Administrators** and **SYSTEM** keep full control, and Administrators
    own the folder.
  - The marker file `BLACKBOX-INBOX.txt` is the one thing senders can
    read, so a sender can tell the collector's inbox from a share that is
    not connected.
- **Linux (SFTP senders):** the inbox is owned by root and the group
  **blackbox-senders** (setup makes it), mode **1730**. Members can create
  files there, but can't list the directory or remove anyone else's files.
  A sender can still remove its own file; that batch is then a number that
  never arrives, which the collector reports as missing. Add the account
  SFTP senders sign in as to the group (`usermod -aG blackbox-senders
  bbsend`). The data folder (`/var/lib/blackbox`) is root-only, so for SFTP
  senders give the collector an inbox outside it, such as
  `/srv/blackbox-inbox`.

**How a sender delivers.** A sender can't look in the inbox, so:

- it writes each file straight under its final name,
  `HOST_SENDERID_SEQ-RANDOM.bbx` (log archives and SCAP results likewise
  end in `-RANDOM`), and only if no file has that name (`O_EXCL`,
  `CREATE_NEW`). The random part follows a dash, so a 0.23 collector reads
  the name too. A name already taken means someone else made that file;
  the batch then goes under a new random part;
- a batch counts as delivered when it was written and closed without an
  error. The collector's list of missing batches (`blackbox gaps`, then
  `blackbox send --resend` on the sender) is the check that it arrived.

**How the collector reads it.** A file that can't be read whole may still
be being written. The collector leaves it for 10 minutes after it was
last written, then moves it to `inbox\rejected` as incomplete (the sender
sends a batch it could not finish again by itself).

**Upgrading from 0.23.** The per-sender folders 0.23 made with
`blackbox inbox add` are no longer used. At the collector's upgrade (and
its next run), what waits in them is moved into the inbox and imported
like any other delivery, and the folders are removed. Each sender's
import record (its last number, its missing batches and the hashes behind
"already imported") is kept by sender ID, not by folder, so nothing is
missed or imported twice. `blackbox inbox add` is gone.

Upgrade the senders first, then the collector:

- a 0.24 sender's files are read by a 0.23 collector as well. While the
  collector is still 0.23, a sender that had its own folder there keeps
  delivering into it (a 0.23 collector refuses a file in the inbox itself
  from a computer that has a folder); once the collector is upgraded and
  the folder is gone, it delivers into the inbox. A 0.23 collector reads
  a file in the inbox itself (not a folder) as soon as it sees it, so a
  batch it catches half written is set aside as incomplete; `blackbox
  gaps` lists it and `blackbox send --resend` on the sender sends it again;
- senders from before 0.24 rename their files into place, which the
  drop-only inbox does not allow on a Windows collector. If the collector
  is upgraded first, their batches wait on the sender, safely, until the
  sender is upgraded too.

**What the collector checks** (each file it can't accept is moved to
`inbox\rejected` with a `NAME.why.txt` note saying why and which account
wrote it; `blackbox status` lists them and exits 4, the next report says
so, and the rest are still imported):

- a batch whose records can't be read (not an event, a bad time, a record
  of no known type) is set aside, and its number stays missing until it
  is sent again with `blackbox send --resend`;
- a batch file over 256 MB is refused before it is read, and an archive
  whose computer name is `.` or `..` is refused;
- a SCAP result must match the hash in its file name.

The account that wrote each file is recorded (in the log, in the note of
a file set aside, and in any High row about the inbox), as information:
with one shared delivery account it says little.

**What it raises as High** (one row in the next report):

- **Two different batches with one number** from a computer: both are
  kept. A batch is "already imported" only when it is the same batch.
- **Two computers using one sender ID** (a computer cloned from another,
  with its data folder): both are kept. Run `blackbox send --new-id` on
  one of them; its waiting batches are renumbered under the new ID.
- **Two different original-log archives** for one computer and period:
  both are filed (the second as `…-2.zip`) and go into the report.
- **A former name that is another computer**: a sender saying it used to
  be called the name of a computer that still reports here is not merged
  with it. A former name is taken only when the same sender used it
  before, or after `blackbox systems rename OLD NEW` on the collector.

A sender's "first batch for this collector" (sent after it moved from
another collector) is taken only when it is close to the next number
expected; a jump is recorded as missing batches, and a gap already
recorded is never erased by it.

## Day to day

**Reviewing.** Open the collector's reports as usual. Start with the
**Systems** page:

- every computer, with its last collection, event counts, high-severity
  events and audit settings
- anything wrong is listed first
- selecting a computer's name filters every event table in the report to
  it; the **All systems** menu above each table does the same

**Checking a computer is working.** Run `blackbox status` as an
administrator or root. It shows:

- the computer's role and its last collection
- on a sender: when it last delivered, and anything waiting to be sent
  (with the reason, if sending failed)
- on a collector: what is in the inbox, and every computer it has heard
  from

```
Blackbox 0.2.0 on WS-07

  Role:             collector (reports on this computer and the computers that send to it)
  Last collection:  2026-10-02 14:05 (12 minutes ago)
  ...
  Inbox:            C:\BlackboxInbox — OK; 0 batches waiting to be imported

Systems (3)
  NAME                 OS       LAST COLLECTION    LAST RECEIVED      NOTE
  ubu-ws12             linux    2026-10-02 13:58   2026-10-02 14:05
  WS-07                windows  2026-10-02 14:05   -                  this computer
  WS-09                windows  2026-09-26 09:00   2026-09-26 09:05   SILENT: LAST COLLECTION 6 DAYS AGO
```

**Adding a computer.** Install Blackbox on it and choose **Send to a
collector**. It appears on the Systems page after its first collection.

**Retiring a computer.** On the collector, run
`blackbox systems remove NAME`. It stops being listed and reported as
silent. Its events stay in earlier reports, and it is listed again if it
ever sends again. Until then it is left out of every warning about
senders in `status`, `blackbox inbox` and the report: missing batches,
"no batch since", silence, delivering into the shared folder (SEC1d).
`blackbox gaps` still lists its missing batches. The report whose period it was retired in shows it
under **Retired** on the Systems page, "retired 7 Oct by alice" (the
account that ran the command), with its events up to then; it is not
counted in **Systems reporting**, the Health checks or **Original logs
missing**, and its card says "Collected until 7 Oct", not "nothing"
(ROLE1b).

**A collector made standalone.** Its reports leave out the computers that
sent to it and sent nothing in the report's period: they are not its
systems any more. One that still sent during the period is in that
report. On a collector, a sender that stops sending (made standalone, or
retired) is shown as not reporting until it is removed with
`blackbox systems remove NAME`, as the gap says.

**Changing where a computer sends.** Run the installer again. It shows the
current settings as the defaults. From a script, run
`blackbox config set send_to \\NEWCOLLECTOR\BlackboxInbox` as an
administrator. The share password is read from `BLACKBOX_SHARE_PASSWORD`.

## When the collector can't be reached

A sender keeps everything until the collector has it.

- **What is kept, and where.** After each collection, new events become
  numbered batches in the outbox: `/var/lib/blackbox/outbox` on Linux,
  `C:\ProgramData\Blackbox\outbox` on Windows. The day's original logs
  and the latest SCAP results wait there too.
- **For how long.** Until they are delivered. Nothing in the outbox is
  ever deleted to make room, however long the collector is away.
- **What you see.**
  - `blackbox status` gives the number waiting, when the oldest was
    queued, and why the last delivery failed. On Linux the reason is in
    the mount's own words, for example "nothing is mounted there; share
    bbsend@COLLECTOR:/C:/BlackboxInbox; last mount error: ssh: connect
    to host COLLECTOR port 22: No route to host".
  - When deliveries keep failing, status says "sending has failed since"
    the first failure.
  - After 24 hours of data waiting, or of every delivery failing, status
    says **NOT SENT**, and `blackbox status` exits with code 4, so
    monitoring can notice. It does the same when the data
    folder's disk has less than 1 GB or 5% free.
- **Sending now.** When the collector is back, the next scheduled run
  sends everything, oldest first. To send at once, run `blackbox send` as
  an administrator or root. The collector skips anything it already has,
  and reports a gap only for batches that never arrive.
- **Sending again.** A sender keeps each batch for `keep_sent_days`
  (14 by default) after delivering it, in `outbox\sent` (root or SYSTEM
  only, like the rest of the data folder, and covered by the audit rule and
  the auditing entry Blackbox recommends for it). If the collector reports
  batches missing, for example because they were deleted from the inbox or
  its data folder was restored from a backup, run on the sender the
  command the report and `blackbox status` give:
  `blackbox send --resend 214-219`. The collector imports those that fill
  the gap and ignores the rest. Each resend is recorded, like a setting
  change, in the report and the system log. Batches older than
  `keep_sent_days` can't be sent again; the command says which. Each
  batch says which batches the sender still keeps, so the collector only
  suggests `--resend` for those, and otherwise says the sender no longer
  keeps them.
- **Gaps that will never be filled.** `blackbox gaps` on the collector
  lists the missing batches, and any that were accepted. When batches are
  known not to be coming (they went to a previous collector, or the
  sender lost them), an administrator can say so:
  `blackbox gaps accept ubuntu-server 1-280 "went to the previous collector"`.
  They are then no longer missing: they stop making `blackbox status`
  exit 4, `status` and `gaps` list them as accepted with who, when and
  why, and the next report has a row saying who accepted them and why
  (recorded like a setting change, in the system log too). Options such
  as `--config FILE` may go before, between or after the arguments; `--`
  ends them, for a reason that starts with a dash (CLI2). Open gaps make
  `blackbox status` exit 4. A gap from batch 1, noticed when the
  collector first heard from a sender, clears by itself once that
  sender's batches say where its earlier batches went. A gap recorded
  before 0.14 may never clear by itself: batches sent before 0.14 say
  nothing about where earlier ones went, so accept it with `blackbox gaps
  accept` once you know where they went (L13c).

In a re-test, 114 batches and 2 log archives queued over 27 hours were
delivered in 47 seconds, with nothing rejected.

## SCAP scan results

A sender also sends its own SCAP scan results (see
[STIG compliance](reports.md#stig-compliance-scap)) to the collector, each
file once, compressed, next to its batches. The collector keeps them in
`scap-received` in its data folder, and its reports show every
computer's latest scan.

## What the report shows

The report points these out, both on its Overview and Audit health pages
and in `summary.json`:

| Situation | What the report says |
|---|---|
| A computer sent nothing in the report period | "The audit trail is not complete": the computer, its last collection, and that it may be off or unable to reach the collector |
| A computer has not collected for more than 36 hours | Flagged on the Systems page |
| A delivery never arrived (for example, deleted from the inbox) | Which batches from which computer are missing, and the `blackbox send --resend` command to run on that computer |
| A computer's clock is ahead of the collector's | The computer and by how much. Event times from it may be wrong |
| Events arrived after the report they belong to | Included in the next report, marked **Late** |
| A delivery is damaged, altered, or not from the folder's computer | It is set aside in `inbox\rejected` with a `.why.txt` note, `blackbox status` lists it and exits 4, and the report says so. The gap it leaves is reported |
| Two different files claim to be the same batch or archive, or two computers share a sender ID | A High row: both are kept (see [How the inbox is protected](#how-the-inbox-is-protected)) |

## Troubleshooting

Run `blackbox status` on the sender first: it shows the last error.

| Symptom | Likely cause |
|---|---|
| "collector inbox not available" | The share or shared folder is not reachable. The message says why, in the mount's own words. Check the collector is on, the VM's shared folder is set up with Auto-mount, and the Linux mount: `systemctl status var-lib-blackbox-collector.mount` (SMB) or `systemctl status blackbox-send.service` (a folder) |
| Other computers can't reach `\\COLLECTOR\BlackboxInbox` | Windows Firewall blocks file sharing in (status says **FIREWALL**). See Scenario 3 |
| "is not a Blackbox inbox" | The folder is reachable, but the collector has not been set up yet, or the path is wrong. Run the installer on the collector first |
| Access denied on a Windows sender | The account is not in **Blackbox Senders** on the collector, or its password changed. Run the installer on the sender again to update it |
| The VM cannot write to `/media/sf_BlackboxInbox` | The Windows account that runs VirtualBox is not in **Blackbox Senders**, or has not signed in again since it was added |
| A computer shows as silent | It was off, or could not reach the collector. Its own `blackbox status` says which |

## How it works

This section is for reviewers.

- **Batches.** After each collection, a sender writes what is new since its
  last batch to a numbered file in its own outbox. The file is compressed
  JSON lines with a SHA-256 checksum and a closing record, so a damaged or
  cut-short file is detected. It then copies waiting batches, oldest
  first, into the inbox:
  - written in place under a name of its own, `HOST_SENDERID_SEQ-RANDOM.bbx`,
    made only if no file has it; the sender can't rename, read or delete
    anything in the inbox. The collector leaves a file that is not
    complete yet for 10 minutes
  - only into a folder that holds the collector's `BLACKBOX-INBOX.txt`
    marker, so a share that is not mounted (an empty local folder) is
    never mistaken for the collector
- **Import.** Each time the collector collects, it imports every complete
  batch in each sender's order. It records each batch's number and hash,
  and skips one it already has, so a batch delivered twice counts once; a
  different batch under a number it has is kept and raised. It then
  deletes the file from the inbox, and logs which account wrote it.
- **Crash safety.**
  - Before appending a batch, the collector notes its data files' sizes.
    If it stops part way, the next run cuts the files back and imports
    the batch again.
  - A sender only marks data as batched after the batch is safely on its
    own disk.
- **Received events count from their arrival.** An event is treated as
  collected when it reached the collector, so it lands in exactly one
  report. If it arrives late, it goes in the next report, marked Late.
- **Identity.** Each sender has a random ID created when it first sends.
  A computer that is reinstalled starts a new sequence instead of looking
  like a gap. A computer cloned with its data folder keeps the ID: the
  collector notices two computers using it, and `blackbox send --new-id`
  gives one a new ID.

**The "Blackbox Senders" group is kept when Blackbox is uninstalled.** A
sender's open connection to the share carries the group's identity, so
deleting the group and making a new one on reinstall would lock out a
sender (a Linux mount never signs in again by itself). On a collector,
`blackbox status` notes "no batch since …" for a sender with nothing
delivered for more than two hours, well before it counts as silent.
