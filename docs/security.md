# Security review notes

This page is for security reviewers, ISSOs and ISSMs approving Blackbox for
use.

## What Blackbox does

- It reads the Windows event logs, or on Linux the auditd log, the system
  log (or journal) and the auth log.
- It writes translated events and reports to its own data folder.
- It runs `auditpol`, `reg query`, `wevtutil gl`, `auditctl -l` and
  `auditctl -s`. These commands read settings for `check`; none of them
  change anything.
- Once a day, with the settings check, it reads the computer's inventory
  (make, model, serial numbers, drives, user accounts) with PowerShell CIM
  queries on Windows, or from `/sys`, `/etc/passwd`, `/etc/group` and the
  lock and expiry fields of `/etc/shadow` on Linux. It keeps only the last
  four digits of each account's SID and nothing about passwords. See
  [reports.md](reports.md#inventory).

## What it does not do

- **It opens no network connections of its own and listens on no port.**
  On a standalone computer it never touches the network. On Linux, the
  systemd service runs with `PrivateNetwork=yes`, so it has no network
  access at all.
- **On a LAN it only reads and writes files.** A computer set to send to a
  collector copies files into the collector's shared folder. It uses the
  operating system's own file sharing:
  - Windows: the SMB client, signed in with the stored account, or the
    computer's domain account
  - Linux: a CIFS mount that systemd sets up before each run; the
    sandboxed service itself still has no network access
  - a VirtualBox shared folder, which needs no network at all

  See [LAN security](#lan-security).
- **It never alters or clears log records.** It never clears, rotates,
  deletes or forwards them. It does write its own change records: when a
  setting is changed, or Blackbox is installed, upgraded or removed, it
  adds an event to the Windows Application log (source Blackbox, event ID
  100) or a line to the Linux journal (identifier `blackbox`), so a copy
  exists outside its own folder.
- **It cannot stop a full log overwriting events.** It collects often
  (every 15 minutes by default), and detects and reports any loss: in
  `blackbox status` (exit code 4) and in the report.
- **It never changes audit settings.** `check` only reports; the fixes it
  suggests are for administrators to apply.
- **It needs no other software:** no runtime, service, database or
  third-party code.

## Privileges

Blackbox runs as SYSTEM on Windows and as root on Linux, only because
reading the Security log or the audit log requires it. Its data folder is
restricted to Administrators and SYSTEM on Windows, and to root on Linux.

The Linux service is also sandboxed with `ProtectSystem=strict`,
`ReadWritePaths=/var/lib/blackbox`, `NoNewPrivileges=yes` and
`PrivateTmp=yes`.

## LAN security

- **Least privilege on the inbox (SEC1, DESIGN1).** The inbox is
  drop-only: senders can add files to it, and nothing else. On a Windows
  collector its access list, set by SID, is:
  - Administrators and SYSTEM: full control (Administrators own it)
  - **Blackbox Senders**: *Create files / write data* and *Synchronize*,
    on the folder only (no List, Read, Delete, Create folders or Change
    permissions; files a sender creates inherit nothing for it)
  - OWNER RIGHTS: no rights, so creating a file gives its account no
    implicit right to read or change the file's permissions
  - the marker `BLACKBOX-INBOX.txt` alone is readable to senders

  On a Linux collector the inbox is `root:blackbox-senders`, mode 1730:
  members create files but can't list it or remove others' files. Setup
  and the upgrade apply this; 0.23's per-sender folders are emptied into
  the inbox and removed. CI checks both with a real non-administrator
  sender account.

  If shared, the share grants Change to that group only. The installer
  creates the group and, when asked, adds named accounts to it. It never
  creates accounts itself.
- **Stored credentials.**
  - Windows: a sender's share password is encrypted with DPAPI in
    **machine scope** (`CRYPTPROTECT_LOCAL_MACHINE`, with a fixed
    Blackbox-specific entropy value) and kept as `share-credential` in the
    data folder. Machine scope is needed because the collection task runs
    as SYSTEM while setup runs as the administrator who installs it; a
    user-scoped key would tie the password to one of them. What this
    means (SEC3d):
    - The encrypted file cannot be decrypted on another computer, so a
      copied file or backup of it is useless elsewhere.
    - On this computer, *any* process that can read the file can decrypt
      it; DPAPI machine scope does not check which account asks. The
      protection is the file's permissions: the data folder grants access
      to Administrators and SYSTEM only. Anyone who is already an
      administrator here can recover the password.
    - So use a dedicated account for the share, a member of **Blackbox
      Senders** only, with no other rights on the collector or elsewhere,
      and change its password if a sender is compromised or retired (run
      the installer on each sender again to store the new one). In a
      domain, leave the account blank and nothing is stored.
  - Linux: the password is in `/etc/blackbox/share.cred`, mode 0600, owned
    by root.
  - Neither is ever written to the settings file or shown on screen.
  - In a domain, Windows senders need no stored password.
- **Passwords typed on command lines are hidden.** Command-line auditing
  records commands as typed, including any password in them. Before an
  event is stored or reported, Blackbox replaces these with `********`:
  - `NAME=value` where the name contains PASSWORD, PASSWD or SECRET
  - PowerShell `-Password …` and `ConvertTo-SecureString '…'`
  - `net user NAME PASSWORD` and `net use \\server\share PASSWORD`
  - `sshpass -p …`, and `echo … | sudo -S`

  PowerShell `-EncodedCommand` is decoded first, so a password inside it
  is hidden too. The original logs are not changed.
- **Original logs are kept unaltered.** The log archives are exact
  copies, exported at every collection, so they are not redacted: a password typed on a command line is
  in them as it is in the log itself. They are in each report's folder
  (and, until a scheduled report takes them, in the data folder's
  `archive-pieces` and `archives` folders, or in `archive_dir` if set: a
  folder Blackbox creates there is restricted the same way; audit it as
  you audit the data folder), which only
  Administrators and SYSTEM (Windows) or root (Linux) can read. Each file's
  SHA-256 is recorded in the zip and checked by the collector, and each
  zip's SHA-256 is in its report's manifest.sha256.
- **Share mount (Linux).** The share is mounted inside Blackbox's data
  folder only, with root-only file permissions and `nosuid,nodev,noexec`.
- **Encrypted in transit (SMB).** A Windows collector turns on SMB 3
  encryption for its `BlackboxInbox` share (`Set-SmbShare -EncryptData
  $true`), so a sender that can't encrypt is refused rather than sending
  in the clear. Linux senders mount it with `seal` (SMB 3 encryption);
  against a collector that doesn't offer encryption, setup fails with
  "could not connect with an encrypted connection" and says how to turn
  it on. Windows senders encrypt automatically when the share asks.
  Batches in a VirtualBox shared folder never cross a network. The share
  has offline caching turned off, so no client keeps a cached copy.
- **Encrypted in transit (SFTP).** An sshfs mount (the route under FIPS)
  is encrypted by SSH. Note for SC-8/SC-13: OpenSSH for Windows, as the
  collector's server, offers no post-quantum key exchange yet, and
  Ubuntu's OpenSSH 10 client warns that the connection may be "stored now,
  decrypted later". The batches are audit records, not classified
  content. If that matters at your site, prefer SMB 3 encryption (AES),
  or keep senders and the collector on an isolated segment. Under FIPS,
  use ECDSA or RSA keys (lan.md).
- **Firewall and network profile.** File sharing must be allowed on the
  collector for the network senders are on. Windows blocks it on a
  network marked **Public**; on an isolated lab network, mark it
  **Private** (Settings > Network > the network > Private), or allow
  "File and Printer Sharing (SMB-In)" for that profile only. Blackbox
  does not change firewall rules or network profiles.
- **Tamper evidence in transit.** Each batch has:
  - a SHA-256 checksum, and a closing record that detects a cut-short file
  - a per-sender sequence number

  The collector reports missing batch numbers, and sets damaged or
  altered batches aside and reports them. These checks detect loss and
  accidental or careless change, not a determined attacker with write
  access to the inbox. Since 0.24 every delivery is also signed (below).
- **Signed deliveries (DESIGN1).** Each sender signs every batch,
  original-log archive and SCAP result with its own Ed25519 key (inside
  Go's FIPS 140-3 module v1.0.0; it works with `GODEBUG=fips140=only`).
  The signature covers the file's SHA-256, the computer's name, its sender
  ID and batch number (an archive: its period; a SCAP result: its hash) and
  the time. The private key is in the data folder (Administrators and
  SYSTEM only, root `0600`), never leaves the computer, and the sender
  checks those permissions in `blackbox status`. The collector pins each
  computer to the first key it signs with (trust on first use;
  `new_senders = hold` makes a new one wait for `blackbox senders
  approve`); a different key later is held, not imported, with a High
  row, until `blackbox senders rekey`; one key on two computers is a High
  row. Host and sender-ID spoofing, a forged first batch number, false
  former names and forged archives or SCAP results can't be made without
  the computer's key. Unsigned deliveries are taken for this release only
  from computers that have never signed (`require_signed = yes` refuses
  them all), and are listed to upgrade. Limits: the first delivery is
  trusted as it comes (compare the key with the sender's `blackbox
  status`), and someone with administrator rights on a sender can use its
  key, as they can change what it collects.
- **No loops, no spoofed collectors.**
  - A computer refuses its own batches.
  - It only delivers to a folder that has the collector's marker file, so
    an unmounted share (an empty local folder) is never written to by
    mistake. The marker is the one file in the drop-only inbox senders
    may read.
- **What a sender can claim.** A sender supplies the host names in its
  data. The Systems page lists every computer seen, so an unexpected one
  stands out. If one computer delivers collection records for another,
  the report marks that system "via" the computer that delivered them.
- **Which account delivered a file (SEC1).** The collector reads the
  owner of each file it imports (the file's owner on NTFS, its user ID on
  Linux), logs it, and puts it in the note of any file it sets aside and
  in any High row about the inbox, as information: senders may share one
  delivery account. A file the collector can't use is set aside in
  `inbox\rejected` with a `.why.txt`, and `blackbox status` exits 4.
- **What the collector raises (SEC1).** Two different batches under one
  number, two computers using one sender ID (a cloned computer), two
  different original-log archives for one period, and a former name that
  is another live computer are each kept and raised as a High row; nothing
  is thrown away unread. A batch is "already imported" only when its
  content hash matches the batch imported under that number.

## Integrity

- Every report folder has a `manifest.sha256`. `blackbox verify` or
  `sha256sum -c manifest.sha256` detects any change, and any file the
  report needs that is missing. `blackbox verify` also fails on any file
  added anywhere in the folder, and on a listed file it can't read. It detects accidental damage, not
  deliberate editing: someone who can change the report can also
  rewrite its manifest. So it supports AU-9 b (detecting unauthorized
  modification), not AU-9 a (protecting the records) or AU-9(3)
  (cryptographic protection), until reports are signed; Blackbox does
  not sign them yet. Keep reports where only administrators can
  write, and copy them off the system for long-term evidence.
- **AU-5.** Blackbox notices auditing stopped, a log cleared or events
  lost at each collection, and reports them in `blackbox status` and the
  next report. Beyond the status icon on Windows it sends no alert, so it
  supports AU-5 only within that interval, and only when `blackbox
  status` (exit code 4 when something needs attention) is run by your
  monitoring.
- **AU-8.** The time checks are basic: a time service running (Windows
  Time synchronising, or chrony or systemd-timesyncd). They do not check
  the STIG's time rules (for example UBTU-24-600160 and UBTU-24-600180,
  how often the clock is compared and how much drift is corrected), and
  they are Blackbox's advice, not STIG rules.
- Collected events are only marked as read after they are safely written
  to disk, so a crash cannot lose them.

## Supply chain

- **No dependencies.** The Go module uses only the Go standard library; it
  has no third-party dependencies.
- **Offline, reproducible builds.** Builds use `-trimpath`, cgo is off, and
  build IDs are stripped, so the same source gives the same binary.
- **Checksums.** Each release publishes a `SHA256SUMS` file. When the
  release key is configured, `SHA256SUMS.asc` is a detached GPG signature
  of it ([how to verify](../README.md#verifying-a-release)).
- **Code signing.** When a code-signing certificate is configured (CI
  secrets `WINDOWS_SIGN_PFX_BASE64` and `WINDOWS_SIGN_PASSWORD`), the
  release signs the console `blackbox.exe` and the setup file with
  Authenticode. The setup file carries the signed `blackbox.exe` and
  installs it unchanged, and installs itself as `blackboxw.exe`, so both
  installed programs keep a valid signature. A signed program whose
  console/windowed mark has to be changed loses its signature instead of
  keeping one that no longer matches. Without the secrets the release is
  built unsigned, as before; nothing else changes.
- **FIPS 140-3 (SC-13).** Releases are built with `GOFIPS140=v1.0.0`
  (`scripts/build.sh`), which links Go's FIPS 140-3 module, the Go
  Cryptographic Module v1.0.0 (CMVP certificate #5247), and turns FIPS
  140-3 mode on by default. Blackbox's own cryptography is SHA-256 (the
  manifests, batch and archive checksums) and `crypto/rand`, both from
  that module. The build checks that the program reports the module, and
  CI runs the tests in FIPS mode. To check a program:

  ```
  blackbox version
  ```

  prints, after the version, a line such as `FIPS 140-3: Go
  Cryptographic Module v1.0.0 (built with GOFIPS140=v1.0.0); FIPS mode
  on`. `go version -m blackbox` shows the same build settings
  (`GOFIPS140=v1.0.0`, `DefaultGODEBUG=fips140=on`). A program built
  without `GOFIPS140` (from source, with plain `go build`) says "not built
  with GOFIPS140"; `GODEBUG=fips140=on` turns FIPS mode on for it at run
  time, but it then uses the standard library's copy of the code, not the
  frozen v1.0.0 module. `GODEBUG=fips140=off` turns FIPS mode off. This is
  Blackbox's own code only: the operating system's SMB, SSH and kernel
  crypto follow the system's FIPS setting (see lan.md).
- **Software bill of materials.** Each release includes
  `blackbox-<version>.spdx.json` (SPDX 2.3), generated by
  `scripts/sbom` from `go.mod` and the Go toolchain that built it.
- **Secrets stay in CI.** The certificate and the GPG key are only in
  the repository's Actions secrets; the workflow writes the certificate
  to the runner's temporary folder for the build and deletes it, and the
  GPG key lives in a temporary keyring that is removed after signing.
- **Tested on every change.** CI runs the unit tests on Linux and Windows.
  It also runs Blackbox against real event logs on a Windows machine, and
  against real auditd on an Ubuntu machine.

## Retention

Reports and collected events are kept forever by default. Set
`retention_days` to prune them ([configuration](configuration.md)). The
period (AU-11) comes from your site's records schedule, not from
Blackbox.
