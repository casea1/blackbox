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
- **It never modifies logs.** It never clears, rotates, deletes or forwards
  them.
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

- **Least privilege on the inbox.** On a Windows collector, the inbox
  folder is restricted by SID to:
  - Administrators and SYSTEM
  - a local group, **Blackbox Senders**, that may add, change and remove files
    there (Modify), and nothing else

  If shared, the share grants Change to that group only. The installer
  creates the group and, when asked, adds named accounts to it. It never
  creates accounts itself.
- **Stored credentials.**
  - Windows: a sender's share password is encrypted with DPAPI, bound to
    the machine. It is kept in the data folder, which only Administrators
    and SYSTEM can read.
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
  (and, until a report takes them, in the data folder's `archive-pieces`
  and `archives` folders), which only
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
  access to the inbox. The batches are not cryptographically signed.
- **No loops, no spoofed collectors.**
  - A computer refuses its own batches.
  - It only delivers to a folder that has the collector's marker file, so
    an unmounted share (an empty local folder) is never written to by
    mistake.
- **What a sender can claim.** A sender supplies the host names in its
  data. The Systems page lists every computer seen, so an unexpected one
  stands out. If one computer delivers collection records for another,
  the report marks that system "via" the computer that delivered them.
- **Which account delivered a batch (not checked yet, L2).** Any member
  of Blackbox Senders can write a batch to the inbox, and the collector
  does not compare the account that wrote the file with the sender it
  claims to be. A sender could therefore deliver batches under another
  sender's name; the sequence numbers would then show a gap or a
  duplicate for the real one, and the report says so. A planned check
  would record, for each sender ID, the account that owned its first
  batch (the file's owner on NTFS, or the mounting account on Linux), and
  set aside later batches owned by anyone else. Until then, give each
  sender its own account, and keep Blackbox Senders to those accounts.

## Integrity

- Every report folder has a `manifest.sha256`. `blackbox verify` or
  `sha256sum -c manifest.sha256` detects any change, and any file the
  report needs that is missing. It detects accidental damage, not
  deliberate editing: someone who can change the report can also
  rewrite its manifest. Keep reports where only administrators can
  write, and copy them off the system for long-term evidence.
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
`retention_days` to prune them ([configuration](configuration.md)).
