# Development

## Layout

| Path | |
|---|---|
| `cmd/blackbox/` | Command-line entry point |
| `internal/winevt/` | Windows Event Log API, event XML parsing and translation |
| `internal/linuxlog/` | auditd, syslog and journal parsing and translation, following rotated log files |
| `internal/collect/` | Collection runs and bookmarks, for Windows and Linux |
| `internal/report/` | Report building (merging duplicates, findings, health) and the HTML template |
| `internal/check/` | Audit-setting checks against the STIG, and the recommended auditd rules |
| `internal/install/` | Windows scheduled task and Linux systemd timer, the setup wizard, LAN setup (inbox, share, mount) |
| `internal/lan/` | Sending batches to a collector and importing them (see [lan.md](lan.md#how-it-works)) |
| `internal/share/` | Reaching a collector's share: Windows share sign-in and DPAPI-protected password, Linux mount point |
| `internal/store/`, `internal/config/`, `internal/app/` | State, settings, and the report schedule |
| `packaging/` | Files shipped in the Linux packages (`install.sh`, …); Windows ships one setup file |
| `testdata/` | Synthetic Windows and Ubuntu logs, used by the tests and the samples |
| `docs/` | Documentation and screenshots |

## Build and test

```sh
go test ./...                     # unit tests
go vet ./... && GOOS=windows go vet ./...
VERSION=0.1.0 scripts/build.sh    # release packages in dist/
TZ=America/New_York scripts/screenshots.sh   # regenerate docs/images
```

Go 1.24 or later is required. There are no other dependencies, and
everything builds offline.

`TestGolden` builds a report from the sample logs in `testdata/` and
compares its detections, rows and `summary.json` with
`internal/report/testdata/golden.txt`. When a change is meant to alter
what a report says, run `go test ./internal/report -run TestGolden -update`
and check the diff of that file with the change. The rules for what is
left out of a report and what is merged into one row are listed at the
top of `internal/report/merge.go`.

`scripts/build.sh` embeds the program icon and version details (publisher,
version, description) in `blackbox.exe`, using `scripts/winres`, a small
standard-library generator. A plain `go build` for Windows works but
produces an exe without them; run
`go run ./scripts/winres -version <version>` first to include them.

## Releasing

Run the **Release** workflow from the Actions tab ("Run workflow", then
enter a version such as `0.2.0`), or push a version tag:

```sh
git tag v0.2.0
git push origin v0.2.0
```

The **Release** workflow then tests, builds the Windows setup file, the Linux
tarballs and `SHA256SUMS`, and publishes them on the
[Releases](https://github.com/casea1/blackbox/releases) page.

## CI

| Job | |
|---|---|
| `test` | Formatting, vet (Linux and Windows), race-enabled tests, and the package build |
| `windows` | Tests on Windows, then `check`, `collect`, `report` and `verify` against the runner's real event logs |
| `linux-live` | Installs auditd with the recommended rules on Ubuntu, makes account and sudoers changes, then checks the report contains them |

A pull request that changes only documentation (files under `docs/`, or
any `.md` file) runs `test` only: the `changes` job skips `linux-live`
and `windows`, which take about 10 minutes. A push to main always runs
every job. Package installs on the Linux runner go through
`scripts/ci-apt.sh`, which gives up on a hung mirror after 5 minutes and
tries again (3 attempts); `linux-live` and `windows` also stop after 30
and 40 minutes.
