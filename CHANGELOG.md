# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Fixed worker thread startup so fields are initialized before `Start`.
- Reworked worker ownership so the form stops and waits for workers before
  freeing shared queues, result lists, and WinSock.
- Protected scan cancellation and queue access with the existing critical
  section.
- Reduced UI synchronization by batching closed-port progress updates.
- Avoided full result-list rebuilds for every open-port update.
- Checked `getsockopt(..., SO_ERROR, ...)` before treating a TCP connect as open.
- Replaced `GetTickCount` with `GetTickCount64` for response timing.
- Added strict numeric IPv4 validation for scan targets and external IP lookup.
- Added WinInet timeouts, response accumulation, response size limit, and IPv4
  validation for the external IP button.
- Changed report output to the user's Documents folder to avoid protected
  executable directories.
- Added CSV escaping and JSON serialization through Delphi JSON classes.
- Fixed UI text: `Address` and `Open Ports`.
- Removed the hard-coded unavailable `Auric` VCL style so the application starts
  without a missing-style dialog.
- Fixed scan progress updates so closed-port progress is flushed regularly
  instead of appearing to jump only when an open port is found.
- Fixed command-line builds by adding `src/PortScanner.rc` and using a resource
  directive that can generate `PortScanner.res` from source.

### Documentation

- Rewrote `README.md` with actual usage, limitations, report behavior, sample
  outputs, repository layout, security notes, and roadmap.
- Added `BUILDING.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `docs/USAGE.md`, `docs/ARCHITECTURE.md`, and
  `docs/TEST_PLAN.md`.
- Renamed sample report files from `sample_repor.*` to `sample_report.*`.
- Synchronized README example values with the files in `docs`.

### Maintenance

- Added GitHub pull request and issue templates.
- Added a lightweight GitHub Actions workflow for repository structure and sample
  consistency checks.
- Updated `.gitignore` for Delphi outputs and runtime scan reports.
- Updated `.gitattributes` for Delphi text files, documentation files, and
  binary assets.

## [1.0]

### Added

- Windows VCL TCP port scanner.
- Configurable TCP port range from `1` to `65535`.
- Multithreaded scanning with up to `256` workers.
- Open-port response time display.
- HTML, CSV, and JSON report export.
