# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses version names from the application source and GitHub
releases when available.

## [Unreleased]

### Documentation

- Rewrote `README.md` with usage, limitations, repository layout, report
  examples, troubleshooting, and detailed Delphi build instructions.
- Documented that the scanner supports numeric IPv4 addresses only.
- Added contribution guidelines in `CONTRIBUTING.md`.
- Added vulnerability reporting and responsible-use guidance in `SECURITY.md`.
- Added this changelog.
- Renamed sample report files from `sample_repor.*` to `sample_report.*`.
- Synchronized README example values with the files in `docs`.

## [1.0]

### Added

- Windows VCL TCP port scanner.
- Configurable TCP port range from `1` to `65535`.
- Multithreaded scanning with up to `256` workers.
- Open-port response time display.
- HTML, CSV, and JSON report export.
