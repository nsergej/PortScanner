# Changelog

All notable changes to PortScanner are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Detailed Delphi 10.4 Sydney build instructions.
- Usage, export-format, troubleshooting, and architecture guides.
- Contribution guidelines and a Contributor Covenant Code of Conduct.
- Private security reporting instructions.
- GitHub issue forms and a pull request template.
- This changelog.

### Changed

- Reworked the README with the current status, limitations, installation, usage, stopping, export, build, and responsible-use information.
- Documented that PortScanner accepts one numeric IPv4 address and does not support IPv6 or DNS host names.
- Synchronized the README result table with the sample reports in `docs`.

### Fixed

- Renamed `sample_repor.csv`, `sample_repor.html`, and `sample_repor.json` to use the correct `sample_report` name.
- Corrected documentation links and English terminology.

## [1.0.0]

### Added

- Windows VCL interface for scanning one numeric IPv4 address.
- Configurable TCP port range from `1` through `65535`.
- Multithreaded processing with up to `256` workers.
- Open-port display with measured connection response time.
- Progress, open-port count, scan-speed status, and scan cancellation.
- Automatic HTML, CSV, and JSON report export after a completed scan.
- External IPv4 address lookup through the **My External IP** button.

[Unreleased]: https://github.com/nsergej/PortScanner/compare/V1.0...HEAD
[1.0.0]: https://github.com/nsergej/PortScanner/releases/tag/V1.0
