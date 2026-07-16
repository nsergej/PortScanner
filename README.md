# PortScanner

[![Release](https://img.shields.io/github/v/release/nsergej/PortScanner)](https://github.com/nsergej/PortScanner/releases)
[![License](https://img.shields.io/github/license/nsergej/PortScanner)](LICENSE)

PortScanner is a Windows VCL desktop application for scanning TCP ports on one
numeric IPv4 address. It uses a bounded worker pool, non-blocking WinSock TCP
connect checks, and records response time for every open port it finds.

Use PortScanner only on systems and networks that you own or have explicit
permission to test.

## Screenshot

<img width="436" height="591" alt="PortScanner main window" src="https://github.com/user-attachments/assets/201fbebb-34f3-49c2-bd53-27eae29a00a4" />

## Features

- Scans a TCP port range from `1` to `65535`.
- Scans one numeric IPv4 address at a time.
- Uses up to `256` worker threads instead of creating one thread per port.
- Measures TCP connect response time for open ports.
- Shows progress, open-port count, and scan speed in the UI.
- Allows stopping an active scan.
- Sorts open ports by port number.
- Exports reports as HTML, CSV, and JSON.
- Writes reports to the current user's Documents folder.
- Can optionally query `https://icanhazip.com/` to fill the external IPv4 field.

## Limitations

- IPv4 only. Host names and IPv6 addresses are not supported.
- TCP only. UDP scanning is not implemented.
- One target address is scanned per run.
- The external IP button depends on a third-party service and validates that the
  response is a numeric IPv4 address before using it.
- No stealth, evasion, credential testing, or network-discovery features are
  included.

Potential future work is tracked in the [Roadmap](#roadmap).

## System Requirements

- Windows 10 or newer for running the application.
- Embarcadero Delphi 10.4 Sydney or a compatible Delphi version with VCL for
  building from source.
- WinSock 2.2, available on supported Windows versions.
- VCL sample controls package, because the UI uses `Vcl.Samples.Spin`.

## Download

Published builds are available on the
[GitHub Releases page](https://github.com/nsergej/PortScanner/releases).

Download the release archive, extract it, and run `PortScanner.exe` on Windows.

## Quick Start

1. Start `PortScanner.exe`.
2. Enter a numeric IPv4 address, for example `127.0.0.1`.
3. Set the start and end ports.
4. Click `Start`.
5. Click `Stop` if you need to cancel the scan.

After a completed scan, reports are written to:

```text
%USERPROFILE%\Documents\PortScanner Reports
```

Report names use this pattern:

```text
portscan_yyyymmdd_hhnnss_<ip>.html
portscan_yyyymmdd_hhnnss_<ip>.csv
portscan_yyyymmdd_hhnnss_<ip>.json
```

See [docs/USAGE.md](docs/USAGE.md) for detailed usage notes.

## Example Results

The sample files in [`docs`](docs) describe the same scan:

- [`docs/sample_report.csv`](docs/sample_report.csv)
- [`docs/sample_report.html`](docs/sample_report.html)
- [`docs/sample_report.json`](docs/sample_report.json)

Scan metadata:

| Field | Value |
| --- | --- |
| Generated | `2026-03-27 01:39:44` |
| Target | `8.8.8.8` |
| Port range | `1 - 1000` |
| Workers | `256` |
| Open ports | `3` |

Open ports:

| # | IP | Port | Response time |
| ---: | --- | ---: | ---: |
| 1 | `8.8.8.8` | `53` | `157 ms` |
| 2 | `8.8.8.8` | `443` | `125 ms` |
| 3 | `8.8.8.8` | `853` | `31 ms` |

CSV:

```csv
Index,IP,Port,ResponseTimeMs
1,8.8.8.8,53,157
2,8.8.8.8,443,125
3,8.8.8.8,853,31
```

JSON:

```json
{
  "scan_info": {
    "date": "2026-03-27 01:39:44",
    "total_ports": 1000,
    "open_ports": 3,
    "workers": 256
  },
  "results": [
    {"index": 1, "ip": "8.8.8.8", "port": 53, "response_time": 157},
    {"index": 2, "ip": "8.8.8.8", "port": 443, "response_time": 125},
    {"index": 3, "ip": "8.8.8.8", "port": 853, "response_time": 31}
  ]
}
```

## Export Formats

- HTML report: human-readable table with generated time, target, port range, and
  actual worker count.
- CSV report: `Index,IP,Port,ResponseTimeMs`.
- JSON report: `scan_info` metadata and a `results` array.

Dynamic HTML text is escaped, CSV fields are quoted when needed, and JSON is
serialized with Delphi JSON classes.

## Build From Source

See [BUILDING.md](BUILDING.md) for complete Delphi IDE and command-line build
instructions.

Short version:

```powershell
$out = Join-Path (Get-Location) "build\Win32"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Push-Location .\src
cgrc .\PortScanner.rc
dcc32 -B -E"$out" -N0"$out" -NH"$out" -NO"$out" -NB"$out" .\PortScanner.dpr
Pop-Location
```

The Delphi IDE project file is [`src/PortScanner.dproj`](src/PortScanner.dproj).
The command-line build runs `cgrc` first so the generated executable includes
the application icon and Windows version information from
[`src/PortScanner.rc`](src/PortScanner.rc).

## Repository Layout

```text
.
|-- .github/
|   |-- ISSUE_TEMPLATE/
|   |-- PULL_REQUEST_TEMPLATE.md
|   `-- workflows/
|-- docs/
|   |-- ARCHITECTURE.md
|   |-- TEST_PLAN.md
|   |-- USAGE.md
|   |-- sample_report.csv
|   |-- sample_report.html
|   `-- sample_report.json
|-- src/
|   |-- PortScanner.dpr
|   |-- PortScanner.dproj
|   |-- PortScanner.rc
|   |-- Unit1.dfm
|   |-- Unit1.pas
|   |-- forbidden.ico
|   `-- forbidden.png
|-- BUILDING.md
|-- CHANGELOG.md
|-- CODE_OF_CONDUCT.md
|-- CONTRIBUTING.md
|-- LICENSE
|-- README.md
`-- SECURITY.md
```

## Architecture

The VCL form owns the UI, scan queue, worker lifecycle, and report export. Worker
threads dequeue ports from a synchronized queue and report progress back to the
main thread in batches. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the
current architecture and known boundaries.

## Testing

This repository does not include a Delphi unit-test framework. The current
verification path is:

- compile with `dcc32` and `dcc64`;
- run repository structure and sample consistency checks;
- follow the manual plan in [docs/TEST_PLAN.md](docs/TEST_PLAN.md).

## Security

Port scanning can be intrusive. Only scan targets where you have explicit
authorization. Do not publish scan results that reveal private systems without
permission.

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## Roadmap

- Add a `.dproj` only when it can be generated and validated against the current
  Delphi version and source layout.
- Add automated Delphi tests if a buildable test project can be kept compatible
  with the supported Delphi version.
- Consider configurable export location in the UI.
- Consider DNS or IPv6 support only as a deliberate architecture change.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening issues or pull requests.

## License

This project is licensed under the [MIT License](LICENSE).
