# PortScanner

[![Release](https://img.shields.io/github/v/release/nsergej/PortScanner)](https://github.com/nsergej/PortScanner/releases)
[![License](https://img.shields.io/github/license/nsergej/PortScanner)](LICENSE)

PortScanner is a Windows VCL desktop application for scanning TCP ports on a
single IPv4 address. It uses multiple worker threads, non-blocking WinSock
sockets, and records response time for every open port it finds.

Use it only on systems and networks where you have explicit permission to scan.

## Important Limitations

- IPv4 only. The application accepts dotted-decimal IPv4 addresses such as
  `192.168.1.10` or `8.8.8.8`.
- Host names and IPv6 addresses are not supported.
- TCP only. UDP scanning is not implemented.
- One target address is scanned at a time.
- Report files are written next to the executable after a scan finishes.

## Features

- Scan any TCP port range from `1` to `65535`.
- Uses up to `256` worker threads.
- Measures response time for open ports.
- Sorts open ports by port number in the result list.
- Shows scan progress and open-port count in the UI.
- Can stop an active scan.
- Can fill the target field with the current external IP address.
- Exports reports as HTML, CSV, and JSON.

## Screenshot

<img width="436" height="591" alt="PortScanner main window" src="https://github.com/user-attachments/assets/201fbebb-34f3-49c2-bd53-27eae29a00a4" />

## Download

Download published builds from the
[GitHub Releases page](https://github.com/nsergej/PortScanner/releases).

The application does not require installation. Run `PortScanner.exe` on Windows.

## Usage

1. Start `PortScanner.exe`.
2. Enter a numeric IPv4 address.
3. Set the start and end ports.
4. Click `Start`.
5. Wait for the scan to finish or click `Stop` to cancel it.

When a scan finishes, the application automatically writes reports beside the
executable using this name pattern:

```text
portscan_yyyymmdd_hhnnss_<ip>.html
portscan_yyyymmdd_hhnnss_<ip>.csv
portscan_yyyymmdd_hhnnss_<ip>.json
```

## Example Results

The sample files in [`docs`](docs) come from the same scan:

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
    "open_ports": 3
  },
  "results": [
    {"index": 1, "ip": "8.8.8.8", "port": 53, "response_time": 157},
    {"index": 2, "ip": "8.8.8.8", "port": 443, "response_time": 125},
    {"index": 3, "ip": "8.8.8.8", "port": 853, "response_time": 31}
  ]
}
```

## Repository Layout

```text
.
|-- docs/
|   |-- sample_report.csv
|   |-- sample_report.html
|   `-- sample_report.json
|-- src/
|   |-- PortScanner.dpr
|   |-- Unit1.dfm
|   |-- Unit1.pas
|   |-- forbidden.ico
|   `-- forbidden.png
|-- CHANGELOG.md
|-- CONTRIBUTING.md
|-- LICENSE
|-- README.md
`-- SECURITY.md
```

## Build Requirements

- Windows 10 or newer.
- Embarcadero Delphi 10.4 Sydney or a compatible Delphi version with VCL.
- Delphi command-line tools available in `PATH`:
  - `cgrc`
  - `dcc32`
  - `dcc64` if building a 64-bit executable
- VCL sample controls package, because the form uses `Vcl.Samples.Spin`.

The repository stores the Delphi source as a `.dpr` project entry point and does
not require third-party libraries.

## Build With Delphi IDE

1. Open RAD Studio or Delphi.
2. Open [`src/PortScanner.dpr`](src/PortScanner.dpr).
3. If Delphi reports that `PortScanner.res` is missing, generate it from the
   existing icon:

   ```powershell
   Set-Location .\src
   'MAINICON ICON "forbidden.ico"' | Set-Content -Encoding ASCII .\PortScanner.rc
   cgrc .\PortScanner.rc
   ```

4. Select the target platform, for example `Win32` or `Win64`.
5. Build the project.
6. Run the generated `PortScanner.exe`.

`PortScanner.rc` and `PortScanner.res` are local resource build artifacts when
created this way. Review them before committing, or remove them after a manual
build if they are not intended to be tracked.

## Build From PowerShell

Run the commands from the repository root in a Delphi-enabled shell, such as the
RAD Studio Command Prompt.

### Prepare the resource file

The project contains `{$R *.res}` in `PortScanner.dpr`, so the compiler expects
`src\PortScanner.res`.

```powershell
Set-Location .\src
if (-not (Test-Path .\PortScanner.res)) {
    'MAINICON ICON "forbidden.ico"' | Set-Content -Encoding ASCII .\PortScanner.rc
    cgrc .\PortScanner.rc
}
Set-Location ..
```

### Build Win32

```powershell
$out = Join-Path (Get-Location) "build\Win32"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Push-Location .\src
dcc32 -B -E"$out" -N0"$out" -NH"$out" -NO"$out" -NB"$out" .\PortScanner.dpr
Pop-Location
```

The executable is written to:

```text
build\Win32\PortScanner.exe
```

### Build Win64

```powershell
$out = Join-Path (Get-Location) "build\Win64"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Push-Location .\src
dcc64 -B -E"$out" -N0"$out" -NH"$out" -NO"$out" -NB"$out" .\PortScanner.dpr
Pop-Location
```

The executable is written to:

```text
build\Win64\PortScanner.exe
```

## Validation Checklist

Before publishing a build:

1. Build the project for the target platform.
2. Start the executable on Windows.
3. Scan a permitted IPv4 target and a small port range.
4. Confirm that open ports appear in the UI.
5. Confirm that HTML, CSV, and JSON reports are created beside the executable.
6. Open each report file and check that the values match the UI results.

## Troubleshooting

### `E1026 File not found: 'PortScanner.res'`

Generate the resource file from `src\forbidden.ico` with `cgrc`:

```powershell
Set-Location .\src
'MAINICON ICON "forbidden.ico"' | Set-Content -Encoding ASCII .\PortScanner.rc
cgrc .\PortScanner.rc
```

### `Vcl.Samples.Spin` cannot be found

Install or enable the VCL sample controls package in Delphi, then rebuild.

### The external IP button returns an address that will not scan

The scanner accepts IPv4 only. If the external IP service returns IPv6, enter an
IPv4 address manually.

## Security

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting and responsible-use
guidance.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening an issue or pull request.

## License

This project is licensed under the [MIT License](LICENSE).
