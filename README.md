[![Release](https://img.shields.io/github/v/release/nsergej/PortScanner)](https://github.com/nsergej/PortScanner/releases)
[![License](https://img.shields.io/github/license/nsergej/PortScanner)](LICENSE)

# PortScanner

## Project Description

PortScanner is a multithreaded TCP port scanner with a graphical interface for Windows. It checks a configurable TCP port range on one numeric IPv4 address, lists open ports, measures connection response time, and produces HTML, CSV, and JSON reports.

## Current Project Status

The current documented version is **1.0.0** (repository tag `V1.0`). The repository contains the Delphi VCL source, application assets, and sample reports. Generated Delphi project and resource files are not tracked, so a local project resource must be configured before building from source.

The repository does not currently include automated builds or automated tests.

## Screenshot

<img width="436" height="591" alt="PortScanner 1.0 application window" src="https://github.com/user-attachments/assets/201fbebb-34f3-49c2-bd53-27eae29a00a4">

## Main Features

- Scans one numeric IPv4 address at a time
- Supports TCP ports from 1 through 65535
- Uses up to 256 worker threads
- Uses non-blocking WinSock connections with a fixed connection timeout
- Lists open ports in ascending port order
- Displays response time for each open port
- Displays scan progress, the number of open ports, and scan speed
- Stops an active scan from the same Start/Stop button
- Automatically exports completed scans to HTML, CSV, and JSON
- Retrieves the external IPv4 address on request through `icanhazip.com`

## Current Limitations

- IPv4 only; IPv6 is not supported
- Numeric IPv4 addresses only; DNS host names are not accepted
- One target address and one continuous port range per scan
- Worker count and connection timeout are fixed in the source code
- Only open ports are displayed and exported
- Reports are exported automatically; there is no manual export command or output-folder selector
- A scan stopped by the user is not exported automatically

## System Requirements

### Running PortScanner

- Windows 10 or later
- Network connectivity to the authorized target
- Permission to scan the selected system or network
- Write access to the directory containing `PortScanner.exe` for report export
- An internet connection only when using **My External IP**

### Building PortScanner

- Embarcadero Delphi 10.4 Sydney
- Windows VCL development components
- A configured 32-bit Windows target

See [BUILDING.md](BUILDING.md) for the complete setup and build procedure.

## Download

Published builds are available on the [GitHub Releases page](https://github.com/nsergej/PortScanner/releases).

## Installation

PortScanner does not require an installer:

1. Download the available release package from GitHub Releases.
2. Extract the files to a directory where your Windows account has write access.
3. Start `PortScanner.exe`.

Do not place the application in a protected directory if you expect it to export reports there.

## Usage

The application opens with a local IPv4 address in the address field and the full port range selected. The interface contains the target address, start and end ports, a Start/Stop button, an open-port counter, a result list, a progress bar, and a status bar.

See [docs/USAGE.md](docs/USAGE.md) for detailed operating instructions and [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common errors.

## Starting a Scan

1. Enter one numeric IPv4 address, such as `192.168.1.10`.
2. Set the first and last TCP ports. Both values must be between `1` and `65535`, and the start value must not exceed the end value.
3. Select **Start**.
4. Monitor the progress bar, status bar, open-port counter, and result list.

Starting a new scan clears the previous on-screen results.

## Stopping a Scan

While a scan is active, the **Start** button changes to **Stop**. Select it to clear the pending port queue and request all worker threads to stop. The button is temporarily disabled until the active workers finish their current work.

Partial results remain visible, but reports are not automatically generated for a stopped scan.

## Export Formats

After a scan finishes normally, PortScanner automatically writes three UTF-8 report files next to the running executable:

```text
portscan_YYYYMMDD_HHMMSS_IP.html
portscan_YYYYMMDD_HHMMSS_IP.csv
portscan_YYYYMMDD_HHMMSS_IP.json
```

Dots in the IPv4 address are replaced with underscores in the file name. See [docs/EXPORT_FORMATS.md](docs/EXPORT_FORMATS.md) for the exact fields and structures.

## Example Results

The following rows match all three sample files in the [`docs`](docs) directory:

| Index | IPv4 address | Port | Response time (ms) |
|------:|--------------|-----:|-------------------:|
| 1 | 8.8.8.8 | 53 | 157 |
| 2 | 8.8.8.8 | 443 | 125 |
| 3 | 8.8.8.8 | 853 | 31 |

Sample reports:

- [CSV report](docs/sample_report.csv)
- [HTML report](docs/sample_report.html)
- [JSON report](docs/sample_report.json)

The samples describe one scan of `8.8.8.8`, ports `1` through `1000`, with three open ports. The HTML and JSON samples use the timestamp `2026-03-27 01:39:44`, and the response times are the values shown above.

## Building from Source

Open `src/PortScanner.dpr` in Delphi 10.4 Sydney and configure the generated project resource before building the 32-bit Windows target. The repository does not track a `.dproj` or `.res` file.

Follow [BUILDING.md](BUILDING.md) for required files, VCL style setup, Debug and Release configurations, and output locations.

## Project Structure

```text
PortScanner/
|-- .github/                   Issue and pull request templates
|-- docs/
|   |-- ARCHITECTURE.md        Current implementation overview
|   |-- EXPORT_FORMATS.md      HTML, CSV, and JSON report definitions
|   |-- TROUBLESHOOTING.md     Common problems and corrective actions
|   |-- USAGE.md               Detailed operating instructions
|   `-- sample_report.*        Synchronized sample reports
|-- src/
|   |-- PortScanner.dpr        Delphi program entry point
|   |-- Unit1.pas              Form logic, workers, scanning, and export
|   |-- Unit1.dfm              VCL form definition
|   |-- forbidden.ico          Application icon asset
|   `-- forbidden.png          Image asset
|-- BUILDING.md                Delphi 10.4 build guide
|-- CHANGELOG.md               Version history
|-- CODE_OF_CONDUCT.md         Community standards
|-- CONTRIBUTING.md            Contribution workflow
|-- LICENSE                    MIT License
|-- README.md                  Project overview
`-- SECURITY.md                Private security reporting policy
```

For a concise implementation description, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Responsible Use

Use PortScanner only on systems and networks that you own or are explicitly authorized to test. Unauthorized scanning may violate laws, contracts, acceptable-use policies, or organizational rules.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. Participation in the project is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

Report potential security issues privately by following [SECURITY.md](SECURITY.md). Do not publish sensitive details in a public GitHub issue.

## License

PortScanner is available under the [MIT License](LICENSE).
