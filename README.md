![Release](https://img.shields.io/github/v/release/nsergej/PortScanner)
![License](https://img.shields.io/github/license/nsergej/PortScanner)

# PortScanner

PortScanner is a fast, multithreaded TCP port scanner with a graphical interface for Windows.

> [!IMPORTANT]
> PortScanner supports numeric IPv4 addresses only. IPv6 addresses and host names are not supported.

## Features

- Scans a single IPv4 address over a configurable TCP port range
- Supports the full TCP port range from 1 to 65535
- Uses multithreaded, non-blocking WinSock operations
- Displays scan progress and response times
- Sorts detected open ports automatically
- Exports reports in HTML, CSV, and JSON formats
- Runs as a native Windows VCL application

## Screenshot

<img width="436" height="591" alt="PortScanner application window" src="https://github.com/user-attachments/assets/201fbebb-34f3-49c2-bd53-27eae29a00a4">

## Requirements

### Running the application

- Windows 10 or later
- A numeric IPv4 target address
- Permission to scan the target system or network

### Building from source

- Embarcadero Delphi 10.4 Sydney
- The Windows VCL application development components
- A configured 32-bit Windows target platform

## Build Instructions for Delphi

The repository contains the Delphi project source in the `src` directory. Build the application as follows:

1. Start Embarcadero RAD Studio 10.4.
2. Select **File > Open** and open `src/PortScanner.dpr`.
3. If RAD Studio asks to create or save a project file, accept the prompt and keep the generated project files in the `src` directory.
4. Select **Project > Options > Application > Icons**.
5. Load `src/forbidden.ico` as the application icon, then select **Save All**. This creates the project resource required by the `{$R *.res}` directive.
6. In **Project Manager**, select the **32-bit Windows** target platform.
7. Choose either the **Debug** or **Release** build configuration.
8. Select **Project > Build PortScanner**.
9. Locate `PortScanner.exe` in the output directory configured by RAD Studio. With the default configuration, it is normally under `src/Win32/Debug` or `src/Win32/Release`.

After the IDE has generated the project resource, the same project can also be rebuilt from the **RAD Studio Command Prompt**:

```powershell
cd path\to\PortScanner\src
dcc32 -B PortScanner.dpr
```

The command-line compiler writes the executable to the configured output directory, or to the current directory when no custom output directory is set.

## Download

Prebuilt releases are available on the [GitHub Releases page](https://github.com/nsergej/PortScanner/releases).

No installer is required. Extract the release archive and run `PortScanner.exe`.

## Usage

1. Start `PortScanner.exe`.
2. Enter a numeric IPv4 address.
3. Set the TCP port range and worker count.
4. Start the scan.
5. Export the results to HTML, CSV, or JSON when required.

Use PortScanner only on systems and networks that you own or are explicitly authorized to test.

## Report Examples

The example below is synchronized with the report files in the [`docs`](docs) directory:

| Index | IPv4 address | Port | Response time (ms) |
|------:|--------------|-----:|-------------------:|
| 1 | 8.8.8.8 | 53 | 157 |
| 2 | 8.8.8.8 | 443 | 125 |
| 3 | 8.8.8.8 | 853 | 31 |

Complete sample reports:

- [CSV report](docs/sample_report.csv)
- [HTML report](docs/sample_report.html)
- [JSON report](docs/sample_report.json)

The HTML and JSON samples were generated on `2026-03-27 01:39:44` for ports `1-1000` with `256` workers. The JSON summary records `1000` scanned ports and `3` open ports.

## Repository Structure

```text
PortScanner/
|-- docs/                  Sample CSV, HTML, and JSON reports
|-- src/                   Delphi VCL project source and application assets
|-- CHANGELOG.md           Notable project changes
|-- CONTRIBUTING.md        Contribution guidelines
|-- LICENSE                MIT License
|-- README.md              Project overview and build instructions
`-- SECURITY.md            Private security reporting policy
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and documentation guidelines.

## Security

For private reporting instructions, see [SECURITY.md](SECURITY.md). Do not publish security-sensitive details in a public issue.

## License

PortScanner is distributed under the [MIT License](LICENSE).
