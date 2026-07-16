# Troubleshooting

## Invalid IP Address

PortScanner accepts one numeric IPv4 address. Check that the value uses four decimal octets separated by dots, for example `192.168.1.10`.

DNS host names and IPv6 addresses are not supported. Remove spaces or other characters before starting the scan.

## Invalid Port Range

Both ports must be between `1` and `65535`, and the start port must not be greater than the end port.

Examples:

- Valid: `1-1000`
- Valid: `443-443`
- Invalid: `0-1000`
- Invalid: `1000-100`
- Invalid: `1-65536`

## No Open Ports Found

A result list with no rows means that no connection attempt was classified as open during the scan. Possible explanations include:

- No TCP service is listening in the selected range.
- A firewall or network device rejects or filters the connection attempts.
- The target is unavailable from the current network.
- The selected range does not include the expected service port.

Confirm the target and range with the system owner. Do not scan a broader range without authorization.

## Scan Takes a Long Time

Each connection attempt can wait up to `1500` milliseconds. Large ranges and filtered targets may therefore take longer than scans where ports reject connections immediately.

Use a smaller authorized range when you only need to check known services. PortScanner automatically uses up to `256` workers; the worker count is not configurable in the interface.

## Report Export Failed

Reports are written next to `PortScanner.exe`. Export fails when the application cannot create files in that directory.

Move the application to a normal user-writable directory, such as a dedicated folder under your user profile, and run the scan again. Keep Windows security protections enabled. If your organization controls folder permissions, ask the administrator for an approved writable location.

The application does not currently provide an output-folder selector.

## Reports Were Not Created After Stop

This is expected behavior in version 1.0.0. Automatic export runs only after a scan completes normally. Partial results from a stopped scan remain visible but are not exported.

## My External IP Failed

The **My External IP** button requests `https://icanhazip.com/`. The request may fail without internet access or when a proxy, firewall, DNS policy, or the remote service blocks the connection.

Enter a numeric IPv4 address manually when the external-address lookup is unavailable.

## PortScanner.res Not Found During Build

The source includes `{$R *.res}`, but the generated project resource is not tracked in the repository. Open `src/PortScanner.dpr` in Delphi and configure the application icon as described in [../BUILDING.md](../BUILDING.md). Save the project before building again.

## Style Auric Not Found at Startup

The current project entry point requests the `Auric` VCL style. In Delphi 10.4, open **Project > Options > Application > Appearance**, enable `Auric`, save the project, and rebuild it. The style must be included in the generated project resources.

See [../BUILDING.md](../BUILDING.md) for the complete project setup.
