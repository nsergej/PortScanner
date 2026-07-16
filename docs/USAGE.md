# Usage

## Authorized Use Only

Only scan systems and networks that you own or have explicit permission to test.

## Scan A Target

1. Start `PortScanner.exe`.
2. Enter a numeric IPv4 address.
3. Set the start and end ports.
4. Click `Start`.
5. Watch progress in the status bar and open ports in the result list.
6. Click `Stop` to cancel an active scan.

The input field accepts digits and dots. Host names and IPv6 addresses are not
supported.

## External IPv4 Button

`My External IP` calls `https://icanhazip.com/` with a timeout and uses the
response only if it is a valid numeric IPv4 address.

## Reports

After a completed scan, PortScanner writes HTML, CSV, and JSON reports to:

```text
%USERPROFILE%\Documents\PortScanner Reports
```

Report filenames include the timestamp and target IPv4 address.

## Report Privacy

Reports contain target IP addresses, open ports, and response times. Treat them
as operational data and do not publish private scan results without permission.
