# Using PortScanner

## Scope

PortScanner checks a continuous range of TCP ports on one numeric IPv4 address. It lists only ports for which a TCP connection succeeds.

Use the application only on systems and networks that you own or are explicitly authorized to scan.

## Starting the Application

Run `PortScanner.exe`. On startup, the application initializes WinSock, places a local IPv4 address in the address field when one can be resolved, and sets the port range to `1-65535`.

The main window contains:

- **Adress**: the numeric IPv4 target address
- **Start**: the first TCP port to check
- **End**: the last TCP port to check
- **Start/Stop**: starts or stops the current scan
- **My External IP**: requests the public IPv4 address from `https://icanhazip.com/`
- **Open Port**: the current number of detected open ports
- Result list: detected open ports and their response times
- Progress bar and status bar: scan progress and current state

The label `Adress` is the spelling currently used by the application interface.

## Entering an IPv4 Address

Enter a numeric dotted-decimal IPv4 address, for example:

```text
192.168.1.10
```

IPv6 addresses and DNS host names are not supported. The field accepts digits, dots, and editing with Backspace. PortScanner validates the complete address when a scan starts.

Selecting **My External IP** makes an HTTPS request to `icanhazip.com` and replaces the address field with the returned value. This action requires internet access and may fail when the service is unavailable or blocked by local network policy.

## Selecting the Port Range

Set both port values between `1` and `65535`:

- **Start** is the first port checked.
- **End** is the last port checked.
- The start port must be less than or equal to the end port.

The number of worker threads is selected automatically. PortScanner creates one worker per port for small ranges and uses no more than `256` workers for larger ranges.

## Starting a Scan

1. Confirm that you are authorized to scan the target.
2. Enter a numeric IPv4 address.
3. Set the start and end ports.
4. Select **Start**.

Starting a scan clears the previous result list and counters. The button caption changes to **Stop**. The status bar initially shows the number of ports and workers, then displays completed ports, total ports, open ports, and the approximate processing rate.

Each connection attempt has a fixed timeout of `1500` milliseconds. Actual scan duration depends on the size of the range, target behavior, local network conditions, and filtering between the application and target.

## Reading the Results

The result list is rebuilt whenever an open port is found. Rows are sorted by port number and contain:

```text
ID  IP              PORT   STATE   RESPONSE
```

- **ID**: one-based result index
- **IP**: scanned IPv4 address
- **PORT**: open TCP port
- **STATE**: `OPEN`
- **RESPONSE**: measured TCP connection time in milliseconds

Closed, rejected, and timed-out ports are counted as processed but are not added to the result list.

## Stopping a Scan

Select **Stop** while a scan is active. PortScanner clears the pending queue and asks the worker threads to stop. The button remains disabled until all active workers have returned from their current operation.

Open ports found before the stop request remain visible. A stopped scan is not automatically exported.

## Completing and Exporting a Scan

When all queued ports have been processed normally, the progress bar reaches 100% and the status bar reports completion. PortScanner then automatically creates HTML, CSV, and JSON files next to the running `PortScanner.exe`.

There is no manual export button and no output-folder selector. See [EXPORT_FORMATS.md](EXPORT_FORMATS.md) for file names and report fields.

## Starting Another Scan

After completion or cancellation, the button returns to **Start**. Change the address or range as needed and start a new scan. Existing on-screen results are cleared when the new scan begins; previously exported files remain on disk.
