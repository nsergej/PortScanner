# Manual Test Plan

Use this plan after code changes and before publishing a release.

## Build Checks

1. Build Win32 with `dcc32`.
2. Build Win64 with `dcc64`.
3. Confirm no generated `.exe`, `.dcu`, `.map`, `.res`, or report files are
   staged for commit.

## Functional Checks

1. Scan `127.0.0.1` with a small port range.
2. Scan one known open port on a system where you have permission.
3. Scan one known closed port on a system where you have permission.
4. Run a full `1..65535` scan only against a test host where the owner has
   explicitly permitted it.
5. Stop an active scan and confirm the UI returns to the idle state.
6. Start a second scan after stopping or completing the first scan.
7. Close the program while a scan is active and confirm it exits cleanly.
8. Enter an invalid IPv4 address and confirm a clear validation message appears.
9. Enter an invalid port range and confirm a clear validation message appears.
10. Use `My External IP` with internet access and confirm the value is IPv4.
11. Disable internet access or block the external IP service and confirm the UI
    shows an error instead of hanging indefinitely.

## Export Checks

1. Complete a scan with at least one open port.
2. Confirm HTML, CSV, and JSON files are written to:

   ```text
   %USERPROFILE%\Documents\PortScanner Reports
   ```

3. Open the HTML report and confirm metadata and rows match the UI.
4. Import the CSV report and confirm the header is
   `Index,IP,Port,ResponseTimeMs`.
5. Parse the JSON report and confirm `scan_info.workers` matches the actual
   worker count used for the scan.
6. Test export when Documents is unavailable or read-only if the environment can
   safely simulate that condition.
