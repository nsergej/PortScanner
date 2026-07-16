# Architecture

PortScanner is a compact Delphi VCL application. The current implementation keeps
the scanner, UI, and export code in `src/Unit1.pas`; this is acceptable for the
current project size, but the boundaries are documented here for future changes.

## Main Components

- `TForm1`: owns the UI, scan state, worker lifecycle, and report export.
- `TPortWorker`: worker thread that dequeues TCP ports and performs non-blocking
  WinSock connect checks.
- `PortQueue`: synchronized queue of pending ports.
- `ScanResults`: sorted list of open ports shown in the UI and exported to
  reports.

## Threading Model

The form creates at most `MAX_WORKERS` worker threads. Workers are created
suspended, initialized, stored, and then started. They are not `FreeOnTerminate`;
the form owns and frees them after completion.

Progress is reported to the UI thread in batches instead of once per scanned
port. Open-port results are still reported immediately so the result list stays
useful during long scans.

On shutdown, the form requests cancellation, clears the queue, waits for running
workers to finish, and only then frees shared state and calls `WSACleanup`.

## Networking

Port scanning uses WinSock TCP sockets with:

- `AF_INET`;
- `SOCK_STREAM`;
- non-blocking `connect`;
- `select` timeout;
- `getsockopt(..., SO_ERROR, ...)` to confirm connection success.

The application is IPv4-only by design in the current architecture.

The optional external IP lookup uses WinInet with explicit send, receive, and
connect timeouts. The response is size-limited and validated as IPv4 before it is
copied into the target field.

## Export

Reports are written to the user's Documents folder under `PortScanner Reports`.
HTML dynamic values are escaped, CSV values are quoted when needed, and JSON is
serialized with Delphi JSON classes.

## Future Refactoring

If the project grows, the next useful split is:

- scanner engine and worker pool;
- report writer;
- VCL form.

That split should be done with tests or a validated manual test plan, not as a
cosmetic rewrite.
