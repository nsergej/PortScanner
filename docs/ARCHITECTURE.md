# Architecture

## Overview

PortScanner is a single-form Windows VCL application written in Delphi. The current implementation is contained primarily in `src/Unit1.pas`, with the form layout in `src/Unit1.dfm` and the program entry point in `src/PortScanner.dpr`.

## Main Form

`TForm1` owns the visible controls and coordinates validation, scan startup, cancellation, progress updates, result display, and report export. WinSock is initialized when the form is created and cleaned up when the form is destroyed.

## Port Queue

The requested inclusive port range is placed in a shared `TQueue<Integer>`. Access to the queue is protected by a `TCriticalSection`. Stopping a scan sets a cancellation flag and clears the remaining queue.

## Worker Threads

`TPortWorker` derives from `TThread`. A scan creates one worker per requested port for small ranges and no more than `256` workers for larger ranges.

Each worker repeatedly removes a port from the queue and attempts a non-blocking TCP connection. The connection uses an IPv4 WinSock socket and `select` with a `1500` millisecond timeout.

## UI Synchronization

Workers call synchronized methods on the main thread after each processed port and when each worker finishes. The main form updates counters, progress, status text, and the visible result list.

## Open-Port Results

Open ports are stored in a `TList<TScanResult>`. Each result contains the IPv4 address, port, open state, and response time. Open results are inserted in ascending port order. Closed and timed-out ports are counted for progress but are not stored in the result list.

## Report Export

After a scan completes normally, the main form serializes the stored open-port results to HTML, CSV, and JSON using `TStringList`. Reports are written as UTF-8 files next to the running executable. A cancelled scan does not invoke the export step.

See [EXPORT_FORMATS.md](EXPORT_FORMATS.md) for the exact report structures.
