# Export Formats

## Export Behavior

PortScanner automatically exports a scan only after every queued port has been processed. A manually stopped scan is not exported.

The three reports are written as UTF-8 text next to the running `PortScanner.exe`. All files from one export use the same base name:

```text
portscan_YYYYMMDD_HHMMSS_IP
```

The date and time are taken from the local system clock. Dots in the IPv4 address are replaced with underscores. For example:

```text
portscan_20260327_013944_8_8_8_8.html
portscan_20260327_013944_8_8_8_8.csv
portscan_20260327_013944_8_8_8_8.json
```

Only open ports are included in result rows.

## HTML

The HTML report is a standalone document with embedded table styling. It contains:

- Generation date and time
- Target IPv4 address
- Start and end ports
- Worker count
- A table of open-port results

HTML table columns:

| Column | Meaning |
|---|---|
| `#` | One-based result index |
| `IP` | Target IPv4 address |
| `Port` | Open TCP port |
| `Response Time (ms)` | Measured connection response time in milliseconds |

See [sample_report.html](sample_report.html).

## CSV

The CSV report begins with this header:

```csv
Index,IP,Port,ResponseTimeMs
```

CSV columns:

| Column | Meaning |
|---|---|
| `Index` | One-based result index |
| `IP` | Target IPv4 address |
| `Port` | Open TCP port |
| `ResponseTimeMs` | Measured connection response time in milliseconds |

The CSV file does not contain separate scan metadata. See [sample_report.csv](sample_report.csv).

## JSON

The JSON report contains a `scan_info` object and a `results` array:

```json
{
  "scan_info": {
    "date": "2026-03-27 01:39:44",
    "total_ports": 1000,
    "open_ports": 3
  },
  "results": []
}
```

JSON fields:

| Field | Type | Meaning |
|---|---|---|
| `scan_info.date` | string | Local generation time in `YYYY-MM-DD HH:MM:SS` format |
| `scan_info.total_ports` | integer | Number of ports in the requested range |
| `scan_info.open_ports` | integer | Number of detected open ports |
| `results[].index` | integer | One-based result index |
| `results[].ip` | string | Target IPv4 address |
| `results[].port` | integer | Open TCP port |
| `results[].response_time` | integer | Measured connection response time in milliseconds |

The JSON report does not include separate start-port, end-port, or worker-count fields. See [sample_report.json](sample_report.json).

## Synchronized Sample Data

All three sample reports describe the same results:

| Index | IPv4 address | Port | Response time (ms) |
|------:|--------------|-----:|-------------------:|
| 1 | 8.8.8.8 | 53 | 157 |
| 2 | 8.8.8.8 | 443 | 125 |
| 3 | 8.8.8.8 | 853 | 31 |

The HTML sample records the range `1-1000` and `256` workers. The JSON sample records `1000` total ports and `3` open ports.
