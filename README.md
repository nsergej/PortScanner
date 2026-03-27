![Release](https://img.shields.io/github/v/release/nsergej/PortScanner)
![License](https://img.shields.io/github/license/nsergej/PortScanner)
# PortScanner v1.0

Fast multithreaded TCP port scanner for Windows with full port range scanning and export to HTML, CSV, JSON.

---

## Features

* Full port range scanning 1 to 65535
* High performance multithreaded engine
* Accurate open port detection
* Response time measurement
* Real time progress and statistics
* Export results to HTML, CSV, JSON

---

## Screenshots

<img width="436" height="591" alt="image" src="https://github.com/user-attachments/assets/201fbebb-34f3-49c2-bd53-27eae29a00a4" />



---

## Usage

1. Run PortScanner.exe
2. Enter target IP address
3. Set port range if needed
4. Click Start

---

## Output

After scan completion, reports are automatically generated:

* HTML report
* CSV file
* JSON file

Example:

```
Port Scan Results
Generated: 2026-03-27

#   IP              Port   Response Time ms
1   8.8.8.8         53     125
2   8.8.8.8         443    125
3   8.8.8.8         853    62
```

---

## Performance

* Up to 256 concurrent workers
* Optimized queue based processing
* Stable under high load

---

## Download

Go to Releases and download the latest version:

👉 https://github.com/nsergej/PortScanner/releases

---

## Technical Details

* Language Delphi VCL
* Networking WinSock
* Non blocking sockets using select
* Thread safe queue with critical sections

---

## License

MIT License

---

## Disclaimer

Use this tool only on systems and networks you own or have permission to test.
