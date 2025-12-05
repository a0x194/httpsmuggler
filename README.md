# HTTPSmuggler

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/go-%3E%3D1.19-00ADD8.svg" alt="Go Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg" alt="Platform">
</p>

<p align="center">
  <b>HTTP Request Smuggling Vulnerability Detector</b><br>
  <sub>Detect CL.TE, TE.CL, and TE.TE smuggling vulnerabilities</sub>
</p>

---

## What is HTTP Request Smuggling?

HTTP Request Smuggling is a technique for interfering with the way a website processes sequences of HTTP requests received from one or more users. It exploits inconsistencies in parsing HTTP requests between front-end and back-end servers.

## Features

- **Multiple attack vector detection:**
  - **CL.TE** - Front-end uses Content-Length, back-end uses Transfer-Encoding
  - **TE.CL** - Front-end uses Transfer-Encoding, back-end uses Content-Length
  - **TE.TE** - Both servers use Transfer-Encoding but can be tricked with obfuscation

- **TE.TE Obfuscation Tests:**
  - Multiple Transfer-Encoding headers
  - Space/tab variations
  - Case variations
  - Invalid chunk specifications

- **Time-based detection** for accurate results
- **Multi-threaded scanning** with configurable concurrency
- **Safe testing approach** - designed to minimize impact

## Installation

### From Source
```bash
git clone https://github.com/a0x194/httpsmuggler.git
cd httpsmuggler
go build -o httpsmuggler main.go
```

### Download Binary
Check the [Releases](https://github.com/a0x194/httpsmuggler/releases) page for pre-built binaries.

## Usage

### Basic scan
```bash
./httpsmuggler -u https://example.com
```

### Scan multiple targets
```bash
./httpsmuggler -l urls.txt -t 5
```

### Verbose mode
```bash
./httpsmuggler -u https://example.com -v -timeout 20
```

### Flags
| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Single target URL | - |
| `-l` | File containing URLs | - |
| `-t` | Number of threads | 5 |
| `-timeout` | Request timeout (seconds) | 15 |
| `-v` | Verbose output | false |
| `-o` | Output file | - |
| `-version` | Show version | - |

## Vulnerability Types

### CL.TE (Content-Length / Transfer-Encoding)
The front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header.

### TE.CL (Transfer-Encoding / Content-Length)
The front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header.

### TE.TE (Transfer-Encoding obfuscation)
Both servers support `Transfer-Encoding`, but one can be induced to not process it by obfuscating the header.

## Example Output

```
  _    _ _______ _______ _____   _____                             _
 | |  | |__   __|__   __|  __ \ / ____|                           | |
 | |__| |  | |     | |  | |__) | (___  _ __ ___  _   _  __ _  __ _| | ___ _ __
 |  __  |  | |     | |  |  ___/ \___ \| '_ ' _ \| | | |/ _' |/ _' | |/ _ \ '__|
 | |  | |  | |     | |  | |     ____) | | | | | | |_| | (_| | (_| | |  __/ |
 |_|  |_|  |_|     |_|  |_|    |_____/|_| |_| |_|\__,_|\__, |\__, |_|\___|_|
                                                        __/ | __/ |
                                                       |___/ |___/
  HTTP Request Smuggling Detector v1.0.0
  Author: a0x194 | https://www.tryharder.space
  More tools: https://www.tryharder.space/tools/

[*] Testing 1 URL(s) for HTTP Request Smuggling...
[*] Testing: CL.TE, TE.CL, TE.TE variants

[POTENTIAL VULNERABILITY] https://example.com
  ├─ Type: CL.TE
  ├─ Technique: Time-based detection
  ├─ Time Difference: 10.234s
  └─ Details: Backend appears to wait for more data (Transfer-Encoding processing)

[*] Scan complete! Found 1 potential vulnerability(ies)
```

## Important Notes

- **Manual verification required** - This tool provides indicators of potential vulnerabilities
- **Use Burp Suite's HTTP Request Smuggler** for detailed exploitation
- **Timing-based detection** may have false positives in high-latency environments
- **Always get proper authorization** before testing

## References

- [PortSwigger - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HTTP Desync Attacks - James Kettle](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)

## Disclaimer

⚠️ **This tool is intended for authorized security testing only.**

HTTP Request Smuggling attacks can cause serious issues including:
- Cache poisoning
- Session hijacking
- Bypassing security controls
- Request hijacking

Always obtain explicit permission before testing any systems.

## Author

**a0x194** - [https://www.tryharder.space](https://www.tryharder.space)

More security tools: [https://www.tryharder.space/tools/](https://www.tryharder.space/tools/)

## License

MIT License - see [LICENSE](LICENSE) file for details.
