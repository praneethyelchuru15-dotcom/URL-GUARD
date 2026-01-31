# URL Guard

A network security tool for analyzing and detecting threats in URLs.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd network_security_tool
    ```
2.  **Install the tool:**
    ```bash
    pip install .
    ```

## Quick Start (Windows)

Use the provided batch script for easy scanning:
```bash
scan https://example.com
```

Or save the report:
```bash
scan https://example.com --output report.json
```

## Usage (Manual)

If you prefer running with Python directly:
```bash
python main.py https://google.com
```

## Features
- URL Connectivity Check
- Text Analysis
- IP Reputation Check
- SSL/TLS Certificate Verification
- HTTP Header Analysis
- Port Scanning
- Whois Lookup
- JSON Report Generation
