# Domain Scanner

A simple Python-based domain scanner that performs basic reconnaissance on a list of domains.

Features:
- DNS resolution (A and AAAA records)
- HTTP(S) status and title extraction
- SSL certificate expiry check
- Basic whois lookup (optional, requires `python-whois`)
- Basic port checks (common ports: 80, 443, 22)
- Concurrent scanning with configurable concurrency
- Outputs results to JSON and optionally to CSV

Requirements
------------
- Python 3.8+
- Install required packages:

```bash
pip install -r requirements.txt
```

Quickstart
----------
1. Add domains (one per line) to `domains.txt` or provide your own file.
2. Run the scanner:

```bash
python scanner.py --input domains.txt --output report.json --concurrency 10
```

Files
-----
- `scanner.py` - main scanner script
- `requirements.txt` - Python dependencies
- `domains.txt` - sample domains file
- `README.md` - this file
- `.gitignore` - files to ignore

Notes
-----
- Whois lookups may be rate-limited depending on your IP and the whois servers.
- SSL expiry check attempts an SNI-enabled TLS handshake; some hosts may block or not respond.
- This tool is intended for authorized scanning only. Do not scan domains you do not have permission to.
