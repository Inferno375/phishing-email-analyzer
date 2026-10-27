# Phishing Email Analyzer (Python)

A lightweight Blue Team / SOC automation tool written in Python that parses raw email files (`.eml`), extracts network headers, traces IP routing paths, decodes file attachments, hashes file payloads, and evaluates Indicators of Compromise (IoCs) against a threat intelligence scoring engine.

## Features
- **Header & Spoof Analysis**: Detects domain mismatches between display headers (`From`) and envelope senders (`Return-Path`).
- **Hop Tracing**: Parses `Received` headers sequentially to trace network transit and isolate the true origin IP address.
- **IoC Extraction**: Uses Regular Expressions (Regex) to extract embedded URLs from plain text bodies and IPv4 addresses from headers.
- **Attachment Decoding & Hashing**: Extracts attached files, flags dangerous extensions (e.g., `.exe`), and generates SHA256 digital signatures.
- **Threat Intelligence & Whitelisting**: Cross-references extracted indicators against threat blacklists while ignoring internal/trusted IP ranges.
- **Weighted Risk Engine**: Aggregates threat indicators into a numerical risk score (0–100) and outputs a structured security assessment report.

## How It Works & Architecture
1. **MIME Parsing**: Uses Python's built-in `email` and `policy` modules to break raw `.eml` files into structural components.
2. **Indicator Harvest**: Regular expressions extract URLs (`https?://...`) and IPv4 routing nodes (`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`).
3. **Detection Rules & Scoring**:
   - `From` domain != `Return-Path` domain: **+30 Risk Score**
   - Executable/Suspicious attachment extension: **+20 Risk Score**
   - Blacklisted IP / URL match: **+40 Risk Score**
   - Blacklisted SHA256 malware hash match: **+50 Risk Score**
4. **Automated Assessment**: Evaluates total score against thresholds:
   - **Score >= 50**: `MALICIOUS`
   - **Score >= 20**: `SUSPICIOUS`
   - **Score < 20**: `CLEAN`

## Requirements
- **Python 3.x** (Uses built-in standard modules: `email`, `re`, `hashlib`). No external `pip` dependencies required.

## Usage
1. Clone this repository:
   ```bash
   git clone [https://github.com/Inferno375/phishing-email-analyzer.git](https://github.com/Inferno375/phishing-email-analyzer.git)
   cd phishing-email-analyzer