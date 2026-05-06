# CyberPy ⚔️

A versatile, menu-driven cybersecurity toolkit written entirely in Python. Covers the full workflow from network reconnaissance through cryptography, encoding, and authorized offensive testing — all from a single interactive launcher with no external GUI required.

> **This is my first public repository.** I'm learning GitHub as I go and will be updating this repo regularly as I build out new tools. Feel free to follow along!

---

## ⚠️ Legal & Ethical Disclaimer

This toolkit is intended **strictly for authorized security testing, educational use, and research in environments you own or have explicit written permission to test** (e.g. your own home lab, school lab exercises, or CTF competitions).

- Do **not** use any tool in this repository against systems, networks, or services you do not own or lack permission to test.
- Unauthorized scanning, credential testing, or vulnerability probing may violate the Computer Fraud and Abuse Act (CFAA), local laws, and institutional policies.
- The author assumes **no liability** for misuse.

We are all adults here — use this responsibly.

---

## 📋 Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Setup Instructions](#setup-instructions)
- [Running the Toolkit](#running-the-toolkit)
- [Tool Reference](#tool-reference)
- [Dependencies](#dependencies)
- [Contributing & Feedback](#contributing--feedback)
- [Author](#author)

---

## Features

- **15 tools** across 4 categories in a single interactive menu
- Zero-dependency design for most tools (stdlib-only where possible)
- All output optionally saved to the `output/` directory as `.txt` or `.json`
- Consistent color-coded terminal UI across every tool
- Threaded scanners for speed — no hanging on large ranges

---

## Project Structure

```
PyReconLab/
│
├── Cybersecurity_Toolkit.py   # Main launcher & interactive menu
├── requirements.txt           # pip dependencies
├── oui.txt                    # OUI/vendor MAC prefix database
│
├── tools/                     # One module per tool
│   ├── __init__.py
│   ├── common.py              # Shared helpers, colors, prompt utilities
│   ├── network_scanner.py
│   ├── port_scanner.py
│   ├── dns_lookup.py
│   ├── vuln_scanner.py
│   ├── exif_extractor.py
│   ├── web_identifier.py
│   ├── ssl_inspector.py
│   ├── header_checker.py
│   ├── hash_checker.py
│   ├── hash_cracker.py
│   ├── cipher_tool.py
│   ├── encoder_decoder.py
│   ├── dir_enumerator.py
│   ├── cred_scanner.py
│   └── vuln_probe.py
│
├── images/                    # Drop images here for EXIF extraction
└── output/                    # Auto-created; all scan reports saved here
```

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/Pstover99/CyberPy.git
cd CyberPy
```

Or download the ZIP from GitHub (Code → Download ZIP) and extract it.

### 2. Create a Virtual Environment

Run this inside the project folder:

```bash
python -m venv .venv
```

A `.venv` folder will appear — this keeps your dependencies isolated from your system Python.

### 3. Activate the Virtual Environment

**Windows (PowerShell):**
```powershell
.venv\Scripts\Activate
```

If PowerShell blocks the script, run this first:
```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
```

**macOS / Linux:**
```bash
source .venv/bin/activate
```

Your prompt will show `(.venv)` when the environment is active.

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs `requests`, `Pillow`, and `builtwith`. All other tools use Python's standard library.

### 5. Create the `images/` Folder

The EXIF extractor scans a local `images/` folder. Create it in the project root and drop any photos you want to analyze inside:

```bash
mkdir images
```

Without this folder the EXIF tool will report an error — everything else works fine regardless.

---

## Running the Toolkit

Make sure your virtual environment is active (`(.venv)` visible in your prompt), then:

```bash
python Cybersecurity_Toolkit.py
```

You'll be greeted by the interactive menu. Type a number and press Enter to launch any tool. Press Enter again when done to return to the menu.

To run a specific tool module directly (useful for scripting):

```bash
python -c "from tools import port_scanner; port_scanner.run()"
```

---

## Tool Reference

### 🌐 Network Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | **Network Scanner** | Threaded ping/ARP sweep of a CIDR range. Resolves MAC addresses and vendor names via a local OUI database and the macvendors.com API. |
| 2 | **Port Scanner** | Threaded TCP connect scan against 21 common ports for a single IP or an entire CIDR range. Results saved to `output/port_scan_results.txt`. |
| 3 | **DNS Lookup** | Forward lookup (hostname → IPs), reverse lookup (IP → PTR), and subdomain enumeration using a built-in wordlist of 50 common prefixes. |

### 🔍 Recon & Analysis

| # | Tool | Description |
|---|------|-------------|
| 4 | **Vulnerability Scanner** | Queries the NIST NVD CVE 2.0 API by keyword. Optionally grabs a service banner first to help generate realistic search terms. |
| 5 | **EXIF Image Extractor** | Walks the `images/` folder and extracts EXIF metadata from JPG, PNG, TIFF, HEIC, and WebP files. Decodes GPS coordinates to decimal degrees. |
| 6 | **Web Technologies** | Fingerprints a website via HTTP header inspection and the `builtwith` library. Identifies server software, frameworks, and CDNs. |
| 7 | **SSL/TLS Inspector** | Connects to any host/port and pulls the TLS certificate. Reports subject, issuer, SANs, cipher suite, and days until expiry. Warns on certs expiring within 30 days. |
| 8 | **HTTP Security Headers** | Audits a website for 8 modern security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, Cache-Control). Grades each PASS / WARN / FAIL with an overall score. |

### 🔐 Cryptography & Encoding

| # | Tool | Description |
|---|------|-------------|
| 9 | **Hash Checker** | Compute MD5, SHA-1, SHA-256, or SHA-512 hashes for files or text strings. Optionally verify against a known hash for integrity checking. |
| 10 | **Hash Cracker** | Dictionary attack against a hex hash. Auto-detects algorithm by digest length. Includes a built-in list of ~220 common passwords; also accepts any custom wordlist file (e.g. `rockyou.txt`). |
| 11 | **Classical Cipher Tool** | Caesar cipher (encrypt, decrypt, brute-force all 25 shifts ranked by English letter-frequency score) and Vigenère cipher (encrypt/decrypt with a text key). |
| 12 | **Encoder / Decoder** | Swiss-army encoding tool: Base64, Hex, URL encoding, ROT13, and 8-bit Binary. Encode or decode any text string in a single step. |

### ⚔️ Offensive Tools *(authorized lab use only)*

| # | Tool | Description |
|---|------|-------------|
| 13 | **Dir Enumerator** | Brute-forces common web paths on a target URL using a built-in wordlist of 141 paths (admin panels, config files, API routes, CMS paths, backup artifacts, and more). Supports custom wordlists. Color-coded by HTTP status code. |
| 14 | **Default Cred Scanner** | Tests 30 well-documented vendor factory default username/password pairs against HTTP Basic Auth and FTP. Useful for identifying misconfigured lab equipment. Requires authorization confirmation before running. |
| 15 | **Web Vuln Probe** | Injects OWASP standard test payloads into URL GET parameters and checks responses for indicators of SQL injection (DBMS error signatures), reflected XSS (unescaped marker reflection), and open redirect (external Location header). Detection only — no data is extracted or modified. Requires authorization confirmation. |

---

## Dependencies

| Package | Used By | Install |
|---------|---------|---------|
| `requests` | Network Scanner, Vuln Scanner, Web Identifier, SSL Inspector, Header Checker, Dir Enumerator, Cred Scanner, Vuln Probe | `pip install requests` |
| `Pillow` | EXIF Image Extractor | `pip install Pillow` |
| `builtwith` | Web Technologies | `pip install builtwith` |

Everything else uses Python's standard library (`socket`, `ssl`, `hashlib`, `ftplib`, `base64`, `urllib`, etc.).

---

## Contributing & Feedback

This repo is open to:

- 🐛 **Bug reports** — open an Issue describing the problem and how to reproduce it
- 💡 **Feature suggestions** — open an Issue with your idea
- 🔧 **Pull requests** — improvements and fixes are welcome; keep the code style consistent with the existing modules
- 🔒 **Security concerns** — if you find a vulnerability in the toolkit itself, please open an Issue

No contribution is too small — even a typo fix helps.

---

## Author

**Parker Stover**  

Email: parkerstover240@outlook.com

[GitHub: Pstover99]

---

*Built with Python 3.10+. Tested on Windows 11 and Ubuntu 22.04.*
