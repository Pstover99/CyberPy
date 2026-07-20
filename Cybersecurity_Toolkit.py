"""
Name:    Parker Stover

Program: Cybersecurity_Toolkit.py

Final project launcher. Every tool lives in the local `tools/` package
and shares a single virtual environment (see requirements.txt). This
file only contains the menu loop - all real work happens in the modules
imported below.

Setup:
    python -m venv .venv
    # Windows:    .venv\Scripts\activate
    # macOS/Lin:  source .venv/bin/activate
    pip install -r requirements.txt
    python Cybersecurity_Toolkit.py
"""

from __future__ import annotations

import sys

from tools import (
    network_scanner,
    port_scanner,
    vuln_scanner,
    exif_extractor,
    web_identifier,
    dns_lookup,
    ssl_inspector,
    hash_checker,
    hash_cracker,
    cipher_tool,
    encoder_decoder,
    header_checker,
    dir_enumerator,
    cred_scanner,
    vuln_probe,
    whois_geo,
    subnet_calc,
    honeypot,
    entropy_analyzer,
)
from tools.common import C


# ------------------------------------------------------------------
# Menu rendering
# ------------------------------------------------------------------
def _opt(num: str, name: str, desc: str) -> str:
    return (f"   {C.KEY}{num}.{C.RESET} "
            f"{C.CYAN}{name:<28}{C.RESET}"
            f"{C.VALUE}{desc}{C.RESET}")


MENU = "\n".join([
    "",
    f"{C.HEADER}{'=' * 60}{C.RESET}",
    f"{C.HEADER}    Parker's Cybersecurity Toolkit{C.RESET}",
    f"{C.HEADER}{'=' * 60}{C.RESET}",
    f" {C.SECTION}Network Tools{C.RESET}",
    _opt(" 1", "Network Scanner",       "ping/ARP sweep of a CIDR range"),
    _opt(" 2", "Port Scanner",          "scan an IP or CIDR for common ports"),
    _opt(" 3", "DNS Lookup",            "forward/reverse DNS & subdomain enum"),
    _opt(" 4", "Subnet Calculator",     "IPv4 network details & usable host range"),
    f" {C.SECTION}Recon & Analysis{C.RESET}",
    _opt(" 5", "WHOIS & Geolocation",   "registrar info & geographic mapping"),
    _opt(" 6", "Vulnerability Scanner", "NIST CVE keyword search"),
    _opt(" 7", "EXIF Image Extractor",  "metadata from ./images"),
    _opt(" 8", "Web Technologies",      "HTTP fingerprint + BuiltWith"),
    _opt(" 9", "SSL/TLS Inspector",     "certificate details & expiry check"),
    _opt("10", "HTTP Security Headers", "audit security headers on a website"),
    f" {C.SECTION}Cryptography & Encoding{C.RESET}",
    _opt("11", "Hash Checker",          "MD5/SHA hash files or text strings"),
    _opt("12", "Hash Cracker",          "dictionary attack on MD5/SHA hashes"),
    _opt("13", "Classical Cipher Tool", "Caesar & Vigenere encode/decode/crack"),
    _opt("14", "Encoder / Decoder",     "Base64, hex, URL, ROT13, binary"),
    _opt("15", "File Entropy Analyzer", "measure file randomness to detect packing"),
    f" {C.SECTION}Offensive Tools  [authorized lab use only]{C.RESET}",
    _opt("16", "Dir Enumerator",        "brute-force common web paths"),
    _opt("17", "Default Cred Scanner",  "test vendor defaults on HTTP/FTP"),
    _opt("18", "Web Vuln Probe",        "detect SQLi, XSS, open redirect"),
    f" {C.SECTION}Defensive & Monitoring{C.RESET}",
    _opt("19", "Local Port Listener",   "honeypot to capture scanner connections"),
    f" {C.SECTION}Exit{C.RESET}",
    _opt("20", "Quit",                  "leave the toolkit"),
    f"{C.HEADER}{'-' * 60}{C.RESET}",
])


ACTIONS = {
    "1":  ("Network Scanner",        network_scanner.run),
    "2":  ("Port Scanner",           port_scanner.run),
    "3":  ("DNS Lookup",             dns_lookup.run),
    "4":  ("Subnet Calculator",      subnet_calc.run),
    "5":  ("WHOIS & Geolocation",    whois_geo.run),
    "6":  ("Vulnerability Scanner",  vuln_scanner.run),
    "7":  ("EXIF Extractor",         exif_extractor.run),
    "8":  ("Web Identifier",         web_identifier.run),
    "9":  ("SSL/TLS Inspector",      ssl_inspector.run),
    "10": ("HTTP Security Headers",  header_checker.run),
    "11": ("Hash Checker",           hash_checker.run),
    "12": ("Hash Cracker",           hash_cracker.run),
    "13": ("Classical Cipher Tool",  cipher_tool.run),
    "14": ("Encoder / Decoder",      encoder_decoder.run),
    "15": ("File Entropy Analyzer",  entropy_analyzer.run),
    "16": ("Dir Enumerator",         dir_enumerator.run),
    "17": ("Default Cred Scanner",   cred_scanner.run),
    "18": ("Web Vuln Probe",         vuln_probe.run),
    "19": ("Local Port Listener",    honeypot.run),
}


def main() -> None:
    """The single required entry point. Loops until the user quits."""
    while True:
        print(MENU)
        choice = input(f"{C.KEY}Enter your choice:{C.RESET} ").strip().lower()

        if choice in ("20", "q", "quit", "exit"):
            print(f"\n{C.GREEN}Goodbye! Thanks for using the toolkit.{C.RESET}\n")
            return

        action = ACTIONS.get(choice)
        if action is None:
            print(f"{C.WARN}Invalid choice. Please pick 1-20.{C.RESET}")
            continue

        label, func = action
        try:
            func()
        except KeyboardInterrupt:
            print(f"\n{C.WARN}Interrupted. Returning to menu.{C.RESET}")
        except Exception as e:
            print(f"\n{C.ERROR}{label} crashed: {e}{C.RESET}")

        input(f"\n{C.BLUE}Press ENTER to return to the menu...{C.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting.\n")
        sys.exit(0)
