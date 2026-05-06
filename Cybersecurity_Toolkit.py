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
    f" {C.SECTION}Recon & Analysis{C.RESET}",
    _opt(" 4", "Vulnerability Scanner", "NIST CVE keyword search"),
    _opt(" 5", "EXIF Image Extractor",  "metadata from ./images"),
    _opt(" 6", "Web Technologies",      "HTTP fingerprint + BuiltWith"),
    _opt(" 7", "SSL/TLS Inspector",     "certificate details & expiry check"),
    _opt(" 8", "HTTP Security Headers", "audit security headers on a website"),
    f" {C.SECTION}Cryptography & Encoding{C.RESET}",
    _opt(" 9", "Hash Checker",          "MD5/SHA hash files or text strings"),
    _opt("10", "Hash Cracker",          "dictionary attack on MD5/SHA hashes"),
    _opt("11", "Classical Cipher Tool", "Caesar & Vigenere encode/decode/crack"),
    _opt("12", "Encoder / Decoder",     "Base64, hex, URL, ROT13, binary"),
    f" {C.SECTION}Offensive Tools  [authorized lab use only]{C.RESET}",
    _opt("13", "Dir Enumerator",        "brute-force common web paths"),
    _opt("14", "Default Cred Scanner",  "test vendor defaults on HTTP/FTP"),
    _opt("15", "Web Vuln Probe",        "detect SQLi, XSS, open redirect"),
    f" {C.SECTION}Exit{C.RESET}",
    _opt("16", "Quit",                  "leave the toolkit"),
    f"{C.HEADER}{'-' * 60}{C.RESET}",
])


ACTIONS = {
    "1":  ("Network Scanner",        network_scanner.run),
    "2":  ("Port Scanner",           port_scanner.run),
    "3":  ("DNS Lookup",             dns_lookup.run),
    "4":  ("Vulnerability Scanner",  vuln_scanner.run),
    "5":  ("EXIF Extractor",         exif_extractor.run),
    "6":  ("Web Identifier",         web_identifier.run),
    "7":  ("SSL/TLS Inspector",      ssl_inspector.run),
    "8":  ("HTTP Security Headers",  header_checker.run),
    "9":  ("Hash Checker",           hash_checker.run),
    "10": ("Hash Cracker",           hash_cracker.run),
    "11": ("Classical Cipher Tool",  cipher_tool.run),
    "12": ("Encoder / Decoder",      encoder_decoder.run),
    "13": ("Dir Enumerator",         dir_enumerator.run),
    "14": ("Default Cred Scanner",   cred_scanner.run),
    "15": ("Web Vuln Probe",         vuln_probe.run),
}


def main() -> None:
    """The single required entry point. Loops until the user quits."""
    while True:
        print(MENU)
        choice = input(f"{C.KEY}Enter your choice:{C.RESET} ").strip().lower()

        if choice in ("16", "q", "quit", "exit"):
            print(f"\n{C.GREEN}Goodbye! Thanks for using the toolkit.{C.RESET}\n")
            return

        action = ACTIONS.get(choice)
        if action is None:
            print(f"{C.WARN}Invalid choice. Please pick 1-16.{C.RESET}")
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
