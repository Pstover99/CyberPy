"""
Name:    Parker Stover
Class:   ITP 270
Date:    04 MAY 2026
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
)
from tools.common import C


# ------------------------------------------------------------------
# Menu rendering
# ------------------------------------------------------------------
# A small helper makes the menu definition easy to read: numbers are
# yellow/bold, tool names are cyan, and descriptions stay default so
# the eye lands on the choice number first.
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
    _opt("1", "Network Scanner",          "ping/ARP sweep of a CIDR range"),
    _opt("2", "Port Scanner",             "scan an IP or CIDR for common ports"),
    f" {C.SECTION}Recon & Analysis{C.RESET}",
    _opt("3", "Vulnerability Scanner",    "NIST CVE keyword search"),
    _opt("4", "EXIF Image Extractor",     "metadata from ./images"),
    _opt("5", "Web Technologies",         "HTTP fingerprint + BuiltWith"),
    f" {C.SECTION}Exit{C.RESET}",
    _opt("6", "Quit",                     "leave the toolkit"),
    f"{C.HEADER}{'-' * 60}{C.RESET}",
])


# Map of menu choice -> (label, callable). The launcher's only job is
# to dispatch into one of these per the user's input.
ACTIONS = {
    "1": ("Network Scanner",        network_scanner.run),
    "2": ("Port Scanner",           port_scanner.run),
    "3": ("Vulnerability Scanner",  vuln_scanner.run),
    "4": ("EXIF Extractor",         exif_extractor.run),
    "5": ("Web Identifier",         web_identifier.run),
}


def main() -> None:
    """The single required entry point. Loops until the user quits."""
    while True:
        print(MENU)
        choice = input(f"{C.KEY}Enter your choice:{C.RESET} ").strip().lower()

        if choice in ("6", "q", "quit", "exit"):
            print(f"\n{C.GREEN}Goodbye! Thanks for using the toolkit.{C.RESET}\n")
            return

        action = ACTIONS.get(choice)
        if action is None:
            print(f"{C.WARN}Invalid choice. Please pick 1-6.{C.RESET}")
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
