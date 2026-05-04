"""
Name: Parker Stover
Class: ITP 270
Date: 09 APR 2026
tools/vuln_scanner.py
---------------------
Search the NIST National Vulnerability Database (NVD) for CVEs that
match a keyword string. Optionally pulls a banner from a target IP/port
to seed the search with realistic terms.

Public functions:
    search_cve(keywords, max_results=20) -> list[dict] | str
    print_results(results)               -> None
    get_banner(ip, port)                 -> str
    run()                                -> menu entry point
"""

from __future__ import annotations

import socket
from typing import Union

import requests

from .common import C, banner, section, prompt_ip, prompt_port, prompt_nonempty


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ------------------------------------------------------------------
# Banner grab (optional - helps the user pick CVE keywords)
# ------------------------------------------------------------------
def get_banner(ip: str, port: int, timeout: float = 5.0) -> str:
    """Connect to ip:port, send a basic HTTP GET, return response headers."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, int(port)))
        s.send(f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
        response = s.recv(4096).decode(errors="ignore")
        return response.split("\r\n\r\n")[0]
    except Exception as e:
        return f"Error retrieving banner: {e}"
    finally:
        s.close()


# ------------------------------------------------------------------
# CVE lookup
# ------------------------------------------------------------------
def search_cve(keywords: str, max_results: int = 20
               ) -> Union[list[dict], str]:
    """
    Query the NVD CVE 2.0 API. Returns the list of vulnerability records
    or an error message string.
    """
    params = {
        "keywordSearch": keywords,
        "resultsPerPage": max_results,
    }
    try:
        resp = requests.get(NVD_URL, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
    except requests.exceptions.RequestException as e:
        return f"Error retrieving CVE data: {e}"
    except ValueError as e:
        return f"Invalid JSON response from NVD: {e}"


def print_results(results: Union[list[dict], str]) -> None:
    """Pretty-print the result list (or error string) returned by search_cve."""
    if isinstance(results, str):
        print(f"{C.ERROR}{results}{C.RESET}")
        return
    if not results:
        print(f"{C.WARN}No vulnerabilities found.{C.RESET}")
        return

    for item in results:
        try:
            cve = item["cve"]
            cve_id = cve["id"]
            description = cve["descriptions"][0]["value"]
            score = _extract_cvss(cve)
            print(f"\n{C.KEY}CVE ID:{C.RESET} {C.BOLD}{cve_id}{C.RESET}"
                  + (f"   {C.YELLOW}CVSS: {score}{C.RESET}" if score else ""))
            print(f"{C.VALUE}{description}{C.RESET}")
        except KeyError:
            continue


def _extract_cvss(cve: dict) -> str | None:
    """Pull the highest-version CVSS base score available, if any."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        records = metrics.get(key) or []
        if records:
            data = records[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or records[0].get("baseSeverity")
            if score is not None:
                return f"{score} ({severity})" if severity else str(score)
    return None


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Vulnerability Scanner (NIST NVD)")

    grab = input("Grab a service banner first to suggest keywords? (y/N): ").strip().lower()
    if grab == "y":
        # prompt_ip and prompt_port loop until valid; either returns None on cancel.
        ip = prompt_ip("  Target IP: ")
        if ip is None:
            print(f"{C.WARN}  Skipping banner grab.{C.RESET}")
        else:
            port = prompt_port("  Port", default=80)
            if port is None:
                print(f"{C.WARN}  Skipping banner grab.{C.RESET}")
            else:
                section("Banner")
                print(get_banner(ip, port))

    keywords = prompt_nonempty("\nEnter keyword(s) to search NIST CVE: ")
    if not keywords:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    print(f"\nSearching NVD for: {C.BOLD}{keywords}{C.RESET} ...")
    results = search_cve(keywords)
    section("CVE Results")
    print_results(results)
