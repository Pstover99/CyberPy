"""
Name: Parker Stover
Class: ITP 270
Date: 28 APR 2026
Project Name: tools/web_identifier.py
-----------------------
Identify the technologies a website is built on by combining HTTP
header inspection with the `builtwith` library's fingerprinting.

Public functions:
    normalize_url(url)              -> str
    fetch_headers(url)              -> dict
    fingerprint_from_headers(hdrs)  -> dict
    analyze_with_builtwith(url)     -> dict
    save_report(url, headers, fp, bw) -> Path
    run()                           -> menu entry point
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import requests

try:  # builtwith is optional - the rest of the tool still runs without it
    import builtwith  # type: ignore
    _HAVE_BUILTWITH = True
except Exception:  # pragma: no cover
    builtwith = None  # type: ignore
    _HAVE_BUILTWITH = False

from .common import OUTPUT_DIR, C, banner, kv, section, prompt_url


# ------------------------------------------------------------------
# URL helpers
# ------------------------------------------------------------------
def normalize_url(url: str) -> str:
    """Add http:// if no scheme was supplied."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url


# ------------------------------------------------------------------
# HTTP / fingerprinting
# ------------------------------------------------------------------
def fetch_headers(url: str, timeout: float = 10.0) -> dict:
    """Issue a GET and return the response headers (or {} on failure)."""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        return dict(resp.headers)
    except requests.exceptions.RequestException as e:
        print(f"{C.ERROR}[!] Error fetching headers: {e}{C.RESET}")
        return {}


def fingerprint_from_headers(headers: dict) -> dict:
    """Pull obvious tech indicators (Server, X-Powered-By, etc.) out of headers."""
    fp: dict = {}
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    if server:
        fp["Server"] = server
    if powered_by:
        fp["X-Powered-By"] = powered_by

    likely = []
    server_l = server.lower()
    powered_l = powered_by.lower()
    if "php" in powered_l:
        likely.append("PHP")
    if "asp" in powered_l:
        likely.append("ASP.NET")
    if "express" in powered_l:
        likely.append("Express / Node.js")
    if "nginx" in server_l:
        likely.append("Nginx")
    if "apache" in server_l:
        likely.append("Apache")
    if "cloudflare" in server_l:
        likely.append("Cloudflare")
    if "iis" in server_l:
        likely.append("Microsoft IIS")
    if likely:
        fp["Likely Technologies"] = ", ".join(likely)
    return fp


def analyze_with_builtwith(url: str) -> dict:
    """Run builtwith.parse on `url`. Returns {} if the lib isn't installed."""
    if not _HAVE_BUILTWITH:
        print(f"{C.WARN}builtwith not installed - skipping. "
              f"`pip install builtwith` to enable.{C.RESET}")
        return {}
    try:
        return builtwith.parse(url)
    except Exception as e:
        print(f"{C.ERROR}[!] BuiltWith error: {e}{C.RESET}")
        return {}


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
def save_report(url: str, headers: dict, fingerprints: dict, bw: dict) -> Path:
    """Write a JSON report of the analysis to OUTPUT_DIR."""
    parsed = urlparse(url)
    safe_host = parsed.netloc.replace(".", "_") or "site"
    out = OUTPUT_DIR / f"web_id_{safe_host}.json"
    payload = {
        "URL": url,
        "Headers": headers,
        "HeaderFingerprints": fingerprints,
        "BuiltWith": bw,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Web Technology Identifier")

    # prompt_url loops until the input looks reasonable; None means cancel.
    raw = prompt_url()
    if raw is None:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    url = normalize_url(raw)
    kv("Normalized URL", url)

    section("HTTP Headers")
    headers = fetch_headers(url)
    if not headers:
        print(f"{C.ERROR}No headers retrieved. Aborting.{C.RESET}")
        return
    for k, v in headers.items():
        kv(k, v)

    section("Header Fingerprinting")
    fp = fingerprint_from_headers(headers)
    if fp:
        for k, v in fp.items():
            kv(k, v)
    else:
        print(f"{C.WARN}No identifiable technologies found in headers.{C.RESET}")

    section("BuiltWith Analysis")
    bw = analyze_with_builtwith(url)
    if bw:
        for tech, items in bw.items():
            kv(tech, ", ".join(items))
    else:
        print(f"{C.WARN}No BuiltWith data available.{C.RESET}")

    save = input("\nSave full report to JSON? (y/N): ").strip().lower()
    if save == "y":
        out = save_report(url, headers, fp, bw)
        kv("Report saved to", out)
