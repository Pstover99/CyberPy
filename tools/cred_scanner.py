"""
Name:  Parker Stover
Class: ITP 270
Date:  04 MAY 2026

tools/cred_scanner.py
---------------------
Default credential scanner.

Tests a curated list of well-known manufacturer / vendor default
username-password pairs against two common services:
  • HTTP Basic Authentication  (via requests)
  • FTP                        (via stdlib ftplib)

This tool is designed for authorized security audits — checking whether
lab equipment, routers, cameras, or web applications were deployed with
factory-default credentials still in place.

IMPORTANT: Only use against systems you own or have explicit written
permission to test. Unauthorized use against systems you do not own
may violate computer fraud laws.

Public functions:
    test_http_basic(url, credentials)   -> list[dict]
    test_ftp(host, port, credentials)   -> list[dict]
    write_results(target, hits)         -> Path
    run()                               -> menu entry point
"""

from __future__ import annotations

import ftplib
import json
import socket
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

from .common import OUTPUT_DIR, C, banner, kv, section, prompt_nonempty, prompt_url


# ------------------------------------------------------------------
# Well-known vendor / manufacturer default credentials
# Source: publicly documented factory defaults (router manuals,
# IoT device docs, application setup guides, CIRT.net defaults list)
# ------------------------------------------------------------------
DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin",        "admin"),
    ("admin",        "password"),
    ("admin",        "1234"),
    ("admin",        "12345"),
    ("admin",        "123456"),
    ("admin",        "admin123"),
    ("admin",        ""),          # blank password
    ("administrator","administrator"),
    ("administrator","password"),
    ("administrator",""),
    ("root",         "root"),
    ("root",         "toor"),
    ("root",         "password"),
    ("root",         "1234"),
    ("root",         ""),
    ("user",         "user"),
    ("user",         "password"),
    ("user",         "1234"),
    ("guest",        "guest"),
    ("guest",        ""),
    ("test",         "test"),
    ("demo",         "demo"),
    ("support",      "support"),
    ("service",      "service"),
    ("manager",      "manager"),
    ("operator",     "operator"),
    # Common router / AP defaults
    ("admin",        "1234567890"),
    ("admin",        "password1"),
    ("cusadmin",     "highspeed"),
    ("Admin",        "Admin"),
]


# ------------------------------------------------------------------
# HTTP Basic Auth
# ------------------------------------------------------------------
def test_http_basic(
    url: str,
    credentials: list[tuple[str, str]] | None = None,
    timeout: float = 6.0,
) -> list[dict]:
    """
    Try each (username, password) pair against `url` using HTTP Basic Auth.

    Returns a list of dicts describing every pair that returned HTTP 200
    (or any non-401/403 success code), i.e. credentials that worked.
    """
    credentials = credentials or DEFAULT_CREDS
    hits: list[dict] = []
    total = len(credentials)

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (security-audit/lab)"

    for i, (user, passwd) in enumerate(credentials, 1):
        print(f"  Trying [{i:>3}/{total}] {user!r} / {passwd!r:<20}", end="\r")
        try:
            resp = session.get(url, auth=HTTPBasicAuth(user, passwd),
                               timeout=timeout, allow_redirects=True)
            if resp.status_code not in (401, 403):
                hit = {
                    "username": user,
                    "password": passwd,
                    "status":   resp.status_code,
                    "url":      url,
                }
                print(
                    f"\n  {C.GREEN}[HIT]  {user!r} / {passwd!r}"
                    f"  →  HTTP {resp.status_code}{C.RESET}"
                )
                hits.append(hit)
        except requests.exceptions.RequestException:
            pass

    print()  # clear progress line
    return hits


# ------------------------------------------------------------------
# FTP
# ------------------------------------------------------------------
def test_ftp(
    host: str,
    port: int = 21,
    credentials: list[tuple[str, str]] | None = None,
    timeout: float = 6.0,
) -> list[dict]:
    """
    Try each (username, password) pair against the FTP service at host:port.

    Returns a list of dicts for every pair that logged in successfully.
    """
    credentials = credentials or DEFAULT_CREDS
    hits: list[dict] = []
    total = len(credentials)

    for i, (user, passwd) in enumerate(credentials, 1):
        print(f"  Trying [{i:>3}/{total}] {user!r} / {passwd!r:<20}", end="\r")
        try:
            with ftplib.FTP(timeout=timeout) as ftp:
                ftp.connect(host, port, timeout=timeout)
                ftp.login(user, passwd)
                # If we get here, login succeeded
                try:
                    welcome = ftp.getwelcome()
                except Exception:
                    welcome = ""
                hit = {
                    "username": user,
                    "password": passwd,
                    "host":     host,
                    "port":     port,
                    "welcome":  welcome,
                }
                print(
                    f"\n  {C.GREEN}[HIT]  {user!r} / {passwd!r}"
                    f"  →  FTP login succeeded{C.RESET}"
                )
                hits.append(hit)
        except ftplib.error_perm:
            pass  # Wrong credentials — expected
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass  # Host unreachable / port closed
        except Exception:
            pass

    print()
    return hits


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
def write_results(target: str, hits: list[dict]) -> Path:
    """Persist credential scan results to OUTPUT_DIR."""
    safe = target.replace(".", "_").replace(":", "_").replace("/", "_")[:40]
    out = OUTPUT_DIR / f"cred_scan_{safe}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"target": target, "hits": hits}, f, indent=4)
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Default Credential Scanner")

    print(
        f"  {C.WARN}Authorization required.{C.RESET}\n"
        "  This tool tests well-known default credentials against services.\n"
        "  Only use against systems you own or have written permission to test.\n"
    )
    confirm = input("  Confirm you have authorization to test the target? (y/N): ").strip().lower()
    if confirm != "y":
        print(f"\n{C.WARN}Aborted. Returning to menu.{C.RESET}")
        return

    print(
        f"\n  {C.KEY}1{C.RESET} HTTP Basic Auth\n"
        f"  {C.KEY}2{C.RESET} FTP\n"
    )
    mode = input(f"{C.KEY}Choose service [1-2]: {C.RESET}").strip()
    if mode not in ("1", "2"):
        print(f"{C.WARN}Invalid choice. Returning to menu.{C.RESET}")
        return

    kv("Default credential pairs", len(DEFAULT_CREDS))
    hits: list[dict] = []
    target_label = ""

    # ---- HTTP Basic Auth ----------------------------------------
    if mode == "1":
        raw = prompt_url("Enter URL to test (e.g. http://192.168.1.1/admin): ")
        if raw is None:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return
        url = raw if raw.startswith(("http://", "https://")) else "http://" + raw
        target_label = url

        section(f"Testing HTTP Basic Auth: {url}")
        hits = test_http_basic(url)

    # ---- FTP ----------------------------------------------------
    elif mode == "2":
        host = prompt_nonempty("Enter FTP host (IP or hostname): ")
        if not host:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return
        from .common import prompt_port
        port = prompt_port("FTP port", default=21) or 21
        target_label = f"{host}:{port}"

        section(f"Testing FTP: {host}:{port}")
        hits = test_ftp(host.strip(), port)

    # ---- Results ------------------------------------------------
    section("Results")
    if hits:
        print(f"  {C.GREEN}Found {len(hits)} working credential(s):{C.RESET}")
        for h in hits:
            print(f"    {C.KEY}User:{C.RESET} {h['username']!r}  "
                  f"{C.KEY}Pass:{C.RESET} {h['password']!r}")
        save = input("\nSave results to JSON? (y/N): ").strip().lower()
        if save == "y":
            out = write_results(target_label, hits)
            kv("Report saved to", out)
    else:
        print(f"  {C.WARN}No default credentials matched.{C.RESET}")
        print(f"  {C.GREEN}Good — the service does not appear to use well-known defaults.{C.RESET}")
