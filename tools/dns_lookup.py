"""
Name:  Parker Stover
Class: ITP 270
Date:  04 MAY 2026

tools/dns_lookup.py
-------------------
DNS reconnaissance tool: resolve hostnames to IP addresses (forward lookup),
map IPs back to hostnames (reverse/PTR lookup), and enumerate common
subdomains for a target domain using a built-in wordlist.

All lookups use Python's standard-library `socket` module — no third-party
DNS library is required.

Public functions:
    resolve_forward(hostname)              -> list[str]
    resolve_reverse(ip)                    -> str
    enum_subdomains(domain, wordlist=None) -> list[dict]
    write_results(domain, data)            -> Path
    run()                                  -> menu entry point
"""

from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .common import OUTPUT_DIR, C, banner, kv, section, prompt_nonempty


# ------------------------------------------------------------------
# Built-in subdomain wordlist (top ~50 most common sub-domain prefixes)
# ------------------------------------------------------------------
DEFAULT_SUBDOMAINS: list[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "blog", "shop", "api", "dev", "staging", "test", "vpn", "cdn",
    "static", "assets", "img", "images", "media", "files", "upload",
    "download", "docs", "help", "support", "portal", "admin", "login",
    "app", "mobile", "m", "secure", "ssl", "git", "github", "gitlab",
    "jira", "confluence", "wiki", "status", "monitor", "ns1", "ns2",
    "mx", "mx1", "mx2", "autodiscover", "cpanel", "whm",
]


# ------------------------------------------------------------------
# Forward lookup
# ------------------------------------------------------------------
def resolve_forward(hostname: str) -> list[str]:
    """
    Resolve `hostname` to all of its IP addresses.

    Returns a (possibly empty) list of IPv4/IPv6 address strings.
    """
    hostname = hostname.strip().lower()
    try:
        results = socket.getaddrinfo(hostname, None)
        # getaddrinfo returns (family, type, proto, canonname, sockaddr) tuples.
        # sockaddr is (ip, port) for IPv4, (ip, port, flow, scope) for IPv6.
        ips: list[str] = []
        seen: set[str] = set()
        for info in results:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips
    except socket.gaierror:
        return []


# ------------------------------------------------------------------
# Reverse lookup
# ------------------------------------------------------------------
def resolve_reverse(ip: str) -> str:
    """
    Perform a reverse DNS lookup on `ip`.

    Returns the PTR hostname string, or '' on failure.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip.strip())
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ------------------------------------------------------------------
# Subdomain enumeration
# ------------------------------------------------------------------
def _check_subdomain(sub: str, domain: str) -> dict | None:
    """
    Try to resolve `sub.domain`. Return a result dict on success, None if
    the subdomain does not resolve.
    """
    fqdn = f"{sub}.{domain}"
    ips = resolve_forward(fqdn)
    if ips:
        return {"subdomain": fqdn, "ips": ips}
    return None


def enum_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    max_workers: int = 30,
) -> list[dict]:
    """
    Try each prefix in `wordlist` (default: DEFAULT_SUBDOMAINS) as a
    subdomain of `domain`. Returns a list of {subdomain, ips} dicts for
    every prefix that resolved.
    """
    domain = domain.strip().lower().lstrip("www.").lstrip("http://").lstrip("https://")
    wordlist = wordlist or DEFAULT_SUBDOMAINS
    found: list[dict] = []

    print(f"\n  Testing {len(wordlist)} subdomain prefix(es) against "
          f"{C.BOLD}{domain}{C.RESET} ...")

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_check_subdomain, sub, domain): sub
            for sub in wordlist
        }
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result:
                    ips_str = ", ".join(result["ips"])
                    print(f"  {C.GREEN}[+] {result['subdomain']}{C.RESET}"
                          f"  →  {C.VALUE}{ips_str}{C.RESET}")
                    found.append(result)
            except Exception:
                pass

    found.sort(key=lambda r: r["subdomain"])
    return found


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
def write_results(domain: str, data: dict) -> Path:
    """Persist a JSON report of the DNS scan to OUTPUT_DIR."""
    safe = domain.replace(".", "_")
    out = OUTPUT_DIR / f"dns_lookup_{safe}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("DNS Lookup")

    print(
        "Options:\n"
        f"  {C.KEY}1{C.RESET} Forward lookup  (hostname → IP addresses)\n"
        f"  {C.KEY}2{C.RESET} Reverse lookup  (IP → hostname)\n"
        f"  {C.KEY}3{C.RESET} Subdomain enum  (brute-force common sub-domains)\n"
    )
    choice = input(f"{C.KEY}Choose [1-3]: {C.RESET}").strip()
    if choice not in ("1", "2", "3"):
        print(f"{C.WARN}Invalid choice. Returning to menu.{C.RESET}")
        return

    report: dict = {}

    # ---- Forward lookup ------------------------------------------
    if choice == "1":
        hostname = prompt_nonempty("Enter hostname (e.g. example.com): ")
        if not hostname:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return

        section(f"Forward Lookup: {hostname}")
        ips = resolve_forward(hostname)
        if ips:
            for ip in ips:
                print(f"  {C.GREEN}{ip}{C.RESET}")
            report = {"type": "forward", "hostname": hostname, "ips": ips}
        else:
            print(f"  {C.WARN}No addresses found for {hostname!r}.{C.RESET}")
            return

    # ---- Reverse lookup ------------------------------------------
    elif choice == "2":
        ip = prompt_nonempty("Enter IP address (e.g. 93.184.216.34): ")
        if not ip:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return

        section(f"Reverse Lookup: {ip}")
        hostname = resolve_reverse(ip)
        if hostname:
            kv("PTR hostname", hostname)
            report = {"type": "reverse", "ip": ip, "hostname": hostname}
        else:
            print(f"  {C.WARN}No PTR record found for {ip!r}.{C.RESET}")
            return

    # ---- Subdomain enum ------------------------------------------
    elif choice == "3":
        domain = prompt_nonempty("Enter base domain (e.g. example.com): ")
        if not domain:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return

        section(f"Subdomain Enumeration: {domain}")
        found = enum_subdomains(domain)

        section("Summary")
        print(f"  Discovered {C.GREEN}{len(found)}{C.RESET} live subdomain(s).")
        if not found:
            return
        report = {"type": "subdomain_enum", "domain": domain, "found": found}

    # ---- Save report? --------------------------------------------
    save = input("\nSave results to JSON? (y/N): ").strip().lower()
    if save == "y" and report:
        target_key = (
            report.get("hostname") or
            report.get("ip") or
            report.get("domain") or
            "unknown"
        )
        out = write_results(target_key, report)
        kv("Report saved to", out)
