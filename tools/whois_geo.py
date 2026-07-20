"""
Name:  Parker Stover

tools/whois_geo.py
------------------
WHOIS & IP Geolocation lookup tool.
Queries RDAP (Registration Data Access Protocol) for domain or IP registration
information, and uses ip-api.com for geographic/network mapping.

Uses the `requests` library. Saves reports in JSON format to `output/`.
"""

from __future__ import annotations

import json
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

import requests

from .common import OUTPUT_DIR, C, banner, kv, section, prompt_nonempty


def is_ip(target: str) -> bool:
    """Return True if the target matches an IPv4 address pattern."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))


def query_geo(target: str) -> dict | None:
    """Query ip-api.com for geolocation info of an IP or domain."""
    url = f"http://ip-api.com/json/{target}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "success":
            return data
        else:
            return {"error": data.get("message", "API query failed")}
    except Exception as e:
        return {"error": str(e)}


def query_rdap(target: str, target_is_ip: bool) -> dict | None:
    """Query rdap.org for registration information."""
    category = "ip" if target_is_ip else "domain"
    url = f"https://rdap.org/{category}/{target}"
    try:
        resp = requests.get(url, headers={"Accept": "application/json"}, timeout=10)
        if resp.status_code == 404:
            return {"error": "Record not found (404)"}
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def parse_rdap_events(events: list) -> dict[str, str]:
    """Extract action dates (registration, expiration, last changed) from RDAP events."""
    parsed = {}
    for ev in events:
        action = ev.get("eventAction")
        date = ev.get("eventDate")
        if action and date:
            # Clean up action names for display (e.g. "last changed" -> "Last Changed")
            clean_name = action.replace("_", " ").title()
            parsed[clean_name] = date
    return parsed


def parse_rdap_registrar(entities: list) -> str:
    """Traverse entities to find the registrar name."""
    for ent in entities:
        roles = ent.get("roles", [])
        if "registrar" in roles:
            # Check vcardArray for FN (formatted name)
            vcard = ent.get("vcardArray", [])
            if len(vcard) > 1:
                properties = vcard[1]
                for prop in properties:
                    if prop[0] == "fn":
                        return prop[3]
    # Fallback to check nested entities
    for ent in entities:
        nested = ent.get("entities", [])
        if nested:
            res = parse_rdap_registrar(nested)
            if res != "Unknown":
                return res
    return "Unknown"


def print_results(target: str, target_is_ip: bool, geo: dict, rdap: dict) -> None:
    """Display parsed WHOIS & Geolocation results with terminal colors."""
    # --- Geolocation ---
    section("Geolocation Details")
    if "error" in geo:
        print(f"  {C.WARN}Could not retrieve Geolocation: {geo['error']}{C.RESET}")
    else:
        kv("Country", f"{geo.get('country')} ({geo.get('countryCode')})")
        kv("Region/City", f"{geo.get('regionName')}, {geo.get('city')}")
        kv("Zip Code", geo.get("zip", "N/A"))
        kv("Lat / Lon", f"{geo.get('lat')}, {geo.get('lon')}")
        kv("ISP", geo.get("isp"))
        kv("Organization", geo.get("org", "N/A"))
        kv("AS / ASN", geo.get("as"))
        kv("Timezone", geo.get("timezone"))

    # --- Registration / WHOIS ---
    section("WHOIS / RDAP Registration Details")
    if "error" in rdap:
        print(f"  {C.WARN}RDAP Query failed or not supported: {rdap['error']}{C.RESET}")
    else:
        if target_is_ip:
            kv("IP Block Range", f"{rdap.get('startAddress')} - {rdap.get('endAddress')}")
            kv("Network Name", rdap.get("name", "N/A"))
            kv("Handle", rdap.get("handle"))
            kv("Parent Handle", rdap.get("parentHandle", "N/A"))
            status = ", ".join(rdap.get("status", []))
            if status:
                kv("Status", status)
        else:
            kv("Domain Name", rdap.get("ldhName"))
            kv("Registrar", parse_rdap_registrar(rdap.get("entities", [])))
            status = ", ".join(rdap.get("status", []))
            if status:
                kv("Status", status)

        # Dates / Events
        events = rdap.get("events", [])
        parsed_dates = parse_rdap_events(events)
        if parsed_dates:
            print(f"\n  {C.CYAN}Relevant Dates:{C.RESET}")
            for key, val in parsed_dates.items():
                kv(f"  {key}", val)


def write_report(target: str, geo: dict, rdap: dict) -> Path:
    """Save WHOIS/RDAP & Geolocation JSON report to output directory."""
    safe_target = re.sub(r"[^a-zA-Z0-9.-]", "_", target)
    out = OUTPUT_DIR / f"whois_geo_{safe_target}.json"
    report = {
        "target": target,
        "is_ip": is_ip(target),
        "geolocation": geo,
        "rdap_whois": rdap
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    return out


def run() -> None:
    banner("WHOIS & IP Geolocation Lookup")
    print("Queries public databases to resolve registrar details and geographic location.")
    print("Supports IP addresses (e.g. 1.1.1.1) or domain names (e.g. cloudflare.com).\n")

    target = prompt_nonempty("Enter Target IP or Domain: ")
    if not target:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    target = target.strip().lower()
    # Strip URL schemes if entered by mistake
    if target.startswith(("http://", "https://")):
        try:
            target = urlparse(target).netloc or target
        except Exception:
            pass

    target_is_ip = is_ip(target)

    # Resolve domain to IP for confirmation if needed, and to check format
    if not target_is_ip:
        print(f"Resolving domain {C.BOLD}{target}{C.RESET} ...")
        try:
            resolved_ip = socket.gethostbyname(target)
            print(f"  Domain resolved to: {C.GREEN}{resolved_ip}{C.RESET}")
        except Exception as e:
            print(f"  {C.WARN}Warning: Could not resolve domain to IP address locally ({e}).{C.RESET}")

    print(f"\nQuerying geolocation and registration data for {C.BOLD}{target}{C.RESET} ...")

    geo = query_geo(target) or {}
    rdap = query_rdap(target, target_is_ip) or {}

    print_results(target, target_is_ip, geo, rdap)

    save = input("\nSave full report to JSON? (y/N): ").strip().lower()
    if save == "y":
        out = write_report(target, geo, rdap)
        kv("Report saved to", out)
