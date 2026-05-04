"""
Name: Parker Stover
Class: ITP 270
Date: 25 MAR 2026
Project name: tools/network_scanner.py
------------------------
Discover live hosts on a network using a threaded ICMP sweep, then look
up each host's MAC address from the local ARP cache and resolve the
vendor from an OUI prefix file (if one is present).

Public functions:
    is_active(ip)       -> bool
    get_mac(ip)         -> str
    get_vendor(mac)     -> str
    scan_network(cidr)  -> list[dict]
    save_active_ips(devices) -> Path
    write_results(devices, target) -> Path
    run()               -> entry point used by the menu
"""

from __future__ import annotations

import ipaddress
import json
import logging
import platform
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .common import OUTPUT_DIR, PROJECT_DIR, C, banner, kv, prompt_cidr


# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
LOG_FILE = OUTPUT_DIR / "network_scan.log"
_log_configured = False


def _configure_logging() -> None:
    """Attach a file handler the first time we run a scan."""
    global _log_configured
    if _log_configured:
        return
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
    )
    _log_configured = True


# ------------------------------------------------------------------
# OUI / vendor lookup
# ------------------------------------------------------------------
# Resolution chain for a MAC address:
#   1. In-memory + on-disk cache (output/mac_vendor_cache.json)
#   2. Local oui.txt   (optional, format: 'AA:BB:CC Vendor Name')
#   3. api.macvendors.com  (free, no key, ~1 request/sec)
#   4. "Unknown"
# Successful lookups from steps 2 and 3 are written back to the cache so
# repeat scans don't hit the network.

_VENDOR_CACHE_FILE = OUTPUT_DIR / "mac_vendor_cache.json"
_LAST_API_CALL: float = 0.0


def _load_oui() -> dict[str, str]:
    """
    Read oui.txt (format: 'AA:BB:CC Vendor Name') if present.

    Blank lines and lines beginning with '#' are skipped so the file
    can be commented and grouped by vendor for human readability.
    """
    oui_map: dict[str, str] = {}
    oui_file = PROJECT_DIR / "oui.txt"
    if not oui_file.exists():
        return oui_map
    with open(oui_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(" ", 1)
            if len(parts) == 2:
                prefix, vendor = parts
                oui_map[prefix.upper()] = vendor
    return oui_map


def _load_vendor_cache() -> dict[str, str]:
    """Load the persisted MAC-prefix -> vendor cache, if any."""
    if _VENDOR_CACHE_FILE.exists():
        try:
            return json.loads(_VENDOR_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_vendor_cache() -> None:
    try:
        _VENDOR_CACHE_FILE.write_text(
            json.dumps(_VENDOR_CACHE, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except Exception:
        pass


_OUI = _load_oui()
_VENDOR_CACHE: dict[str, str] = _load_vendor_cache()


def _lookup_vendor_online(mac: str) -> str:
    """
    Query api.macvendors.com for the vendor of `mac`.
    Returns '' on any failure (no key required, ~1 req/sec free tier).
    """
    global _LAST_API_CALL
    try:
        import requests  # already in requirements.txt

        # Throttle: api.macvendors.com asks for at most ~1 request/second.
        elapsed = time.time() - _LAST_API_CALL
        if elapsed < 1.1:
            time.sleep(1.1 - elapsed)
        _LAST_API_CALL = time.time()

        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if resp.status_code == 200 and resp.text.strip():
            return resp.text.strip()
    except Exception:
        pass
    return ""


def get_vendor(mac: str) -> str:
    """Map a MAC to a vendor name via the cache -> oui.txt -> online chain."""
    if not mac or mac == "Unknown":
        return "Unknown"
    prefix = mac.upper().replace("-", ":")[0:8]

    # 1. Cached
    if prefix in _VENDOR_CACHE:
        return _VENDOR_CACHE[prefix]

    # 2. Local OUI file
    if prefix in _OUI:
        _VENDOR_CACHE[prefix] = _OUI[prefix]
        _save_vendor_cache()
        return _OUI[prefix]

    # 3. Online lookup
    vendor = _lookup_vendor_online(mac)
    if vendor:
        _VENDOR_CACHE[prefix] = vendor
        _save_vendor_cache()
        return vendor

    return "Unknown"


# ------------------------------------------------------------------
# Ping / ARP - cross-platform
# ------------------------------------------------------------------
def is_active(ip: str) -> bool:
    """
    Send a single ICMP echo to `ip` and return True on success.
    Works on Windows, Linux, and macOS.
    """
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", "1", "-w", "300", str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


_MAC_RE = re.compile(
    r"([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12}"
)


def get_mac(ip: str) -> str:
    """
    Pull the MAC for `ip` out of the local ARP cache.

    Note: `arp -a <ip>` on Windows and `arp -n <ip>` on Linux do NOT filter
    the output to a single entry - they print the whole table for the
    interface that routes to `ip`. So we have to look line-by-line for the
    one whose address column matches our target, then extract the MAC from
    THAT line. (Earlier versions just grabbed the first MAC in the output,
    which was usually the gateway.)
    """
    if platform.system().lower().startswith("win"):
        cmd = ["arp", "-a", str(ip)]
    else:
        cmd = ["arp", "-n", str(ip)]

    try:
        output = subprocess.check_output(
            cmd, text=True, stderr=subprocess.DEVNULL, timeout=3,
        )
    except Exception:
        return "Unknown"

    ip_str = str(ip)
    for line in output.splitlines():
        # Split on whitespace and require an exact token match so 192.168.1.1
        # doesn't mistakenly grab the row for 192.168.1.10.
        if ip_str in line.split():
            match = _MAC_RE.search(line)
            if match:
                mac = match.group(0)
                if len(mac) == 12:  # bare 12-hex form
                    mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
                return mac.upper().replace("-", ":")

    return "Unknown"


# ------------------------------------------------------------------
# Scan / save
# ------------------------------------------------------------------
def scan_network(network_range: str, max_threads: int = 30) -> list[dict]:
    """
    Threaded ping sweep of `network_range` (CIDR). Returns a list of
    {ip, mac, vendor} dicts for every host that responded.
    """
    _configure_logging()

    try:
        network = ipaddress.ip_network(network_range, strict=False)
    except ValueError:
        print(f"{C.ERROR}Invalid CIDR. Example: 192.168.1.0/24{C.RESET}")
        return []

    hosts = list(network.hosts())
    total = len(hosts)
    devices: list[dict] = []

    print(f"\nScanning {total} hosts on {network_range} ...\n")

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(is_active, str(ip)): ip for ip in hosts}
        completed = 0
        last_pct = 0
        for fut in as_completed(futures):
            ip = futures[fut]
            completed += 1
            pct = int(completed / total * 100)
            if pct - last_pct >= 5:
                print(f"  Progress: {pct}% complete", end="\r")
                last_pct = pct
            try:
                if fut.result():
                    mac = get_mac(str(ip))
                    vendor = get_vendor(mac)
                    devices.append({
                        "ip": str(ip),
                        "mac": mac,
                        "vendor": vendor,
                    })
                    print(f"  {C.GREEN}{ip}{C.RESET} is active "
                          f"(MAC: {mac}, Vendor: {vendor})")
                    logging.info("%s active - MAC: %s - Vendor: %s",
                                 ip, mac, vendor)
            except Exception as e:
                logging.error("Error scanning %s: %s", ip, e)

    print(f"\nFound {len(devices)} active device(s) on {network_range}.")
    logging.info("Total active on %s: %d", network_range, len(devices))
    return devices


def save_active_ips(devices: list[dict]) -> Path:
    """Persist the IP list to OUTPUT_DIR/active_ips.txt for the port scanner."""
    out = OUTPUT_DIR / "active_ips.txt"
    with open(out, "w", encoding="utf-8") as f:
        for d in devices:
            f.write(d["ip"] + "\n")
    return out


def write_results(devices: list[dict], target: str) -> Path:
    """Write a human-readable report of the network scan."""
    out = OUTPUT_DIR / "network_scan_results.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write("Network Scan Results\n")
        f.write("====================\n\n")
        f.write(f"Network Range: {target}\n\n")
        for d in devices:
            f.write(f"IP Address : {d['ip']}\n")
            f.write(f"MAC Address: {d['mac']}\n")
            f.write(f"Vendor     : {d['vendor']}\n\n")
        f.write(f"Total Active Devices: {len(devices)}\n")
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Network Scanner")

    # prompt_cidr loops until the user supplies a valid CIDR or cancels.
    _hosts, target = prompt_cidr()
    if not target:
        return  # user cancelled

    devices = scan_network(target)
    if not devices:
        return

    active_file = save_active_ips(devices)
    report_file = write_results(devices, target)

    kv("Active IPs saved to", active_file)
    kv("Report written to",   report_file)
