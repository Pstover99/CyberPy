"""
Name: Parker Stover
Class: ITP 270
Date: 15 APR 2026
Project name: tools/port_scanner.py
---------------------
Threaded TCP port scanner that tests the COMMON_PORTS list against a
single IP address or every host in a CIDR network.

Public functions:
    scan_ports_for_ip(ip)                      -> dict
    scan_targets(targets, ports=None)          -> list[dict]
    write_results(results, target)             -> Path
    run()                                      -> menu entry point
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .common import COMMON_PORTS, OUTPUT_DIR, C, banner, kv, prompt_target


def _check_port(ip: str, port: int, timeout: float = 0.4) -> bool:
    """Return True if (ip, port) accepts a TCP connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def scan_ports_for_ip(ip: str, ports: list[int] | None = None,
                      timeout: float = 0.4) -> dict:
    """
    Scan one IP for the given ports (default: COMMON_PORTS) using a small
    thread pool. Returns a dict with the ip, list of open ports, and total.
    """
    ports = ports or COMMON_PORTS
    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=min(20, len(ports))) as pool:
        futures = {pool.submit(_check_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                if fut.result():
                    open_ports.append(port)
            except Exception:
                pass

    open_ports.sort()
    return {"ip": ip, "open_ports": open_ports, "total": len(open_ports)}


def scan_targets(targets: list[str],
                 ports: list[int] | None = None) -> list[dict]:
    """Scan a list of IPs sequentially (each IP runs threaded internally)."""
    results: list[dict] = []
    for i, ip in enumerate(targets, 1):
        print(f"\n[{i}/{len(targets)}] Scanning {C.BOLD}{ip}{C.RESET} ...")
        result = scan_ports_for_ip(ip, ports=ports)
        if result["open_ports"]:
            for p in result["open_ports"]:
                print(f"  {C.GREEN}Port {p}: Open{C.RESET}")
        else:
            print(f"  {C.WARN}No common ports open.{C.RESET}")
        print(f"  Total open: {result['total']}")
        results.append(result)
    return results


def write_results(results: list[dict], target: str) -> Path:
    """Persist a port scan report to OUTPUT_DIR/port_scan_results.txt."""
    out = OUTPUT_DIR / "port_scan_results.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write("Port Scan Results\n")
        f.write("=================\n\n")
        f.write(f"Target: {target}\n\n")
        for r in results:
            f.write(f"IP: {r['ip']}\n")
            for p in r["open_ports"]:
                f.write(f"  Port {p}: Open\n")
            f.write(f"  Total open: {r['total']}\n")
            f.write("-" * 40 + "\n")
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Port Scanner")
    print("You can scan a single IP (192.168.1.10) or a network "
          "in CIDR notation (192.168.1.0/24).")
    targets, normalized = prompt_target("Enter target: ")
    if not targets:
        return

    print(f"\nScanning {len(targets)} host(s) for {len(COMMON_PORTS)} common ports.")
    results = scan_targets(targets)
    out = write_results(results, normalized)
    kv("Report written to", out)
