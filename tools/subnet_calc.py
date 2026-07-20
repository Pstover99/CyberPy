"""
Name:  Parker Stover

tools/subnet_calc.py
--------------------
IPv4 Subnet Calculator tool.
Given an IP address and a netmask (in CIDR notation), computes network details,
host ranges, masks, and their binary representations.

Uses only Python's standard-library `ipaddress` module.
"""

from __future__ import annotations

import ipaddress

from .common import C, banner, kv, section, prompt_nonempty


def to_binary(ip_str: str) -> str:
    """Convert an IPv4 address string (e.g. 192.168.1.1) to its binary format."""
    try:
        return ".".join(f"{int(octet):08b}" for octet in ip_str.split("."))
    except Exception:
        return "N/A"


def calculate_subnet(cidr_str: str) -> dict | None:
    """Calculate and return network parameters from a CIDR range string."""
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError as e:
        print(f"{C.ERROR}[!] Invalid network/CIDR notation: {e}{C.RESET}")
        return None

    net_addr = str(net.network_address)
    broadcast_addr = str(net.broadcast_address)
    netmask = str(net.netmask)
    wildcard = str(net.hostmask)
    num_addresses = net.num_addresses

    # Usable hosts logic depending on prefix size
    if num_addresses > 2:
        first_host = str(net.network_address + 1)
        last_host = str(net.broadcast_address - 1)
        usable_count = num_addresses - 2
    elif num_addresses == 2:  # /31 subnet
        first_host = net_addr
        last_host = broadcast_addr
        usable_count = 2
    else:  # /32 single host
        first_host = net_addr
        last_host = net_addr
        usable_count = 1

    return {
        "cidr": str(net),
        "network_address": net_addr,
        "broadcast_address": broadcast_addr,
        "netmask": netmask,
        "wildcard_mask": wildcard,
        "first_host": first_host,
        "last_host": last_host,
        "usable_hosts": usable_count,
        "total_hosts": num_addresses,
        "prefix_len": net.prefixlen,
    }


def print_results(res: dict) -> None:
    """Print the subnet calculation details including binary format."""
    section("Network Configuration")
    kv("CIDR Range", res["cidr"])
    kv("Subnet Mask", f"{res['netmask']} (/{res['prefix_len']})")
    kv("Wildcard Mask", res["wildcard_mask"])

    section("Addresses & Usable Range")
    kv("Network Address", res["network_address"])
    kv("Broadcast Address", res["broadcast_address"])

    if res["usable_hosts"] > 1:
        kv("Usable Host Range", f"{res['first_host']} - {res['last_host']}")
    else:
        kv("Usable Host Range", res["first_host"])

    kv("Usable Hosts Count", f"{res['usable_hosts']:,}")
    kv("Total Addresses", f"{res['total_hosts']:,}")

    section("Binary Representation")
    print(f"  {C.KEY}Network   :{C.RESET} {C.CYAN}{to_binary(res['network_address'])}{C.RESET}")
    print(f"  {C.KEY}Netmask   :{C.RESET} {C.CYAN}{to_binary(res['netmask'])}{C.RESET}")
    print(f"  {C.KEY}Wildcard  :{C.RESET} {C.CYAN}{to_binary(res['wildcard_mask'])}{C.RESET}")
    print(f"  {C.KEY}Broadcast :{C.RESET} {C.CYAN}{to_binary(res['broadcast_address'])}{C.RESET}")


def run() -> None:
    banner("IPv4 Subnet Calculator")
    print("Computes network information, usable host ranges, and binary equivalents.")
    print("Format: IP/Prefix (e.g. 192.168.1.0/24 or 10.0.0.45/22).\n")

    raw = prompt_nonempty("Enter CIDR network: ")
    if not raw:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    res = calculate_subnet(raw.strip())
    if res is not None:
        print_results(res)
