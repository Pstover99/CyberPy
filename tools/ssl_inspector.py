"""
Name:  Parker Stover

tools/ssl_inspector.py
----------------------
Inspect the SSL/TLS certificate presented by a remote HTTPS server.
Reports the certificate subject, issuer, validity window, Subject
Alternative Names (SANs), and warns when the cert is already expired
or will expire within 30 days.

Uses only Python's standard-library `ssl` and `socket` modules — no
third-party dependencies required.

Public functions:
    get_certificate(host, port)     -> dict | None
    days_until_expiry(cert_info)    -> int
    print_cert_info(cert_info)      -> None
    write_results(host, cert_info)  -> Path
    run()                           -> menu entry point
"""

from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path

from .common import OUTPUT_DIR, C, banner, kv, section, prompt_nonempty, prompt_port


# Warn if fewer than this many days remain on the cert.
EXPIRY_WARN_DAYS = 30


# ------------------------------------------------------------------
# Certificate fetching
# ------------------------------------------------------------------
def get_certificate(host: str, port: int = 443, timeout: float = 10.0) -> dict | None:
    """
    Connect to `host`:`port` with TLS and retrieve the peer certificate.

    Returns a dict of parsed certificate fields, or None on failure.
    The dict always contains at least:
        host, port, subject, issuer, not_before, not_after, sans, version
    """
    host = host.strip().lower()
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
    except ssl.SSLCertVerificationError as e:
        # Re-try without verification so we can still show the cert details.
        # We flag this as untrusted in the output.
        ctx_noverify = ssl.create_default_context()
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with ctx_noverify.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
            cert["_verification_error"] = str(e)
        except Exception as inner:
            print(f"{C.ERROR}[!] Could not connect to {host}:{port} — {inner}{C.RESET}")
            return None
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"{C.ERROR}[!] Connection failed: {e}{C.RESET}")
        return None

    # ---- Parse the raw cert dict returned by Python's ssl module ----
    def _flatten_rdn(rdn_seq) -> dict:
        """Convert ((('CN', 'example.com'),),) → {'CN': 'example.com'}."""
        out: dict = {}
        for rdn in rdn_seq:
            for key, val in rdn:
                out[key] = val
        return out

    subject = _flatten_rdn(cert.get("subject", ()))
    issuer  = _flatten_rdn(cert.get("issuer", ()))

    # Subject Alternative Names
    sans = [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"]

    # Validity window — Python gives these as strings like "Jan  1 00:00:00 2026 GMT"
    def _parse_cert_date(s: str) -> datetime:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

    not_before_str = cert.get("notBefore", "")
    not_after_str  = cert.get("notAfter",  "")
    try:
        not_before_dt = _parse_cert_date(not_before_str)
        not_after_dt  = _parse_cert_date(not_after_str)
    except ValueError:
        not_before_dt = None
        not_after_dt  = None

    return {
        "host":               host,
        "port":               port,
        "subject":            subject,
        "issuer":             issuer,
        "not_before":         not_before_str,
        "not_after":          not_after_str,
        "not_before_dt":      not_before_dt,
        "not_after_dt":       not_after_dt,
        "sans":               sans,
        "version":            cert.get("version"),
        "serial_number":      cert.get("serialNumber"),
        "cipher":             cipher,
        "verification_error": cert.get("_verification_error"),
    }


# ------------------------------------------------------------------
# Expiry helpers
# ------------------------------------------------------------------
def days_until_expiry(cert_info: dict) -> int:
    """
    Return the number of whole days until the certificate expires.
    Negative values mean the certificate has already expired.
    Returns 0 if the expiry date could not be parsed.
    """
    dt = cert_info.get("not_after_dt")
    if dt is None:
        return 0
    delta = dt - datetime.now(tz=timezone.utc)
    return delta.days


# ------------------------------------------------------------------
# Display
# ------------------------------------------------------------------
def print_cert_info(cert_info: dict) -> None:
    """Pretty-print certificate details to stdout using the toolkit color scheme."""

    section("Subject")
    for key, val in cert_info["subject"].items():
        kv(key, val)

    section("Issuer")
    for key, val in cert_info["issuer"].items():
        kv(key, val)

    section("Validity")
    kv("Not Before", cert_info["not_before"])
    kv("Not After",  cert_info["not_after"])

    days = days_until_expiry(cert_info)
    if days < 0:
        print(f"  {C.ERROR}CERTIFICATE EXPIRED {abs(days)} day(s) ago!{C.RESET}")
    elif days <= EXPIRY_WARN_DAYS:
        print(f"  {C.WARN}WARNING: expires in {days} day(s)!{C.RESET}")
    else:
        print(f"  {C.GREEN}Valid for {days} more day(s).{C.RESET}")

    section("Subject Alternative Names (SANs)")
    sans = cert_info.get("sans", [])
    if sans:
        for san in sans:
            print(f"  {C.VALUE}{san}{C.RESET}")
    else:
        print(f"  {C.WARN}None listed.{C.RESET}")

    section("Connection Details")
    kv("TLS Version",  cert_info["version"])
    kv("Serial Number", cert_info.get("serial_number", "N/A"))
    cipher = cert_info.get("cipher")
    if cipher:
        kv("Cipher Suite", cipher[0])
        kv("Protocol",     cipher[1])
        kv("Key Bits",     cipher[2])

    if cert_info.get("verification_error"):
        section("Trust Warning")
        print(f"  {C.ERROR}Certificate did NOT pass verification:{C.RESET}")
        print(f"  {C.WARN}{cert_info['verification_error']}{C.RESET}")


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
def _json_serialisable(obj):
    """JSON-safe copy — strip non-serialisable objects (datetime, etc.)."""
    if isinstance(obj, dict):
        return {k: _json_serialisable(v) for k, v in obj.items()
                if not isinstance(v, datetime)}
    if isinstance(obj, list):
        return [_json_serialisable(i) for i in obj]
    return obj


def write_results(host: str, cert_info: dict) -> Path:
    """Write a JSON report of the certificate scan to OUTPUT_DIR."""
    safe = host.replace(".", "_").replace(":", "_")
    out = OUTPUT_DIR / f"ssl_report_{safe}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(_json_serialisable(cert_info), f, indent=4)
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("SSL / TLS Certificate Inspector")

    host = prompt_nonempty("Enter hostname or IP (e.g. example.com): ")
    if not host:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    port = prompt_port("Port", default=443)
    if port is None:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    print(f"\nConnecting to {C.BOLD}{host}:{port}{C.RESET} ...")
    cert_info = get_certificate(host, port)
    if cert_info is None:
        return

    print_cert_info(cert_info)

    save = input("\nSave full report to JSON? (y/N): ").strip().lower()
    if save == "y":
        out = write_results(host, cert_info)
        kv("Report saved to", out)
