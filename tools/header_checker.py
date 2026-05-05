"""
Name:  Parker Stover
Class: ITP 270
Date:  04 MAY 2026

tools/header_checker.py
-----------------------
HTTP Security Header Auditor. Fetches a URL and inspects the response
headers for the presence and basic correctness of modern security
directives. Each header is graded PASS / WARN / FAIL, and an overall
score is computed.

Headers checked
---------------
  Strict-Transport-Security  (HSTS)
  Content-Security-Policy    (CSP)
  X-Frame-Options
  X-Content-Type-Options
  Referrer-Policy
  Permissions-Policy
  X-XSS-Protection           (legacy, flagged if absent OR set insecurely)
  Cache-Control              (checks for sensitive page caching)

Requires: `requests` (already in requirements.txt).

Public functions:
    audit_headers(url)          -> dict   {header_name: {status, detail}}
    score(audit)                -> tuple[int, int]  (earned, possible)
    print_report(url, audit)    -> None
    save_report(url, audit)     -> Path
    run()                       -> menu entry point
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import requests

from .common import OUTPUT_DIR, C, banner, kv, section, prompt_url


# ------------------------------------------------------------------
# Grade constants
# ------------------------------------------------------------------
PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

_GRADE_COLOR = {
    PASS: C.GREEN,
    WARN: C.YELLOW,
    FAIL: C.ERROR,
}

_GRADE_POINTS = {PASS: 2, WARN: 1, FAIL: 0}


# ------------------------------------------------------------------
# Individual header checks
# Each check returns (status, detail_message).
# ------------------------------------------------------------------

def _check_hsts(headers: dict) -> tuple[str, str]:
    val = headers.get("Strict-Transport-Security", "")
    if not val:
        return FAIL, "Missing. Browsers won't enforce HTTPS-only."
    val_lower = val.lower()
    if "max-age=0" in val_lower:
        return FAIL, f"max-age=0 effectively disables HSTS. Value: {val!r}"
    try:
        age = int([p for p in val_lower.split(";")
                   if "max-age" in p][0].split("=")[1].strip())
        if age < 15768000:  # < ~6 months
            return WARN, f"max-age={age} is low (recommend ≥ 15768000). Value: {val!r}"
    except (IndexError, ValueError):
        return WARN, f"Could not parse max-age. Value: {val!r}"
    return PASS, f"Present. Value: {val!r}"


def _check_csp(headers: dict) -> tuple[str, str]:
    val = headers.get("Content-Security-Policy", "")
    if not val:
        return FAIL, "Missing. No policy to restrict resource origins."
    val_lower = val.lower()
    if "unsafe-inline" in val_lower and "unsafe-eval" in val_lower:
        return WARN, "Both 'unsafe-inline' and 'unsafe-eval' present — weakens XSS protection."
    if "unsafe-inline" in val_lower:
        return WARN, "'unsafe-inline' present — inline scripts allowed, reduces XSS protection."
    if "*" in val and "default-src" in val_lower:
        return WARN, "Wildcard (*) in default-src allows any origin."
    return PASS, "Present with no obvious unsafe directives."


def _check_xframe(headers: dict) -> tuple[str, str]:
    val = headers.get("X-Frame-Options", "")
    if not val:
        return FAIL, "Missing. Site may be embeddable in iframes (clickjacking risk)."
    val_upper = val.strip().upper()
    if val_upper in ("DENY", "SAMEORIGIN"):
        return PASS, f"Present. Value: {val!r}"
    if val_upper.startswith("ALLOW-FROM"):
        return WARN, f"ALLOW-FROM is deprecated in modern browsers. Value: {val!r}"
    return WARN, f"Unrecognised value: {val!r}"


def _check_xcto(headers: dict) -> tuple[str, str]:
    val = headers.get("X-Content-Type-Options", "")
    if not val:
        return FAIL, "Missing. Browsers may MIME-sniff responses (sniffing attacks)."
    if val.strip().lower() == "nosniff":
        return PASS, "Present. Value: 'nosniff'"
    return WARN, f"Unexpected value: {val!r} (should be 'nosniff')."


def _check_referrer(headers: dict) -> tuple[str, str]:
    val = headers.get("Referrer-Policy", "")
    if not val:
        return WARN, "Missing. Browser default may leak Referer headers."
    safe_values = {
        "no-referrer", "no-referrer-when-downgrade",
        "same-origin", "origin", "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if val.strip().lower() in safe_values:
        return PASS, f"Present. Value: {val!r}"
    if val.strip().lower() in ("unsafe-url", "origin-when-cross-origin"):
        return WARN, f"Value {val!r} may leak full URL to third parties."
    return WARN, f"Unrecognised value: {val!r}"


def _check_permissions(headers: dict) -> tuple[str, str]:
    val = headers.get("Permissions-Policy", "")
    if not val:
        return WARN, "Missing. Browser features (camera, mic, geolocation) unrestricted."
    return PASS, f"Present. Value: {val!r}"


def _check_xss_protection(headers: dict) -> tuple[str, str]:
    val = headers.get("X-XSS-Protection", "")
    if not val:
        return WARN, "Missing. Legacy header, but still expected by some scanners."
    val_stripped = val.strip()
    if val_stripped == "0":
        return WARN, "Set to '0' (disabled). Some older browsers lose XSS filter."
    if val_stripped.startswith("1"):
        return PASS, f"Present. Value: {val!r}"
    return WARN, f"Unrecognised value: {val!r}"


def _check_cache(headers: dict) -> tuple[str, str]:
    val = headers.get("Cache-Control", "")
    if not val:
        return WARN, "Missing. Responses may be cached by proxies/browsers."
    val_lower = val.lower()
    if "no-store" in val_lower:
        return PASS, f"'no-store' present — sensitive data won't be cached. Value: {val!r}"
    if "private" in val_lower:
        return PASS, f"'private' present — only user's browser may cache. Value: {val!r}"
    if "public" in val_lower:
        return WARN, f"'public' — responses may be cached by shared proxies. Value: {val!r}"
    return WARN, f"Caching directives unclear. Value: {val!r}"


# ------------------------------------------------------------------
# Orchestration
# ------------------------------------------------------------------
_CHECKS: list[tuple[str, str, object]] = [
    ("Strict-Transport-Security", "HSTS",             _check_hsts),
    ("Content-Security-Policy",   "CSP",              _check_csp),
    ("X-Frame-Options",           "X-Frame-Options",  _check_xframe),
    ("X-Content-Type-Options",    "X-Content-Type-Options", _check_xcto),
    ("Referrer-Policy",           "Referrer-Policy",  _check_referrer),
    ("Permissions-Policy",        "Permissions-Policy", _check_permissions),
    ("X-XSS-Protection",          "X-XSS-Protection", _check_xss_protection),
    ("Cache-Control",             "Cache-Control",    _check_cache),
]


def audit_headers(url: str, timeout: float = 10.0) -> dict:
    """
    Fetch `url` and run every security header check.

    Returns a dict keyed by the friendly header label:
        {label: {"status": PASS|WARN|FAIL, "detail": str}}
    Also includes a special "_meta" key with the URL and HTTP status code.
    """
    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = dict(resp.headers)
        http_status = resp.status_code
        final_url = resp.url
    except requests.exceptions.SSLError:
        # Fall back to http if https fails
        try:
            url_http = url.replace("https://", "http://", 1)
            resp = requests.get(url_http, timeout=timeout, allow_redirects=True)
            headers = dict(resp.headers)
            http_status = resp.status_code
            final_url = resp.url
        except requests.exceptions.RequestException as e:
            return {"_meta": {"url": url, "error": str(e)}}
    except requests.exceptions.RequestException as e:
        return {"_meta": {"url": url, "error": str(e)}}

    result: dict = {
        "_meta": {"url": final_url, "http_status": http_status},
    }
    for header_name, label, check_fn in _CHECKS:
        status, detail = check_fn(headers)
        result[label] = {"status": status, "detail": detail}

    return result


def score(audit: dict) -> tuple[int, int]:
    """
    Compute (earned_points, possible_points) from an audit result.
    Each header is worth 2 points (PASS=2, WARN=1, FAIL=0).
    """
    earned = 0
    possible = 0
    for key, val in audit.items():
        if key == "_meta":
            continue
        possible += 2
        earned += _GRADE_POINTS.get(val["status"], 0)
    return earned, possible


# ------------------------------------------------------------------
# Display
# ------------------------------------------------------------------
def print_report(url: str, audit: dict) -> None:
    """Pretty-print the audit result to stdout."""
    meta = audit.get("_meta", {})
    if "error" in meta:
        print(f"{C.ERROR}[!] Could not fetch {url}: {meta['error']}{C.RESET}")
        return

    section("Security Header Audit")
    kv("URL",         meta.get("url", url))
    kv("HTTP Status", meta.get("http_status", "?"))

    print()
    col_w = 28
    for label, val in audit.items():
        if label == "_meta":
            continue
        status = val["status"]
        detail = val["detail"]
        color  = _GRADE_COLOR[status]
        grade_badge = f"{color}[{status}]{C.RESET}"
        print(f"  {grade_badge}  {C.KEY}{label:<{col_w}}{C.RESET}  {detail}")

    earned, possible = score(audit)
    pct = int(earned / possible * 100) if possible else 0
    section("Overall Score")
    score_color = C.GREEN if pct >= 75 else (C.YELLOW if pct >= 50 else C.ERROR)
    print(f"  {score_color}{earned}/{possible} points ({pct}%){C.RESET}")
    if pct == 100:
        print(f"  {C.GREEN}Excellent — all security headers present and well-configured!{C.RESET}")
    elif pct >= 75:
        print(f"  {C.GREEN}Good — a few headers could be tightened.{C.RESET}")
    elif pct >= 50:
        print(f"  {C.WARN}Fair — several important headers are missing or misconfigured.{C.RESET}")
    else:
        print(f"  {C.ERROR}Poor — this site is missing most security headers.{C.RESET}")


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
def save_report(url: str, audit: dict) -> Path:
    """Write a JSON audit report to OUTPUT_DIR."""
    parsed = urlparse(url)
    safe = (parsed.netloc or "site").replace(".", "_").replace(":", "_")
    out = OUTPUT_DIR / f"headers_{safe}.json"
    # Strip non-serialisable meta keys
    with open(out, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=4)
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("HTTP Security Header Checker")

    raw = prompt_url("Enter URL to audit (e.g. example.com): ")
    if raw is None:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    print(f"\nFetching {C.BOLD}{raw}{C.RESET} ...")
    audit = audit_headers(raw)
    print_report(raw, audit)

    if "_meta" in audit and "error" not in audit["_meta"]:
        save = input("\nSave report to JSON? (y/N): ").strip().lower()
        if save == "y":
            out = save_report(raw, audit)
            kv("Report saved to", out)
