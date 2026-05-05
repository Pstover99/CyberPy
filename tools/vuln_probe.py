"""
Name:  Parker Stover
Class: ITP 270
Date:  04 MAY 2026

tools/vuln_probe.py
-------------------
Web application vulnerability probe.

Sends OWASP standard test payloads into URL GET parameters and analyses
HTTP responses for *indicators* of common weaknesses. This is detection
and triage — it identifies parameters that *may* be vulnerable so that
a human tester can verify and assess impact.

Detection categories
--------------------
  SQL Injection   — probes trigger DBMS error messages visible in the
                    response body. Detection only; no data is read or
                    modified.

  Reflected XSS   — a harmless marker string is injected; the response
                    is checked for unescaped reflection. No script is
                    executed by this tool.

  Open Redirect   — redirect payloads are appended to parameters; the
                    Location header is checked for external-domain
                    forwarding.

IMPORTANT: Only test applications you own or have explicit written
permission to audit. Active HTTP requests are made against the target.

Public functions:
    probe_sqli(url, param, ...)       -> dict
    probe_xss(url, param, ...)        -> dict
    probe_redirect(url, param, ...)   -> dict
    run_all_probes(url, params)       -> list[dict]
    write_results(url, results)       -> Path
    run()                             -> menu entry point
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import requests

from .common import OUTPUT_DIR, C, banner, kv, section, prompt_nonempty


# ------------------------------------------------------------------
# SQL Injection — detection payloads & error signatures
# Source: OWASP Testing Guide WSTG-INPV-05
# ------------------------------------------------------------------
_SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1; SELECT 1--",
]

# Known DBMS error string fragments (case-insensitive match in body)
_SQLI_ERRORS: list[str] = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ora-\d{4,5}",          # Oracle
    r"pg::syntaxerror",      # PostgreSQL
    r"sqlstate",
    r"sqlite.*error",
    r"microsoft.*odbc.*driver",
    r"jdbc.*exception",
    r"syntax error.*sql",
    r"db2 sql error",
    r"dynamic sql error",
]

_SQLI_RE = re.compile(
    "|".join(_SQLI_ERRORS),
    re.IGNORECASE | re.DOTALL,
)


# ------------------------------------------------------------------
# Reflected XSS — probe marker & detection
# Source: OWASP Testing Guide WSTG-INPV-01
# ------------------------------------------------------------------
# A non-executable marker — just angle-bracket HTML to see if the server
# reflects it without HTML-encoding. Scripts are intentionally avoided.
_XSS_MARKER = "<xss-probe-1a2b>"


# ------------------------------------------------------------------
# Open Redirect — payloads
# Source: OWASP Testing Guide WSTG-CLNT-04
# ------------------------------------------------------------------
_REDIRECT_PAYLOADS = [
    "//example.com",
    "https://example.com",
    "//example.com/%2f..",
    "/\\example.com",
]

_EXTERNAL_RE = re.compile(r"https?://example\.com", re.IGNORECASE)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _inject(url: str, param: str, value: str) -> str:
    """Return a copy of `url` with `param` replaced by `value`."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _get(session: requests.Session, url: str,
         timeout: float = 8.0) -> requests.Response | None:
    """GET `url`, return Response or None on error."""
    try:
        return session.get(url, timeout=timeout, allow_redirects=False)
    except requests.exceptions.RequestException:
        return None


# ------------------------------------------------------------------
# Probe functions
# ------------------------------------------------------------------
def probe_sqli(url: str, param: str,
               session: requests.Session | None = None,
               timeout: float = 8.0) -> dict:
    """
    Test `param` in `url` for SQL injection by looking for DBMS error
    strings in the response body. Detection only — no data is read.

    Returns a result dict with keys: param, vulnerable (bool), evidence.
    """
    session = session or requests.Session()
    evidence: list[str] = []

    for payload in _SQLI_PAYLOADS:
        test_url = _inject(url, param, payload)
        resp = _get(session, test_url, timeout)
        if resp is None:
            continue
        match = _SQLI_RE.search(resp.text)
        if match:
            snippet = resp.text[max(0, match.start() - 40):match.end() + 40].strip()
            evidence.append(f"Payload {payload!r}  →  ...{snippet}...")
            break  # one confirmed hit is enough

    return {
        "type":       "SQL Injection",
        "param":      param,
        "vulnerable": bool(evidence),
        "evidence":   evidence,
        "remediation": "Use parameterised queries / prepared statements."
                       " Never concatenate user input into SQL strings.",
    }


def probe_xss(url: str, param: str,
              session: requests.Session | None = None,
              timeout: float = 8.0) -> dict:
    """
    Test `param` in `url` for reflected XSS by checking whether a
    harmless marker string appears unescaped in the response body.

    Returns a result dict with keys: param, vulnerable (bool), evidence.
    """
    session = session or requests.Session()
    test_url = _inject(url, param, _XSS_MARKER)
    resp = _get(session, test_url, timeout)

    vulnerable = False
    evidence: list[str] = []

    if resp is not None and _XSS_MARKER in resp.text:
        vulnerable = True
        idx = resp.text.index(_XSS_MARKER)
        snippet = resp.text[max(0, idx - 30):idx + len(_XSS_MARKER) + 30]
        evidence.append(f"Marker reflected unescaped: ...{snippet}...")

    return {
        "type":       "Reflected XSS",
        "param":      param,
        "vulnerable": vulnerable,
        "evidence":   evidence,
        "remediation": "HTML-encode all user-supplied output. Adopt a strict"
                       " Content-Security-Policy header.",
    }


def probe_redirect(url: str, param: str,
                   session: requests.Session | None = None,
                   timeout: float = 8.0) -> dict:
    """
    Test `param` in `url` for open redirect by checking whether the
    server issues a 3xx redirect to an external domain.

    Returns a result dict with keys: param, vulnerable (bool), evidence.
    """
    session = session or requests.Session()
    evidence: list[str] = []

    for payload in _REDIRECT_PAYLOADS:
        test_url = _inject(url, param, payload)
        resp = _get(session, test_url, timeout)
        if resp is None:
            continue
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if _EXTERNAL_RE.search(location):
                evidence.append(
                    f"Payload {payload!r}  →  Location: {location}"
                )
                break

    return {
        "type":       "Open Redirect",
        "param":      param,
        "vulnerable": bool(evidence),
        "evidence":   evidence,
        "remediation": "Validate redirect targets against an allowlist of"
                       " trusted internal paths. Never accept user-controlled URLs.",
    }


# ------------------------------------------------------------------
# Orchestration
# ------------------------------------------------------------------
def run_all_probes(url: str, params: list[str]) -> list[dict]:
    """
    Run all three probe types against every parameter in `params`.
    Returns a flat list of result dicts.
    """
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (security-audit/lab)"
    results: list[dict] = []

    for param in params:
        print(f"\n  {C.BOLD}Parameter: {param!r}{C.RESET}")
        for probe_fn in (probe_sqli, probe_xss, probe_redirect):
            r = probe_fn(url, param, session)
            label = r["type"]
            if r["vulnerable"]:
                print(f"    {C.ERROR}[VULN] {label}{C.RESET}")
                for ev in r["evidence"]:
                    print(f"      {C.YELLOW}{ev}{C.RESET}")
            else:
                print(f"    {C.GREEN}[OK]   {label}{C.RESET}")
            results.append(r)

    return results


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
def write_results(url: str, results: list[dict]) -> Path:
    """Persist probe results to OUTPUT_DIR."""
    safe = urlparse(url).netloc.replace(".", "_").replace(":", "_") or "site"
    out = OUTPUT_DIR / f"vuln_probe_{safe}.json"
    payload = {"url": url, "results": results}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Web Vulnerability Probe")

    print(
        f"  {C.WARN}Authorization required.{C.RESET}\n"
        "  Injects OWASP test payloads into URL parameters and checks\n"
        "  responses for SQL injection, reflected XSS, and open redirect.\n"
        "  Detection only — no data is modified or extracted.\n"
        "  Only test applications you own or have permission to audit.\n"
    )
    confirm = input("  Confirm you have authorization? (y/N): ").strip().lower()
    if confirm != "y":
        print(f"\n{C.WARN}Aborted. Returning to menu.{C.RESET}")
        return

    # Target URL
    raw_url = prompt_nonempty(
        "Enter target URL with parameters\n"
        "  (e.g. http://lab.local/search?q=test&page=1): "
    )
    if not raw_url:
        print(f"{C.WARN}Cancelled.{C.RESET}")
        return

    url = raw_url if raw_url.startswith(("http://", "https://")) else "http://" + raw_url

    # Parse parameters from the URL
    parsed = urlparse(url)
    discovered_params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    if not discovered_params:
        print(f"{C.WARN}No query parameters detected in the URL.{C.RESET}")
        print("  Make sure to include parameters, e.g. ?id=1&name=test")
        manual = prompt_nonempty("Enter parameter name(s) to test (comma-separated): ")
        if not manual:
            return
        discovered_params = [p.strip() for p in manual.split(",") if p.strip()]
    else:
        print(f"\n  Detected parameters: {C.CYAN}{', '.join(discovered_params)}{C.RESET}")
        custom = input("  Test all? (Y/n): ").strip().lower()
        if custom == "n":
            manual = prompt_nonempty("Enter parameter name(s) to test (comma-separated): ")
            if not manual:
                return
            discovered_params = [p.strip() for p in manual.split(",") if p.strip()]

    section(f"Probing {url}")
    results = run_all_probes(url, discovered_params)

    # Summary
    section("Summary")
    vulns = [r for r in results if r["vulnerable"]]
    clean = [r for r in results if not r["vulnerable"]]
    print(f"  Parameters tested : {len(discovered_params)}")
    print(f"  Probes run        : {len(results)}")
    print(f"  {C.ERROR}Potential findings: {len(vulns)}{C.RESET}")
    print(f"  {C.GREEN}Clean checks      : {len(clean)}{C.RESET}")

    if vulns:
        print(f"\n  {C.WARN}Findings (verify manually before reporting):{C.RESET}")
        for r in vulns:
            print(f"    {C.KEY}{r['type']}{C.RESET} in param {r['param']!r}")
            print(f"    Remediation: {r['remediation']}")

    save = input("\nSave full report to JSON? (y/N): ").strip().lower()
    if save == "y":
        out = write_results(url, results)
        kv("Report saved to", out)
