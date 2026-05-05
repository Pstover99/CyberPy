"""
Name:  Parker Stover
Class: ITP 270
Date:  04 MAY 2026

tools/dir_enumerator.py
-----------------------
Web directory / path enumerator (mini Gobuster / DirBuster).

Key improvement over naive status-code scanners:
  Wildcard / false-positive detection
  ------------------------------------
  Many modern web servers (WordPress, Squarespace, most CMSes) return
  HTTP 200 for *every* URL — including ones that don't exist — because
  the application handles routing and serves a custom "page not found"
  page rather than a real HTTP 404.  Blindly trusting status codes in
  this environment produces almost entirely false positives.

  This tool probes two guaranteed-nonexistent UUID paths before scanning
  to build a "not-found fingerprint" for the specific server.  Every
  subsequent result is compared against that fingerprint:

    • Body hash match     → false positive (same page returned for any URL)
    • Body size within 2% → likely false positive (dynamic 404 page)
    • Redirect same dest  → false positive (all unknown paths go to home)

  Responses that are immune to this filter:
    • 401 Auth Required  — always real (server acknowledged the path)
    • 403 Forbidden      — always real (path exists, access denied)
    • 405 Method N/A     — always real
    • 500 Server Error   — kept (path may exist but app crashes on it)

Confidence levels printed next to each hit:
  [HIGH]  — 401/403/405, or body clearly differs from baseline
  [MED]   — status differs from baseline but content similarity unclear

IMPORTANT: Only use against web servers you own or have explicit
written permission to test.

Public functions:
    get_baseline(session, base_url, timeout)    -> list[dict]
    is_false_positive(result, baselines)        -> bool
    enumerate_paths(base_url, wordlist, ...)    -> list[dict]
    write_results(base_url, hits)               -> Path
    run()                                       -> menu entry point
"""

from __future__ import annotations

import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from .common import OUTPUT_DIR, C, banner, kv, section, prompt_url


# ------------------------------------------------------------------
# Built-in wordlist  (common paths across real sites, CMSes & CTFs)
# ------------------------------------------------------------------
BUILTIN_PATHS: list[str] = [
    # Standard web files (almost always worth checking)
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "security.txt", ".well-known/security.txt",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "favicon.ico", "humans.txt",

    # Admin / management panels
    "admin", "admin/", "administrator", "administration",
    "admin/login", "admin/login.php", "admin/index.php",
    "admin/dashboard", "admin/panel", "admin/console",
    "manage", "management", "panel", "control",
    "cpanel", "webadmin", "siteadmin", "controlpanel",
    "backend", "back-end", "staff", "moderator",

    # Authentication
    "login", "login.php", "login.html", "login.aspx",
    "signin", "sign-in", "sign_in",
    "logout", "sign-out", "sign_out",
    "register", "signup", "sign-up", "sign_up",
    "auth", "authenticate", "authentication",
    "forgot-password", "reset-password", "password-reset",
    "two-factor", "2fa", "mfa",

    # WordPress (extremely common for small orgs and church sites)
    "wp-admin", "wp-admin/", "wp-login.php",
    "wp-content", "wp-content/uploads", "wp-content/plugins",
    "wp-content/themes", "wp-includes",
    "wp-json", "wp-json/wp/v2",
    "xmlrpc.php", "wp-cron.php", "wp-config.php",
    "readme.html", "license.txt",

    # Other CMS platforms
    "joomla", "administrator/index.php",   # Joomla
    "drupal", "user/login", "user/register",  # Drupal
    "typo3", "typo3/index.php",            # TYPO3
    "craft", "craft/admin",                # Craft CMS
    "ghost", "ghost/signin",              # Ghost
    "umbraco", "umbraco/login.aspx",      # Umbraco

    # API endpoints
    "api", "api/", "api/v1", "api/v2", "api/v3",
    "api/v1/", "api/v2/", "v1", "v2",
    "graphql", "graphiql", "playground",
    "rest", "rest/v1", "rest/api",
    "swagger", "swagger-ui", "swagger-ui.html",
    "swagger.json", "openapi.json", "api-docs",
    "redoc", ".well-known/openid-configuration",

    # Config / sensitive files
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git", ".git/HEAD", ".git/config", ".git/index",
    ".svn", ".svn/entries",
    ".htaccess", ".htpasswd", ".htusers",
    "web.config", "web.config.bak",
    "config", "config.php", "config.yml", "config.yaml",
    "config.json", "config.xml", "config.ini",
    "configuration.php", "settings.py", "settings.php",
    "app.config", "appsettings.json",
    "database.yml", "database.php", "db.php",
    "Dockerfile", "docker-compose.yml",
    ".dockerignore", ".gitignore",

    # Backup / archive files
    "backup", "backups", "bak",
    "backup.zip", "backup.tar.gz", "backup.sql",
    "backup.php", "backup.bak", "backup.old",
    "site.zip", "website.zip", "archive.zip",
    "db.sql", "database.sql", "dump.sql",
    "data.sql", "mysql.sql",

    # Debug / development / status
    "debug", "debug.php", "debug.log",
    "test", "test.php", "test.html",
    "testing", "dev", "development",
    "phpinfo.php", "info.php", "phpinfo",
    "server-status", "server-info",
    "status", "health", "healthcheck", "health-check",
    "ping", "metrics", "monitor",
    "actuator", "actuator/health", "actuator/env",  # Spring Boot
    "console", "h2-console",                        # Java/H2 DB

    # Uploads / media
    "upload", "uploads", "uploaded", "files", "file",
    "media", "images", "img", "assets", "static",
    "content", "documents", "docs",
    "download", "downloads", "attachments",
    "audio", "video", "gallery",

    # User-facing
    "dashboard", "home", "portal", "profile",
    "account", "accounts", "user", "users",
    "search", "results", "feed",

    # Common flat pages (informational sites)
    "about", "about-us", "contact", "contact-us",
    "services", "faq", "help", "support", "privacy",
    "terms", "sitemap",

    # Logs
    "logs", "log", "error_log", "access_log",
    "error.log", "access.log", "app.log", "debug.log",
    "application.log",

    # Infrastructure / misc
    "old", "new", "tmp", "temp", "cache",
    "private", "secret", "hidden",
    "include", "includes", "lib", "libs",
    "vendor", "node_modules", "src", "app",
    "public", "dist", "build", "out",
    "cgi-bin", "cgi",
    "phpmyadmin", "pma", "mysqladmin",
    "webmail", "mail", "email", "smtp",
    "ftp", "sftp",
]


# HTTP status codes considered noteworthy before baseline filtering
_INTERESTING = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500}

_CODE_LABELS = {
    200: "FOUND",       204: "NO CONTENT",
    301: "REDIRECT",    302: "REDIRECT",   303: "REDIRECT",
    307: "REDIRECT",    308: "REDIRECT",
    401: "AUTH REQUIRED", 403: "FORBIDDEN",
    405: "METHOD N/A",  500: "SERVER ERROR",
}

_CODE_COLORS = {
    200: C.GREEN,  201: C.GREEN,  204: C.GREEN,
    301: C.BLUE,   302: C.BLUE,   303: C.BLUE,
    307: C.BLUE,   308: C.BLUE,
    401: C.YELLOW, 403: C.YELLOW, 405: C.YELLOW,
    500: C.RED,
}

# These status codes are always genuine — the server explicitly
# acknowledged the path exists, regardless of body content.
_ALWAYS_REAL = {401, 403, 405}


# ------------------------------------------------------------------
# Baseline fingerprinting
# ------------------------------------------------------------------
def get_baseline(
    session: requests.Session,
    base_url: str,
    timeout: float = 8.0,
) -> list[dict]:
    """
    Probe two guaranteed-nonexistent paths and return their response
    fingerprints. Used to identify what "not found" looks like on this
    particular server before the main scan starts.
    """
    baselines: list[dict] = []
    for _ in range(2):
        fake = f"/{uuid.uuid4().hex}_notreal_{uuid.uuid4().hex[:6]}/"
        url = base_url.rstrip("/") + fake
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            baselines.append({
                "status":    resp.status_code,
                "size":      len(resp.content),
                "hash":      hashlib.md5(resp.content).hexdigest(),
                "final_url": resp.url,
            })
        except requests.exceptions.RequestException:
            pass
    return baselines


def is_false_positive(result: dict, baselines: list[dict]) -> bool:
    """
    Return True if `result` matches the server's "not found" fingerprint,
    i.e. it is almost certainly a false positive.

    Checks (in order):
      1. 401/403/405 are always genuine — return False immediately.
      2. Exact body hash match → false positive.
      3. Body size within 2% of baseline → likely false positive.
      4. Redirect destination matches baseline → false positive.
    """
    if not baselines:
        return False

    # Auth-required / forbidden / method-not-allowed are always real.
    if result["status"] in _ALWAYS_REAL:
        return False

    result_hash = result.get("hash", "")
    result_size = result.get("size", 0)
    result_dest = result.get("final_url", "")

    for bl in baselines:
        # Different status from baseline → genuinely different response
        if result["status"] != bl["status"]:
            continue

        # Exact content match → definitely the same "not found" page
        if result_hash and result_hash == bl["hash"]:
            return True

        # Size within 2% of baseline (dynamic tokens change the hash
        # slightly but the page is essentially identical)
        if bl["size"] > 0:
            diff = abs(result_size - bl["size"]) / bl["size"]
            if diff <= 0.02:
                return True

        # Both redirect to the same destination (e.g. all 404s → homepage)
        if result_dest and result_dest == bl.get("final_url", ""):
            return True

    return False


# ------------------------------------------------------------------
# Per-path probe
# ------------------------------------------------------------------
def _probe(
    base_url: str,
    path: str,
    session: requests.Session,
    timeout: float,
) -> dict | None:
    """GET base_url/path and return a fingerprinted result dict, or None."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        if resp.status_code in _INTERESTING:
            return {
                "url":       url,
                "path":      path,
                "status":    resp.status_code,
                "label":     _CODE_LABELS.get(resp.status_code,
                                              str(resp.status_code)),
                "size":      len(resp.content),
                "hash":      hashlib.md5(resp.content).hexdigest(),
                "final_url": resp.url,
            }
    except requests.exceptions.RequestException:
        pass
    return None


# ------------------------------------------------------------------
# Main scan
# ------------------------------------------------------------------
def enumerate_paths(
    base_url: str,
    wordlist: list[str] | None = None,
    baselines: list[dict] | None = None,
    max_workers: int = 15,
    timeout: float = 8.0,
) -> list[dict]:
    """
    Enumerate paths on `base_url`. Filters results through `baselines`
    (the not-found fingerprint) before returning.

    Returns confirmed hit dicts sorted by status then path, each
    annotated with a 'confidence' key ('HIGH' or 'MED').
    """
    wordlist = wordlist or BUILTIN_PATHS
    baselines = baselines or []
    hits: list[dict] = []
    filtered = 0

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (security-audit/lab)"

    total = len(wordlist)
    done = 0

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_probe, base_url, path, session, timeout): path
            for path in wordlist
        }
        for fut in as_completed(futures):
            done += 1
            print(f"  Scanning: {done}/{total} "
                  f"({filtered} filtered)  ", end="\r")
            try:
                result = fut.result()
                if result is None:
                    continue
                if is_false_positive(result, baselines):
                    filtered += 1
                    continue

                # Assign confidence
                if result["status"] in _ALWAYS_REAL:
                    result["confidence"] = "HIGH"
                elif baselines:
                    # Status differs from baseline → content is genuinely
                    # different from the not-found page
                    result["confidence"] = "HIGH"
                else:
                    result["confidence"] = "MED"

                color = _CODE_COLORS.get(result["status"], C.RESET)
                conf_color = C.GREEN if result["confidence"] == "HIGH" else C.YELLOW
                print(
                    f"  {color}[{result['status']} {result['label']}]{C.RESET}"
                    f"  {conf_color}[{result['confidence']}]{C.RESET}"
                    f"  {result['url']}"
                    f"  ({result['size']:,} bytes)"
                )
                hits.append(result)
            except Exception:
                pass

    print(f"  Done. {filtered} response(s) filtered as false positives.        ")
    hits.sort(key=lambda h: (h["status"], h["path"]))
    return hits


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
def write_results(base_url: str, hits: list[dict]) -> Path:
    """Save confirmed enumeration results to OUTPUT_DIR."""
    safe = urlparse(base_url).netloc.replace(".", "_").replace(":", "_") or "site"
    out = OUTPUT_DIR / f"dir_enum_{safe}.json"
    # Strip hash/final_url from JSON output to keep it readable
    clean = [
        {k: v for k, v in h.items() if k not in ("hash", "final_url")}
        for h in hits
    ]
    payload = {"base_url": base_url, "confirmed_hits": clean, "total": len(clean)}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Web Directory Enumerator")

    print(
        f"  {C.WARN}Authorization required.{C.RESET} Only scan web servers you own\n"
        f"  or have explicit written permission to test.\n"
    )
    confirm = input(
        "  Do you have authorization to scan the target? (y/N): "
    ).strip().lower()
    if confirm != "y":
        print(f"\n{C.WARN}Aborted. Returning to menu.{C.RESET}")
        return

    raw = prompt_url(
        "Target base URL (e.g. http://192.168.1.10 or https://lab.local): "
    )
    if raw is None:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    base_url = raw if raw.startswith(("http://", "https://")) else "https://" + raw

    # Wordlist selection
    print(
        f"\n  {C.KEY}1{C.RESET} Built-in wordlist  ({len(BUILTIN_PATHS)} paths)\n"
        f"  {C.KEY}2{C.RESET} Custom wordlist file\n"
        f"  {C.KEY}3{C.RESET} Both\n"
    )
    wl_choice = input(f"{C.KEY}Wordlist [1-3, default 1]: {C.RESET}").strip() or "1"

    wordlist: list[str] = []
    if wl_choice in ("1", "3"):
        wordlist.extend(BUILTIN_PATHS)
    if wl_choice in ("2", "3"):
        raw_path = input("  Wordlist file path: ").strip().strip('"').strip("'")
        if raw_path:
            try:
                words = (
                    Path(raw_path)
                    .read_text(encoding="utf-8", errors="ignore")
                    .splitlines()
                )
                wordlist.extend(w.strip() for w in words if w.strip())
                print(f"  Loaded {len(words):,} additional paths.")
            except OSError as e:
                print(f"{C.ERROR}[!] Could not read wordlist: {e}{C.RESET}")
                if wl_choice == "2":
                    return

    if not wordlist:
        print(f"{C.WARN}Empty wordlist. Returning to menu.{C.RESET}")
        return

    # --- Baseline fingerprinting ---
    section("Baseline Fingerprinting")
    print(f"  Probing server to detect wildcard / custom-404 responses ...")

    bl_session = requests.Session()
    bl_session.headers["User-Agent"] = "Mozilla/5.0 (security-audit/lab)"
    baselines = get_baseline(bl_session, base_url)

    if baselines:
        bl = baselines[0]
        kv("Not-found status", bl["status"])
        kv("Not-found body size", f"{bl['size']:,} bytes")
        if bl["status"] == 200:
            print(
                f"  {C.WARN}Server returns HTTP 200 for non-existent paths.{C.RESET}\n"
                f"  {C.WARN}Wildcard filtering active — false positives will be suppressed.{C.RESET}"
            )
        else:
            print(f"  {C.GREEN}Server returns proper {bl['status']} for missing paths.{C.RESET}")
    else:
        print(f"  {C.WARN}Could not reach server for baseline — filtering disabled.{C.RESET}")

    # --- Main scan ---
    section(f"Scanning  {base_url}")
    print(f"  Paths to test : {len(wordlist):,}\n")

    hits = enumerate_paths(base_url, wordlist, baselines)

    # --- Summary ---
    section("Summary")
    kv("Target",      base_url)
    kv("Paths tested", f"{len(wordlist):,}")
    high = [h for h in hits if h.get("confidence") == "HIGH"]
    med  = [h for h in hits if h.get("confidence") == "MED"]
    print(
        f"  {C.GREEN}HIGH confidence hits: {len(high)}{C.RESET}\n"
        f"  {C.YELLOW}MED  confidence hits: {len(med)}{C.RESET}"
    )

    if hits:
        save = input("\nSave confirmed results to JSON? (y/N): ").strip().lower()
        if save == "y":
            out = write_results(base_url, hits)
            kv("Report saved to", out)
    else:
        print(f"\n  {C.WARN}No confirmed paths found.{C.RESET}")
