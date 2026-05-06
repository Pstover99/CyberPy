"""
Name: Parker Stover

tools/common.py
---------------
Shared helpers used by every tool in the package: project paths, the
common-port list, ANSI color codes, and a small parser that turns a user
input string into a list of IP addresses (single IP or CIDR range).
"""

from __future__ import annotations

import ipaddress
from pathlib import Path


# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------
# Project root is the parent folder of /tools.
PROJECT_DIR = Path(__file__).resolve().parent.parent

# Where tool output files (.txt, .json, .log) are written.
OUTPUT_DIR = PROJECT_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

# Folder the EXIF tool walks for images.
IMAGES_DIR = PROJECT_DIR / "images"


# ------------------------------------------------------------------
# Common ports - reused by both the port scanner and any vuln-search
# workflow that wants the same set of "interesting" ports.
# ------------------------------------------------------------------
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 465, 587, 993, 995, 1433, 3389,
    8080, 8443, 9100,
]


# ------------------------------------------------------------------
# Minimal ANSI color helper. We avoid pulling in `colorama` so the
# venv stays small; on Windows 10+ the terminal handles ANSI natively.
# ------------------------------------------------------------------
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"

    HEADER  = CYAN + BOLD
    SECTION = MAGENTA + BOLD
    KEY     = YELLOW + BOLD
    VALUE   = GREEN
    WARN    = YELLOW
    ERROR   = RED + BOLD


def banner(title: str) -> None:
    """Print a section banner."""
    print(f"\n{C.HEADER}{'=' * 60}{C.RESET}")
    print(f"{C.HEADER} {title}{C.RESET}")
    print(f"{C.HEADER}{'=' * 60}{C.RESET}")


def section(title: str) -> None:
    """Print a smaller sub-section header."""
    print(f"\n{C.SECTION}--- {title} ---{C.RESET}")


def kv(key: str, value) -> None:
    """Print a colored key/value pair."""
    print(f"  {C.KEY}{key}:{C.RESET} {C.VALUE}{value}{C.RESET}")


# ------------------------------------------------------------------
# Target parser - shared by network and port scanners.
# ------------------------------------------------------------------
def parse_target(target: str) -> tuple[list[str], str]:
    """
    Convert a user-supplied target string into a list of IP strings.

    Accepts either a single IP ("10.0.0.5") or CIDR notation
    ("10.0.0.0/24"). Returns (ip_list, normalized_target).
    Returns ([], original) if the input cannot be parsed.
    """
    target = target.strip()
    if not target:
        return [], target

    # Single IP
    try:
        ipaddress.ip_address(target)
        return [target], target
    except ValueError:
        pass

    # CIDR network
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in net.hosts()], str(net)
    except ValueError:
        return [], target


# ------------------------------------------------------------------
# Validating input prompts - loop until the user supplies a value
# that parses correctly, or types a blank line / 'q' to cancel.
# ------------------------------------------------------------------
# Every prompt helper below is built on a single internal loop:
#   - keep asking with `prompt_msg`
#   - hand the raw string to a `validator` callable
#   - validator returns (ok: bool, value, err_msg)
#   - return value on success, None when the user cancels
# Cancellation is intentionally easy so a misclick on a menu item
# never traps the user inside a tool: blank line OR 'q'/'quit'/'cancel'.
_CANCEL_TOKENS = {"q", "quit", "cancel", "back", "exit"}


def _prompt_loop(prompt_msg, validator, *, allow_blank_cancel: bool = True):
    """Repeatedly call input() until validator says ok. None means cancel."""
    while True:
        raw = input(prompt_msg).strip()
        if not raw:
            if allow_blank_cancel:
                return None
            print(f"{C.WARN}  Input required (or type 'q' to cancel).{C.RESET}")
            continue
        if raw.lower() in _CANCEL_TOKENS:
            return None
        ok, value, err = validator(raw)
        if ok:
            return value
        print(f"{C.ERROR}  {err}{C.RESET}")
        print(f"{C.WARN}  Try again, or press Enter to cancel.{C.RESET}")


# --- validators ---------------------------------------------------

def _v_cidr(raw):
    try:
        net = ipaddress.ip_network(raw, strict=False)
        return True, ([str(h) for h in net.hosts()], str(net)), ""
    except ValueError:
        return False, None, (
            f"Invalid CIDR notation: {raw!r}. "
            f"Example: 192.168.1.0/24"
        )


def _v_ip_or_cidr(raw):
    # Single IP
    try:
        ipaddress.ip_address(raw)
        return True, ([raw], raw), ""
    except ValueError:
        pass
    # CIDR
    try:
        net = ipaddress.ip_network(raw, strict=False)
        return True, ([str(h) for h in net.hosts()], str(net)), ""
    except ValueError:
        return False, None, (
            f"Invalid IP or CIDR: {raw!r}. "
            f"Example: 192.168.1.10  or  192.168.1.0/24"
        )


def _v_ip(raw):
    try:
        ipaddress.ip_address(raw)
        return True, raw, ""
    except ValueError:
        return False, None, f"Invalid IP address: {raw!r}. Example: 192.168.1.10"


def _v_port(raw):
    try:
        port = int(raw)
    except ValueError:
        return False, None, f"Port must be a number, got {raw!r}"
    if not 1 <= port <= 65535:
        return False, None, f"Port must be 1-65535 (got {port})"
    return True, port, ""


def _v_url(raw):
    # Cheap validation - reject obviously broken inputs. The actual HTTP
    # request will surface deeper problems with a proper error.
    if " " in raw or "\t" in raw:
        return False, None, "URL cannot contain whitespace."
    cleaned = raw
    for scheme in ("http://", "https://"):
        if cleaned.lower().startswith(scheme):
            cleaned = cleaned[len(scheme):]
            break
    if "." not in cleaned and "localhost" not in cleaned.lower():
        return False, None, (
            f"That doesn't look like a URL: {raw!r}. "
            f"Example: example.com  or  https://example.com"
        )
    return True, raw, ""


# --- public helpers -----------------------------------------------

def prompt_target(
    prompt_msg: str = "Enter an IP or CIDR (e.g. 192.168.1.10 or 192.168.1.0/24): ",
) -> tuple[list[str], str]:
    """
    Loop-prompt for a single IP or a CIDR network.

    Returns (ip_list, normalized_target). On user cancel, returns ([], "")
    so existing call sites that branch on `if not targets` still work.
    """
    result = _prompt_loop(prompt_msg, _v_ip_or_cidr)
    if result is None:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return [], ""
    return result


def prompt_cidr(
    prompt_msg: str = "Enter network range in CIDR notation (e.g. 192.168.1.0/24): ",
) -> tuple[list[str], str]:
    """Loop-prompt strictly for a CIDR. Returns ([], '') on cancel."""
    result = _prompt_loop(prompt_msg, _v_cidr)
    if result is None:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return [], ""
    return result


def prompt_ip(prompt_msg: str = "Target IP: ") -> str | None:
    """Loop-prompt for a single IP address. None on cancel."""
    return _prompt_loop(prompt_msg, _v_ip)


def prompt_port(prompt_msg: str = "Port", default: int | None = None) -> int | None:
    """
    Loop-prompt for a TCP port (1-65535). None on cancel.
    If `default` is supplied, an empty line returns `default` instead of
    cancelling.
    """
    label = f"{prompt_msg} [{default}]: " if default is not None else f"{prompt_msg}: "
    while True:
        raw = input(label).strip()
        if not raw:
            return default  # may be None (cancel) or the supplied default
        if raw.lower() in _CANCEL_TOKENS:
            return None
        ok, value, err = _v_port(raw)
        if ok:
            return value
        print(f"{C.ERROR}  {err}{C.RESET}")
        print(f"{C.WARN}  Try again, or press Enter to "
              f"{'use the default' if default is not None else 'cancel'}.{C.RESET}")


def prompt_url(
    prompt_msg: str = "Enter a URL to analyze (e.g. example.com): ",
) -> str | None:
    """Loop-prompt for a URL string. None on cancel."""
    return _prompt_loop(prompt_msg, _v_url)


def prompt_nonempty(prompt_msg: str) -> str | None:
    """Loop-prompt for any non-empty value. None on cancel."""
    def _v(raw):
        return True, raw, ""
    return _prompt_loop(prompt_msg, _v, allow_blank_cancel=True)
