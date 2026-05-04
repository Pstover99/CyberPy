"""
Name: Parker Stover
Class: ITP 270
Date: 04 MAY 2026
Project Name: tools/hash_tool.py
-----------------------
File integrity hasher and password-breach checker.

Two related capabilities live in one tool because they share the same
underlying primitive (cryptographic hashing):

  1. Hash a file with MD5/SHA1/SHA256/SHA512 - the standard way to
     verify a download, fingerprint a piece of malware, or compare two
     files for byte-exact equality.

  2. Check a password against Have I Been Pwned using the k-anonymity
     range API. We SHA-1 the password locally, send only the first 5
     hex chars of the digest, and search the response for the remaining
     35 - so the full hash (let alone the password) never leaves the
     machine.

Public functions:
    hash_file(path, algos=None)        -> dict[str, str]
    verify_file(path, expected, algo)  -> bool
    check_password_pwned(password)     -> int  (count, 0 = not found)
    run()                              -> menu entry point
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import requests

from .common import (
    OUTPUT_DIR, C, banner, kv, section,
    prompt_nonempty,
)


# Algorithms offered to the user. SHA256 is the modern default; MD5 and
# SHA1 are kept because vendors and older advisories still publish them.
SUPPORTED_ALGOS = ("md5", "sha1", "sha256", "sha512")

# HIBP "Pwned Passwords" range endpoint. The service responds with one
# line per matching SHA-1 suffix in the form:  SUFFIX:COUNT
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


# ------------------------------------------------------------------
# File hashing
# ------------------------------------------------------------------
def hash_file(path: str | Path,
              algos: tuple[str, ...] | None = None,
              chunk_size: int = 1 << 16) -> dict[str, str]:
    """
    Compute one or more hex digests for `path`.

    Reads the file in 64 KiB chunks so even multi-gigabyte files do not
    blow up memory. Returns {algo_name: hex_digest}.
    """
    algos = algos or SUPPORTED_ALGOS
    hashers = {name: hashlib.new(name) for name in algos}

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            for h in hashers.values():
                h.update(chunk)

    return {name: h.hexdigest() for name, h in hashers.items()}


def verify_file(path: str | Path, expected: str, algo: str = "sha256") -> bool:
    """Return True if the `algo` digest of `path` matches `expected` (case-insensitive)."""
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"Unsupported algorithm: {algo!r}")
    actual = hash_file(path, algos=(algo,))[algo]
    return actual.lower() == expected.strip().lower()


# ------------------------------------------------------------------
# Have I Been Pwned - k-anonymity password check
# ------------------------------------------------------------------
def check_password_pwned(password: str, timeout: float = 10.0) -> int:
    """
    Check `password` against the HIBP Pwned Passwords database.

    The full SHA-1 digest is computed locally; only the first 5 hex
    characters are ever sent to the API. The response is searched for
    the remaining 35 characters - if found, the integer that follows is
    the number of times that hash has appeared in known breaches.

    Returns 0 when the password has not been seen, or -1 on network
    error so callers can distinguish "safe" from "unknown".
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers={"Add-Padding": "true"},  # pad response to defeat traffic analysis
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException:
        return -1

    # Each line: "SUFFIX:COUNT". A count of 0 is the padding noise HIBP
    # adds when "Add-Padding" is set - skip those rows.
    for line in resp.text.splitlines():
        if ":" not in line:
            continue
        line_suffix, _, count = line.partition(":")
        if line_suffix.strip().upper() == suffix:
            try:
                n = int(count.strip())
                return n if n > 0 else 0
            except ValueError:
                return 0
    return 0


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
def _write_hash_report(path: Path, digests: dict[str, str]) -> Path:
    """Persist the hash output so the user can paste it into a verification ticket."""
    out = OUTPUT_DIR / "file_hashes.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write("File Hash Report\n")
        f.write("================\n\n")
        f.write(f"File : {path}\n")
        f.write(f"Size : {path.stat().st_size:,} bytes\n\n")
        for algo, digest in digests.items():
            f.write(f"{algo.upper():<8}: {digest}\n")
    return out


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def _hash_flow() -> None:
    """Sub-menu: hash a single file, optionally verify against an expected digest."""
    raw = prompt_nonempty("Path to file: ")
    if raw is None:
        return
    path = Path(raw.strip().strip('"').strip("'")).expanduser()
    if not path.is_file():
        print(f"{C.ERROR}Not a file: {path}{C.RESET}")
        return

    section(f"Hashing {path.name}")
    print(f"Reading {path.stat().st_size:,} bytes ...")
    digests = hash_file(path)
    for algo, digest in digests.items():
        kv(algo.upper(), digest)

    out = _write_hash_report(path, digests)
    kv("Report written to", out)

    verify = input(
        f"\n{C.KEY}Verify against an expected digest?{C.RESET} (y/N): "
    ).strip().lower()
    if verify != "y":
        return

    expected = prompt_nonempty("  Expected digest: ")
    if expected is None:
        return
    # Pick the algorithm whose digest length matches the user's input
    # so they don't have to remember whether they have an MD5 or SHA256.
    algo_by_len = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    algo = algo_by_len.get(len(expected.strip()))
    if not algo:
        print(f"{C.ERROR}Could not infer algorithm from digest length "
              f"({len(expected.strip())}). Expected 32/40/64/128 hex chars."
              f"{C.RESET}")
        return

    ok = digests[algo].lower() == expected.strip().lower()
    if ok:
        print(f"  {C.GREEN}MATCH - {algo.upper()} digest is valid.{C.RESET}")
    else:
        print(f"  {C.ERROR}MISMATCH - file does NOT match the expected "
              f"{algo.upper()} digest.{C.RESET}")


def _password_flow() -> None:
    """Sub-menu: HIBP k-anonymity check for a user-supplied password."""
    # getpass would mask the password, but on some Windows terminals the
    # masked input swallows control characters. Plain input keeps the
    # tool reliable; the value never leaves the local machine in full.
    pw = prompt_nonempty("Password to check (echoed locally; only a "
                         "5-char SHA1 prefix is sent): ")
    if pw is None:
        return

    section("Have I Been Pwned")
    print("Hashing locally and querying HIBP range API ...")
    count = check_password_pwned(pw)

    if count == -1:
        print(f"{C.ERROR}Network error - could not reach HIBP.{C.RESET}")
    elif count == 0:
        print(f"  {C.GREEN}Good news: this password was NOT found in HIBP's "
              f"breach corpus.{C.RESET}")
    else:
        print(f"  {C.ERROR}WARNING: this password has appeared "
              f"{count:,} time(s) in known breaches.{C.RESET}")
        print(f"  {C.WARN}Stop using it everywhere it is set.{C.RESET}")


def run() -> None:
    banner("Hash & Breach Checker")
    print(_opt_line("1", "Hash / verify a file (MD5, SHA1, SHA256, SHA512)"))
    print(_opt_line("2", "Check a password against Have I Been Pwned"))
    print(_opt_line("q", "Cancel - return to main menu"))

    choice = input(f"\n{C.KEY}Choose:{C.RESET} ").strip().lower()
    if choice == "1":
        _hash_flow()
    elif choice == "2":
        _password_flow()
    else:
        print(f"{C.WARN}Cancelled.{C.RESET}")


def _opt_line(num: str, desc: str) -> str:
    return f"  {C.KEY}{num}.{C.RESET} {C.VALUE}{desc}{C.RESET}"
