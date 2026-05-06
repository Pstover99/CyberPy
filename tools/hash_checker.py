"""
Name:  Parker Stover

tools/hash_checker.py
---------------------
Compute cryptographic hashes for files or plain-text strings, and
optionally verify a computed hash against a known reference value.

Supported algorithms: MD5, SHA-1, SHA-256, SHA-512.

Uses only Python's standard-library `hashlib` and `pathlib` — no
third-party dependencies are required.

Public functions:
    hash_string(text, algorithm)        -> str
    hash_file(path, algorithm)          -> str | None
    verify_hash(computed, known)        -> bool
    write_results(label, results)       -> Path
    run()                               -> menu entry point
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .common import OUTPUT_DIR, C, banner, kv, section


# ------------------------------------------------------------------
# Supported algorithms (display name → hashlib name)
# ------------------------------------------------------------------
ALGORITHMS: dict[str, str] = {
    "1": "md5",
    "2": "sha1",
    "3": "sha256",
    "4": "sha512",
}

ALGO_LABELS: dict[str, str] = {
    "md5":    "MD5",
    "sha1":   "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
}

# Block size used when reading large files (1 MiB chunks).
_CHUNK = 1 << 20


# ------------------------------------------------------------------
# Core hashing functions
# ------------------------------------------------------------------
def hash_string(text: str, algorithm: str = "sha256") -> str:
    """
    Compute the hash of a UTF-8 text string.

    `algorithm` must be a hashlib-recognised name ('md5', 'sha1',
    'sha256', 'sha512').  Returns the hex-digest string.
    """
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def hash_file(path: str | Path, algorithm: str = "sha256") -> str | None:
    """
    Compute the hash of a file in streaming chunks (handles large files).

    Returns the hex-digest string, or None if the file cannot be read.
    """
    path = Path(path)
    if not path.is_file():
        print(f"{C.ERROR}[!] Not a file or file not found: {path}{C.RESET}")
        return None

    h = hashlib.new(algorithm)
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(_CHUNK):
                h.update(chunk)
    except OSError as e:
        print(f"{C.ERROR}[!] Could not read file: {e}{C.RESET}")
        return None

    return h.hexdigest()


# ------------------------------------------------------------------
# Verification
# ------------------------------------------------------------------
def verify_hash(computed: str, known: str) -> bool:
    """
    Compare `computed` against a `known` reference hash (case-insensitive,
    strip whitespace).  Returns True only on an exact match.

    Uses `hmac.compare_digest` internally to avoid timing side-channels.
    """
    import hmac
    return hmac.compare_digest(computed.strip().lower(), known.strip().lower())


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------
def write_results(label: str, results: dict) -> Path:
    """Persist the hash results to OUTPUT_DIR/hash_<label>.json."""
    safe = label.replace("/", "_").replace("\\", "_").replace(".", "_")[:40]
    out = OUTPUT_DIR / f"hash_{safe}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    return out


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------
def _pick_algorithm() -> str | None:
    """Prompt the user to choose an algorithm. Returns the hashlib name or None."""
    print(
        f"\n  {C.KEY}1{C.RESET} MD5      (fast, legacy — not collision-resistant)\n"
        f"  {C.KEY}2{C.RESET} SHA-1    (legacy — avoid for new designs)\n"
        f"  {C.KEY}3{C.RESET} SHA-256  (recommended)\n"
        f"  {C.KEY}4{C.RESET} SHA-512  (strongest)\n"
    )
    choice = input(f"{C.KEY}Choose algorithm [1-4, default 3]: {C.RESET}").strip()
    if not choice:
        choice = "3"
    algo = ALGORITHMS.get(choice)
    if algo is None:
        print(f"{C.WARN}Invalid choice. Returning to menu.{C.RESET}")
    return algo


def _compute_and_display(
    label: str,
    digest: str | None,
    algo: str,
) -> dict | None:
    """Print the result and optionally verify against a known hash."""
    if digest is None:
        return None

    label_display = ALGO_LABELS.get(algo, algo.upper())
    section(f"{label_display} Hash Result")
    kv("Input",     label)
    kv("Algorithm", label_display)
    kv("Hash",      digest)

    verify = input("\nVerify against a known hash? (y/N): ").strip().lower()
    match: bool | None = None
    if verify == "y":
        known = input("  Paste known hash: ").strip()
        match = verify_hash(digest, known)
        if match:
            print(f"  {C.GREEN}✔  Hashes MATCH — integrity verified.{C.RESET}")
        else:
            print(f"  {C.ERROR}✘  Hashes do NOT match — possible tampering or wrong file!{C.RESET}")

    return {
        "input":     label,
        "algorithm": label_display,
        "hash":      digest,
        "verified":  match,
    }


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Hash Checker / File Integrity")

    print(
        "What would you like to hash?\n"
        f"  {C.KEY}1{C.RESET} A file (integrity check)\n"
        f"  {C.KEY}2{C.RESET} A text string\n"
    )
    mode = input(f"{C.KEY}Choose [1-2]: {C.RESET}").strip()
    if mode not in ("1", "2"):
        print(f"{C.WARN}Invalid choice. Returning to menu.{C.RESET}")
        return

    algo = _pick_algorithm()
    if algo is None:
        return

    results: dict | None = None

    # ---- Hash a file ---------------------------------------------
    if mode == "1":
        raw_path = input("Enter file path: ").strip()
        if not raw_path:
            print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
            return

        path = Path(raw_path.strip('"').strip("'"))
        print(f"\nHashing {C.BOLD}{path}{C.RESET} ...")
        digest = hash_file(path, algo)
        results = _compute_and_display(str(path), digest, algo)

    # ---- Hash a string -------------------------------------------
    elif mode == "2":
        text = input("Enter text to hash: ")
        if not text:
            print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
            return

        digest = hash_string(text, algo)
        results = _compute_and_display(repr(text), digest, algo)

    # ---- Save report? --------------------------------------------
    if results:
        save = input("\nSave results to JSON? (y/N): ").strip().lower()
        if save == "y":
            label = results.get("input", "output")
            out = write_results(label, results)
            kv("Report saved to", out)
