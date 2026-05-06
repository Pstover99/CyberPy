"""
Name:  Parker Stover

tools/hash_cracker.py
---------------------
Dictionary-based hash cracker. Given a hex-encoded hash, the tool
automatically detects the most likely algorithm by digest length, then
walks through candidate passwords one by one until it finds a match
or exhausts the wordlist.

Two wordlist sources:
  1. A built-in list of the ~200 most commonly seen passwords (always
     available, no files needed).
  2. An optional user-supplied plaintext wordlist (one word per line),
     such as rockyou.txt or any custom list.

Supported algorithms:  MD5 (32 hex chars)
                       SHA-1 (40 hex chars)
                       SHA-256 (64 hex chars)
                       SHA-512 (128 hex chars)

Uses only Python's standard-library `hashlib` — no extra dependencies.

Public functions:
    detect_algorithm(hash_str)              -> str | None
    crack(hash_str, wordlist, algorithm)    -> str | None
    run()                                   -> menu entry point
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from .common import C, banner, kv, section, prompt_nonempty


# ------------------------------------------------------------------
# Algorithm detection by digest length
# ------------------------------------------------------------------
_LENGTH_TO_ALGO: dict[int, str] = {
    32:  "md5",
    40:  "sha1",
    64:  "sha256",
    128: "sha512",
}


def detect_algorithm(hash_str: str) -> str | None:
    """
    Guess the hash algorithm from the length of `hash_str`.
    Returns a hashlib name ('md5', 'sha1', etc.) or None if unknown.
    """
    return _LENGTH_TO_ALGO.get(len(hash_str.strip()))


# ------------------------------------------------------------------
# Built-in wordlist (top ~200 most common passwords)
# ------------------------------------------------------------------
BUILTIN_WORDLIST: list[str] = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball", "iloveyou",
    "trustno1", "1234567890", "sunshine", "master", "123321", "letmein",
    "welcome", "shadow", "ashley", "football", "jesus", "michael",
    "ninja", "mustang", "password1", "123qwe", "passw0rd", "admin",
    "test", "guest", "root", "toor", "pass", "abc123", "qwerty123",
    "1q2w3e4r", "monkey", "superman", "batman", "aa123456", "1q2w3e",
    "samsung", "killer", "hunter", "george", "qazwsx", "charlie",
    "donald", "harley", "ranger", "daniel", "master1", "jordan",
    "harley1", "ranger1", "whatever", "thomas", "andrew", "summer",
    "pokemon", "tigger", "jessica", "taylor", "cookie", "hello",
    "joshua", "hockey", "soccer", "anthony", "maverick", "gabriel",
    "pepper", "cheese", "qwertyuiop", "password2", "pass1234",
    "0987654321", "987654321", "555555", "3rJs1la7qE", "159753",
    "666666", "777777", "888888", "121212", "222222", "000000",
    "11111111", "1111111", "99999999", "88888888", "77777777",
    "66666666", "55555555", "44444444", "33333333", "22222222",
    "00000000", "asdfghjkl", "zxcvbnm", "abcdefgh", "abcdef",
    "princess", "sunshine1", "iloveyou1", "abc1234", "1234abcd",
    "love", "secret", "computer", "super", "matrix", "freedom",
    "baseball1", "football1", "soccer1", "basketball", "hockey1",
    "guitar", "red123", "blue123", "green1", "yellow1", "black1",
    "white1", "password123", "p@ssword", "p@ss1234", "P@$$word",
    "changeme", "pass@123", "1Password", "Password1", "Password123",
    "Admin123", "admin123", "Admin@123", "root123", "toor123",
    "qwerty1", "qwerty12", "q1w2e3r4", "q1w2e3r4t5", "zaq12wsx",
    "1qaz2wsx", "2wsxcde3", "zxcvbn", "asdfgh", "poiuyt",
    "love123", "secret123", "hello123", "world123", "test123",
    "user", "login", "access", "network", "internet", "server",
    "system", "windows", "linux", "macos", "router", "switch",
    "firewall", "proxy", "database", "oracle", "mysql", "postgres",
    "mongo", "redis", "elastic", "hadoop", "spark", "docker",
    "kubernetes", "ansible", "terraform", "jenkins", "github",
    "bitbucket", "jira", "confluence", "slack", "zoom", "teams",
    "office365", "google", "facebook", "twitter", "instagram",
    "netflix", "amazon", "apple", "microsoft", "ibm", "cisco",
    "vmware", "oracle1", "sap123", "abcd1234", "1234qwer",
    "monkey1", "dragon1", "ninja1", "superman1", "batman1",
    "", "a", "1", "12", "123", "1234", "12345",
]


# ------------------------------------------------------------------
# Core cracker
# ------------------------------------------------------------------
def crack(
    hash_str: str,
    wordlist: list[str],
    algorithm: str,
) -> str | None:
    """
    Try every password in `wordlist` against `hash_str` using `algorithm`.

    Returns the plaintext password on success, or None if not found.
    Progress is printed every 500 attempts.
    """
    hash_str = hash_str.strip().lower()
    total = len(wordlist)
    start = time.perf_counter()

    for i, word in enumerate(wordlist, 1):
        h = hashlib.new(algorithm)
        h.update(word.encode("utf-8", errors="replace"))
        if h.hexdigest() == hash_str:
            elapsed = time.perf_counter() - start
            print(f"\n  {C.GREEN}[+] CRACKED after {i:,} attempt(s) "
                  f"in {elapsed:.2f}s!{C.RESET}")
            return word

        if i % 500 == 0 or i == total:
            elapsed = time.perf_counter() - start
            rate = i / elapsed if elapsed > 0 else 0
            print(f"  Tried {i:>6,}/{total:,} passwords "
                  f"({rate:,.0f}/s) ...", end="\r")

    elapsed = time.perf_counter() - start
    print(f"\n  {C.WARN}[-] Hash not cracked after {total:,} "
          f"attempt(s) in {elapsed:.2f}s.{C.RESET}")
    return None


def _load_wordlist_file(path: Path) -> list[str] | None:
    """Read a plaintext wordlist file (one word per line). None on error."""
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        words = [ln.rstrip("\r\n") for ln in lines]
        print(f"  Loaded {len(words):,} words from {path.name}")
        return words
    except OSError as e:
        print(f"{C.ERROR}[!] Could not read wordlist: {e}{C.RESET}")
        return None


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Hash Cracker")
    print(
        "Performs a dictionary attack to find the plaintext behind a hash.\n"
        f"  Supported: {C.CYAN}MD5{C.RESET} (32), "
        f"{C.CYAN}SHA-1{C.RESET} (40), "
        f"{C.CYAN}SHA-256{C.RESET} (64), "
        f"{C.CYAN}SHA-512{C.RESET} (128)  hex chars.\n"
    )

    # --- Get the hash ---
    hash_str = prompt_nonempty("Paste the hash to crack: ")
    if not hash_str:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    hash_str = hash_str.strip().lower()

    # Validate hex
    try:
        int(hash_str, 16)
    except ValueError:
        print(f"{C.ERROR}[!] That doesn't look like a hex hash.{C.RESET}")
        return

    # Auto-detect algorithm
    algo = detect_algorithm(hash_str)
    if algo is None:
        print(f"{C.WARN}[!] Unrecognised hash length ({len(hash_str)} chars). "
              f"Expected 32, 40, 64, or 128.{C.RESET}")
        return

    kv("Detected algorithm", algo.upper())

    # --- Choose wordlist ---
    section("Wordlist")
    print(
        f"  {C.KEY}1{C.RESET} Use built-in wordlist "
        f"({len(BUILTIN_WORDLIST):,} common passwords)\n"
        f"  {C.KEY}2{C.RESET} Load a custom wordlist file "
        f"(e.g. rockyou.txt)\n"
        f"  {C.KEY}3{C.RESET} Both (built-in first, then file)\n"
    )
    wl_choice = input(f"{C.KEY}Choose [1-3, default 1]: {C.RESET}").strip() or "1"
    if wl_choice not in ("1", "2", "3"):
        print(f"{C.WARN}Invalid choice.{C.RESET}")
        return

    wordlist: list[str] = []

    if wl_choice in ("1", "3"):
        wordlist.extend(BUILTIN_WORDLIST)

    if wl_choice in ("2", "3"):
        raw_path = input("  Wordlist file path: ").strip().strip('"').strip("'")
        if not raw_path:
            if wl_choice == "2":
                print(f"{C.WARN}No path given. Cancelled.{C.RESET}")
                return
        else:
            words = _load_wordlist_file(Path(raw_path))
            if words is None and wl_choice == "2":
                return
            if words:
                wordlist.extend(words)

    if not wordlist:
        print(f"{C.WARN}Wordlist is empty. Cancelled.{C.RESET}")
        return

    # --- Crack ---
    section("Cracking")
    print(f"  Hash     : {C.BOLD}{hash_str}{C.RESET}")
    print(f"  Algorithm: {algo.upper()}")
    print(f"  Words    : {len(wordlist):,}\n")

    result = crack(hash_str, wordlist, algo)

    section("Result")
    if result is not None:
        kv("Plaintext", result)
    else:
        print(f"  {C.WARN}Not found in the provided wordlist.{C.RESET}")
        print(f"  {C.WARN}Try a larger wordlist such as rockyou.txt.{C.RESET}")
