"""
Name:  Parker Stover
Class: ITP 270
Date:  04 MAY 2026

tools/cipher_tool.py
--------------------
Classical cipher encode / decode / crack tool.

Supported ciphers
-----------------
  Caesar    — fixed shift cipher (A-Z only; preserves case, skips non-alpha).
              Encode, decode (with known shift), or brute-force all 25 shifts
              and rank them by English letter-frequency score so the most
              likely plaintext bubbles to the top.

  Vigenère  — polyalphabetic substitution with a text key.
              Encode or decode with a known key.

Uses only Python's standard library — no third-party packages required.

Public functions:
    caesar_encrypt(text, shift)             -> str
    caesar_decrypt(text, shift)             -> str
    caesar_brute(ciphertext)               -> list[dict]  (all 25 shifts, scored)
    vigenere_encrypt(text, key)             -> str
    vigenere_decrypt(text, key)             -> str
    run()                                   -> menu entry point
"""

from __future__ import annotations

from .common import C, banner, kv, section, prompt_nonempty


# ------------------------------------------------------------------
# English letter-frequency table (relative frequencies, a=0 … z=25)
# Source: classic ETAOIN SHRDLU ordering
# ------------------------------------------------------------------
_EN_FREQ: dict[int, float] = {
    0:  8.167,   # a
    1:  1.492,   # b
    2:  2.782,   # c
    3:  4.253,   # d
    4: 12.702,   # e
    5:  2.228,   # f
    6:  2.015,   # g
    7:  6.094,   # h
    8:  6.966,   # i
    9:  0.153,   # j
    10: 0.772,   # k
    11: 4.025,   # l
    12: 2.406,   # m
    13: 6.749,   # n
    14: 7.507,   # o
    15: 1.929,   # p
    16: 0.095,   # q
    17: 5.987,   # r
    18: 6.327,   # s
    19: 9.056,   # t
    20: 2.758,   # u
    21: 0.978,   # v
    22: 2.360,   # w
    23: 0.150,   # x
    24: 1.974,   # y
    25: 0.074,   # z
}


def _score_english(text: str) -> float:
    """
    Score `text` by how closely its letter distribution matches English.
    Higher score = more likely to be English plaintext.
    """
    text_lower = text.lower()
    total = sum(1 for c in text_lower if c.isalpha()) or 1
    score = 0.0
    for c in text_lower:
        if c.isalpha():
            score += _EN_FREQ.get(ord(c) - ord("a"), 0.0)
    return score / total


# ------------------------------------------------------------------
# Caesar cipher
# ------------------------------------------------------------------
def caesar_encrypt(text: str, shift: int) -> str:
    """
    Shift every alphabetic character in `text` forward by `shift` positions.
    Case is preserved; non-alphabetic characters are passed through unchanged.
    """
    shift = shift % 26
    result: list[str] = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    """Reverse a Caesar cipher: shift every alpha character back by `shift`."""
    return caesar_encrypt(text, -shift)


def caesar_brute(ciphertext: str) -> list[dict]:
    """
    Try all 25 non-trivial Caesar shifts and return a list of dicts, each
    containing {'shift', 'plaintext', 'score'}, sorted descending by score
    (most likely English plaintext first).
    """
    candidates = []
    for shift in range(1, 26):
        pt = caesar_decrypt(ciphertext, shift)
        candidates.append({
            "shift":     shift,
            "plaintext": pt,
            "score":     _score_english(pt),
        })
    candidates.sort(key=lambda d: d["score"], reverse=True)
    return candidates


# ------------------------------------------------------------------
# Vigenère cipher
# ------------------------------------------------------------------
def _clean_key(key: str) -> str:
    """Strip non-alpha characters from the key and upper-case it."""
    return "".join(c.upper() for c in key if c.isalpha())


def vigenere_encrypt(text: str, key: str) -> str:
    """
    Vigenère encrypt `text` with `key` (case-insensitive, alpha only in key).
    Non-alpha characters in the plaintext are passed through unchanged and
    do NOT advance the key position.
    """
    key = _clean_key(key)
    if not key:
        return text
    result: list[str] = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[ki % len(key)]) - ord("A")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_decrypt(text: str, key: str) -> str:
    """
    Vigenère decrypt `text` with `key`.
    Non-alpha characters are passed through, key position not advanced.
    """
    key = _clean_key(key)
    if not key:
        return text
    result: list[str] = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[ki % len(key)]) - ord("A")
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


# ------------------------------------------------------------------
# Menu helpers
# ------------------------------------------------------------------
def _get_shift(prompt_str: str = "Shift (1-25): ") -> int | None:
    """Loop-prompt for a Caesar shift value. None on cancel."""
    while True:
        raw = input(prompt_str).strip()
        if not raw or raw.lower() in ("q", "quit", "cancel", "back"):
            return None
        try:
            shift = int(raw)
            if 1 <= shift <= 25:
                return shift
            print(f"{C.WARN}  Shift must be 1-25.{C.RESET}")
        except ValueError:
            print(f"{C.ERROR}  Enter a whole number between 1 and 25.{C.RESET}")


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Classical Cipher Tool")

    print(
        f"  {C.KEY}1{C.RESET} Caesar — encrypt\n"
        f"  {C.KEY}2{C.RESET} Caesar — decrypt (known shift)\n"
        f"  {C.KEY}3{C.RESET} Caesar — brute-force crack (all 25 shifts)\n"
        f"  {C.KEY}4{C.RESET} Vigenère — encrypt\n"
        f"  {C.KEY}5{C.RESET} Vigenère — decrypt\n"
    )
    choice = input(f"{C.KEY}Choose [1-5]: {C.RESET}").strip()
    if choice not in ("1", "2", "3", "4", "5"):
        print(f"{C.WARN}Invalid choice. Returning to menu.{C.RESET}")
        return

    # ---- Caesar encrypt / decrypt --------------------------------
    if choice in ("1", "2"):
        label = "plaintext" if choice == "1" else "ciphertext"
        text = prompt_nonempty(f"Enter {label}: ")
        if not text:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return

        shift = _get_shift()
        if shift is None:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return

        if choice == "1":
            output = caesar_encrypt(text, shift)
            section("Caesar Encrypted")
        else:
            output = caesar_decrypt(text, shift)
            section("Caesar Decrypted")

        kv("Shift",  shift)
        kv("Input",  text)
        kv("Output", output)

    # ---- Caesar brute-force -------------------------------------
    elif choice == "3":
        ciphertext = prompt_nonempty("Enter ciphertext to crack: ")
        if not ciphertext:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return

        candidates = caesar_brute(ciphertext)

        section("Caesar Brute-Force Results (top 5 by English score)")
        for i, c in enumerate(candidates[:5], 1):
            print(
                f"\n  {C.KEY}#{i}{C.RESET}  Shift {c['shift']:>2}  "
                f"(score: {c['score']:.2f})"
            )
            print(f"  {C.VALUE}{c['plaintext']}{C.RESET}")

        show_all = input("\nShow all 25 shifts? (y/N): ").strip().lower()
        if show_all == "y":
            section("All 25 Shifts")
            for c in candidates:
                print(
                    f"  Shift {c['shift']:>2}  score {c['score']:5.2f}  "
                    f"{C.VALUE}{c['plaintext']}{C.RESET}"
                )

    # ---- Vigenère encrypt / decrypt -----------------------------
    elif choice in ("4", "5"):
        label = "plaintext" if choice == "4" else "ciphertext"
        text = prompt_nonempty(f"Enter {label}: ")
        if not text:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return

        key = prompt_nonempty("Enter key (letters only): ")
        if not key:
            print(f"{C.WARN}Cancelled.{C.RESET}")
            return

        cleaned_key = _clean_key(key)
        if not cleaned_key:
            print(f"{C.ERROR}Key must contain at least one letter.{C.RESET}")
            return

        if choice == "4":
            output = vigenere_encrypt(text, cleaned_key)
            section("Vigenère Encrypted")
        else:
            output = vigenere_decrypt(text, cleaned_key)
            section("Vigenère Decrypted")

        kv("Key",    cleaned_key)
        kv("Input",  text)
        kv("Output", output)
