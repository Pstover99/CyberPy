"""
Name:  Parker Stover
Class: ITP 270
Date:  04 MAY 2026

tools/encoder_decoder.py
------------------------
Swiss-army encoding / decoding tool. Supports the most common
transformations encountered in CTF challenges, malware analysis,
and web security work.

Supported schemes
-----------------
  Base64       — standard (RFC 4648) encode and decode
  Hex          — encode text to hex bytes; decode hex back to text
  URL Encoding — percent-encode / decode a string (RFC 3986)
  ROT13        — letter-rotation cipher (encode == decode)
  Binary       — text ↔ space-separated 8-bit binary strings

Uses only Python's standard library (`base64`, `urllib.parse`, `codecs`).

Public functions:
    b64_encode(text)     -> str
    b64_decode(data)     -> str
    hex_encode(text)     -> str
    hex_decode(data)     -> str
    url_encode(text)     -> str
    url_decode(data)     -> str
    rot13(text)          -> str
    bin_encode(text)     -> str
    bin_decode(data)     -> str
    run()                -> menu entry point
"""

from __future__ import annotations

import base64
import codecs
import binascii
from urllib.parse import quote, unquote

from .common import C, banner, kv, section, prompt_nonempty


# ------------------------------------------------------------------
# Base64
# ------------------------------------------------------------------
def b64_encode(text: str) -> str:
    """UTF-8 encode `text`, then Base64-encode the bytes. Returns an ASCII str."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def b64_decode(data: str) -> str:
    """
    Base64-decode `data` and return the decoded UTF-8 string.
    Raises ValueError on invalid input.
    """
    # Add padding if missing
    data = data.strip()
    padding = (4 - len(data) % 4) % 4
    try:
        raw = base64.b64decode(data + "=" * padding)
        return raw.decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Base64 decode error: {e}") from e


# ------------------------------------------------------------------
# Hex
# ------------------------------------------------------------------
def hex_encode(text: str) -> str:
    """Encode `text` as space-separated hex byte pairs (e.g. '48 65 6c 6c 6f')."""
    return " ".join(f"{b:02x}" for b in text.encode("utf-8"))


def hex_decode(data: str) -> str:
    """
    Decode a hex string (with or without spaces/0x prefixes) back to text.
    Raises ValueError on invalid hex.
    """
    # Strip spaces, 0x prefixes, and colons so we handle multiple common formats
    cleaned = data.strip().replace(" ", "").replace("0x", "").replace(":", "")
    try:
        raw = bytes.fromhex(cleaned)
        return raw.decode("utf-8", errors="replace")
    except ValueError as e:
        raise ValueError(f"Hex decode error: {e}") from e


# ------------------------------------------------------------------
# URL encoding
# ------------------------------------------------------------------
def url_encode(text: str) -> str:
    """Percent-encode all characters except unreserved ones (RFC 3986)."""
    return quote(text, safe="")


def url_decode(data: str) -> str:
    """Decode a percent-encoded URL string."""
    return unquote(data)


# ------------------------------------------------------------------
# ROT13
# ------------------------------------------------------------------
def rot13(text: str) -> str:
    """Apply ROT13 to `text` (encode and decode are identical operations)."""
    return codecs.encode(text, "rot_13")


# ------------------------------------------------------------------
# Binary (8-bit per character)
# ------------------------------------------------------------------
def bin_encode(text: str) -> str:
    """
    Encode each character in `text` as an 8-bit binary string.
    Bytes are separated by spaces (e.g. 'Hello' → '01001000 01100101 …').
    """
    return " ".join(f"{b:08b}" for b in text.encode("utf-8"))


def bin_decode(data: str) -> str:
    """
    Decode a space-separated binary string back to text.
    Raises ValueError on malformed input.
    """
    tokens = data.strip().split()
    try:
        raw = bytes(int(t, 2) for t in tokens)
        return raw.decode("utf-8", errors="replace")
    except ValueError as e:
        raise ValueError(f"Binary decode error: {e}") from e


# ------------------------------------------------------------------
# Menu helpers
# ------------------------------------------------------------------
_SCHEMES = {
    "1": ("Base64",       b64_encode,  b64_decode),
    "2": ("Hex",          hex_encode,  hex_decode),
    "3": ("URL Encoding", url_encode,  url_decode),
    "4": ("ROT13",        rot13,       rot13),       # symmetric
    "5": ("Binary",       bin_encode,  bin_decode),
}


def _pick_scheme() -> tuple[str, object, object] | None:
    """Prompt user to pick an encoding scheme. Returns (name, enc_fn, dec_fn) or None."""
    print(
        f"\n  {C.KEY}1{C.RESET} Base64\n"
        f"  {C.KEY}2{C.RESET} Hex\n"
        f"  {C.KEY}3{C.RESET} URL Encoding\n"
        f"  {C.KEY}4{C.RESET} ROT13\n"
        f"  {C.KEY}5{C.RESET} Binary (8-bit)\n"
    )
    choice = input(f"{C.KEY}Choose scheme [1-5]: {C.RESET}").strip()
    entry = _SCHEMES.get(choice)
    if entry is None:
        print(f"{C.WARN}Invalid choice.{C.RESET}")
    return entry  # None if not found


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("Encoder / Decoder")

    print(
        f"  {C.KEY}1{C.RESET} Encode\n"
        f"  {C.KEY}2{C.RESET} Decode\n"
    )
    direction = input(f"{C.KEY}Choose [1-2]: {C.RESET}").strip()
    if direction not in ("1", "2"):
        print(f"{C.WARN}Invalid choice. Returning to menu.{C.RESET}")
        return

    scheme = _pick_scheme()
    if scheme is None:
        return

    name, enc_fn, dec_fn = scheme
    fn = enc_fn if direction == "1" else dec_fn
    op_label = "Encode" if direction == "1" else "Decode"

    text = prompt_nonempty(f"Enter text to {op_label.lower()} ({name}): ")
    if not text:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    section(f"{name} {op_label} Result")
    try:
        output = fn(text)
        kv("Input",  text)
        kv("Output", output)
    except (ValueError, UnicodeDecodeError) as e:
        print(f"{C.ERROR}[!] {op_label} failed: {e}{C.RESET}")
