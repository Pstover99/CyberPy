"""
Name:  Parker Stover

tools/entropy_analyzer.py
-------------------------
File Entropy & Packing Analyzer.
Calculates the Shannon Entropy of a target file (range 0.0 to 8.0).
High entropy indicators imply compression, encryption, or packed code
common in malware payloads and obfuscated scripts.

Uses only Python's standard-library `math` and `collections` modules.
"""

from __future__ import annotations

import collections
import math
from pathlib import Path

from .common import C, banner, kv, section, prompt_nonempty


def calculate_entropy(filepath: Path) -> tuple[float, int] | None:
    """Read file and calculate its Shannon Entropy and file size."""
    if not filepath.exists() or not filepath.is_file():
        print(f"{C.ERROR}[!] File does not exist or is not a valid file.{C.RESET}")
        return None

    try:
        size = filepath.stat().st_size
        if size == 0:
            return 0.0, 0

        counter = collections.Counter()
        # Read in blocks to handle large files efficiently without exhausting memory
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                counter.update(chunk)

        entropy = 0.0
        for count in counter.values():
            p_x = count / size
            entropy += - p_x * math.log2(p_x)

        return entropy, size
    except Exception as e:
        print(f"{C.ERROR}[!] Failed to read file: {e}{C.RESET}")
        return None


def get_assessment(entropy: float) -> str:
    """Return a descriptive assessment based on the entropy score."""
    if entropy < 4.0:
        return f"{C.GREEN}LOW ENTROPY ({entropy:.2f}){C.RESET} - Standard plaintext, source code, or highly structured data."
    elif entropy < 6.8:
        return f"{C.CYAN}MEDIUM ENTROPY ({entropy:.2f}){C.RESET} - Standard compiled binaries, mixed text/binary structures."
    else:
        return (
            f"{C.ERROR}HIGH ENTROPY ({entropy:.2f}){C.RESET} - Highly random content. "
            f"Likely compressed, encrypted, or packed/obfuscated code."
        )


def run() -> None:
    banner("File Entropy & Packing Analyzer")
    print("Measures the randomness (entropy) of a file to check for packing/encryption.")
    print("Values close to 8.0 indicate encrypted/packed binaries or compressed archives.\n")

    raw_path = prompt_nonempty("Enter path to file: ")
    if not raw_path:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    # Strip surrounding quotes if dragged & dropped in terminal
    clean_path = raw_path.strip().strip("'").strip('"')
    path = Path(clean_path)

    result = calculate_entropy(path)
    if result is None:
        return

    entropy, size = result

    section("Analysis Results")
    kv("Target File", path.name)
    kv("Absolute Path", path.resolve())
    kv("File Size", f"{size:,} bytes ({size / 1024:.2f} KB)")
    kv("Shannon Entropy", f"{entropy:.4f} bits per byte")

    section("Obfuscation / Packing Assessment")
    print(f"  {get_assessment(entropy)}\n")
