"""
Name: Parker Stover
Class: ITP 270
Date: 15 APR 2026
Project Name: tools/exif_extractor.py
-----------------------
Walk the project's `images/` folder, pull EXIF metadata out of each
picture, and print the results - including a decoded GPS coordinate
when the photo has one.

Public functions:
    get_exif_metadata(image_path)        -> dict
    decode_gps_info(exif)                -> None (mutates `exif`)
    scan_directory(images_dir)           -> dict (summary stats)
    run()                                -> menu entry point
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

from .common import IMAGES_DIR, C, banner, section


SUPPORTED_EXTS = {".jpg", ".jpeg", ".tiff", ".tif", ".png", ".heic", ".webp"}


# ------------------------------------------------------------------
# EXIF helpers
# ------------------------------------------------------------------
def get_exif_metadata(image_path: str | Path) -> dict:
    """Open `image_path` and return a dict of decoded EXIF tags."""
    exif_data: dict = {}
    with Image.open(image_path) as image:
        if hasattr(image, "_getexif"):
            raw = image._getexif()
            if raw:
                for tag, value in raw.items():
                    decoded = TAGS.get(tag, tag)
                    exif_data[decoded] = value
    decode_gps_info(exif_data)
    return exif_data


def _to_degrees(value) -> float:
    d, m, s = (float(x) for x in value[:3])
    return d + (m / 60.0) + (s / 3600.0)


def decode_gps_info(exif: dict) -> None:
    """Decode the GPSInfo block in-place into a {Latitude, Longitude} dict."""
    if "GPSInfo" not in exif:
        return

    gps = {GPSTAGS.get(k, k): v for k, v in exif["GPSInfo"].items()}

    lat = gps.get("GPSLatitude")
    lat_ref = gps.get("GPSLatitudeRef")
    lon = gps.get("GPSLongitude")
    lon_ref = gps.get("GPSLongitudeRef")

    if not (lat and lon and lat_ref and lon_ref):
        exif["GPSInfo"] = gps
        return

    lat_val = _to_degrees(lat)
    if lat_ref != "N":
        lat_val = -lat_val
    lon_val = _to_degrees(lon)
    if lon_ref != "E":
        lon_val = -lon_val

    exif["GPSInfo"] = {"Latitude": lat_val, "Longitude": lon_val}


# ------------------------------------------------------------------
# Directory walk
# ------------------------------------------------------------------
def _iter_images(images_dir: Path) -> Iterable[Path]:
    """Yield image paths under `images_dir` whose extension is supported."""
    for path in images_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTS:
            yield path


def _print_exif(exif: dict) -> None:
    for key, value in exif.items():
        if key == "GPSInfo":
            print(f"  {C.BLUE}GPS Metadata:{C.RESET}")
            for gps_key, gps_value in value.items():
                print(f"    {C.KEY}{gps_key}:{C.RESET} {C.VALUE}{gps_value}{C.RESET}")
        else:
            print(f"  {C.KEY}{key}:{C.RESET} {C.VALUE}{value}{C.RESET}")


def scan_directory(images_dir: Path | None = None) -> dict:
    """
    Walk `images_dir` and print EXIF for every supported image.
    Returns a small summary dict the caller can log/inspect.
    """
    images_dir = Path(images_dir) if images_dir else IMAGES_DIR
    if not images_dir.exists():
        print(f"{C.ERROR}No 'images' folder found at: {images_dir}{C.RESET}")
        print(f"Create the folder and drop pictures into it, then re-run.")
        return {"processed": 0, "with_metadata": 0, "no_metadata": []}

    processed = 0
    with_meta = 0
    without: list[str] = []

    for path in _iter_images(images_dir):
        processed += 1
        print(f"\n{C.BOLD}[+] {path.relative_to(images_dir)}{C.RESET}")
        try:
            exif = get_exif_metadata(path)
            if exif:
                with_meta += 1
                _print_exif(exif)
            else:
                without.append(path.name)
                print(f"  {C.WARN}No EXIF metadata found.{C.RESET}")
        except Exception as e:
            print(f"  {C.ERROR}Error: {e}{C.RESET}")

    section("Summary")
    print(f"  Total images processed: {processed}")
    print(f"  Images with metadata  : {with_meta}")
    if without:
        print(f"  {C.WARN}Images without metadata:{C.RESET}")
        for name in without:
            print(f"    - {name}")

    return {"processed": processed, "with_metadata": with_meta, "no_metadata": without}


# ------------------------------------------------------------------
# Menu entry point
# ------------------------------------------------------------------
def run() -> None:
    banner("EXIF Image Data Extractor")
    print(f"Scanning images in: {IMAGES_DIR}")
    scan_directory(IMAGES_DIR)
