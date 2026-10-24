"""Small helpers: read-only file access, digests, name normalisation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from pathlib import Path

from .models import ScanWarning

_PEP503 = re.compile(r"[-_.]+")
_HEX = re.compile(r"^[0-9a-f]+$")
_HEX_LEN = {"md5": 32, "sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}

# Upper bound for files we read fully into memory (metadata, package.json, .pth).
MAX_TEXT_BYTES = 8 * 1024 * 1024


class Warnings:
    """Collects non-fatal problems (NFR-10): a missing or unreadable location never fails a scan."""

    def __init__(self) -> None:
        self.items: list[ScanWarning] = []

    def add(self, location: str | os.PathLike, message: str) -> None:
        self.items.append(ScanWarning(str(location), message))


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem in ("PyPI", "conda"):
        return _PEP503.sub("-", name).lower()
    return name.lower()


def normalize_digest(value: str, default_algo: str = "sha256") -> str | None:
    """Return "algo:hexdigest" for the many digest spellings tools use.

    Accepts "algo:hex", "algo=hex", "algo=<urlsafe-b64>" (wheel RECORD),
    "algo-<b64>" (npm/SRI integrity), and bare hex or bare RECORD base64.
    """
    v = value.strip()
    if not v:
        return None
    algo = default_algo
    m = re.match(r"^(md5|sha1|sha256|sha384|sha512)[:=-](.+)$", v, re.IGNORECASE)
    if m:
        algo, v = m.group(1).lower(), m.group(2)
    low = v.lower()
    if _HEX.match(low) and len(low) == _HEX_LEN.get(algo, -1):
        return f"{algo}:{low}"
    try:
        raw = base64.urlsafe_b64decode(v.replace("+", "-").replace("/", "_") + "=" * (-len(v) % 4))
    except (binascii.Error, ValueError):
        return None
    if len(raw) * 2 != _HEX_LEN.get(algo, -1):
        return None
    return f"{algo}:{raw.hex()}"


def read_text(path: Path, warnings: Warnings | None = None, limit: int = MAX_TEXT_BYTES) -> str | None:
    """Read a file as text without ever writing to or executing it (NFR-1, NFR-3)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        if warnings is not None:
            warnings.add(path, f"unreadable: {exc.strerror or exc}")
        return None
    if len(data) > limit:
        if warnings is not None:
            warnings.add(path, f"skipped: larger than {limit} bytes")
        return None
    return data.decode("utf-8", errors="replace")


def file_digest(path: Path, algo: str = "sha256") -> str | None:
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return f"{algo}:{h.hexdigest()}"


def safe_scandir(path: Path, warnings: Warnings | None = None) -> list[os.DirEntry]:
    try:
        with os.scandir(path) as it:
            return sorted(it, key=lambda e: e.name)
    except FileNotFoundError:
        return []
    except OSError as exc:
        if warnings is not None:
            warnings.add(path, f"cannot list directory: {exc.strerror or exc}")
        return []


def is_dir(entry: os.DirEntry, follow_symlinks: bool = False) -> bool:
    try:
        return entry.is_dir(follow_symlinks=follow_symlinks)
    except OSError:
        return False


def home_dirs() -> list[Path]:
    """Home directories to check for persistence paths: the current user's, plus everyone's when root."""
    homes = {Path.home()}
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        for base in (Path("/home"), Path("/Users")):
            for entry in safe_scandir(base):
                if is_dir(entry) and not entry.name.startswith("."):
                    homes.add(Path(entry.path))
        homes.add(Path("/root"))
    return sorted(h for h in homes if h.is_dir())
