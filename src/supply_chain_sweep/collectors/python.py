"""Python packages from site-packages: dist-info, egg-info and .pth files (FR-2, NFR-1).

Metadata comes from METADATA / PKG-INFO / RECORD on disk. No interpreter is
ever started, so a malicious .pth file cannot run during the scan.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Ecosystem, Package, SourceType
from ..util import file_digest, is_dir, normalize_digest, read_text, safe_scandir
from . import Context

_DIST_INFO = re.compile(r"^(?P<name>.+?)-(?P<version>[^-]+?)\.(dist-info|egg-info)$")


@dataclass
class PthFile:
    path: Path
    site_dir: Path
    env: Path
    content: str
    sha256: str


@dataclass
class SiteScan:
    packages: list[Package] = field(default_factory=list)
    pth_files: list[PthFile] = field(default_factory=list)
    # Every top-level entry name in the site dir, for IOC file-name checks.
    entries: list[Path] = field(default_factory=list)


def parse_metadata(text: str) -> dict[str, str]:
    """Read the RFC 822 header block of METADATA / PKG-INFO."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break
        if line[:1] in (" ", "\t") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        out.setdefault(key.strip().lower(), value.strip())
    return out


def parse_record(text: str) -> tuple[list[str], list[str]]:
    files, hashes = [], []
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        files.append(row[0])
        if len(row) > 1 and row[1]:
            digest = normalize_digest(row[1])
            if digest:
                hashes.append(digest)
    return files, hashes


def read_dist_info(path: Path, ctx: Context, **pkg_kwargs) -> Package | None:
    """Build a Package from a *.dist-info or *.egg-info directory (or egg-info file)."""
    is_egg = path.suffix == ".egg-info"
    if path.is_dir():
        meta_file = path / ("PKG-INFO" if is_egg else "METADATA")
    else:
        meta_file = path  # legacy single-file egg-info
    text = read_text(meta_file, ctx.warnings) if meta_file.exists() else None
    meta = parse_metadata(text) if text else {}
    name, version = meta.get("name"), meta.get("version")
    if not (name and version):
        m = _DIST_INFO.match(path.name)
        if not m:
            ctx.warnings.add(path, "no package name/version in metadata")
            return None
        name, version = m.group("name"), m.group("version")

    files: list[str] = []
    hashes: list[str] = []
    extra: dict[str, str] = {}
    if path.is_dir():
        record = path / "RECORD"
        if record.exists():
            text = read_text(record, ctx.warnings)
            if text:
                files, hashes = parse_record(text)
        else:
            for listing in ("installed-files.txt", "SOURCES.txt"):
                text = read_text(path / listing) if (path / listing).exists() else None
                if text:
                    files = [ln.strip() for ln in text.splitlines() if ln.strip()]
                    break
        installer = path / "INSTALLER"
        if installer.exists():
            extra["installer"] = (read_text(installer) or "").strip()
    return Package(
        ecosystem=Ecosystem.PYPI,
        name=name,
        version=version,
        location=str(path),
        files=files,
        hashes=hashes,
        extra=extra,
        **pkg_kwargs,
    )


def scan_site_dir(site: Path, env: Path, ctx: Context, source_type: SourceType = SourceType.ENVIRONMENT) -> SiteScan:
    result = SiteScan()
    for entry in safe_scandir(site, ctx.warnings):
        p = Path(entry.path)
        result.entries.append(p)
        if entry.name.endswith((".dist-info", ".egg-info")):
            pkg = read_dist_info(p, ctx, source_type=source_type, container=str(env))
            if pkg:
                result.packages.append(pkg)
        elif entry.name.endswith(".pth") and not is_dir(entry):
            text = read_text(p, ctx.warnings)
            digest = file_digest(p)
            if text is not None and digest:
                result.pth_files.append(PthFile(p, site, env, text, digest))
    return result
