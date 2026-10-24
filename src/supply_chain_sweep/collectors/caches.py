"""pip, uv and npm caches (FR-3, FR-5).

Archives are opened as zip/tar for their metadata member only; nothing is
extracted to disk or executed.
"""

from __future__ import annotations

import json
import re
import tarfile
import zipfile
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..models import Ecosystem, Package, SourceType
from ..util import MAX_TEXT_BYTES, is_dir, normalize_digest, read_text, safe_scandir
from . import Context
from .python import parse_metadata, read_dist_info


def _walk_files(root: Path, ctx: Context, max_depth: int = 8):
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        for entry in safe_scandir(d, ctx.warnings if depth == 0 else None):
            if is_dir(entry):
                if depth < max_depth:
                    stack.append((Path(entry.path), depth + 1))
            elif entry.is_file(follow_symlinks=False):
                yield Path(entry.path)


def parse_wheel_filename(name: str) -> tuple[str, str] | None:
    parts = name.removesuffix(".whl").split("-")
    if len(parts) < 5:
        return None
    return parts[0], parts[1]


def _zip_metadata(path: Path) -> dict[str, str] | None:
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                n = info.filename
                if n.count("/") == 1 and n.endswith(".dist-info/METADATA") and info.file_size < MAX_TEXT_BYTES:
                    return parse_metadata(zf.read(info).decode("utf-8", "replace"))
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
        return None
    return None


def _tar_metadata(path: Path) -> dict[str, str] | None:
    try:
        with tarfile.open(path, "r:*") as tf:
            for member in tf:
                if member.isfile() and member.name.count("/") == 1 and member.name.endswith("/PKG-INFO"):
                    if member.size >= MAX_TEXT_BYTES:
                        return None
                    fh = tf.extractfile(member)  # reads the member into memory only
                    return parse_metadata(fh.read().decode("utf-8", "replace")) if fh else None
    except (tarfile.TarError, OSError, EOFError, ValueError):
        return None
    return None


def _sniff(path: Path) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(4)
    except OSError:
        return b""


def scan_pip_cache(cache: Path, ctx: Context) -> list[Package]:
    out = []
    wheels = cache / "wheels"
    if wheels.is_dir():
        for f in _walk_files(wheels, ctx):
            if f.suffix == ".whl" and (parsed := parse_wheel_filename(f.name)):
                out.append(_cache_pkg(Ecosystem.PYPI, *parsed, f, cache, ctx, "pip-wheel"))
    for http in ("http-v2", "http"):
        if not (cache / http).is_dir():
            continue
        for f in _walk_files(cache / http, ctx):
            if http == "http-v2" and not f.name.endswith(".body"):
                continue
            magic = _sniff(f)
            meta = None
            if magic.startswith(b"PK\x03\x04") or http == "http":
                meta = _zip_metadata(f)
            if meta is None and magic.startswith(b"\x1f\x8b"):
                meta = _tar_metadata(f)
            if meta and meta.get("name") and meta.get("version"):
                out.append(_cache_pkg(Ecosystem.PYPI, meta["name"], meta["version"], f, cache, ctx, "pip-http"))
    return out


def scan_uv_cache(cache: Path, ctx: Context) -> list[Package]:
    out = []
    for bucket in safe_scandir(cache, ctx.warnings):
        if not (is_dir(bucket) and bucket.name.startswith("archive-v")):
            continue
        for unpacked in safe_scandir(Path(bucket.path)):
            if not is_dir(unpacked):
                continue
            for entry in safe_scandir(Path(unpacked.path)):
                if entry.name.endswith(".dist-info") and is_dir(entry):
                    pkg = read_dist_info(
                        Path(entry.path), ctx, source_type=SourceType.CACHE, container=str(cache)
                    )
                    if pkg:
                        pkg.extra["cache"] = "uv-archive"
                        out.append(pkg)
    return out


_TARBALL = re.compile(r"^/(?P<name>(?:@[^/]+/)?[^/]+)/-/(?:@[^/]+/)?(?P<file>[^/]+)\.tgz$")


def parse_npm_tarball_url(url: str) -> tuple[str, str] | None:
    """https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz -> ("@scope/pkg", "1.2.3")."""
    m = _TARBALL.match(unquote(urlparse(url).path))
    if not m:
        return None
    name = m.group("name")
    base = name.rsplit("/", 1)[-1]
    file = m.group("file")
    if not file.startswith(base + "-"):
        return None
    return name, file[len(base) + 1 :]


def scan_npm_cache(cacache: Path, ctx: Context) -> list[Package]:
    """Read npm's content-addressable cache index (index-v5) for tarball entries."""
    out: dict[tuple[str, str], Package] = {}
    index = cacache / "index-v5"
    if not index.is_dir():
        return []
    for f in _walk_files(index, ctx):
        text = read_text(f)
        if not text:
            continue
        for line in text.splitlines():
            _, _, payload = line.partition("\t")
            try:
                entry = json.loads(payload)
            except json.JSONDecodeError:
                continue
            key = entry.get("key", "") if isinstance(entry, dict) else ""
            url = key.split(":", 2)[-1] if key.startswith("make-fetch-happen:request-cache:") else ""
            parsed = parse_npm_tarball_url(url) if url else None
            if not parsed:
                continue
            pkg = out.get(parsed)
            if pkg is None:
                pkg = out[parsed] = Package(
                    ecosystem=Ecosystem.NPM,
                    name=parsed[0],
                    version=parsed[1],
                    source_type=SourceType.CACHE,
                    location=f"{cacache}#{parsed[0]}@{parsed[1]}",
                    container=str(cacache),
                    extra={"cache": "npm-cacache"},
                )
            for integ in str(entry.get("integrity") or "").split():
                d = normalize_digest(integ)
                if d and d not in pkg.hashes:
                    pkg.hashes.append(d)
    return [out[k] for k in sorted(out)]


def _cache_pkg(eco: Ecosystem, name: str, version: str, path: Path, cache: Path, ctx: Context, kind: str) -> Package:
    return Package(
        ecosystem=eco,
        name=name,
        version=version,
        source_type=SourceType.CACHE,
        location=str(path),
        container=str(cache),
        hashes=ctx.archive_hash(path),
        extra={"cache": kind},
    )

