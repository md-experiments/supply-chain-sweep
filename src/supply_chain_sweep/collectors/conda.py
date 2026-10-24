"""Conda environments (conda-meta/*.json) and the conda package cache (FR-1)."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Ecosystem, Package, SourceType
from ..util import is_dir, normalize_digest, read_text, safe_scandir
from . import Context

ARCHIVE_SUFFIXES = (".conda", ".tar.bz2")


def _record_hashes(meta: dict) -> list[str]:
    hashes = []
    for key in ("sha256", "md5"):
        if meta.get(key):
            d = normalize_digest(f"{key}:{meta[key]}")
            if d:
                hashes.append(d)
    for entry in (meta.get("paths_data") or {}).get("paths", []):
        if entry.get("sha256"):
            d = normalize_digest(f"sha256:{entry['sha256']}")
            if d:
                hashes.append(d)
    return hashes


def scan_conda_env(env: Path, ctx: Context) -> list[Package]:
    out = []
    for entry in safe_scandir(env / "conda-meta", ctx.warnings):
        if not entry.name.endswith(".json"):
            continue
        text = read_text(Path(entry.path), ctx.warnings)
        try:
            meta = json.loads(text) if text else None
        except json.JSONDecodeError:
            ctx.warnings.add(entry.path, "invalid JSON")
            continue
        if not isinstance(meta, dict) or not meta.get("name") or not meta.get("version"):
            continue
        extra = {k: str(meta[k]) for k in ("build", "channel") if meta.get(k)}
        out.append(
            Package(
                ecosystem=Ecosystem.CONDA,
                name=meta["name"],
                version=str(meta["version"]),
                source_type=SourceType.ENVIRONMENT,
                location=entry.path,
                container=str(env),
                hashes=_record_hashes(meta),
                files=list(meta.get("files") or []),
                extra=extra,
            )
        )
    return out


def split_conda_filename(stem: str) -> tuple[str, str, str] | None:
    """"name-with-dashes-1.2.3-py311_0" -> (name, version, build)."""
    parts = stem.rsplit("-", 2)
    if len(parts) != 3 or not all(parts):
        return None
    return parts[0], parts[1], parts[2]


def scan_conda_pkgs(pkgs: Path, ctx: Context) -> list[Package]:
    out = []
    for entry in safe_scandir(pkgs, ctx.warnings):
        p = Path(entry.path)
        if is_dir(entry):
            index = p / "info" / "index.json"
            if not index.exists():
                continue
            text = read_text(index, ctx.warnings)
            try:
                meta = json.loads(text) if text else {}
            except json.JSONDecodeError:
                continue
            if meta.get("name") and meta.get("version"):
                files_txt = read_text(p / "info" / "files") if (p / "info" / "files").exists() else ""
                out.append(
                    Package(
                        ecosystem=Ecosystem.CONDA,
                        name=meta["name"],
                        version=str(meta["version"]),
                        source_type=SourceType.CACHE,
                        location=str(p),
                        container=str(pkgs),
                        files=[ln for ln in (files_txt or "").splitlines() if ln],
                        extra={"build": str(meta.get("build", "")), "cache": "conda-extracted"},
                    )
                )
        elif entry.name.endswith(ARCHIVE_SUFFIXES):
            stem = entry.name.removesuffix(".conda").removesuffix(".tar.bz2")
            parsed = split_conda_filename(stem)
            if not parsed:
                continue
            name, version, build = parsed
            out.append(
                Package(
                    ecosystem=Ecosystem.CONDA,
                    name=name,
                    version=version,
                    source_type=SourceType.CACHE,
                    location=str(p),
                    container=str(pkgs),
                    hashes=ctx.archive_hash(p),
                    extra={"build": build, "cache": "conda-archive"},
                )
            )
    return out
