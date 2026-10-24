"""Pinned versions from requirements*.txt, uv.lock, poetry.lock and package-lock.json (FR-6)."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from ..models import Ecosystem, Package, SourceType
from ..util import normalize_digest, read_text
from . import Context

_REQ_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;\\#,]+)")
_REQ_HASH = re.compile(r"--hash[=\s]+([a-z0-9]+:[0-9a-fA-F]+)")


def _pkg(eco: Ecosystem, name: str, version: str, path: Path, hashes=None, extra=None) -> Package:
    return Package(
        ecosystem=eco,
        name=name,
        version=version,
        source_type=SourceType.LOCKFILE,
        location=str(path),
        container=str(path),
        hashes=[d for d in (normalize_digest(h) for h in hashes or ()) if d],
        extra=extra or {},
    )


def parse_requirements(path: Path, text: str) -> list[Package]:
    out = []
    # Join backslash continuations so `--hash` lines attach to their requirement.
    for line in text.replace("\\\n", " ").splitlines():
        line = line.split(" #", 1)[0]
        m = _REQ_PIN.match(line)
        if m:
            out.append(_pkg(Ecosystem.PYPI, m.group(1), m.group(2), path, _REQ_HASH.findall(line)))
    return out


def parse_uv_lock(path: Path, data: dict) -> list[Package]:
    out = []
    for p in data.get("package", []):
        if not p.get("name") or not p.get("version"):
            continue
        hashes = [w.get("hash", "") for w in p.get("wheels", [])]
        if isinstance(p.get("sdist"), dict):
            hashes.append(p["sdist"].get("hash", ""))
        out.append(_pkg(Ecosystem.PYPI, p["name"], str(p["version"]), path, hashes))
    return out


def parse_poetry_lock(path: Path, data: dict) -> list[Package]:
    legacy = (data.get("metadata") or {}).get("files") or {}
    out = []
    for p in data.get("package", []):
        if not p.get("name") or not p.get("version"):
            continue
        files = p.get("files") or legacy.get(p["name"], [])
        out.append(_pkg(Ecosystem.PYPI, p["name"], str(p["version"]), path, [f.get("hash", "") for f in files]))
    return out


def parse_package_lock(path: Path, data: dict) -> list[Package]:
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        for rel, meta in packages.items():
            if not rel or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or rel.rsplit("node_modules/", 1)[-1]
            if meta.get("version"):
                out.append(_pkg(Ecosystem.NPM, name, str(meta["version"]), path, str(meta.get("integrity", "")).split()))
        return out

    def walk(deps: dict) -> None:  # lockfileVersion 1
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append(_pkg(Ecosystem.NPM, name, str(meta["version"]), path, str(meta.get("integrity", "")).split()))
                walk(meta.get("dependencies"))

    walk(data.get("dependencies"))
    return out


def scan_lockfile(path: Path, ctx: Context) -> list[Package]:
    text = read_text(path, ctx.warnings)
    if text is None:
        return []
    try:
        if path.name == "uv.lock":
            return parse_uv_lock(path, tomllib.loads(text))
        if path.name == "poetry.lock":
            return parse_poetry_lock(path, tomllib.loads(text))
        if path.name == "package-lock.json":
            return parse_package_lock(path, json.loads(text))
        return parse_requirements(path, text)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError, AttributeError, TypeError) as exc:
        ctx.warnings.add(path, f"could not parse lockfile: {exc}")
        return []
