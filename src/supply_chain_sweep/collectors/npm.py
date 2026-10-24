"""Installed npm packages under node_modules, including nested and pnpm layouts (FR-5)."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Ecosystem, Package, SourceType
from ..util import is_dir, normalize_digest, read_text, safe_scandir
from . import Context


def _integrity_map(node_modules: Path, ctx: Context) -> dict[str, list[str]]:
    """npm v7+ writes node_modules/.package-lock.json with per-package integrity."""
    lock = node_modules / ".package-lock.json"
    if not lock.exists():
        return {}
    text = read_text(lock, ctx.warnings)
    try:
        data = json.loads(text) if text else {}
    except json.JSONDecodeError:
        return {}
    base = node_modules.parent
    out = {}
    for rel, meta in (data.get("packages") or {}).items():
        if isinstance(meta, dict) and meta.get("integrity"):
            digests = [d for d in (normalize_digest(i) for i in meta["integrity"].split()) if d]
            out[str((base / rel).resolve())] = digests
    return out


def scan_node_modules(node_modules: Path, ctx: Context) -> list[Package]:
    container = str(node_modules.parent)
    integrity = _integrity_map(node_modules, ctx)
    out: list[Package] = []
    seen: set[str] = set()

    def visit_pkg(pkg_dir: Path, depth: int) -> None:
        manifest = pkg_dir / "package.json"
        if manifest.exists():
            key = str(pkg_dir)
            if key in seen:
                return
            seen.add(key)
            text = read_text(manifest, ctx.warnings)
            try:
                meta = json.loads(text) if text else {}
            except json.JSONDecodeError:
                ctx.warnings.add(manifest, "invalid JSON")
                meta = {}
            if isinstance(meta, dict) and meta.get("name") and meta.get("version"):
                scripts = meta.get("scripts") if isinstance(meta.get("scripts"), dict) else {}
                hooks = sorted(k for k in scripts if k in ("preinstall", "install", "postinstall"))
                out.append(
                    Package(
                        ecosystem=Ecosystem.NPM,
                        name=str(meta["name"]),
                        version=str(meta["version"]),
                        source_type=SourceType.ENVIRONMENT,
                        location=str(pkg_dir),
                        container=container,
                        hashes=integrity.get(str(pkg_dir.resolve()), []),
                        extra={"install_scripts": ",".join(hooks)} if hooks else {},
                    )
                )
        nested = pkg_dir / "node_modules"
        if depth < 40 and nested.is_dir():
            visit_dir(nested, depth + 1)

    def visit_dir(nm: Path, depth: int) -> None:
        for entry in safe_scandir(nm, ctx.warnings):
            # Symlinked packages (pnpm, workspaces) are reached through their real location.
            if not is_dir(entry) or entry.is_symlink():
                continue
            p = Path(entry.path)
            if entry.name == ".pnpm":
                for store in safe_scandir(p):
                    if is_dir(store) and (Path(store.path) / "node_modules").is_dir():
                        visit_dir(Path(store.path) / "node_modules", depth + 1)
            elif entry.name.startswith("."):
                continue
            elif entry.name.startswith("@"):
                for scoped in safe_scandir(p):
                    if is_dir(scoped) and not scoped.is_symlink():
                        visit_pkg(Path(scoped.path), depth)
            else:
                visit_pkg(p, depth)

    visit_dir(node_modules, 0)
    return out
