"""Find every environment, package directory, cache and lockfile under the scan roots.

The walk only lists directories and checks names. It never follows directory
symlinks (no loops, no escaping the roots) and never opens anything for writing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .util import Warnings, home_dirs, is_dir, read_text, safe_scandir

LOCKFILE_NAMES = {"uv.lock", "poetry.lock", "package-lock.json"}
_REQUIREMENTS = re.compile(r"^requirements.*\.txt$|^.*requirements\.txt$", re.IGNORECASE)

# Directory names never worth descending into.
SKIP_NAMES = {".git", ".hg", ".svn", "__pycache__", ".Trash", ".mypy_cache", ".pytest_cache", ".tox-cache"}
# Absolute paths never worth descending into.
SKIP_ABS = {"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containerd", "/System", "/private/var/vm"}


@dataclass
class SiteDir:
    path: Path
    env: Path  # environment root (venv, conda env or interpreter prefix)
    env_kind: str  # "venv", "conda", "system"


@dataclass
class Discovery:
    site_dirs: list[SiteDir] = field(default_factory=list)
    conda_envs: list[Path] = field(default_factory=list)
    conda_pkg_dirs: list[Path] = field(default_factory=list)
    node_modules: list[Path] = field(default_factory=list)
    lockfiles: list[Path] = field(default_factory=list)
    pip_caches: list[Path] = field(default_factory=list)
    uv_caches: list[Path] = field(default_factory=list)
    npm_caches: list[Path] = field(default_factory=list)

    def environments(self) -> list[Path]:
        envs = {s.env for s in self.site_dirs} | set(self.conda_envs)
        return sorted(envs)


def is_lockfile(name: str) -> bool:
    return name in LOCKFILE_NAMES or bool(_REQUIREMENTS.match(name))


def _under(path: Path, roots: list[Path]) -> bool:
    return any(path == r or r in path.parents for r in roots)


def _system_prefix(site: Path) -> Path:
    # <prefix>/lib/python3.X/site-packages -> <prefix>; /usr/lib/python3/dist-packages -> /usr
    parts = site.parts
    for i in range(len(parts) - 1, 0, -1):
        if parts[i] in ("lib", "lib64", "Lib"):
            return Path(*parts[:i]) if i > 0 else site
    return site.parent


class Walker:
    def __init__(self, exclude: list[Path], max_depth: int, warnings: Warnings) -> None:
        self.exclude = [p.resolve() if p.exists() else p for p in exclude]
        self.max_depth = max_depth
        self.warnings = warnings
        self.seen: set[tuple[int, int]] = set()
        self.found = Discovery()
        self.cache_dirs: set[Path] = set()

    def walk(self, root: Path) -> None:
        try:
            root = root.resolve()
        except OSError:
            pass
        if not root.exists():
            return
        if not root.is_dir():
            if is_lockfile(root.name):
                self.found.lockfiles.append(root)
            return
        self._visit(root, None, "", 0)

    def _visit(self, path: Path, env: Path | None, env_kind: str, depth: int) -> None:
        if depth > self.max_depth or str(path) in SKIP_ABS or path in self.cache_dirs:
            return
        if any(path == e or e in path.parents for e in self.exclude):
            return
        try:
            st = path.stat()
        except OSError as exc:
            self.warnings.add(path, f"cannot stat: {exc.strerror or exc}")
            return
        ident = (st.st_dev, st.st_ino)
        if ident in self.seen:
            return
        self.seen.add(ident)

        entries = safe_scandir(path, self.warnings if depth == 0 else None)
        names = {e.name for e in entries}

        if "pyvenv.cfg" in names:
            env, env_kind = path, "venv"
        if "conda-meta" in names and (path / "conda-meta").is_dir():
            env, env_kind = path, "conda"
            self.found.conda_envs.append(path)
            if "pkgs" in names:
                pkgs = path / "pkgs"
                self.found.conda_pkg_dirs.append(pkgs)
                self.cache_dirs.add(pkgs)

        for entry in entries:
            name = entry.name
            if not is_dir(entry):
                if is_lockfile(name) and entry.is_file():
                    self.found.lockfiles.append(Path(entry.path))
                continue
            child = Path(entry.path)
            if name in SKIP_NAMES:
                continue
            if name in ("site-packages", "dist-packages"):
                owner = env or _system_prefix(child)
                self.found.site_dirs.append(SiteDir(child, owner, env_kind or "system"))
                continue
            if name == "node_modules":
                self.found.node_modules.append(child)
                continue
            if name == "pkgs" and (child / "urls.txt").exists():
                if child not in self.found.conda_pkg_dirs:
                    self.found.conda_pkg_dirs.append(child)
                continue
            self._visit(child, env, env_kind, depth + 1)


def _cache_locations(homes: list[Path]) -> tuple[list[Path], list[Path], list[Path], list[Path]]:
    pip, uv, npm, conda_pkgs = [], [], [], []
    env = os.environ
    if env.get("PIP_CACHE_DIR"):
        pip.append(Path(env["PIP_CACHE_DIR"]))
    if env.get("UV_CACHE_DIR"):
        uv.append(Path(env["UV_CACHE_DIR"]))
    if env.get("npm_config_cache"):
        npm.append(Path(env["npm_config_cache"]) / "_cacache")
    if env.get("CONDA_PKGS_DIRS"):
        conda_pkgs += [Path(p) for p in env["CONDA_PKGS_DIRS"].split(os.pathsep) if p]
    xdg = env.get("XDG_CACHE_HOME")
    for home in homes:
        caches = [home / ".cache", home / "Library" / "Caches"]
        if xdg and home == Path.home():
            caches.insert(0, Path(xdg))
        for c in caches:
            pip.append(c / "pip")
            uv.append(c / "uv")
        npm.append(home / ".npm" / "_cacache")
        conda_pkgs.append(home / ".conda" / "pkgs")
        conda_pkgs += _condarc_list(home / ".condarc", "pkgs_dirs")
    return pip, uv, npm, conda_pkgs


def _condarc_list(path: Path, key: str) -> list[Path]:
    """Minimal YAML list reader for `key:` followed by `- item` lines in .condarc."""
    text = read_text(path)
    if not text:
        return []
    out, active = [], False
    for line in text.splitlines():
        if re.match(rf"^{key}\s*:", line):
            active = True
            continue
        if active:
            m = re.match(r"^\s+-\s*(.+?)\s*$", line)
            if m:
                out.append(Path(m.group(1).strip("'\"")).expanduser())
            elif line.strip() and not line.startswith((" ", "\t")):
                active = False
    return out


def _conda_env_roots(homes: list[Path]) -> list[Path]:
    roots = []
    for home in homes:
        text = read_text(home / ".conda" / "environments.txt")
        if text:
            roots += [Path(line.strip()) for line in text.splitlines() if line.strip()]
        roots += _condarc_list(home / ".condarc", "envs_dirs")
    return roots


def discover(
    roots: list[Path],
    exclude: list[Path],
    warnings: Warnings,
    *,
    include_caches: bool = True,
    restrict: bool = False,
    max_depth: int = 12,
) -> Discovery:
    """Walk the roots and locate caches (FR-1 to FR-3, FR-5, FR-6).

    With ``restrict`` (a user-supplied path filter) only the given roots are
    searched; well-known cache and conda locations outside them are ignored.
    """
    homes = home_dirs()
    pip, uv, npm, conda_pkgs = _cache_locations(homes) if include_caches else ([], [], [], [])
    all_roots = list(roots)
    if not restrict:
        all_roots += _conda_env_roots(homes)
        if Path.home() in roots:
            all_roots += [h for h in homes if h not in roots]

    walker = Walker(exclude, max_depth, warnings)
    for c in pip + uv + npm:
        walker.cache_dirs.add(c.resolve() if c.exists() else c)
    for root in sorted(set(all_roots), key=lambda p: (len(p.parts), str(p))):
        walker.walk(root)
    found = walker.found

    def keep(p: Path) -> bool:
        return p.is_dir() and (not restrict or _under(p.resolve(), [r.resolve() for r in roots]))

    found.pip_caches = sorted({p.resolve() for p in pip if keep(p)})
    found.uv_caches = sorted({p.resolve() for p in uv if keep(p)})
    found.npm_caches = sorted({p.resolve() for p in npm if keep(p)})
    found.conda_pkg_dirs = sorted({p.resolve() for p in found.conda_pkg_dirs + conda_pkgs if keep(p)})
    found.site_dirs.sort(key=lambda s: str(s.path))
    found.conda_envs = sorted(set(found.conda_envs))
    found.node_modules = sorted(set(found.node_modules))
    found.lockfiles = sorted(set(found.lockfiles))
    return found
