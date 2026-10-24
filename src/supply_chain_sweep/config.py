"""Configuration: defaults, optional TOML config file, CLI overrides (FR-7)."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def data_dir() -> Path:
    if os.environ.get("SWEEP_HOME"):
        return Path(os.environ["SWEEP_HOME"]).expanduser()
    base = os.environ.get("XDG_DATA_HOME") or "~/.local/share"
    return Path(base).expanduser() / "supply-chain-sweep"


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "supply-chain-sweep"


def default_config_path() -> Path:
    if os.environ.get("SWEEP_CONFIG"):
        return Path(os.environ["SWEEP_CONFIG"]).expanduser()
    return config_dir() / "config.toml"


def default_roots() -> list[Path]:
    """Places to walk for environments, node_modules and lockfiles."""
    roots = [Path.home()]
    candidates = [
        "/opt",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/usr/local",  # /usr/local/anaconda3 etc.
        "/srv",
    ]
    if sys.platform == "darwin":
        candidates += [
            "/Library/Frameworks/Python.framework",
            "/opt/homebrew",
            "/usr/local/Cellar",
            "/Applications",
        ]
    roots += [Path(c) for c in candidates]
    for var in ("CONDA_PREFIX", "VIRTUAL_ENV"):
        if os.environ.get(var):
            roots.append(Path(os.environ[var]))
    return roots


@dataclass
class PthAllow:
    name: str  # fnmatch pattern against the file name
    sha256: str = ""  # optional: exact content hash
    contains: str = ""  # optional: required substring of the content


@dataclass
class Config:
    roots: list[Path] = field(default_factory=default_roots)
    exclude: list[Path] = field(default_factory=list)
    profile_dirs: list[Path] = field(default_factory=lambda: [config_dir() / "profiles"])
    feeds: list[str] = field(default_factory=lambda: ["PyPI", "npm"])
    docker: bool = True
    caches: bool = True
    lockfiles: bool = True
    hash_archives: bool = True
    pth_allowlist: list[PthAllow] = field(default_factory=list)
    logs: list[Path] = field(default_factory=list)
    alert_command: str = ""
    max_depth: int = 12
    data_dir: Path = field(default_factory=data_dir)


def _paths(values) -> list[Path]:
    return [Path(os.path.expandvars(str(v))).expanduser() for v in values or ()]


def load_config(path: Path | None = None) -> Config:
    cfg = Config()
    explicit = path is not None
    path = path or default_config_path()
    if not path.exists():
        if explicit:
            raise FileNotFoundError(f"config file not found: {path}")
        return cfg
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)

    scan = raw.get("scan", raw)
    if "roots" in scan:
        roots = _paths(scan["roots"])
        cfg.roots = roots if scan.get("only_roots") else cfg.roots + roots
    cfg.exclude += _paths(scan.get("exclude"))
    cfg.profile_dirs += _paths(scan.get("profile_dirs"))
    cfg.logs += _paths(scan.get("logs"))
    for key in ("docker", "caches", "lockfiles", "hash_archives"):
        if key in scan:
            setattr(cfg, key, bool(scan[key]))
    if "max_depth" in scan:
        cfg.max_depth = int(scan["max_depth"])
    if "feeds" in raw.get("intel", {}):
        cfg.feeds = list(raw["intel"]["feeds"])
    for entry in raw.get("pth_allowlist", []):
        cfg.pth_allowlist.append(
            PthAllow(entry["name"], entry.get("sha256", ""), entry.get("contains", ""))
        )
    cfg.alert_command = raw.get("alert", {}).get("command", "")
    if raw.get("data_dir"):
        cfg.data_dir = Path(raw["data_dir"]).expanduser()
    return cfg
