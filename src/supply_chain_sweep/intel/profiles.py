"""User-defined IOC profiles in TOML (FR-14).

Example::

    id = "litellm-2026-03"
    name = "LiteLLM PyPI compromise"
    references = ["https://..."]

    file_names = ["litellm_init.pth"]          # files that should never be in an install
    hashes = ["sha256:71e35aef..."]            # hex, algo:hex or wheel RECORD base64
    persistence_paths = ["~/.config/sysmon/sysmon.py"]
    domains = ["models.litellm.cloud"]

    # [[packages]] tables go last: TOML assigns later keys to the table.
    [[packages]]
    ecosystem = "PyPI"
    name = "litellm"
    versions = ["1.82.7", "1.82.8"]
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from ..util import Warnings, normalize_digest, normalize_name


@dataclass
class ProfilePackage:
    ecosystem: str
    name: str
    versions: list[str]  # empty means every version


@dataclass
class Profile:
    id: str
    name: str
    description: str = ""
    references: list[str] = field(default_factory=list)
    packages: list[ProfilePackage] = field(default_factory=list)
    file_names: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    persistence_paths: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    source: str = ""

    def matches_package(self, ecosystem: str, name: str) -> list[ProfilePackage]:
        eco_pypi = ecosystem in ("PyPI", "conda")
        out = []
        for p in self.packages:
            same_eco = p.ecosystem == ecosystem or (eco_pypi and p.ecosystem in ("PyPI", "conda"))
            if same_eco and normalize_name(p.ecosystem, p.name) == normalize_name(ecosystem, name):
                out.append(p)
        return out


def parse_profile(data: dict, source: str) -> Profile:
    if not data.get("id"):
        raise ValueError("profile is missing 'id'")
    for p in data.get("packages", []):
        misplaced = set(p) & {"file_names", "hashes", "persistence_paths", "domains", "references"}
        if misplaced:
            raise ValueError(
                f"{', '.join(sorted(misplaced))} ended up inside [[packages]]; move top-level keys above it"
            )
    hashes = []
    for h in data.get("hashes", []):
        d = normalize_digest(str(h))
        if not d:
            raise ValueError(f"unrecognised hash {h!r}")
        hashes.append(d)
    return Profile(
        id=str(data["id"]),
        name=str(data.get("name", data["id"])),
        description=str(data.get("description", "")),
        references=[str(r) for r in data.get("references", [])],
        packages=[
            ProfilePackage(
                str(p.get("ecosystem", "PyPI")),
                str(p["name"]),
                [str(v) for v in p.get("versions", [])],
            )
            for p in data.get("packages", [])
        ],
        file_names=[str(f) for f in data.get("file_names", [])],
        hashes=hashes,
        persistence_paths=[str(p) for p in data.get("persistence_paths", [])],
        domains=[str(d).lower() for d in data.get("domains", [])],
        source=source,
    )


def builtin_profiles() -> list[tuple[str, bytes]]:
    pkg = resources.files("supply_chain_sweep") / "profiles"
    return sorted((f"builtin:{p.name}", p.read_bytes()) for p in pkg.iterdir() if p.name.endswith(".toml"))


def load_profiles(dirs: list[Path], warnings: Warnings, extra_files: list[Path] = ()) -> list[Profile]:
    sources: list[tuple[str, bytes]] = builtin_profiles()
    files = list(extra_files)
    for d in dirs:
        if d.is_dir():
            files += sorted(d.glob("*.toml"))
    for f in files:
        try:
            sources.append((str(f), f.read_bytes()))
        except OSError as exc:
            warnings.add(f, f"cannot read profile: {exc.strerror or exc}")
    profiles: dict[str, Profile] = {}
    for src, raw in sources:
        try:
            prof = parse_profile(tomllib.loads(raw.decode("utf-8")), src)
        except (tomllib.TOMLDecodeError, ValueError, KeyError, UnicodeDecodeError) as exc:
            warnings.add(src, f"invalid profile: {exc}")
            continue
        profiles[prof.id] = prof  # a user profile with the same id overrides the built-in one
    return [profiles[k] for k in sorted(profiles)]
