"""Version ordering per ecosystem and OSV `affected` evaluation."""

from __future__ import annotations

import re
from functools import total_ordering
from typing import Any

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@total_ordering
class SemVer:
    __slots__ = ("core", "pre")

    def __init__(self, text: str) -> None:
        m = _SEMVER.match(text.strip())
        if not m:
            raise ValueError(text)
        self.core = tuple(int(x or 0) for x in m.group(1, 2, 3))
        self.pre = tuple(m.group(4).split(".")) if m.group(4) else ()

    @staticmethod
    def _pre_key(pre: tuple[str, ...]) -> tuple:
        # A release sorts after any of its prereleases; numeric ids sort before alphanumeric.
        if not pre:
            return (1,)
        return (0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre))

    def _key(self) -> tuple:
        return (self.core, self._pre_key(self.pre))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SemVer) and self._key() == other._key()

    def __lt__(self, other: SemVer) -> bool:
        return self._key() < other._key()

    def __hash__(self) -> int:
        return hash(self._key())


def parse_version(ecosystem: str, text: str) -> Any | None:
    try:
        if ecosystem == "npm":
            return SemVer(text)
        return Version(text)
    except (InvalidVersion, ValueError):
        return None


def versions_equal(ecosystem: str, a: str, b: str) -> bool:
    if a == b:
        return True
    pa, pb = parse_version(ecosystem, a), parse_version(ecosystem, b)
    return pa is not None and pa == pb


def is_affected(ecosystem: str, version: str, affected: dict) -> bool:
    """Evaluate one OSV `affected[]` entry against a version (OSV schema semantics)."""
    for v in affected.get("versions") or ():
        if versions_equal(ecosystem, version, v):
            return True
    ranges = [r for r in affected.get("ranges") or () if r.get("type") in ("ECOSYSTEM", "SEMVER")]
    if not ranges:
        return False
    parsed = parse_version(ecosystem, version)
    if parsed is None:
        return False
    for rng in ranges:
        if _in_range(ecosystem, parsed, rng.get("events") or ()):
            return True
    return False


def _in_range(ecosystem: str, version: Any, events: Any) -> bool:
    keyed = []
    for ev in events:
        kind, raw = next(iter(ev.items()), (None, None))
        if kind not in ("introduced", "fixed", "last_affected", "limit") or raw is None:
            continue
        if kind == "introduced" and raw == "0":
            keyed.append(((0,), kind, None))
            continue
        pv = parse_version(ecosystem, raw)
        if pv is None:
            continue
        keyed.append(((1, pv), kind, pv))
    # Stable sort: at equal versions, "introduced" comes before closing events.
    order = {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 1}
    keyed.sort(key=lambda k: (k[0], order[k[1]]))
    affected = False
    for _, kind, pv in keyed:
        if kind == "introduced":
            if pv is None or version >= pv:
                affected = True
        elif kind == "fixed":
            if version >= pv:
                affected = False
        elif kind == "last_affected":
            if version > pv:
                affected = False
        elif kind == "limit":
            if version >= pv:
                affected = False
    return affected
