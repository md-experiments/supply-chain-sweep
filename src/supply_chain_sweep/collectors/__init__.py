"""Collectors turn discovered locations into Package records, reading files only."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..util import Warnings, file_digest


@dataclass
class Context:
    warnings: Warnings = field(default_factory=Warnings)
    # Hash a file; the scanner swaps in a version backed by the on-disk hash cache.
    hasher: Callable[[Path], str | None] = file_digest
    hash_archives: bool = True

    def archive_hash(self, path: Path) -> list[str]:
        if not self.hash_archives:
            return []
        digest = self.hasher(path)
        return [digest] if digest else []
