"""Core data types shared by collectors, matchers and reporters."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field


class Ecosystem(str, enum.Enum):
    PYPI = "PyPI"
    CONDA = "conda"
    NPM = "npm"


class SourceType(str, enum.Enum):
    ENVIRONMENT = "environment"
    IMAGE = "image"
    CACHE = "cache"
    LOCKFILE = "lockfile"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"  # network monitor only
    LOW = "low"  # network monitor only
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


@dataclass
class Package:
    """One package found somewhere on the host (FR-8)."""

    ecosystem: Ecosystem
    name: str
    version: str
    source_type: SourceType
    location: str
    # Grouping root: the environment, image, cache or lockfile the package belongs to.
    container: str = ""
    # Normalised "algo:hex" digests of the package's files or archive.
    hashes: list[str] = field(default_factory=list)
    # File paths belonging to the package, relative to its install root. Used for
    # IOC file-name checks; not persisted.
    files: list[str] = field(default_factory=list, repr=False)
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.ecosystem.value, self.name, self.version, self.location)

    def to_dict(self, include_hashes: bool = True) -> dict:
        d = {
            "ecosystem": self.ecosystem.value,
            "name": self.name,
            "version": self.version,
            "source_type": self.source_type.value,
            "location": self.location,
            "container": self.container,
        }
        if include_hashes:
            d["hashes"] = sorted(set(self.hashes))
        if self.extra:
            d["extra"] = dict(sorted(self.extra.items()))
        return d


@dataclass
class Finding:
    severity: Severity
    rule: str  # e.g. "malicious-package", "ioc-hash", "pth-exec"
    title: str
    location: str
    action: str
    advisory: str = ""  # OSV id or profile id
    package: dict | None = None
    details: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        pkg = ""
        if self.package:
            pkg = f"{self.package['ecosystem']}/{self.package['name']}@{self.package['version']}"
        return "|".join([self.rule, self.advisory, pkg, self.location])

    def sort_key(self) -> tuple:
        return (self.severity.rank, self.rule, self.advisory, self.location, self.title)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ScanWarning:
    location: str
    message: str

    def to_dict(self) -> dict:
        return {"location": self.location, "message": self.message}
