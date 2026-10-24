"""Turn an inventory into findings (FR-15 to FR-20)."""

from __future__ import annotations

import fnmatch
import gzip
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .collectors.python import PthFile
from .config import PthAllow
from .intel.osv import OsvDB
from .intel.profiles import Profile
from .models import Finding, Package, Severity, SourceType
from .util import Warnings, file_digest, home_dirs
from .versions import is_affected, versions_equal

# --- IOC set ---------------------------------------------------------------


@dataclass
class IocSet:
    """IOCs merged from loaded profiles and OSV advisories' database_specific.iocs."""

    hashes: dict[str, set[str]] = field(default_factory=dict)  # digest -> source ids
    # basename -> source ids. Profile names alone are critical evidence.
    file_names: dict[str, set[str]] = field(default_factory=dict)
    # basename -> {source id: expected digests}. OSV archive members: verified by hash.
    hashed_file_names: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    paths: dict[str, set[str]] = field(default_factory=dict)
    domains: dict[str, set[str]] = field(default_factory=dict)

    def add(self, kind: str, value: str, source: str) -> None:
        getattr(self, kind).setdefault(value, set()).add(source)


def build_iocs(profiles: list[Profile], osv: OsvDB | None) -> IocSet:
    iocs = IocSet()
    for prof in profiles:
        for h in prof.hashes:
            iocs.add("hashes", h, prof.id)
        for f in prof.file_names:
            iocs.add("file_names", f, prof.id)
        for p in prof.persistence_paths:
            iocs.add("paths", p, prof.id)
        for d in prof.domains:
            iocs.add("domains", d, prof.id)
    if osv is not None:
        for adv_id, kind, value, note in osv.iocs():
            if kind == "hash":
                iocs.add("hashes", value, adv_id)
            elif kind == "path":
                iocs.add("paths", value, adv_id)
            elif kind == "domain":
                iocs.add("domains", value, adv_id)
            elif kind == "file":
                digests = json.loads(note).get("digests", []) if note.startswith("{") else []
                if digests:
                    iocs.hashed_file_names.setdefault(value, {})[adv_id] = digests
    return iocs


# --- actions ---------------------------------------------------------------


def package_action(pkg: Package) -> str:
    if pkg.source_type is SourceType.ENVIRONMENT:
        return (
            f"Treat {pkg.container} as compromised: stop using its interpreter, rotate every credential "
            "reachable from this host, and rebuild the environment pinned to a safe version."
        )
    if pkg.source_type is SourceType.IMAGE:
        return f"Do not run {pkg.container}; rebuild it from a clean base and check where it was deployed."
    if pkg.source_type is SourceType.CACHE:
        return (
            f"Purge this entry from {pkg.container} so it cannot be reinstalled, and check whether it "
            "was installed anywhere (the cache means it was downloaded)."
        )
    return f"Pin a safe version in {pkg.location}, regenerate it, and check environments built from it."


PTH_ACTION = (
    "Inspect this file: it runs on every start of this interpreter. If you don't recognise it, treat "
    "the environment as compromised. If it is benign, add it to pth_allowlist in the config file."
)
IOC_FILE_ACTION = (
    "A file from a known attack is installed here and may run on every interpreter start: treat the "
    "environment as compromised, keep a copy for forensics, rotate credentials reachable from this host, "
    "and rebuild the environment."
)
PERSIST_ACTION = (
    "Host shows signs the payload ran: preserve the file for forensics, then remove the persistence, "
    "rotate all credentials reachable from this host, and consider reimaging."
)
DOMAIN_ACTION = (
    "Logs show contact with a known-malicious domain: assume credentials on this host were exfiltrated "
    "and rotate them; find the process responsible."
)


# --- .pth heuristics -------------------------------------------------------

_SUSPICIOUS = re.compile(
    r"exec\s*\(|eval\s*\(|compile\s*\(|base64|b64decode|zlib|marshal|subprocess|os\.system|popen|socket|"
    r"urllib|http\.client|requests|__import__\(\s*['\"](?!_distutils_hack)",
    re.IGNORECASE,
)

# (file name pattern, regex every executable line must match). Content is checked too,
# so a malicious file reusing a well-known name is still flagged.
BUILTIN_PTH_ALLOW: list[tuple[str, re.Pattern]] = [
    ("distutils-precedence.pth", re.compile(r"^import os; var = 'SETUPTOOLS_USE_DISTUTILS'; .*__import__\('_distutils_hack'\)\.add_shim\(\); ?$")),
    ("_virtualenv.pth", re.compile(r"^import _virtualenv\s*$")),
    ("__editable__*.pth", re.compile(r"^import __editable___[\w.]+_finder; __editable___[\w.]+_finder\.install\([^()]*\)\s*$")),
    ("*-nspkg.pth", re.compile(r"^import sys, types, os;")),
    ("easy-install.pth", re.compile(r"^import sys; sys\.__(plen|egginsert)")),
    ("*coverage*.pth", re.compile(r"^import coverage; coverage\.process_startup\(\)\s*$")),
    ("pywin32.pth", re.compile(r"^import pywin32_bootstrap\s*$")),
]


def pth_exec_lines(content: str) -> list[str]:
    """Lines Python's site module would exec (those starting with "import")."""
    return [ln.rstrip() for ln in content.splitlines() if ln.startswith(("import ", "import\t"))]


def pth_allowed(pth: PthFile, lines: list[str], user_allow: list[PthAllow]) -> bool:
    name = pth.path.name
    for rule in user_allow:
        if not fnmatch.fnmatch(name, rule.name):
            continue
        if rule.sha256 and f"sha256:{rule.sha256.lower().removeprefix('sha256:')}" != pth.sha256:
            continue
        if rule.contains and rule.contains not in pth.content:
            continue
        return True
    for pattern, regex in BUILTIN_PTH_ALLOW:
        if fnmatch.fnmatch(name, pattern):
            if all(regex.search(ln) and not _SUSPICIOUS.search(ln) for ln in lines):
                return True
    return False


# --- matcher ---------------------------------------------------------------


class Matcher:
    def __init__(
        self,
        osv: OsvDB | None,
        profiles: list[Profile],
        pth_allowlist: list[PthAllow],
        warnings: Warnings,
    ) -> None:
        self.osv = osv
        self.profiles = profiles
        self.pth_allowlist = pth_allowlist
        self.warnings = warnings
        self.iocs = build_iocs(profiles, osv)

    # FR-15, FR-20 ------------------------------------------------------------
    def match_packages(self, packages: list[Package]) -> list[Finding]:
        out = []
        for pkg in packages:
            malicious: list[str] = []
            vulns: dict[str, list[str]] = {}
            for prof in self.profiles:
                for pp in prof.matches_package(pkg.ecosystem.value, pkg.name):
                    if not pp.versions or any(versions_equal("PyPI" if pp.ecosystem != "npm" else "npm", pkg.version, v) for v in pp.versions):
                        malicious.append(prof.id)
            if self.osv is not None:
                eco = "PyPI" if pkg.ecosystem.value in ("PyPI", "conda") else pkg.ecosystem.value
                for adv_id, affected in self.osv.candidates(eco, pkg.name):
                    if not is_affected(eco, pkg.version, affected):
                        continue
                    adv = self.osv.advisory(adv_id)
                    if adv is None:
                        continue
                    if adv.malicious:
                        malicious.append(adv_id)
                    else:
                        vulns[adv_id] = adv.aliases
            ref = pkg.to_dict(include_hashes=False)
            label = f"{pkg.name} {pkg.version}"
            if malicious:
                ids = sorted(set(malicious), key=lambda i: (not i.startswith("MAL-"), i))
                out.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        rule="malicious-package",
                        title=f"Known-malicious package {label} ({pkg.ecosystem.value}, {pkg.source_type.value})",
                        location=pkg.location,
                        action=package_action(pkg),
                        advisory=ids[0],
                        package=ref,
                        details={"advisories": ids, "container": pkg.container,
                                 **({"note": "conda package matched by PyPI name"} if pkg.ecosystem.value == "conda" else {})},
                    )
                )
            if vulns:
                ids = _dedupe_aliases(vulns)
                out.append(
                    Finding(
                        severity=Severity.INFO,
                        rule="vulnerable-package",
                        title=f"{label} has {len(ids)} known vulnerabilit{'y' if len(ids) == 1 else 'ies'}",
                        location=pkg.location,
                        action="Upgrade to a fixed version; see the listed advisories.",
                        advisory=ids[0],
                        package=ref,
                        details={"advisories": ids},
                    )
                )
        return out

    # FR-16 -------------------------------------------------------------------
    def match_hashes(self, packages: list[Package], pth_files: list[PthFile]) -> list[Finding]:
        out = []
        if not self.iocs.hashes:
            return out
        for pkg in packages:
            hits = sorted({h for h in pkg.hashes if h in self.iocs.hashes})
            if hits:
                sources = sorted(set().union(*(self.iocs.hashes[h] for h in hits)))
                out.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        rule="ioc-hash",
                        title=f"{pkg.name} {pkg.version} contains files with known-malicious hashes",
                        location=pkg.location,
                        action=package_action(pkg),
                        advisory=sources[0],
                        package=pkg.to_dict(include_hashes=False),
                        details={"hashes": hits, "sources": sources},
                    )
                )
        for pth in pth_files:
            if pth.sha256 in self.iocs.hashes:
                sources = sorted(self.iocs.hashes[pth.sha256])
                out.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        rule="ioc-hash",
                        title=f"Known-malicious .pth file {pth.path.name}",
                        location=str(pth.path),
                        action=IOC_FILE_ACTION,
                        advisory=sources[0],
                        details={"hashes": [pth.sha256], "sources": sources, "environment": str(pth.env)},
                    )
                )
        return out

    # FR-17 -------------------------------------------------------------------
    def match_pth(self, pth_files: list[PthFile]) -> list[Finding]:
        out = []
        for pth in pth_files:
            if pth.sha256 in self.iocs.hashes or pth.path.name in self.iocs.file_names:
                continue  # already reported as critical
            lines = pth_exec_lines(pth.content)
            if not lines or pth_allowed(pth, lines, self.pth_allowlist):
                continue
            suspicious = any(_SUSPICIOUS.search(ln) for ln in lines)
            out.append(
                Finding(
                    severity=Severity.HIGH,
                    rule="pth-exec",
                    title=f".pth file {pth.path.name} executes code at interpreter start"
                    + (" (obfuscation/network/exec patterns)" if suspicious else ""),
                    location=str(pth.path),
                    action=PTH_ACTION,
                    details={
                        "environment": str(pth.env),
                        "sha256": pth.sha256,
                        "lines": [ln[:200] for ln in lines[:5]],
                        "suspicious": suspicious,
                    },
                )
            )
        return out

    # FR-18 -------------------------------------------------------------------
    def match_files(self, packages: list[Package], site_entries: list[tuple[Path, Path]]) -> list[Finding]:
        """IOC file names inside installs. `site_entries` is (entry path, env root)."""
        out: dict[str, Finding] = {}
        names = self.iocs.file_names
        hashed = self.iocs.hashed_file_names

        def report(path: str, sources: list[str], severity: Severity, title: str, details: dict) -> None:
            out.setdefault(
                path,
                Finding(severity, "ioc-file", title, path, IOC_FILE_ACTION,
                        advisory=sources[0], details={"sources": sources, **details}),
            )

        for entry, env in site_entries:
            name = entry.name
            if name in names:
                report(str(entry), sorted(names[name]), Severity.CRITICAL, f"IOC file {name} present in {env}", {"environment": str(env)})
            elif name in hashed and entry.is_file():
                digest = file_digest(entry)
                srcs = sorted(a for a, ds in hashed[name].items() if digest in ds)
                if srcs:
                    report(str(entry), srcs, Severity.CRITICAL, f"IOC file {name} present in {env}",
                           {"environment": str(env), "sha256": digest})
        for pkg in packages:
            for rel in pkg.files:
                name = PurePosixPath(rel).name
                if name in names:
                    base = Path(pkg.location).parent if pkg.source_type is SourceType.ENVIRONMENT else Path(pkg.location)
                    loc = str(base / rel) if pkg.source_type is not SourceType.IMAGE else f"{pkg.container}:{rel}"
                    report(loc, sorted(names[name]), Severity.CRITICAL,
                           f"IOC file {name} shipped by {pkg.name} {pkg.version}", {"package": f"{pkg.name}@{pkg.version}"})
        return [out[k] for k in sorted(out)]

    def match_persistence(self, homes: list[Path] | None = None) -> list[Finding]:
        out = []
        homes = homes if homes is not None else home_dirs()
        for raw, sources in sorted(self.iocs.paths.items()):
            candidates = [h / raw[2:] for h in homes] if raw.startswith("~/") else [Path(raw)]
            for p in candidates:
                try:
                    exists = os.path.lexists(p)
                except OSError:
                    exists = False
                if exists:
                    out.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            rule="ioc-persistence",
                            title=f"Persistence / dropped file from IOC profile: {raw}",
                            location=str(p),
                            action=PERSIST_ACTION,
                            advisory=sorted(sources)[0],
                            details={"sources": sorted(sources), "sha256": file_digest(p) if p.is_file() else None},
                        )
                    )
        return out

    # FR-19 -------------------------------------------------------------------
    def match_logs(self, logs: list[Path]) -> list[Finding]:
        if not logs or not self.iocs.domains:
            return []
        domains = sorted(self.iocs.domains)
        pattern = re.compile(
            r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)*(" + "|".join(re.escape(d) for d in domains) + r")(?![A-Za-z0-9-])",
            re.IGNORECASE,
        )
        hits: dict[tuple[str, str], list[int]] = {}
        for path in _expand_logs(logs, self.warnings):
            opener = gzip.open if path.suffix == ".gz" else open
            try:
                with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        for m in pattern.finditer(line):
                            hits.setdefault((str(path), m.group(1).lower()), []).append(lineno)
            except (OSError, EOFError) as exc:
                self.warnings.add(path, f"cannot read log: {exc}")
        out = []
        for (path, domain), lines in sorted(hits.items()):
            sources = sorted(self.iocs.domains.get(domain, {"?"}))
            out.append(
                Finding(
                    severity=Severity.CRITICAL,
                    rule="ioc-domain",
                    title=f"Log shows contact with IOC domain {domain} ({len(lines)} line(s))",
                    location=f"{path}:{lines[0]}",
                    action=DOMAIN_ACTION,
                    advisory=sources[0],
                    details={"domain": domain, "lines": lines[:20], "sources": sources},
                )
            )
        return out


def _expand_logs(paths: list[Path], warnings: Warnings) -> list[Path]:
    out = []
    for p in paths:
        if p.is_dir():
            out += sorted(f for f in p.rglob("*") if f.is_file())
        elif p.exists():
            out.append(p)
        else:
            warnings.add(p, "log path not found")
    return out


def _dedupe_aliases(vulns: dict[str, list[str]]) -> list[str]:
    """Collapse advisories that describe the same issue (GHSA/PYSEC/CVE aliases)."""
    kept: list[str] = []
    covered: set[str] = set()
    for adv_id in sorted(vulns, key=lambda i: (not i.startswith("GHSA-"), i)):
        if adv_id in covered:
            continue
        kept.append(adv_id)
        covered.add(adv_id)
        covered.update(vulns[adv_id])
    return sorted(kept)


def dedupe(findings: list[Finding]) -> list[Finding]:
    by_fp: dict[str, Finding] = {}
    for f in findings:
        by_fp.setdefault(f.fingerprint, f)
    return sorted(by_fp.values(), key=Finding.sort_key)
