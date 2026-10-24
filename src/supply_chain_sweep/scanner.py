"""Scan orchestration: discover, collect, match, persist."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .collectors import Context
from .collectors.caches import scan_npm_cache, scan_pip_cache, scan_uv_cache
from .collectors.conda import scan_conda_env, scan_conda_pkgs
from .collectors.docker import scan_images
from .collectors.lockfiles import scan_lockfile
from .collectors.npm import scan_node_modules
from .collectors.python import PthFile, scan_site_dir
from .config import Config
from .discovery import Discovery, discover
from .intel.osv import OsvDB
from .intel.profiles import Profile, load_profiles
from .matching import Matcher, dedupe
from .models import Finding, Package, Severity, SourceType
from .state import Diff, State
from .util import Warnings


@dataclass
class ScanOptions:
    paths: list[Path] = field(default_factory=list)  # FR-24: restrict to these paths
    profile: str | None = None  # FR-24: only this threat profile
    images: bool = True
    logs: list[Path] = field(default_factory=list)
    extra_profiles: list[Path] = field(default_factory=list)
    persist: bool = True


@dataclass
class ScanResult:
    started: str
    scope: str
    packages: list[Package]
    findings: list[Finding]
    warnings: Warnings
    discovery: Discovery
    diff: Diff | None
    new_critical: list[Finding]
    intel: dict
    profiles: list[Profile]
    images: int = 0
    scan_id: int | None = None

    @property
    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    @property
    def has_critical(self) -> bool:
        return any(f.severity is Severity.CRITICAL for f in self.findings)


def _scope(options: ScanOptions) -> str:
    if not options.paths and not options.profile:
        return "full"
    raw = "|".join(sorted(str(p) for p in options.paths)) + "#" + (options.profile or "")
    return "filtered:" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def run_scan(cfg: Config, options: ScanOptions, log: Callable[[str], None] = lambda _m: None) -> ScanResult:
    started = datetime.now(UTC).isoformat(timespec="seconds")
    warnings = Warnings()
    state = State(cfg.data_dir)
    ctx = Context(warnings=warnings, hasher=state.cached_digest, hash_archives=cfg.hash_archives)

    restrict = bool(options.paths)
    roots = [p.expanduser() for p in options.paths] if restrict else cfg.roots
    for p in roots:
        if restrict and not p.exists():
            warnings.add(p, "scan path does not exist")
    log("discovering environments, caches and lockfiles ...")
    found = discover(roots, cfg.exclude, warnings, include_caches=cfg.caches, restrict=restrict, max_depth=cfg.max_depth)

    # --- collect (I/O bound; threads keep NFR-6 in reach) ------------------
    packages: list[Package] = []
    pth_files: list[PthFile] = []
    site_entries: list[tuple[Path, Path]] = []
    jobs: list[Callable[[], object]] = []
    for site in found.site_dirs:
        jobs.append(lambda s=site: ("site", s, scan_site_dir(s.path, s.env, ctx)))
    for env in found.conda_envs:
        jobs.append(lambda e=env: ("pkgs", None, scan_conda_env(e, ctx)))
    for pkgs in found.conda_pkg_dirs:
        jobs.append(lambda d=pkgs: ("pkgs", None, scan_conda_pkgs(d, ctx)))
    for cache in found.pip_caches:
        jobs.append(lambda c=cache: ("pkgs", None, scan_pip_cache(c, ctx)))
    for cache in found.uv_caches:
        jobs.append(lambda c=cache: ("pkgs", None, scan_uv_cache(c, ctx)))
    for cache in found.npm_caches:
        jobs.append(lambda c=cache: ("pkgs", None, scan_npm_cache(c, ctx)))
    for nm in found.node_modules:
        jobs.append(lambda n=nm: ("pkgs", None, scan_node_modules(n, ctx)))
    if cfg.lockfiles:
        for lf in found.lockfiles:
            jobs.append(lambda f=lf: ("pkgs", None, scan_lockfile(f, ctx)))

    image_count = 0
    if options.images and cfg.docker and not restrict:
        def docker_job():
            def get(i):
                with state.lock:
                    return state.sbom_get(i)

            def put(i, s):
                with state.lock:
                    state.sbom_put(i, s)

            pkgs, imgs = scan_images(ctx, get, put)
            return ("images", len(imgs), pkgs)

        jobs.append(docker_job)

    log(
        f"collecting from {len(found.site_dirs)} site dirs, {len(found.conda_envs)} conda envs, "
        f"{len(found.node_modules)} node_modules, {len(found.lockfiles)} lockfiles, "
        f"{len(found.pip_caches) + len(found.uv_caches) + len(found.npm_caches) + len(found.conda_pkg_dirs)} caches ..."
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        for kind, meta, result in pool.map(lambda j: j(), jobs):
            if kind == "site":
                packages += result.packages
                pth_files += result.pth_files
                site_entries += [(e, meta.env) for e in result.entries]
            elif kind == "images":
                image_count = meta
                packages += result
            else:
                packages += result

    packages = _unique(packages)
    pth_files.sort(key=lambda p: str(p.path))
    site_entries.sort()

    # --- intel ---------------------------------------------------------------
    osv_path = cfg.data_dir / "osv.db"
    osv = OsvDB(osv_path) if osv_path.exists() else None
    intel = {"feeds": {}, "stats": {}}
    if osv is not None:
        intel["feeds"] = {k: {"last_modified": v[0], "synced_at": v[1]} for k, v in osv.feed_state().items()}
        intel["stats"] = osv.stats()
    if osv is None or not intel["feeds"]:
        warnings.add(str(osv_path), "no threat data cached; run `sweep update` (only IOC profiles were checked)")

    profiles = load_profiles(cfg.profile_dirs, warnings, options.extra_profiles)
    if options.profile:
        profiles = [p for p in profiles if p.id == options.profile]
        if not profiles:
            raise SystemExit(f"unknown profile: {options.profile}")
        osv_for_match = None
    else:
        osv_for_match = osv

    log(f"matching {len(packages)} packages ...")
    matcher = Matcher(osv_for_match, profiles, cfg.pth_allowlist, warnings)
    findings = matcher.match_packages(packages)
    findings += matcher.match_hashes(packages, pth_files)
    if not options.profile:
        findings += matcher.match_pth(pth_files)
    findings += matcher.match_files(packages, site_entries)
    if not restrict:
        findings += matcher.match_persistence()
    findings += matcher.match_logs(list(cfg.logs) + list(options.logs))
    findings = dedupe(findings)
    if osv is not None:
        osv.close()

    scope = _scope(options)
    diff = state.diff(scope, packages)
    previous = state.previous_findings(scope)
    new_critical = [f for f in findings if f.severity is Severity.CRITICAL and f.fingerprint not in previous]

    result = ScanResult(
        started=started, scope=scope, packages=packages, findings=findings, warnings=warnings,
        discovery=found, diff=diff, new_critical=new_critical, intel=intel, profiles=profiles,
        images=image_count,
    )
    if options.persist:
        summary = {"packages": len(packages), **result.counts}
        result.scan_id = state.save_scan(scope, started, packages, findings, summary)
    else:
        state.conn.commit()
    state.close()
    return result


def _unique(packages: list[Package]) -> list[Package]:
    seen: dict[tuple, Package] = {}
    for p in packages:
        seen.setdefault((p.ecosystem.value, p.name, p.version, p.source_type.value, p.location), p)
    order = {s: i for i, s in enumerate(SourceType)}
    return sorted(seen.values(), key=lambda p: (order[p.source_type], p.container, p.location, p.name, p.version))
