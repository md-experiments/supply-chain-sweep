"""Human-readable summary, JSON and SARIF output (FR-21, FR-22)."""

from __future__ import annotations

import json
import os
import sys
from typing import TextIO

from . import __version__
from .models import Finding, Severity
from .scanner import ScanResult

_COLORS = {Severity.CRITICAL: "\033[1;31m", Severity.HIGH: "\033[33m", Severity.INFO: "\033[36m"}
_RESET = "\033[0m"


def _use_color(stream: TextIO) -> bool:
    return stream.isatty() and not os.environ.get("NO_COLOR")


def print_summary(result: ScanResult, stream: TextIO = sys.stdout, verbose: bool = False) -> None:
    color = _use_color(stream)

    def tag(sev: Severity) -> str:
        label = sev.value.upper()
        return f"{_COLORS[sev]}{label}{_RESET}" if color else label

    w = stream.write
    d = result.discovery
    envs = d.environments()
    w(f"supply-chain-sweep {__version__}\n")
    w(
        f"Scanned {len(result.packages)} packages in {len(envs)} environments, "
        f"{len(d.node_modules)} node_modules trees, {len(d.lockfiles)} lockfiles, "
        f"{len(d.pip_caches) + len(d.uv_caches) + len(d.npm_caches) + len(d.conda_pkg_dirs)} caches, "
        f"{result.images} images\n"
    )
    feeds = result.intel.get("feeds") or {}
    if feeds:
        synced = ", ".join(f"{k} (synced {v['synced_at']})" for k, v in sorted(feeds.items()))
        w(f"Threat data: {result.intel['stats'].get('advisories', 0)} OSV advisories "
          f"({result.intel['stats'].get('malicious', 0)} malicious) - {synced}\n")
    w(f"Profiles: {', '.join(p.id for p in result.profiles) or 'none'}\n\n")

    shown = [f for f in result.findings if verbose or f.severity is not Severity.INFO]
    for f in shown:
        w(f"[{tag(f.severity)}] {f.title}\n")
        w(f"    where:  {f.location}\n")
        if f.advisory:
            ids = f.details.get("advisories") or f.details.get("sources") or [f.advisory]
            w(f"    why:    {', '.join(ids)}\n")
        if f.rule == "pth-exec":
            for ln in f.details.get("lines", [])[:3]:
                w(f"    code:   {ln[:120]}\n")
        w(f"    action: {f.action}\n\n")

    info = [f for f in result.findings if f.severity is Severity.INFO]
    if info and not verbose:
        w(f"{len(info)} package(s) with ordinary known vulnerabilities (info); use --verbose or --json to list them.\n\n")

    if result.diff and result.diff.previous_scan is not None:
        df = result.diff
        w(f"Since previous scan #{df.previous_scan}: {len(df.added)} added, {len(df.changed)} changed, "
          f"{len(df.removed)} removed\n")
        for item in (df.added[:10] if verbose else df.added[:5]):
            w(f"    + {item['name']} {item['version']}  {item['location']}\n")
        for item in df.changed[:10 if verbose else 5]:
            w(f"    ~ {item['after']['name']} {item['before']['version']} -> {item['after']['version']}  "
              f"{item['after']['location']}\n")
        w("\n")

    if result.warnings.items:
        w(f"{len(result.warnings.items)} warning(s) (locations skipped or unreadable)" + (":\n" if verbose else "; use --verbose to list.\n"))
        if verbose:
            for wn in result.warnings.items:
                w(f"    ! {wn.location}: {wn.message}\n")

    c = result.counts
    verdict = "COMPROMISE INDICATORS FOUND" if result.has_critical else "No known-malicious packages or IOCs found"
    w(f"\n{verdict}: {c['critical']} critical, {c['high']} high, {c['info']} info\n")


def to_json(result: ScanResult, include_inventory: bool = False) -> dict:
    out = {
        "tool": {"name": "supply-chain-sweep", "version": __version__},
        "scan": {"started": result.started, "scope": result.scope, "id": result.scan_id},
        "summary": {"packages": len(result.packages), "images": result.images, **result.counts},
        "intel": result.intel,
        "profiles": [p.id for p in result.profiles],
        "findings": [f.to_dict() for f in result.findings],
        "new_critical": [f.fingerprint for f in result.new_critical],
        "warnings": [w.to_dict() for w in result.warnings.items],
    }
    if result.diff and result.diff.previous_scan is not None:
        out["changes"] = {
            "previous_scan": result.diff.previous_scan,
            "added": result.diff.added,
            "changed": result.diff.changed,
            "removed": result.diff.removed,
        }
    if include_inventory:
        out["inventory"] = [p.to_dict() for p in result.packages]
    return out


_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "warning", Severity.INFO: "note"}
_RULES = {
    "malicious-package": "Known-malicious package version",
    "ioc-hash": "File hash matches a known-malicious file",
    "ioc-file": "IOC file present",
    "ioc-persistence": "Persistence path or dropped file from an IOC profile",
    "ioc-domain": "Log entry mentions an IOC domain",
    "pth-exec": ".pth file executes code at interpreter start",
    "vulnerable-package": "Package version with known vulnerabilities",
}


def _sarif_location(f: Finding) -> dict:
    loc = f.location
    line = None
    if f.rule == "ioc-domain" and ":" in loc:
        loc, _, ln = loc.rpartition(":")
        line = int(ln) if ln.isdigit() else None
    phys: dict = {"artifactLocation": {"uri": ("file://" + loc) if loc.startswith("/") else loc}}
    if line:
        phys["region"] = {"startLine": line}
    return {"physicalLocation": phys}


def to_sarif(result: ScanResult) -> dict:
    rules_used = sorted({f.rule for f in result.findings})
    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.rule,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}. {f.action}"},
            "locations": [_sarif_location(f)],
            "partialFingerprints": {"sweepFingerprint/v1": f.fingerprint},
            "properties": {"severity": f.severity.value, "advisory": f.advisory, **({"package": f.package} if f.package else {})},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "supply-chain-sweep",
                "version": __version__,
                "informationUri": "https://github.com/md-experiments/supply-chain-sweep",
                "rules": [{"id": r, "shortDescription": {"text": _RULES.get(r, r)}} for r in rules_used],
            }},
            "results": results,
        }],
    }


def dump(data: dict, path: str) -> None:
    text = json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
    if path == "-":
        sys.stdout.write(text)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
