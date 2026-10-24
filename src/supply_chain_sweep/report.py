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


def print_findings(findings: list[Finding], stream: TextIO = sys.stdout, verbose: bool = False,
                   heading: str = "") -> None:
    """Plain list of findings, used by the monitor and the combined report."""
    color = _use_color(stream)
    w = stream.write
    if heading:
        w(f"{heading}\n\n")
    shown = [f for f in findings if verbose or f.severity is not Severity.INFO]
    for f in shown:
        label = f.severity.value.upper()
        w(f"[{_COLORS.get(f.severity, '') + label + _RESET if color and f.severity in _COLORS else label}] "
          f"{f.title}\n")
        d = f.details
        if f.rule.startswith("network-"):
            proc = d.get("process", {})
            w(f"    when:    {d.get('first_seen')} .. {d.get('last_seen')} (x{d.get('count')})  id={d['id'][:8]}\n")
            if d.get("ips"):
                w(f"    ips:     {', '.join(d['ips'][:5])}\n")
            if proc.get("cmdline") or proc.get("exe"):
                w(f"    process: pid {proc.get('pid', '?')} {proc.get('cmdline') or proc.get('exe')}"[:200] + "\n")
            if d.get("env") or d.get("container"):
                w(f"    env:     {d.get('env') or d.get('container') + ' (' + str(d.get('image')) + ')'}\n")
            for s in d.get("signals", []):
                w(f"    signal:  {s['signal']}: {s['detail']}\n")
            if d.get("inventory"):
                inv = d["inventory"]
                w(f"    scanner: {inv['packages']} packages in scan #{inv['scan_id']}"
                  + (f", {len(inv['findings'])} critical/high finding(s)" if inv.get("findings") else "") + "\n")
            if d.get("targeted_scan"):
                ts = d["targeted_scan"]
                w(f"    rescan:  {ts.get('critical', 0)} critical, {ts.get('high', 0)} high\n")
        else:
            w(f"    where:   {f.location}\n")
        w(f"    action:  {f.action}\n\n")
    counts = {s: sum(1 for f in findings if f.severity is s) for s in Severity}
    w(", ".join(f"{n} {s.value}" for s, n in counts.items() if n) or "no findings")
    w("\n")


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


_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "warning", Severity.MEDIUM: "warning",
                Severity.LOW: "note", Severity.INFO: "note"}
_RULES = {
    "malicious-package": "Known-malicious package version",
    "ioc-hash": "File hash matches a known-malicious file",
    "ioc-file": "IOC file present",
    "ioc-persistence": "Persistence path or dropped file from an IOC profile",
    "ioc-domain": "Log entry mentions an IOC domain",
    "pth-exec": ".pth file executes code at interpreter start",
    "vulnerable-package": "Package version with known vulnerabilities",
    "network-threat": "Process contacted a threat-listed domain or IP",
    "network-cloud-metadata": "Process queried the cloud metadata endpoint",
    "network-lookalike": "Process contacted a domain imitating a known vendor or package",
    "network-new-domain": "Process contacted a recently registered domain",
    "network-direct-ip": "Process connected to an IP without a DNS lookup",
    "network-out-of-baseline": "Process contacted a domain outside its learned baseline",
    "network-first-seen": "First contact with a domain from this host",
    "monitor-health": "Network monitor stopped or capture disabled",
}


def _sarif_location(f: Finding) -> dict:
    loc = f.location
    line = None
    if f.rule == "ioc-domain" and ":" in loc:
        loc, _, ln = loc.rpartition(":")
        line = int(ln) if ln.isdigit() else None
    if f.rule.startswith("network-"):
        loc = f"dns:{loc}" if not loc.replace(".", "").isdigit() and ":" not in loc else f"ip:{loc}"
    phys: dict = {"artifactLocation": {"uri": ("file://" + loc) if loc.startswith("/") else loc}}
    if line:
        phys["region"] = {"startLine": line}
    return {"physicalLocation": phys}


def to_sarif(result: ScanResult) -> dict:
    return sarif_for(result.findings)


def sarif_for(findings: list[Finding]) -> dict:
    rules_used = sorted({f.rule for f in findings})
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}. {f.action}"},
            "locations": [_sarif_location(f)],
            "partialFingerprints": {"sweepFingerprint/v1": f.fingerprint},
            "properties": {"severity": f.severity.value, "advisory": f.advisory,
                           **({"package": f.package} if f.package else {}),
                           **({"network": f.details} if f.rule.startswith("network-") else {})},
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
