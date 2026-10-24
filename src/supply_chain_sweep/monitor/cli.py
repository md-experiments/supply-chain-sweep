"""`sweep monitor ...` and `sweep report` commands."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from ..models import Finding, Severity
from ..report import dump, print_findings, sarif_for
from .daemon import Monitor, digest, health, health_findings
from .detect import to_finding
from .domains import DEFAULT_ALLOW
from .enrich import update_feeds, update_psl
from .ingest import ingest_file
from .procinfo import CATEGORIES as CATEGORIES_ALL
from .service import DATA_DIR, service_definition
from .store import MonitorStore

EXIT_CLEAN, EXIT_CRITICAL, EXIT_ERROR = 0, 1, 2


def monitor_dir(cfg) -> Path:
    """The monitor's data dir: $SWEEP_HOME, else the system service's dir if it exists, else the user's."""
    if os.environ.get("SWEEP_HOME"):
        return cfg.data_dir
    system = Path(DATA_DIR)
    if (system / "monitor.db").exists() and os.access(system / "monitor.db", os.R_OK):
        return system
    return cfg.data_dir


def _err(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def _store(args) -> MonitorStore:
    return MonitorStore(monitor_dir(args.cfg))


def _parse_since(text: str) -> float:
    units = {"m": 60, "h": 3600, "d": 86400}
    if text and text[-1] in units and text[:-1].replace(".", "").isdigit():
        return time.time() - float(text[:-1]) * units[text[-1]]
    return datetime.fromisoformat(text).replace(tzinfo=UTC).timestamp()


def cmd_run(args) -> int:
    cfg = args.cfg
    if args.interface:
        cfg.monitor.interfaces = args.interface
    cfg.data_dir = monitor_dir(cfg)
    mon = Monitor(cfg, log=_err)
    try:
        return mon.run()
    finally:
        mon.close()


def cmd_status(args) -> int:
    store = _store(args)
    st = health(store)
    open_rows = store.findings("open")
    st["open_findings"] = {s.value: sum(1 for r in open_rows if r["severity"] == s.value)
                           for s in Severity if s is not Severity.INFO}
    learning_start = store.get_meta("learning_start")
    if learning_start:
        left = args.cfg.monitor.learning_days * 86400 - (time.time() - learning_start)
        st["learning"] = f"{left / 86400:.1f} days left" if left > 0 else "complete"
    st["data"] = str(store.path)
    with store.lock:
        st["events_stored"] = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    store.close()
    if args.json:
        print(json.dumps(st, indent=2, default=str))
    else:
        for k, v in st.items():
            if k == "issues":
                for issue in v:
                    print(f"issue:            {issue}")
            elif v not in (None, [], ""):
                print(f"{k + ':':17} {v}")
    return EXIT_ERROR if st["state"] == "stopped-unexpectedly" else EXIT_CLEAN


def cmd_ingest(args) -> int:
    cfg = args.cfg
    cfg.data_dir = monitor_dir(cfg)
    mon = Monitor(cfg, log=_err)
    total = 0
    try:
        for path in args.file:
            try:
                n = mon.process(ingest_file(Path(path), args.format, args.category))
            except (OSError, ValueError) as exc:
                _err(f"cannot ingest {path}: {exc}")
                return EXIT_ERROR
            _err(f"{path}: {n} events")
            total += n
        mon.reload_indicators()
        mon.wait_for_scans()
        rows = [r for r in mon.store.findings("open") if r["last_ts"] >= 0]
    finally:
        mon.close()
    findings = [to_finding(r) for r in rows]
    _emit(args, findings, heading=f"Ingested {total} events")
    return EXIT_CRITICAL if any(f.severity is Severity.CRITICAL for f in findings) else EXIT_CLEAN


def _emit(args, findings: list[Finding], heading: str = "") -> None:
    findings = sorted(findings, key=Finding.sort_key)
    if getattr(args, "json", None):
        dump({"findings": [f.to_dict() for f in findings]}, args.json)
    if getattr(args, "sarif", None):
        dump(sarif_for(findings), args.sarif)
    if "-" not in (getattr(args, "json", None), getattr(args, "sarif", None)):
        print_findings(findings, verbose=getattr(args, "verbose", False), heading=heading)


def cmd_findings(args) -> int:
    store = _store(args)
    since = _parse_since(args.since) if args.since else 0.0
    rows = store.findings(None if args.all else "open", since)
    findings = [to_finding(r) for r in rows]
    if args.severity:
        rank = Severity(args.severity).rank
        findings = [f for f in findings if f.severity.rank <= rank]
    findings += health_findings(store)
    store.close()
    _emit(args, findings, heading=f"{len(rows)} network finding(s)")
    return EXIT_CRITICAL if any(f.severity is Severity.CRITICAL for f in findings) else EXIT_CLEAN


def cmd_benign(args) -> int:
    """MON-23: mark a finding benign and allowlist its domain for that process category."""
    store = _store(args)
    f = store.get_finding(args.id)
    if f is None:
        _err(f"no finding {args.id}")
        return EXIT_ERROR
    category = "*" if args.everywhere else f["data"]["category"]
    target = f["data"]["domain"]
    if not args.dismiss_only:
        store.allow(category, target, "user", note=f"benign finding {f['id'][:8]}")
    f["status"] = "dismissed" if args.dismiss_only else "benign"
    store.put_finding(f)
    store.close()
    if args.dismiss_only:
        print(f"dismissed {f['id'][:8]}")
    else:
        print(f"{f['id'][:8]} marked benign; {target} allowed for {category}")
    return EXIT_CLEAN


def cmd_allow(args) -> int:
    """MON-18: review, add and remove allowlist entries."""
    store = _store(args)
    try:
        if args.action == "add":
            for d in args.domain:
                store.allow(args.category, d, "user", note=args.note or "")
                if d.lower() in DEFAULT_ALLOW:
                    store.restore_default(d)
            print(f"allowed {', '.join(args.domain)} for {args.category}")
        elif args.action == "remove":
            for d in args.domain:
                n = store.disallow(None if args.category == "*" and args.all_categories else args.category, d)
                if d.lower() in DEFAULT_ALLOW:
                    store.remove_default(d)
                    n += 1
                print(f"{d}: removed {n} entr{'y' if n == 1 else 'ies'}")
        else:
            removed = store.removed_defaults()
            rows = [r for r in store.allowlist() if args.learned or r["source"] != "learned"]
            if args.json:
                print(json.dumps({"defaults": [d for d in DEFAULT_ALLOW if d not in removed], "entries": rows,
                                  "removed_defaults": sorted(removed)}, indent=2))
                return EXIT_CLEAN
            if not args.no_defaults:
                print("default (all categories):")
                print("  " + ", ".join(d for d in DEFAULT_ALLOW if d not in removed))
            for r in rows:
                note = f"  # {r['note']}" if r["note"] else ""
                print(f"{r['category']:16} {r['domain']:40} {r['source']}{note}")
            learned = sum(1 for r in store.allowlist() if r["source"] == "learned")
            if learned and not args.learned:
                print(f"({learned} learned baseline entries hidden; use --learned)")
    finally:
        store.close()
    return EXIT_CLEAN


def cmd_digest(args) -> int:
    store = _store(args)
    text, _n = digest(store, time.time() - args.hours * 3600)
    store.close()
    sys.stdout.write(text)
    return EXIT_CLEAN


def cmd_retro(args) -> int:
    cfg = args.cfg
    cfg.data_dir = monitor_dir(cfg)
    mon = Monitor(cfg, log=_err)
    try:
        if args.all:
            mon.store.set_meta("ioc_checked", [])
        rows = mon.reload_indicators()
    finally:
        mon.close()
    _emit(args, [to_finding(r) for r in rows], heading=f"{len(rows)} retroactive match(es) in stored DNS history")
    return EXIT_CRITICAL if any(r["severity"] == "critical" for r in rows) else EXIT_CLEAN


def cmd_feeds(args) -> int:
    store = _store(args)
    errors = update_feeds(store, args.cfg.monitor.threat_feeds, log=_err)
    if args.cfg.monitor.psl_download:
        err = update_psl(Path(store.path).parent / "public_suffix_list.dat")
        if err:
            errors.append(f"public suffix list: {err}")
    store.close()
    for e in errors:
        _err(f"update failed: {e}")
    if not args.cfg.monitor.threat_feeds:
        _err("no [monitor] threat_feeds configured; IOC profiles and OSV indicators are always used")
    return EXIT_ERROR if errors else EXIT_CLEAN


def cmd_events(args) -> int:
    store = _store(args)
    rows = store.recent_events(_parse_since(args.since), args.limit)
    store.close()
    if args.category:
        rows = [r for r in rows if r["category"] == args.category]
    for r in reversed(rows):
        proc = json.loads(r["process"])
        when = datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        who = proc.get("cmdline") or proc.get("exe") or proc.get("name") or "?"
        print(f"{when}  {r['category']:15} {(r['name'] or r['dst_ip'])[:50]:50} {who[:80]}")
    return EXIT_CLEAN


def cmd_install(args) -> int:
    path, text, commands = service_definition(args.notify_user or os.environ.get("SUDO_USER", ""))
    if not args.yes:
        print(text)
        _err(f"Save as {path} and run: " + " && ".join(" ".join(c) for c in commands))
        _err("Or re-run as root with --yes to install it.")
        return EXIT_CLEAN
    path.write_text(text, encoding="utf-8")
    for c in commands:
        subprocess.run(c, check=True)
    store = MonitorStore(Path(DATA_DIR))
    store.set_meta("installed_unit", str(path))
    store.close()
    _err(f"installed and started {path}")
    return EXIT_CLEAN


def cmd_report(args) -> int:
    """MON-27: scanner findings from the last full scan plus open monitor findings, in one report."""
    from ..state import State

    cfg = args.cfg
    findings: list[Finding] = []
    state = State(cfg.data_dir)
    scan = state.last_scan_id("full")
    if scan is not None:
        for (data,) in state.conn.execute("SELECT data FROM findings WHERE scan_id = ?", (scan,)):
            d = json.loads(data)
            findings.append(Finding(Severity(d["severity"]), d["rule"], d["title"], d["location"], d["action"],
                                    d.get("advisory", ""), d.get("package"), d.get("details", {})))
    state.close()
    mdir = monitor_dir(cfg)
    if (mdir / "monitor.db").exists():
        store = MonitorStore(mdir)
        findings += [to_finding(r) for r in store.findings("open")]
        findings += health_findings(store)
        store.close()
    heading = f"Combined report: scan #{scan}" if scan is not None else "Combined report (no full scan yet)"
    _emit(args, findings, heading=heading)
    return EXIT_CRITICAL if any(f.severity is Severity.CRITICAL for f in findings) else EXIT_CLEAN


def retro_after_update(cfg, extra_profiles: list[Path] = ()) -> list[dict]:
    """MON-25 hook for `sweep update` and `sweep scan`: check new indicators against stored DNS history."""
    mdir = monitor_dir(cfg)
    if not (mdir / "monitor.db").exists():
        return []
    cfg.data_dir, saved = mdir, cfg.data_dir
    try:
        mon = Monitor(cfg, extra_profiles=list(extra_profiles))
        try:
            return mon.reload_indicators()
        finally:
            mon.close()
    finally:
        cfg.data_dir = saved


def add_parsers(sub) -> None:
    m = sub.add_parser("monitor", help="network monitor: DNS lookups and connections per process")
    msub = m.add_subparsers(dest="monitor_command", required=True)

    r = msub.add_parser("run", help="run the monitor in the foreground (needs CAP_NET_RAW)")
    r.add_argument("--interface", action="append", metavar="IFACE", help="capture only on this interface")
    r.set_defaults(func=cmd_run)

    st = msub.add_parser("status", help="is the monitor running, and is capture healthy?")
    st.add_argument("--json", action="store_true")
    st.set_defaults(func=cmd_status)

    ing = msub.add_parser("ingest", help="import DNS logs (dnsmasq/Pi-hole, NextDNS CSV, JSON lines, pcap)")
    ing.add_argument("file", nargs="+")
    ing.add_argument("--format", choices=("auto", "dnsmasq", "nextdns", "jsonl", "pcap"), default="auto")
    ing.add_argument("--category", choices=CATEGORIES_ALL, default="unknown",
                     help="process category to assume for these events (logs have no process info)")
    ing.add_argument("--json", metavar="FILE")
    ing.add_argument("--sarif", metavar="FILE")
    ing.add_argument("-v", "--verbose", action="store_true")
    ing.set_defaults(func=cmd_ingest)

    f = msub.add_parser("findings", help="list network findings")
    f.add_argument("--all", action="store_true", help="include benign and dismissed findings")
    f.add_argument("--since", metavar="WHEN", help="e.g. 24h, 7d, or an ISO date")
    f.add_argument("--severity", choices=[s.value for s in Severity], help="minimum severity")
    f.add_argument("--json", metavar="FILE")
    f.add_argument("--sarif", metavar="FILE")
    f.add_argument("-v", "--verbose", action="store_true")
    f.set_defaults(func=cmd_findings)

    b = msub.add_parser("benign", help="mark a finding benign and allowlist its domain")
    b.add_argument("id", help="finding id (prefix is enough)")
    b.add_argument("--everywhere", action="store_true", help="allow for every category, not just this one")
    b.add_argument("--dismiss-only", action="store_true", help="dismiss without allowlisting")
    b.set_defaults(func=cmd_benign)

    a = msub.add_parser("allow", help="review or edit the allowlist")
    a.add_argument("action", choices=("list", "add", "remove"))
    a.add_argument("domain", nargs="*")
    a.add_argument("--category", choices=("*", *CATEGORIES_ALL), default="*")
    a.add_argument("--all-categories", action="store_true", help="with remove: every category")
    a.add_argument("--note")
    a.add_argument("--learned", action="store_true", help="with list: include learned baseline entries")
    a.add_argument("--no-defaults", action="store_true", help="with list: hide the built-in allowlist")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_allow)

    d = msub.add_parser("digest", help="print the digest of medium and low findings")
    d.add_argument("--hours", type=float, default=24)
    d.set_defaults(func=cmd_digest)

    rt = msub.add_parser("retro", help="search stored DNS history for newly added IOC domains")
    rt.add_argument("--all", action="store_true", help="re-check every indicator, not only new ones")
    rt.add_argument("--json", metavar="FILE")
    rt.add_argument("--sarif", metavar="FILE")
    rt.set_defaults(func=cmd_retro)

    fd = msub.add_parser("feeds", help="refresh configured threat feeds and the public suffix list")
    fd.set_defaults(func=cmd_feeds)

    ev = msub.add_parser("events", help="show recent raw events")
    ev.add_argument("--since", default="1h")
    ev.add_argument("--limit", type=int, default=200)
    ev.add_argument("--category", choices=CATEGORIES_ALL)
    ev.set_defaults(func=cmd_events)

    ins = msub.add_parser(
        "install", help="install the background service (systemd / launchd)",
        description="Prints the service definition, or installs it with --yes (as root). The service runs "
                    "with CAP_NET_RAW (packet capture), CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH (map sockets "
                    "to processes via /proc), restarts on failure, and starts at boot.")
    ins.add_argument("--yes", action="store_true", help="write the unit file and enable the service")
    ins.add_argument("--notify-user", metavar="USER", help="desktop user to notify")
    ins.set_defaults(func=cmd_install)

    rep = sub.add_parser("report", help="combined report of scanner and monitor findings")
    rep.add_argument("--json", metavar="FILE")
    rep.add_argument("--sarif", metavar="FILE")
    rep.add_argument("-v", "--verbose", action="store_true")
    rep.set_defaults(func=cmd_report)
