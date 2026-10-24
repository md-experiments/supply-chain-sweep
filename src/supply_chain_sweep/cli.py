"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .intel.osv import OsvDB, sync
from .intel.profiles import load_profiles
from .report import dump, print_summary, to_json, to_sarif
from .scanner import ScanOptions, run_scan
from .state import State
from .util import Warnings

EXIT_CLEAN, EXIT_CRITICAL, EXIT_ERROR = 0, 1, 2


def _err(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def _config(args):
    cfg = load_config(Path(args.config).expanduser() if args.config else None)
    if getattr(args, "root", None):
        roots = [Path(r).expanduser() for r in args.root]
        cfg.roots = roots if args.only_roots else cfg.roots + roots
    if getattr(args, "exclude", None):
        cfg.exclude += [Path(e).expanduser() for e in args.exclude]
    for flag, attr in (("no_caches", "caches"), ("no_lockfiles", "lockfiles"), ("no_images", "docker"),
                       ("no_hash_archives", "hash_archives")):
        if getattr(args, flag, False):
            setattr(cfg, attr, False)
    if getattr(args, "feed", None):
        cfg.feeds = args.feed
    return cfg


def cmd_update(args) -> int:
    cfg = _config(args)
    db = OsvDB(cfg.data_dir / "osv.db")
    log = (lambda _m: None) if args.quiet else (lambda m: _err(m))
    log(f"Refreshing OSV threat data ({', '.join(cfg.feeds)}) into {db.path}")
    errors = sync(db, cfg.feeds, full=args.full, log=log)
    stats = db.stats()
    db.close()
    for e in errors:
        _err(f"update failed: {e}")
    if not args.quiet:
        _err(f"{stats['advisories']} advisories cached ({stats['malicious']} malicious)")
    return EXIT_ERROR if errors else EXIT_CLEAN


def cmd_scan(args) -> int:
    cfg = _config(args)
    log = (lambda _m: None) if args.quiet else (lambda m: _err(m))
    sync_errors: list[str] = []
    if not args.offline:
        db = OsvDB(cfg.data_dir / "osv.db")
        log("refreshing threat data (use --offline to skip) ...")
        sync_errors = sync(db, cfg.feeds, log=log)
        db.close()
    options = ScanOptions(
        paths=[Path(p).expanduser() for p in args.path or []],
        profile=args.profile,
        images=not args.no_images,
        logs=[Path(p).expanduser() for p in args.logs or []],
        extra_profiles=[Path(p).expanduser() for p in args.profile_file or []],
        persist=not args.no_save,
    )
    result = run_scan(cfg, options, log=log)
    for e in sync_errors:
        result.warnings.add("osv", f"threat data refresh failed, using cached data: {e}")

    if args.json:
        dump(to_json(result, include_inventory=args.inventory), args.json)
    if args.sarif:
        dump(to_sarif(result), args.sarif)
    if not args.quiet and "-" not in (args.json, args.sarif):
        print_summary(result, verbose=args.verbose)
    elif args.quiet and result.has_critical and "-" not in (args.json, args.sarif):
        for f in result.findings:
            if f.severity.value == "critical":
                print(f"CRITICAL {f.title} @ {f.location}")

    if result.new_critical:
        _alert(result, args.alert_cmd or cfg.alert_command, args.notify)
    return EXIT_CRITICAL if result.has_critical else EXIT_CLEAN


def _alert(result, command: str, notify: bool) -> None:
    """FR-25: tell someone about critical findings that the previous scan did not have."""
    n = len(result.new_critical)
    message = f"supply-chain-sweep: {n} new critical finding(s): " + "; ".join(
        f.title for f in result.new_critical[:3]
    )
    if command:
        payload = json.dumps({"new_critical": [f.to_dict() for f in result.new_critical]}, default=str)
        try:
            subprocess.run(shlex.split(command), input=payload, text=True, timeout=60, check=False,
                           env={**__import__("os").environ, "SWEEP_NEW_CRITICAL": str(n), "SWEEP_MESSAGE": message})
        except (OSError, subprocess.TimeoutExpired) as exc:
            _err(f"alert command failed: {exc}")
    if notify:
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", "-u", "critical", "Supply chain scanner", message], check=False)
        elif shutil.which("osascript"):
            safe = message.replace('"', "'")
            subprocess.run(["osascript", "-e", f'display notification "{safe}" with title "Supply chain scanner"'],
                           check=False)
        else:
            _err(message)


def cmd_profiles(args) -> int:
    cfg = _config(args)
    warnings = Warnings()
    for p in load_profiles(cfg.profile_dirs, warnings, [Path(f) for f in args.profile_file or []]):
        pkgs = ", ".join(f"{x.name} {'/'.join(x.versions) or '*'}" for x in p.packages) or "-"
        print(f"{p.id:24} {p.name}\n{'':24} packages: {pkgs}\n{'':24} source: {p.source}")
    for w in warnings.items:
        _err(f"warning: {w.location}: {w.message}")
    return EXIT_CLEAN


def cmd_history(args) -> int:
    cfg = _config(args)
    state = State(cfg.data_dir)
    for h in state.history(args.limit):
        s = h["summary"]
        print(f"#{h['id']:<4} {h['started']}  {h['scope']:<26} packages={s.get('packages', '?')} "
              f"critical={s.get('critical', '?')} high={s.get('high', '?')} info={s.get('info', '?')}")
    state.close()
    return EXIT_CLEAN


def cmd_schedule(args) -> int:
    exe = shutil.which("sweep") or f"{sys.executable} -m supply_chain_sweep"
    cmd = f"{exe} scan --quiet --notify --json {Path.home()}/.local/share/supply-chain-sweep/last-scan.json"
    if args.alert_cmd:
        cmd += f" --alert-cmd {shlex.quote(args.alert_cmd)}"
    cron = {"hourly": "17 * * * *", "daily": "17 9 * * *"}[args.interval]
    line = f"{cron} {cmd} >/dev/null 2>&1  # supply-chain-sweep"
    if sys.platform == "darwin" and not args.cron:
        interval = 3600 if args.interval == "hourly" else 86400
        argv = "".join(f"<string>{a}</string>" for a in shlex.split(cmd))
        print(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.supply-chain-sweep.scan</string>
  <key>ProgramArguments</key><array>{argv}</array>
  <key>StartInterval</key><integer>{interval}</integer>
</dict></plist>
<!-- save as ~/Library/LaunchAgents/com.supply-chain-sweep.scan.plist, then:
     launchctl load ~/Library/LaunchAgents/com.supply-chain-sweep.scan.plist -->""")
        return EXIT_CLEAN
    if not args.install:
        print(line)
        _err("Add this line with `crontab -e`, or re-run with --install.")
        return EXIT_CLEAN
    current = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    lines = [ln for ln in current.stdout.splitlines() if "# supply-chain-sweep" not in ln]
    lines.append(line)
    subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True)
    _err(f"Installed crontab entry: {line}")
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sweep",
        description="Find known-malicious Python and npm packages on this host, and signs they ran.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--config", help="config file (default: ~/.config/supply-chain-sweep/config.toml)")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan the host (default command)")
    s.add_argument("--path", action="append", metavar="PATH", help="scan only this path (repeatable)")
    s.add_argument("--root", action="append", metavar="PATH", help="add a scan root (repeatable)")
    s.add_argument("--only-roots", action="store_true", help="with --root: replace the default roots")
    s.add_argument("--exclude", action="append", metavar="PATH", help="skip this path (repeatable)")
    s.add_argument("--profile", metavar="ID", help="check only this threat profile")
    s.add_argument("--profile-file", action="append", metavar="FILE", help="load an extra IOC profile")
    s.add_argument("--logs", action="append", metavar="PATH", help="DNS/proxy/system log file or dir to search for IOC domains")
    s.add_argument("--offline", action="store_true", help="do not refresh threat data; use the local cache")
    s.add_argument("--no-images", action="store_true", help="skip Docker images")
    s.add_argument("--no-caches", action="store_true", help="skip pip/uv/npm/conda caches")
    s.add_argument("--no-lockfiles", action="store_true", help="skip lockfiles and requirement files")
    s.add_argument("--no-hash-archives", action="store_true", help="do not hash cached archives")
    s.add_argument("--json", metavar="FILE", help="write JSON results ('-' for stdout)")
    s.add_argument("--sarif", metavar="FILE", help="write SARIF results ('-' for stdout)")
    s.add_argument("--inventory", action="store_true", help="include the full package inventory in JSON")
    s.add_argument("--no-save", action="store_true", help="do not store this scan in the local history")
    s.add_argument("--alert-cmd", metavar="CMD", help="run CMD with new critical findings as JSON on stdin")
    s.add_argument("--notify", action="store_true", help="desktop notification on new critical findings")
    s.add_argument("-v", "--verbose", action="store_true", help="list info findings, changes and warnings")
    s.add_argument("-q", "--quiet", action="store_true", help="print only critical findings")
    s.set_defaults(func=cmd_scan)

    u = sub.add_parser("update", help="refresh the local OSV threat data")
    u.add_argument("--full", action="store_true", help="re-download full exports instead of incremental")
    u.add_argument("--feed", action="append", metavar="ECOSYSTEM", help="OSV ecosystem to sync (default: PyPI, npm)")
    u.add_argument("-q", "--quiet", action="store_true")
    u.set_defaults(func=cmd_update)

    pr = sub.add_parser("profiles", help="list loaded IOC profiles")
    pr.add_argument("--profile-file", action="append", metavar="FILE")
    pr.set_defaults(func=cmd_profiles)

    h = sub.add_parser("history", help="list previous scans")
    h.add_argument("--limit", type=int, default=10)
    h.set_defaults(func=cmd_history)

    sc = sub.add_parser("schedule", help="print or install a periodic scan (cron / launchd)")
    sc.add_argument("--interval", choices=("hourly", "daily"), default="daily")
    sc.add_argument("--install", action="store_true", help="add the entry to your crontab")
    sc.add_argument("--cron", action="store_true", help="on macOS, print a cron line instead of a launchd plist")
    sc.add_argument("--alert-cmd", metavar="CMD")
    sc.set_defaults(func=cmd_schedule)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # `sweep [--config F] [scan options]` defaults to the scan command.
    i = 2 if argv[:1] == ["--config"] else 0
    if argv[i:i + 1] not in (["scan"], ["update"], ["profiles"], ["history"], ["schedule"], ["-h"], ["--help"], ["--version"]):
        argv.insert(i, "scan")
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except (FileNotFoundError, ValueError) as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
