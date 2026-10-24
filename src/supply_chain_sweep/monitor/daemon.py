"""The monitor service: capture -> attribution -> detection -> alerts (MON-19, MON-20, MON-24 to MON-26,
MON-NFR-3, MON-NFR-6, MON-NFR-8, MON-NFR-11)."""

from __future__ import annotations

import json
import os
import queue
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

from ..config import Config
from ..intel.osv import OsvDB
from ..intel.profiles import load_profiles
from ..models import Finding, Severity
from ..state import State
from ..util import Warnings
from .detect import Detector, to_finding
from .domains import Suffixes
from .enrich import RegistrationAge, ioc_indicators, update_feeds, update_psl
from .store import Event, MonitorStore

HEARTBEAT_EVERY = 30
STALE_AFTER = 180
QUIET_DNS_HOURS = 24


class Notifier:
    """Desktop notification plus optional alert command, capped per day (MON-19, MON-NFR-12)."""

    def __init__(self, cfg: Config, store: MonitorStore, log: Callable[[str], None]) -> None:
        self.cfg = cfg.monitor
        self.store = store
        self.log = log

    def send(self, title: str, body: str, payload: dict | None = None, force: bool = False) -> bool:
        day = datetime.now().strftime("%Y-%m-%d")
        key = f"alerts:{day}"
        sent = int(self.store.get_meta(key, 0))
        if sent >= self.cfg.max_alerts_per_day and not force:
            self.log(f"alert suppressed (daily cap {self.cfg.max_alerts_per_day}): {title}")
            return False
        self.store.set_meta(key, sent + 1)
        if self.cfg.alert_command:
            try:
                subprocess.run(shlex.split(self.cfg.alert_command), input=json.dumps(payload or {}, default=str),
                               text=True, timeout=60, check=False,
                               env={**os.environ, "SWEEP_ALERT_TITLE": title, "SWEEP_ALERT_BODY": body})
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.log(f"alert command failed: {exc}")
        if self.cfg.notify:
            self._desktop(title, body)
        self.log(f"ALERT {title}: {body}")
        return True

    def _desktop(self, title: str, body: str) -> None:
        user = self.cfg.notify_user or os.environ.get("SUDO_USER", "")
        try:
            if sys.platform == "darwin" and shutil.which("osascript"):
                script = f'display notification "{_q(body)}" with title "{_q(title)}"'
                cmd = ["osascript", "-e", script]
                if os.geteuid() == 0 and user:
                    import pwd

                    cmd = ["launchctl", "asuser", str(pwd.getpwnam(user).pw_uid), *cmd]
                subprocess.run(cmd, timeout=10, check=False, capture_output=True)
            elif shutil.which("notify-send"):
                cmd = ["notify-send", "-u", "critical", "-a", "supply-chain-sweep", title, body]
                if os.geteuid() == 0 and user and shutil.which("runuser"):
                    import pwd

                    uid = pwd.getpwnam(user).pw_uid
                    cmd = ["runuser", "-u", user, "--", "env", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                           *cmd]
                subprocess.run(cmd, timeout=10, check=False, capture_output=True)
        except (OSError, KeyError, subprocess.TimeoutExpired) as exc:
            self.log(f"desktop notification failed: {exc}")


def _q(text: str) -> str:
    return text.replace("\\", "").replace('"', "'")[:240]


class Monitor:
    def __init__(self, cfg: Config, log: Callable[[str], None] = lambda _m: None,
                 rdap_opener=None, scan_runner=None, extra_profiles: list[Path] = ()) -> None:
        self.cfg = cfg
        self.extra_profiles = list(extra_profiles)
        self.log = log
        self.store = MonitorStore(cfg.data_dir)
        self.warnings = Warnings()
        self.suffixes = Suffixes.load(cfg.data_dir / "public_suffix_list.dat")
        kwargs = {"opener": rdap_opener} if rdap_opener else {}
        self.rdap = RegistrationAge(self.store, cfg.monitor.rdap, cfg.monitor.rdap_per_hour, **kwargs)
        self.notifier = Notifier(cfg, self.store, log)
        self.scan_runner = scan_runner or _targeted_scan
        self.detector = Detector(self.store, cfg.monitor, self.load_indicators(), self.suffixes, self.rdap,
                                 on_finding=self._on_finding)
        self._scans: list[threading.Thread] = []
        self._stop = threading.Event()
        self._last: dict[str, float] = {}
        self._cpu = (time.monotonic(), _cpu_seconds())

    # --- indicators ----------------------------------------------------------
    def load_indicators(self) -> dict[str, set[str]]:
        profiles = load_profiles(self.cfg.profile_dirs, self.warnings, self.extra_profiles)
        osv_path = self.cfg.data_dir / "osv.db"
        osv = OsvDB(osv_path) if osv_path.exists() else None
        try:
            return ioc_indicators(profiles, osv, self.store)
        finally:
            if osv is not None:
                osv.close()

    def reload_indicators(self) -> list[dict]:
        self.detector.indicators = self.load_indicators()
        return self.detector.retro_check()  # MON-25

    # --- findings ------------------------------------------------------------
    def _on_finding(self, f: dict, is_new: bool) -> None:
        d = f["data"]
        containers = [c for c in (d.get("env"),) if c]
        if d.get("image"):
            containers += [f"docker:{d['image']}", f"docker:{d['image']}:latest"]
        if containers and "inventory" not in d:
            summary = self.inventory_link(containers)  # MON-24
            if summary:
                d["inventory"] = summary
                self.store.put_finding(f)
        if not is_new or f["severity"] != Severity.CRITICAL.value or f.get("notified"):
            return
        finding = to_finding(f)
        threat = any(s["signal"] == "threat_feed" for s in d.get("signals", []))
        if self.notifier.send(f"Supply chain monitor: {finding.severity.value}", finding.title,
                              {"finding": finding.to_dict()}, force=threat):
            f["notified"] = 1
            self.store.put_finding(f)
        if self.cfg.monitor.scan_on_critical and d.get("env") and Path(d["env"]).is_dir():  # MON-26
            t = threading.Thread(target=self._run_scan, args=(f["id"], d["env"]), daemon=True)
            t.start()
            self._scans.append(t)

    def scanner_dirs(self) -> list[Path]:
        """Scanner data dirs whose inventory can be linked: ours, and (as a root service) each user's."""
        from ..config import data_dir as user_data_dir
        from ..util import home_dirs

        dirs = [self.cfg.data_dir]
        if os.environ.get("XDG_DATA_HOME") or not os.environ.get("SWEEP_HOME"):
            dirs.append(user_data_dir())
        dirs += [h / ".local" / "share" / "supply-chain-sweep" for h in home_dirs()]
        out = []
        for d in dirs:
            if (d / "state.db").exists() and d not in out:
                out.append(d)
        return out

    def inventory_link(self, containers: list[str]) -> dict | None:
        import sqlite3

        for d in self.scanner_dirs():
            try:
                state = State(d, readonly=True)
            except sqlite3.Error:
                continue
            try:
                summary = state.container_summary(containers)
            except sqlite3.Error:
                summary = None
            finally:
                state.conn.close()
            if summary:
                summary["data_dir"] = str(d)
                return summary
        return None

    def _run_scan(self, fid: str, env: str) -> None:
        try:
            summary = self.scan_runner(self.cfg, env)
        except Exception as exc:  # noqa: BLE001 - a failed scan must not stop monitoring
            summary = {"error": str(exc)}
        f = self.store.get_finding(fid)
        if f is not None:
            f["data"]["targeted_scan"] = summary
            self.store.put_finding(f)
            self.store.commit()
        self.log(f"targeted scan of {env}: {summary}")

    def wait_for_scans(self, timeout: float = 120) -> None:
        for t in self._scans:
            t.join(timeout)

    def process(self, events: Iterable[Event]) -> int:
        n = 0
        for ev in events:
            self.detector.handle(ev)
            n += 1
            if n % 500 == 0:
                self.store.commit()
        self.store.commit()
        return n

    # --- periodic work ---------------------------------------------------------
    def _due(self, key: str, every: float, now: float) -> bool:
        if now - self._last.get(key, 0) >= every:
            self._last[key] = now
            return True
        return False

    def periodic(self, stats: dict | None = None, backend: str = "", helper_pid: int | None = None) -> None:
        now = time.time()
        if self._due("heartbeat", HEARTBEAT_EVERY, now):
            self.heartbeat(stats or {}, backend, helper_pid)
        if self._due("prune", 3600, now):
            removed = self.store.prune(self.cfg.monitor.retention_days)  # MON-NFR-3
            if removed:
                self.log(f"pruned {removed} events older than {self.cfg.monitor.retention_days} days")
        if self._due("indicators", 3600, now):
            for f in self.reload_indicators():
                self.log(f"retroactive IOC match: {to_finding(f).title}")
        if self._due("feeds", 86400, now) and self.cfg.monitor.threat_feeds:
            for err in update_feeds(self.store, self.cfg.monitor.threat_feeds, self.log):
                self.log(f"feed update failed: {err}")
        psl = self.cfg.data_dir / "public_suffix_list.dat"
        if self.cfg.monitor.psl_download and self._due("psl", 86400, now):
            if not psl.exists() or now - psl.stat().st_mtime > 30 * 86400:
                if update_psl(psl) is None:
                    self.suffixes = self.detector.suffixes = Suffixes.load(psl)
        self.maybe_digest(now)
        self.store.commit()

    def heartbeat(self, stats: dict, backend: str, helper_pid: int | None = None) -> None:
        mono, cpu = time.monotonic(), _cpu_seconds()
        pct = 100.0 * (cpu - self._cpu[1]) / max(mono - self._cpu[0], 1e-6)
        self._cpu = (mono, cpu)
        hb = self.store.get_meta("heartbeat", {})
        last_dns = hb.get("last_dns_ts", 0)
        if stats.get("dns", 0) > hb.get("dns", 0) or (stats.get("dns") and not last_dns):
            last_dns = time.time()
        rss, anon = _mem_mb()
        hrss, hanon = _mem_mb(helper_pid) if helper_pid else (0.0, 0.0)
        hcpu = _helper_cpu(helper_pid, self) if helper_pid else 0.0
        self.store.set_meta("heartbeat", {
            "ts": time.time(), "pid": os.getpid(), "backend": backend, "started": self._last.get("started", 0),
            "cpu_percent": round(pct + hcpu, 2), "rss_mb": round(rss + hrss, 1), "anon_mb": round(anon + hanon, 1),
            "helper_rss_mb": round(hrss, 1) if helper_pid else None, "last_dns_ts": last_dns, **stats,
        })
        self.store.commit()

    def maybe_digest(self, now: float) -> str | None:
        """Write the daily digest of medium and low findings once a day at digest_hour (MON-20)."""
        local = datetime.fromtimestamp(now)
        day = local.strftime("%Y-%m-%d")
        if local.hour < self.cfg.monitor.digest_hour or self.store.get_meta("last_digest") == day:
            return None
        self.store.set_meta("last_digest", day)
        text, count = digest(self.store, now - 86400)
        out = self.cfg.data_dir / "digests" / f"{day}.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        if count:
            self.notifier.send("Supply chain monitor: daily digest",
                               f"{count} medium/low network finding(s); see {out}", force=True)
        return str(out)

    # --- service loop ------------------------------------------------------------
    def run(self, backend=None) -> int:
        from .capture import MacCapture, default_backend, make_tracker

        backend = backend or default_backend(self.cfg.monitor.interfaces)
        report_unclean_stop(self.store, self.notifier)
        self._last["started"] = time.time()
        self.store.set_meta("running", {"pid": os.getpid(), "started": time.time(), "backend": backend.name})
        self.store.set_meta("expected_running", True)
        self.store.commit()

        def on_signal(signum, _frame):
            self._stop.set()

        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)

        work: queue.Queue[Event | None] = queue.Queue(maxsize=10000)
        kernel = None
        if not isinstance(backend, MacCapture) and self.cfg.monitor.attribution in ("auto", "ebpf"):
            from .ebpf import KernelAttributor

            if KernelAttributor.available():
                kernel = KernelAttributor()
                if not kernel.start():
                    self.log(f"eBPF attribution unavailable ({kernel.error}); using /proc only")
                    kernel = None
            elif self.cfg.monitor.attribution == "ebpf":
                self.log("attribution = ebpf needs root and bpftrace; using /proc only")
        tracker = make_tracker(kernel=kernel) if not isinstance(backend, MacCapture) else None
        stats = tracker.stats if tracker else {"packets": 0, "dns": 0, "events": 0}
        attribution = "macos-pktap" if tracker is None else ("ebpf+proc" if kernel else "proc")
        backend_label = f"{backend.name} ({attribution})"

        def enqueue(events) -> None:
            for ev in events:
                try:
                    work.put_nowait(ev)
                except queue.Full:
                    stats["dropped"] = stats.get("dropped", 0) + 1

        def tick() -> None:
            if tracker is not None:
                enqueue(tracker.poll(time.time()) + tracker.expire(time.time()))
            if kernel is not None and not kernel.alive():
                self.log("eBPF helper exited; attribution falls back to /proc")
            self.periodic(stats, backend_label, kernel.proc.pid if kernel is not None and kernel.proc else None)

        def worker():
            while True:
                ev = work.get()
                if ev is None:
                    break
                try:
                    self.detector.handle(ev)
                except Exception as exc:  # noqa: BLE001 - keep monitoring
                    self.log(f"detector error: {exc}")
            self.store.commit()

        wt = threading.Thread(target=worker, daemon=True)
        wt.start()
        self.log(f"monitor running ({backend_label}); data in {self.store.path}")
        try:
            self.reload_indicators()
            self._cpu = (time.monotonic(), _cpu_seconds())  # measure steady state, not start-up
            stopped = self._stop.is_set
            if isinstance(backend, MacCapture):
                for ev in backend.events(stopped, tick):
                    stats["dns"] += 1
                    stats["events"] += 1
                    work.put(ev)
            else:
                for pkt in backend.packets(stopped, tick):
                    enqueue(tracker.feed(pkt))
        except PermissionError as exc:
            self.log(f"capture needs privileges (CAP_NET_RAW): {exc}")
            self.store.set_meta("expected_running", False)
            return 2
        finally:
            work.put(None)
            wt.join(30)
            backend.close()
            if kernel is not None:
                kernel.stop()
            self.heartbeat(stats, backend_label)
            self.store.set_meta("expected_running", False)
            self.store.set_meta("clean_stop", time.time())
            self.store.commit()
        return 0

    def close(self) -> None:
        self.store.close()


def _targeted_scan(cfg: Config, env: str) -> dict:
    from ..scanner import ScanOptions, run_scan

    result = run_scan(cfg, ScanOptions(paths=[Path(env)], images=False))
    return {
        "scanned": datetime.now(UTC).isoformat(timespec="seconds"),
        "packages": len(result.packages),
        **result.counts,
        "findings": [f.title for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)][:10],
    }


def _helper_cpu(pid: int, owner) -> float:
    """CPU percent of the bpftrace helper since the previous heartbeat."""
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
            fields = fh.read().rpartition(")")[2].split()
        ticks = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        return 0.0
    now = time.monotonic()
    last = getattr(owner, "_helper_cpu", None)
    owner._helper_cpu = (now, ticks)
    if last is None:
        return 0.0
    return 100.0 * (ticks - last[1]) / max(now - last[0], 1e-6)


def _cpu_seconds() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def _mem_mb(pid: int | str = "self") -> tuple[float, float]:
    """(RSS, anonymous) memory in MB. Anonymous memory is the real cost: file pages are shared, reclaimable
    library code (most of bpftrace's RSS is LLVM)."""
    vals = {}
    try:
        with open(f"/proc/{pid}/smaps_rollup", encoding="ascii") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                if key in ("Rss", "Pss_Anon", "Anonymous"):
                    vals[key] = int(rest.split()[0]) / 1024
    except (OSError, ValueError, IndexError):
        return (_rss_mb(), _rss_mb()) if pid == "self" else (0.0, 0.0)
    return vals.get("Rss", 0.0), vals.get("Pss_Anon", vals.get("Anonymous", 0.0))


def _rss_mb() -> float:
    try:
        with open("/proc/self/statm", encoding="ascii") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1e6
    except (OSError, ValueError, IndexError):
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return r / 1e6 if sys.platform == "darwin" else r / 1e3


# --- digest and health ----------------------------------------------------------

def digest(store: MonitorStore, since: float) -> tuple[str, int]:
    rows = [r for r in store.findings("open", since) if r["severity"] in ("medium", "low")]
    day = datetime.now().strftime("%Y-%m-%d")
    lines = [f"Supply chain monitor digest for {day}: {len(rows)} medium/low finding(s)", ""]
    for r in rows:
        f = to_finding(r)
        lines.append(f"[{f.severity.value.upper()}] {f.title}  x{r['count']}  id={r['id'][:8]}")
        proc = f.details.get("process", {})
        if proc.get("cmdline"):
            lines.append(f"    process: {proc['cmdline'][:160]}")
        if f.details.get("env"):
            lines.append(f"    env:     {f.details['env']}")
    return "\n".join(lines) + "\n", len(rows)


def health(store: MonitorStore, now: float | None = None) -> dict:
    """Is the monitor running, and has capture gone quiet? (MON-NFR-11)"""
    now = now or time.time()
    hb = store.get_meta("heartbeat")
    expected = store.get_meta("expected_running", False)
    status = {"state": "never-run", "issues": []}
    if not hb:
        return status
    age = now - hb["ts"]
    status.update({k: hb.get(k) for k in ("backend", "pid", "packets", "dns", "events", "attributed", "dropped",
                                          "cpu_percent", "rss_mb", "anon_mb", "helper_rss_mb")})
    status["heartbeat_age_s"] = round(age)
    if not expected:
        status["state"] = "stopped"
    elif age < STALE_AFTER:
        status["state"] = "running"
        quiet = now - (hb.get("last_dns_ts") or hb.get("started") or now)
        if quiet > QUIET_DNS_HOURS * 3600 and now - (hb.get("started") or now) > QUIET_DNS_HOURS * 3600:
            status["issues"].append(f"no DNS traffic captured for {quiet / 3600:.0f} h: capture may be disabled")
        if (hb.get("cpu_percent") or 0) > 2.0:
            status["issues"].append(f"CPU use {hb['cpu_percent']}% is above the 2% budget")
        if (hb.get("anon_mb") or hb.get("rss_mb") or 0) > 100:
            status["issues"].append(f"memory {hb.get('anon_mb') or hb['rss_mb']} MB is above the 100 MB budget")
        if hb.get("dropped"):
            status["issues"].append(f"{hb['dropped']} events dropped under load")
    else:
        status["state"] = "stopped-unexpectedly"
        status["issues"].append(f"monitor stopped reporting {age / 60:.0f} min ago without a clean shutdown "
                                "(killed, crashed or capture disabled)")
    return status


def health_findings(store: MonitorStore) -> list[Finding]:
    st = health(store)
    out = []
    for issue in st["issues"]:
        out.append(Finding(
            severity=Severity.HIGH if st["state"] != "running" else Severity.MEDIUM,
            rule="monitor-health",
            title=f"Network monitor: {issue}",
            location=str(store.path),
            action="Check `sweep monitor status` and the service logs (journalctl -u sweep-monitor); restart it "
                   "with `systemctl restart sweep-monitor` and find out why it stopped.",
            details={"state": st["state"]},
        ))
    return out


def report_unclean_stop(store: MonitorStore, notifier: Notifier | None) -> dict | None:
    """At start-up, record a gap left by a monitor that was killed (MON-NFR-11)."""
    hb = store.get_meta("heartbeat")
    if not hb or not store.get_meta("expected_running", False):
        return None
    gap = time.time() - hb["ts"]
    if gap < STALE_AFTER:
        return None
    gaps = store.get_meta("gaps", [])
    gaps.append({"from": hb["ts"], "to": time.time()})
    store.set_meta("gaps", gaps[-50:])
    if notifier is not None:
        notifier.send("Supply chain monitor was stopped",
                      f"Monitoring was interrupted for {gap / 60:.0f} minutes without a clean shutdown.", force=True)
    return gaps[-1]
