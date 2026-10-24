"""Signals, scoring and findings for network events (MON-8 to MON-17, MON-21, MON-25)."""

from __future__ import annotations

import hashlib
import ipaddress
import time
from collections.abc import Callable
from datetime import UTC, datetime

from ..config import MonitorConfig
from ..models import Finding, Severity
from .domains import BRANDS, DEFAULT_ALLOW, Suffixes, is_ip, lookalike, matches_domain
from .enrich import RegistrationAge, match_indicator
from .store import Event, MonitorStore

MONITORED = ("package_manager", "interpreter", "container")
METADATA_IPS = {"169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200"}

WEIGHTS = {
    "threat_feed": 100,
    "cloud_metadata": 50,
    "lookalike": 40,
    "newly_registered": 40,
    "direct_ip": 30,
    "out_of_baseline": 25,
    "first_seen": 15,
}
THRESHOLDS = [(90, Severity.CRITICAL), (60, Severity.HIGH), (35, Severity.MEDIUM), (15, Severity.LOW)]
RULES = {
    "threat_feed": "network-threat",
    "cloud_metadata": "network-cloud-metadata",
    "lookalike": "network-lookalike",
    "newly_registered": "network-new-domain",
    "direct_ip": "network-direct-ip",
    "out_of_baseline": "network-out-of-baseline",
    "first_seen": "network-first-seen",
}


def severity_for(score: int) -> Severity | None:
    for limit, sev in THRESHOLDS:
        if score >= limit:
            return sev
    return None


def _non_routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if ip in METADATA_IPS:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_unspecified


class Detector:
    def __init__(
        self,
        store: MonitorStore,
        cfg: MonitorConfig,
        indicators: dict[str, set[str]],
        suffixes: Suffixes | None = None,
        rdap: RegistrationAge | None = None,
        on_finding: Callable[[dict, bool], None] | None = None,
    ) -> None:
        self.store = store
        self.cfg = cfg
        self.indicators = indicators
        self.suffixes = suffixes or Suffixes()
        self.rdap = rdap
        self.on_finding = on_finding
        self.brands = {**BRANDS, **{k.lower(): v for k, v in cfg.brands.items()}}
        self._allow_cache: dict[str, tuple[float, set[str]]] = {}
        for entry in cfg.allow:  # MON-18: allowlist entries from the config file
            store.allow(entry.get("category", "*"), entry["domain"], "config")

    # --- allowlist ----------------------------------------------------------
    def allowed(self, name: str, category: str) -> bool:
        cached = self._allow_cache.get(category)
        if cached is None or time.monotonic() - cached[0] > 30:
            removed = self.store.removed_defaults()
            rules = {d for d in DEFAULT_ALLOW if d not in removed} | self.store.allowed_domains(category)
            cached = (time.monotonic(), rules)
            self._allow_cache[category] = cached
        rules = cached[1]
        if is_ip(name):
            addr = ipaddress.ip_address(name)
            for r in rules:
                try:
                    if addr in ipaddress.ip_network(r, strict=False):
                        return True
                except ValueError:
                    continue
            return False
        return any(matches_domain(name, r) for r in rules)

    def invalidate_allowlist(self) -> None:
        self._allow_cache.clear()

    def in_learning(self, ts: float) -> bool:
        start = self.store.get_meta("learning_start")
        if start is None:
            self.store.set_meta("learning_start", ts)
            start = ts
        return ts - float(start) < self.cfg.learning_days * 86400

    # --- main entry ---------------------------------------------------------
    def handle(self, ev: Event, retro: bool = False) -> dict | None:
        """Score one event, store it, and create or update its finding. Returns the finding if any."""
        target = ev.target.rstrip(".").lower()
        if not target:
            return None
        ev.rd = ev.rd or (self.suffixes.registered(target) if ev.name else target)
        category = ev.category
        browser = category == "browser"
        if not retro:
            self.store.add_event(ev)
        signals: list[dict] = []

        # MON-8: threat feeds and IOC profiles, for every category including browsers (MON-17).
        hits = []
        for value in [target, *ev.answers] if ev.kind == "dns" else [target]:
            hit = match_indicator(value, self.indicators)
            if hit:
                hits.append(hit)
        if hits:
            sources = sorted({s for _, srcs in hits for s in srcs})
            signals.append({"signal": "threat_feed", "detail": f"{hits[0][0]} listed by {', '.join(sources)}",
                            "sources": sources})

        allowed = self.allowed(target, category)
        first_seen = False if retro else self.store.mark_seen(ev.rd, ev.ts)
        learning = self.in_learning(ev.ts)
        skip_heuristics = browser and self.cfg.exclude_browsers

        if not allowed and not skip_heuristics:
            if ev.kind == "dns":
                why = lookalike(target, ev.rd, self.brands)
                if why:
                    signals.append({"signal": "lookalike", "detail": why})
            else:
                if ev.dst_ip in METADATA_IPS and category in (*MONITORED, "other"):
                    signals.append({"signal": "cloud_metadata", "detail": f"cloud metadata endpoint {ev.dst_ip}"})
                elif category in MONITORED and not _non_routable(ev.dst_ip):
                    signals.append({"signal": "direct_ip",
                                    "detail": f"connection to {ev.dst_ip}:{ev.dst_port} with no DNS lookup"})
            if category in MONITORED and ev.kind == "dns":
                if first_seen and not learning:
                    signals.append({"signal": "first_seen", "detail": f"{ev.rd} never seen on this host before"})
                if not learning:
                    signals.append({"signal": "out_of_baseline",
                                    "detail": f"{ev.rd} is not in the {category} baseline"})
            elif first_seen and not learning and ev.kind == "dns" and category in ("other", "unknown"):
                signals.append({"signal": "first_seen", "detail": f"{ev.rd} never seen on this host before"})

            # MON-9: only domains that already look unusual are sent to RDAP.
            if ev.kind == "dns" and signals and self.rdap is not None:
                created = self.rdap.created(ev.rd)
                if created is not None:
                    age = (datetime.fromtimestamp(ev.ts, UTC) - created).days
                    if 0 <= age <= self.cfg.new_domain_days:
                        signals.append({"signal": "newly_registered",
                                        "detail": f"{ev.rd} registered {created.date()} ({age} days before)"})

        # MON-14: learn the per-category baseline from quiet traffic during the learning period.
        if learning and not retro and category in MONITORED and ev.kind == "dns" and not signals:
            self.store.allow(category, ev.rd, "learned", ts=ev.ts)
            self.invalidate_allowlist()

        if not signals:
            return None
        return self._record(ev, category, signals, retro)

    # --- scoring and findings ------------------------------------------------
    def score(self, category: str, signals: list[dict]) -> tuple[int, Severity | None]:
        names = {s["signal"] for s in signals}
        factor = 1.0 if category in MONITORED else 0.6
        raw = sum(WEIGHTS[n] for n in names)
        score = int(round(raw * (1.0 if "threat_feed" in names else factor)))
        sev = severity_for(score)
        # MON-13 / MON-19 escalations.
        if "threat_feed" in names or (category in ("interpreter", "package_manager") and "lookalike" in names
              and names & {"first_seen", "newly_registered"}):
            sev = Severity.CRITICAL
        return score, sev

    def _record(self, ev: Event, category: str, signals: list[dict], retro: bool) -> dict | None:
        score, sev = self.score(category, signals)
        if sev is None:
            return None
        proc = ev.process
        scope = proc.get("env") or proc.get("container") or proc.get("exe") or proc.get("name") or "?"
        fid = hashlib.sha256(f"{ev.rd}|{category}|{scope}".encode()).hexdigest()[:16]
        existing = self.store.get_finding(fid)
        now_names = sorted({s["signal"] for s in signals})
        if existing:
            f = existing
            data = f["data"]
            prev_sev = Severity(f["severity"])
            data["names"] = sorted(set(data.get("names", [])) | ({ev.name} if ev.name else set()))[:20]
            data["ips"] = sorted(set(data.get("ips", [])) | set(ev.answers) | ({ev.dst_ip} if ev.dst_ip else set()))[:20]
            merged = {s["signal"]: s for s in data.get("signals", [])}
            merged.update({s["signal"]: s for s in signals})
            data["signals"] = [merged[k] for k in sorted(merged)]
            score, sev2 = self.score(category, data["signals"])
            sev = sev2 or sev
            escalated = sev.rank < prev_sev.rank
            f.update(last_ts=max(f["last_ts"], ev.ts), first_ts=min(f["first_ts"], ev.ts), count=f["count"] + 1,
                     score=max(score, f["score"]), severity=(sev if escalated else prev_sev).value)
            if f["status"] != "open" and escalated:
                f["status"] = "open"  # re-open a dismissed finding when it gets worse
            data["process"] = _process_view(proc)
            is_new = escalated
        else:
            data = {
                "domain": ev.rd,
                "names": [ev.name] if ev.name else [],
                "ips": sorted(set(ev.answers) | ({ev.dst_ip} if ev.dst_ip else set())),
                "kind": ev.kind,
                "category": category,
                "process": _process_view(proc),
                "env": proc.get("env", ""),
                "container": proc.get("container", ""),
                "image": proc.get("image", ""),
                "signals": signals,
                "source": ev.source,
                "retroactive": retro,
            }
            f = {"id": fid, "first_ts": ev.ts, "last_ts": ev.ts, "count": 1, "severity": sev.value, "score": score,
                 "status": "open", "data": data, "notified": 0}
            is_new = True
        data["primary"] = _primary(now_names if not existing else [s["signal"] for s in data["signals"]])
        self.store.put_finding(f)
        if self.on_finding is not None:
            self.on_finding(f, is_new)
        return f

    # --- MON-25 ------------------------------------------------------------------
    def retro_check(self) -> list[dict]:
        """Search stored history for indicators added since the last check."""
        checked = set(self.store.get_meta("ioc_checked", []))
        new = {k: v for k, v in self.indicators.items() if k not in checked}
        if not new:
            return []
        out = []
        with self.store.lock:
            names = [r[0] for r in self.store.conn.execute(
                "SELECT DISTINCT name FROM events WHERE name != '' UNION SELECT DISTINCT dst_ip FROM events "
                "WHERE dst_ip != ''")]
        hit_names = sorted({n for n in names if match_indicator(n, new)})
        saved, self.indicators = self.indicators, new
        try:
            for name in hit_names:
                for ev in self.store.events_for_domain(name):
                    f = self.handle(ev, retro=True)
                    if f is not None and f not in out:
                        out.append(f)
        finally:
            self.indicators = saved
        self.store.set_meta("ioc_checked", sorted(self.indicators))
        self.store.commit()
        return out


def _process_view(proc: dict) -> dict:
    if proc.get("category") == "browser":
        return {k: proc[k] for k in ("name", "category") if k in proc}
    return {k: proc[k] for k in ("pid", "name", "exe", "cmdline", "ppid", "parent", "via", "category")
            if proc.get(k)}


def _primary(names: list[str]) -> str:
    return min(names, key=lambda n: -WEIGHTS[n]) if names else ""


ACTIONS = {
    "threat_feed": "A process contacted a known-malicious indicator: treat {where} as compromised, rotate credentials "
                   "reachable from this host, and run `sweep scan --path {path}`.",
    "lookalike": "{who} contacted a domain imitating a known vendor. Check what it was doing; if unexpected, scan "
                 "{where} and rotate credentials. If benign: `sweep monitor benign {id}`.",
    "newly_registered": "{who} contacted a recently registered domain. If unexpected, scan {where}. If benign: "
                        "`sweep monitor benign {id}`.",
    "cloud_metadata": "{who} queried the cloud metadata endpoint, a common credential-theft step. Confirm it is "
                      "expected; otherwise scan {where} and rotate cloud credentials.",
    "direct_ip": "{who} connected to an IP address without a DNS lookup. Check the destination; if unexpected, scan "
                 "{where}. If benign: `sweep monitor benign {id}`.",
    "out_of_baseline": "{who} contacted a domain outside its baseline. Review it; if benign, "
                       "`sweep monitor benign {id}` adds it to the allowlist.",
    "first_seen": "First contact with this domain from this host. Review it; if benign, "
                  "`sweep monitor benign {id}`.",
}


def to_finding(row: dict) -> Finding:
    """A stored network finding in the scanner's Finding shape (MON-21, MON-22)."""
    d = row["data"]
    proc = d.get("process", {})
    who = f"{d['category'].replace('_', ' ')} {proc.get('name') or proc.get('exe') or 'process'}".strip()
    where = d.get("env") or (f"container {d['container']} ({d.get('image')})" if d.get("container") else "this host")
    primary = d.get("primary") or "first_seen"
    action = ACTIONS[primary].format(who=who, where=where, path=d.get("env") or "<env>", id=row["id"][:8])
    labels = ", ".join(s["signal"].replace("_", "-") for s in d.get("signals", []))
    target = d.get("names", [d["domain"]])[0] if d.get("names") else (d.get("ips") or [d["domain"]])[0]
    advisory = next((s["sources"][0] for s in d.get("signals", []) if s.get("sources")), "")
    details = {
        "id": row["id"],
        "status": row["status"],
        "count": row["count"],
        "score": row["score"],
        "first_seen": _iso(row["first_ts"]),
        "last_seen": _iso(row["last_ts"]),
        **{k: d.get(k) for k in ("domain", "names", "ips", "kind", "category", "process", "env", "container",
                                 "image", "signals", "source", "retroactive", "inventory", "targeted_scan")
           if d.get(k) not in (None, "", [], {})},
    }
    return Finding(
        severity=Severity(row["severity"]),
        rule=RULES.get(primary, "network-event"),
        title=f"{who} contacted {target} ({labels})",
        location=target,
        action=action,
        advisory=advisory,
        details=details,
    )


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")
