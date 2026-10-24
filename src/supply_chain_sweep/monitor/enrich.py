"""Enrichment: IOC domains, optional threat feeds, registration age (MON-8, MON-9, MON-NFR-2).

External services receive a single registered domain per request and nothing
else. Each one can be switched off in the config.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from ..intel.osv import OsvDB
from ..intel.profiles import Profile
from .domains import PSL_URL, is_ip, valid_hostname
from .store import MonitorStore

USER_AGENT = "supply-chain-sweep-monitor/0.2"
RDAP_URL = "https://rdap.org/domain/{}"


def _get(url: str, timeout: float = 10.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, */*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def ioc_indicators(profiles: list[Profile], osv: OsvDB | None, store: MonitorStore | None) -> dict[str, set[str]]:
    """Domain and IP indicators mapped to their sources (profile ids, OSV ids, feeds)."""
    out: dict[str, set[str]] = {}
    for p in profiles:
        for d in [*p.domains, *p.ips]:
            out.setdefault(d.lower(), set()).add(p.id)
    if osv is not None:
        for adv_id, kind, value, _note in osv.iocs():
            if kind == "domain":
                out.setdefault(value.lower(), set()).add(adv_id)
    if store is not None:
        for d, feeds in store.feed_domains().items():
            out.setdefault(d, set()).update(feeds)
    return out


def match_indicator(name: str, indicators: dict[str, set[str]]) -> tuple[str, set[str]] | None:
    """The indicator `name` falls under (exact, or a parent domain), with its sources."""
    name = name.rstrip(".").lower()
    if name in indicators:
        return name, indicators[name]
    if is_ip(name):
        return None
    parts = name.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in indicators:
            return parent, indicators[parent]
    return None


_HOSTS_LINE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)")


def parse_feed(text: str, fmt: str) -> set[str]:
    """Parse a hosts-file, plain domain list or IP list feed."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if fmt == "hosts":
            m = _HOSTS_LINE.match(line)
            value = m.group(1) if m else ""
        else:
            value = line.split()[0].strip("|^").removeprefix("||")
        value = value.lower().rstrip(".")
        if value in ("localhost", "0.0.0.0", ""):
            continue
        if is_ip(value) or valid_hostname(value):
            out.add(value)
    return out


def update_feeds(store: MonitorStore, feeds: list[dict], log: Callable[[str], None] = print,
                 opener: Callable[[str], bytes] = _get) -> list[str]:
    errors = []
    for feed in feeds:
        name, url, fmt = feed.get("name") or feed["url"], feed["url"], feed.get("format", "domains")
        try:
            domains = parse_feed(opener(url).decode("utf-8", "replace"), fmt)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            errors.append(f"{name}: {exc}")
            continue
        store.replace_feed(name, domains)
        log(f"  feed {name}: {len(domains)} indicators")
    return errors


def update_psl(path: Path, opener: Callable[[str], bytes] = _get) -> str | None:
    try:
        data = opener(PSL_URL)
    except (urllib.error.URLError, OSError) as exc:
        return str(exc)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return None


class RegistrationAge:
    """Registration date via RDAP, cached locally; at most `per_hour` lookups (MON-9)."""

    def __init__(self, store: MonitorStore, enabled: bool = True, per_hour: int = 60,
                 opener: Callable[[str], bytes] = _get) -> None:
        self.store = store
        self.enabled = enabled
        self.per_hour = per_hour
        self.opener = opener
        self._window: list[float] = []

    def created(self, domain: str) -> datetime | None:
        if is_ip(domain) or "." not in domain:
            return None
        cached = self.store.rdap_get(domain)
        if cached is not None:
            created, checked, error = cached
            if created:
                return datetime.fromisoformat(created)
            if error and time.time() - checked < 86400:
                return None
            if not error:
                return None
        if not self.enabled:
            return None
        now = time.time()
        self._window = [t for t in self._window if now - t < 3600]
        if len(self._window) >= self.per_hour:
            return None
        self._window.append(now)
        try:
            data = json.loads(self.opener(RDAP_URL.format(domain)))
        except urllib.error.HTTPError as exc:
            self.store.rdap_put(domain, "", f"http {exc.code}")
            return None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.store.rdap_put(domain, "", str(exc)[:200])
            return None
        for ev in data.get("events") or ():
            if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                try:
                    dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                except ValueError:
                    continue
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                self.store.rdap_put(domain, dt.isoformat())
                return dt
        self.store.rdap_put(domain, "", "")
        return None
