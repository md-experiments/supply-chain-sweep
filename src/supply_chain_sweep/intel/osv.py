"""Local OSV mirror (FR-11 to FR-13, NFR-4, NFR-5).

The scanner downloads OSV's public per-ecosystem exports and matches locally,
so nothing about the host (not even package names) leaves the machine. Scans
read only the local database and work offline.

First sync: ``<ecosystem>/all.zip``. Later syncs: ``modified_id.csv`` lists
records newest-first, so only records changed since the last sync are fetched.
"""

from __future__ import annotations

import io
import json
import re
import sqlite3
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from ..util import normalize_digest, normalize_name

BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
USER_AGENT = "supply-chain-sweep/0.1"
# Past this many changed records, a fresh all.zip is cheaper than per-record fetches.
INCREMENTAL_LIMIT = 3000

_MALWARE_TEXT = re.compile(r"\bmalware\b|\bmalicious (code|package|version|release)s?\b|credential[- ]harvest", re.IGNORECASE)

SCHEMA = """
CREATE TABLE IF NOT EXISTS feed_state (
    ecosystem TEXT PRIMARY KEY, last_modified TEXT, synced_at TEXT
);
CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY, modified TEXT, summary TEXT, malicious INTEGER,
    aliases TEXT, severity TEXT, refs TEXT, withdrawn TEXT
);
CREATE TABLE IF NOT EXISTS affected (
    adv_id TEXT, ecosystem TEXT, name TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS affected_pkg ON affected (ecosystem, name);
CREATE INDEX IF NOT EXISTS affected_adv ON affected (adv_id);
CREATE TABLE IF NOT EXISTS iocs (
    adv_id TEXT, kind TEXT, value TEXT, note TEXT
);
CREATE INDEX IF NOT EXISTS iocs_adv ON iocs (adv_id);
"""


@dataclass
class Advisory:
    id: str
    summary: str
    malicious: bool
    aliases: list[str]
    severity: str
    references: list[str]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "summary": self.summary,
            "malicious": self.malicious,
            "aliases": self.aliases,
            "severity": self.severity,
            "references": self.references,
        }


def is_malicious(record: dict) -> bool:
    ids = [record.get("id", "")] + list(record.get("aliases") or [])
    if any(i.startswith("MAL-") for i in ids):
        return True
    cwes = (record.get("database_specific") or {}).get("cwe_ids") or []
    if "CWE-506" in cwes:  # Embedded Malicious Code
        return True
    return bool(_MALWARE_TEXT.search(record.get("summary") or ""))


def _severity(record: dict) -> str:
    ds = record.get("database_specific") or {}
    if isinstance(ds.get("severity"), str):
        return ds["severity"].upper()
    for s in record.get("severity") or ():
        if s.get("score"):
            return s["score"]
    return ""


def extract_iocs(record: dict) -> list[tuple[str, str, str]]:
    """Pull hash, file and domain IOCs from an advisory's database_specific.iocs block."""
    iocs = (record.get("database_specific") or {}).get("iocs") or {}
    if not isinstance(iocs, dict):
        return []
    out: list[tuple[str, str, str]] = []
    for d in iocs.get("domains") or ():
        if isinstance(d, str) and d:
            out.append(("domain", d.lower(), ""))
    for u in iocs.get("urls") or ():
        host = urlparse(u).hostname if isinstance(u, str) else None
        if host:
            out.append(("domain", host.lower(), ""))
    for f in iocs.get("files") or ():
        if not isinstance(f, dict):
            continue
        note = str(f.get("note", ""))
        digests = [normalize_digest(f"{a}:{v}") for a, v in (f.get("digests") or {}).items()]
        digests = [d for d in digests if d]
        for d in digests:
            out.append(("hash", d, note))
        for p in f.get("paths") or ():
            if not isinstance(p, str):
                continue
            if f.get("source") == "DROPPED" or p.startswith(("/", "~")):
                out.append(("path", p, note))
            else:
                # Archive member: remember the file name and the digest it should have.
                out.append(("file", p.rsplit("/", 1)[-1], json.dumps({"note": note, "digests": digests})))
    return out


class OsvDB:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self._cache: dict[tuple[str, str], list[tuple[str, dict]]] = {}

    def close(self) -> None:
        self.conn.close()

    # --- writes -----------------------------------------------------------
    def upsert(self, records: Iterable[dict]) -> int:
        n = 0
        cur = self.conn.cursor()
        for rec in records:
            adv_id = rec.get("id")
            if not adv_id:
                continue
            cur.execute("DELETE FROM affected WHERE adv_id = ?", (adv_id,))
            cur.execute("DELETE FROM iocs WHERE adv_id = ?", (adv_id,))
            cur.execute(
                "INSERT OR REPLACE INTO advisories VALUES (?,?,?,?,?,?,?,?)",
                (
                    adv_id,
                    rec.get("modified", ""),
                    (rec.get("summary") or rec.get("details") or "")[:500],
                    int(is_malicious(rec)),
                    json.dumps(sorted(rec.get("aliases") or [])),
                    _severity(rec),
                    json.dumps([r.get("url") for r in rec.get("references") or [] if r.get("url")][:10]),
                    rec.get("withdrawn") or "",
                ),
            )
            for aff in rec.get("affected") or ():
                pkg = aff.get("package") or {}
                eco, name = pkg.get("ecosystem", ""), pkg.get("name", "")
                if not eco or not name:
                    continue
                eco = eco.split(":", 1)[0]  # "Debian:12" -> "Debian"
                data = {k: aff[k] for k in ("versions", "ranges") if aff.get(k)}
                cur.execute(
                    "INSERT INTO affected VALUES (?,?,?,?)",
                    (adv_id, eco, normalize_name(eco, name), json.dumps(data)),
                )
            for kind, value, note in extract_iocs(rec):
                cur.execute("INSERT INTO iocs VALUES (?,?,?,?)", (adv_id, kind, value, note))
            n += 1
        self.conn.commit()
        self._cache.clear()
        return n

    def set_feed_state(self, ecosystem: str, last_modified: str) -> None:
        now = datetime.now(UTC).isoformat(timespec="seconds")
        self.conn.execute(
            "INSERT OR REPLACE INTO feed_state VALUES (?,?,?)", (ecosystem, last_modified, now)
        )
        self.conn.commit()

    # --- reads ------------------------------------------------------------
    def feed_state(self) -> dict[str, tuple[str, str]]:
        rows = self.conn.execute("SELECT ecosystem, last_modified, synced_at FROM feed_state").fetchall()
        return {r[0]: (r[1], r[2]) for r in rows}

    def candidates(self, ecosystem: str, name: str) -> list[tuple[str, dict]]:
        key = (ecosystem, normalize_name(ecosystem, name))
        if key not in self._cache:
            rows = self.conn.execute(
                "SELECT a.adv_id, a.data FROM affected a JOIN advisories v ON v.id = a.adv_id "
                "WHERE a.ecosystem = ? AND a.name = ? AND v.withdrawn = '' ORDER BY a.adv_id",
                key,
            ).fetchall()
            self._cache[key] = [(r[0], json.loads(r[1])) for r in rows]
        return self._cache[key]

    def advisory(self, adv_id: str) -> Advisory | None:
        row = self.conn.execute(
            "SELECT id, summary, malicious, aliases, severity, refs FROM advisories WHERE id = ?", (adv_id,)
        ).fetchone()
        if not row:
            return None
        return Advisory(row[0], row[1], bool(row[2]), json.loads(row[3]), row[4], json.loads(row[5]))

    def iocs(self) -> list[tuple[str, str, str, str]]:
        """All IOCs from non-withdrawn malicious advisories: (adv_id, kind, value, note)."""
        return self.conn.execute(
            "SELECT i.adv_id, i.kind, i.value, i.note FROM iocs i JOIN advisories v ON v.id = i.adv_id "
            "WHERE v.withdrawn = '' AND v.malicious = 1 ORDER BY i.adv_id, i.kind, i.value"
        ).fetchall()

    def stats(self) -> dict[str, int]:
        total = self.conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
        mal = self.conn.execute("SELECT COUNT(*) FROM advisories WHERE malicious = 1").fetchone()[0]
        return {"advisories": total, "malicious": mal}


# --- network sync ---------------------------------------------------------

Opener = Callable[[str], io.BufferedIOBase]


def _open(url: str, timeout: int = 60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def _full_sync(db: OsvDB, eco: str, opener: Opener, log: Callable[[str], None]) -> str:
    log(f"  downloading {eco}/all.zip ...")
    with tempfile.TemporaryFile(dir=db.path.parent) as tmp:
        with opener(f"{BASE_URL}/{eco}/all.zip") as resp:
            while chunk := resp.read(1 << 20):
                tmp.write(chunk)
        tmp.seek(0)
        newest = ""
        with zipfile.ZipFile(tmp) as zf:

            def records():
                nonlocal newest
                for name in zf.namelist():
                    if name.endswith(".json"):
                        rec = json.loads(zf.read(name))
                        newest = max(newest, _ts(rec.get("modified", "")))
                        yield rec

            db.conn.execute("DELETE FROM affected WHERE ecosystem = ?", (eco,))
            n = db.upsert(records())
    log(f"  {eco}: {n} advisories")
    return newest


def _ts(value: str) -> str:
    """Normalise RFC 3339 timestamps so they compare correctly as strings."""
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", value)
    if not m:
        return value
    return f"{m.group(1)}.{(m.group(2) or '').ljust(9, '0')[:9]}Z"


def _changed_since(eco: str, since: str, opener: Opener) -> tuple[list[str], str] | None:
    """IDs modified after `since`, from the newest-first modified_id.csv. None if too many."""
    ids, newest = [], ""
    with opener(f"{BASE_URL}/{eco}/modified_id.csv") as resp:
        for raw in io.TextIOWrapper(resp, encoding="utf-8"):
            ts, _, adv_id = raw.strip().partition(",")
            if not adv_id:
                continue
            newest = newest or _ts(ts)
            if _ts(ts) <= _ts(since):
                break
            ids.append(adv_id)
            if len(ids) > INCREMENTAL_LIMIT:
                return None
    return ids, newest or since


def sync(db: OsvDB, ecosystems: list[str], *, full: bool = False, opener: Opener = _open,
         log: Callable[[str], None] = print) -> list[str]:
    """Refresh the local mirror. Returns error messages; a failed feed keeps its old data."""
    errors = []
    state = db.feed_state()
    for eco in ecosystems:
        try:
            last = state.get(eco, ("", ""))[0]
            changed = None if (full or not last) else _changed_since(eco, last, opener)
            if changed is None:
                newest = _full_sync(db, eco, opener, log)
            else:
                ids, newest = changed
                log(f"  {eco}: {len(ids)} changed advisories")

                def fetch(adv_id: str, eco: str = eco) -> dict:
                    with opener(f"{BASE_URL}/{eco}/{adv_id}.json") as r:
                        return json.loads(r.read())

                with ThreadPoolExecutor(max_workers=16) as pool:
                    db.upsert(pool.map(fetch, ids))
            db.set_feed_state(eco, newest)
        except (urllib.error.URLError, OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
            errors.append(f"{eco}: {exc}")
    return errors
