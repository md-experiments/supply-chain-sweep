"""Local persistence: inventory per scan, findings, hash and SBOM caches (FR-9, FR-10)."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding, Package
from .util import file_digest

KEEP_SCANS = 30

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, started TEXT, finished TEXT, scope TEXT, summary TEXT
);
CREATE TABLE IF NOT EXISTS packages (
    scan_id INTEGER, ecosystem TEXT, name TEXT, version TEXT, source_type TEXT,
    location TEXT, container TEXT, hashes TEXT, extra TEXT
);
CREATE INDEX IF NOT EXISTS packages_scan ON packages (scan_id);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER, fingerprint TEXT, severity TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS findings_scan ON findings (scan_id);
CREATE TABLE IF NOT EXISTS hash_cache (
    path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER, digest TEXT
);
CREATE TABLE IF NOT EXISTS sbom_cache (
    image_id TEXT PRIMARY KEY, data TEXT
);
"""


@dataclass
class Diff:
    added: list[dict]
    changed: list[dict]  # {"before": ..., "after": ...}
    removed: list[dict]
    previous_scan: int | None


class State:
    def __init__(self, data_dir: Path, readonly: bool = False) -> None:
        self.lock = threading.Lock()
        if readonly:
            self.conn = sqlite3.connect(f"file:{data_dir / 'state.db'}?mode=ro", uri=True, check_same_thread=False)
            return
        data_dir.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(data_dir / "state.db", check_same_thread=False)
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    # --- caches -----------------------------------------------------------
    def cached_digest(self, path: Path) -> str | None:
        """sha256 of a file, reusing the stored value while size and mtime are unchanged."""
        try:
            st = path.stat()
        except OSError:
            return None
        key = str(path)
        with self.lock:
            row = self.conn.execute("SELECT size, mtime_ns, digest FROM hash_cache WHERE path = ?", (key,)).fetchone()
        if row and row[0] == st.st_size and row[1] == st.st_mtime_ns:
            return row[2]
        digest = file_digest(path)
        if digest:
            with self.lock:
                self.conn.execute(
                    "INSERT OR REPLACE INTO hash_cache VALUES (?,?,?,?)", (key, st.st_size, st.st_mtime_ns, digest)
                )
        return digest

    def sbom_get(self, image_id: str) -> dict | None:
        row = self.conn.execute("SELECT data FROM sbom_cache WHERE image_id = ?", (image_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def sbom_put(self, image_id: str, sbom: dict) -> None:
        keep = {"artifacts": [
            {k: a.get(k) for k in ("type", "name", "version", "locations", "metadata")} for a in sbom.get("artifacts", [])
            if a.get("type") in ("python", "npm", "conda")
        ]}
        self.conn.execute("INSERT OR REPLACE INTO sbom_cache VALUES (?,?)", (image_id, json.dumps(keep)))

    # --- scans --------------------------------------------------------------
    def last_scan_id(self, scope: str) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM scans WHERE scope = ? AND finished IS NOT NULL ORDER BY id DESC LIMIT 1", (scope,)
        ).fetchone()
        return row[0] if row else None

    def previous_findings(self, scope: str) -> set[str]:
        scan = self.last_scan_id(scope)
        if scan is None:
            return set()
        return {r[0] for r in self.conn.execute("SELECT fingerprint FROM findings WHERE scan_id = ?", (scan,))}

    def inventory(self, scan_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ecosystem, name, version, source_type, location, container, hashes, extra FROM packages "
            "WHERE scan_id = ? ORDER BY location, ecosystem, name, version",
            (scan_id,),
        ).fetchall()
        keys = ("ecosystem", "name", "version", "source_type", "location", "container", "hashes", "extra")
        out = []
        for r in rows:
            d = dict(zip(keys, r))
            d["hashes"] = json.loads(d["hashes"])
            d["extra"] = json.loads(d["extra"])
            out.append(d)
        return out

    def diff(self, scope: str, packages: list[Package]) -> Diff:
        prev = self.last_scan_id(scope)
        if prev is None:
            return Diff([], [], [], None)
        before = {(p["ecosystem"], p["name"].lower(), p["location"]): p for p in self.inventory(prev)}
        after = {(p.ecosystem.value, p.name.lower(), p.location): p.to_dict(include_hashes=False) for p in packages}
        added, changed = [], []
        for key in sorted(after):
            if key not in before:
                added.append(after[key])
            elif before[key]["version"] != after[key]["version"]:
                changed.append({"before": {k: before[key][k] for k in ("name", "version", "location")},
                                "after": after[key]})
        removed = [{k: before[key][k] for k in ("ecosystem", "name", "version", "location")}
                   for key in sorted(before) if key not in after]
        return Diff(added, changed, removed, prev)

    def save_scan(self, scope: str, started: str, packages: list[Package], findings: list[Finding], summary: dict) -> int:
        cur = self.conn.cursor()
        cur.execute("INSERT INTO scans (started, scope) VALUES (?, ?)", (started, scope))
        scan_id = cur.lastrowid
        cur.executemany(
            "INSERT INTO packages VALUES (?,?,?,?,?,?,?,?,?)",
            [
                (scan_id, p.ecosystem.value, p.name, p.version, p.source_type.value, p.location, p.container,
                 json.dumps(sorted(set(p.hashes))), json.dumps(p.extra, sort_keys=True))
                for p in packages
            ],
        )
        cur.executemany(
            "INSERT INTO findings VALUES (?,?,?,?)",
            [(scan_id, f.fingerprint, f.severity.value, json.dumps(f.to_dict(), sort_keys=True)) for f in findings],
        )
        now = datetime.now(UTC).isoformat(timespec="seconds")
        cur.execute("UPDATE scans SET finished = ?, summary = ? WHERE id = ?", (now, json.dumps(summary), scan_id))
        self._prune(cur)
        self.conn.commit()
        return scan_id

    def _prune(self, cur: sqlite3.Cursor) -> None:
        old = [r[0] for r in cur.execute("SELECT id FROM scans ORDER BY id DESC LIMIT -1 OFFSET ?", (KEEP_SCANS,))]
        for scan_id in old:
            for table in ("packages", "findings"):
                cur.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan_id,))
            cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        stale = [r[0] for r in cur.execute("SELECT path FROM hash_cache") if not os.path.exists(r[0])]
        cur.executemany("DELETE FROM hash_cache WHERE path = ?", [(p,) for p in stale])

    def container_summary(self, containers: list[str]) -> dict | None:
        """What the last full scan found in an environment or image (network monitor link, MON-24)."""
        scan = self.last_scan_id("full")
        if scan is None or not containers:
            return None
        marks = ",".join("?" * len(containers))
        n = self.conn.execute(
            f"SELECT COUNT(*) FROM packages WHERE scan_id = ? AND container IN ({marks})", (scan, *containers)
        ).fetchone()[0]
        if not n:
            return None
        crit = []
        for (data,) in self.conn.execute(
            "SELECT data FROM findings WHERE scan_id = ? AND severity IN ('critical', 'high')", (scan,)
        ):
            f = json.loads(data)
            where = (f.get("package") or {}).get("container") or f.get("details", {}).get("environment", "")
            if where in containers:
                crit.append({"severity": f["severity"], "title": f["title"], "location": f["location"]})
        started = self.conn.execute("SELECT started FROM scans WHERE id = ?", (scan,)).fetchone()[0]
        return {"scan_id": scan, "scanned": started, "packages": n, "findings": crit[:10]}

    def history(self, limit: int = 10) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, started, finished, scope, summary FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            {"id": r[0], "started": r[1], "finished": r[2], "scope": r[3], "summary": json.loads(r[4] or "{}")}
            for r in rows
        ]
