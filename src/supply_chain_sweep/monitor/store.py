"""Local storage for the monitor (MON-NFR-1, MON-NFR-3, MON-NFR-4).

Everything stays in ``monitor.db`` next to the scanner's state. Raw events are
pruned after the retention period; findings are kept until dismissed.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, name TEXT, rd TEXT, qtype TEXT, rcode TEXT,
    answers TEXT, dst_ip TEXT, dst_port INTEGER, category TEXT, env TEXT, container TEXT, image TEXT,
    process TEXT, source TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_name ON events (name);
CREATE INDEX IF NOT EXISTS events_rd ON events (rd);
CREATE TABLE IF NOT EXISTS seen (rd TEXT PRIMARY KEY, first_ts REAL, last_ts REAL, count INTEGER);
CREATE TABLE IF NOT EXISTS allowlist (
    category TEXT, domain TEXT, source TEXT, added_ts REAL, note TEXT, PRIMARY KEY (category, domain)
);
CREATE TABLE IF NOT EXISTS removed_defaults (domain TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, first_ts REAL, last_ts REAL, count INTEGER, severity TEXT, score INTEGER,
    status TEXT, data TEXT, notified INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS findings_status ON findings (status);
CREATE TABLE IF NOT EXISTS rdap (domain TEXT PRIMARY KEY, created TEXT, checked_ts REAL, error TEXT);
CREATE TABLE IF NOT EXISTS feed_domains (domain TEXT, feed TEXT, PRIMARY KEY (domain, feed));
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

PROCESS_KEYS_BROWSER = ("name", "category")


@dataclass
class Event:
    ts: float
    kind: str  # "dns" or "conn"
    name: str = ""  # queried name (dns) or "" (conn)
    qtype: str = ""
    rcode: str = ""
    answers: list[str] = field(default_factory=list)
    dst_ip: str = ""
    dst_port: int = 0
    process: dict = field(default_factory=dict)
    source: str = "capture"  # capture, pcap, dnsmasq, nextdns, jsonl
    rd: str = ""

    @property
    def category(self) -> str:
        return self.process.get("category", "unknown")

    @property
    def target(self) -> str:
        return self.name or self.dst_ip

    def to_dict(self) -> dict:
        return asdict(self)


class MonitorStore:
    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "monitor.db"
        # Rollback journal rather than WAL, so users can read the service's database with read access only.
        self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        try:
            self.conn.executescript(SCHEMA)
        except sqlite3.OperationalError:
            pass  # read-only access to an existing database
        self.lock = threading.RLock()

    def close(self) -> None:
        with self.lock:
            self.conn.commit()
            self.conn.close()

    def commit(self) -> None:
        with self.lock:
            self.conn.commit()

    # --- meta -------------------------------------------------------------
    def get_meta(self, key: str, default=None):
        with self.lock:
            row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_meta(self, key: str, value) -> None:
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, json.dumps(value)))

    # --- events -------------------------------------------------------------
    def add_event(self, ev: Event) -> None:
        proc = dict(ev.process)
        answers = ev.answers
        if ev.category == "browser":
            # MON-NFR-4: browser events are kept as domain-only records.
            proc = {k: proc[k] for k in PROCESS_KEYS_BROWSER if k in proc}
            answers = []
        with self.lock:
            self.conn.execute(
                "INSERT INTO events (ts, kind, name, rd, qtype, rcode, answers, dst_ip, dst_port, category, env,"
                " container, image, process, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ev.ts, ev.kind, ev.name, ev.rd, ev.qtype, ev.rcode, json.dumps(answers), ev.dst_ip, ev.dst_port,
                 ev.category, proc.get("env", ""), proc.get("container", ""), proc.get("image", ""),
                 json.dumps(proc, sort_keys=True), ev.source),
            )

    def events_for_domain(self, domain: str) -> list[Event]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT ts, kind, name, qtype, rcode, answers, dst_ip, dst_port, process, source, rd FROM events "
                "WHERE name = ? OR name LIKE ? OR dst_ip = ? ORDER BY ts",
                (domain, "%." + domain, domain),
            ).fetchall()
        return [Event(r[0], r[1], r[2], r[3], r[4], json.loads(r[5]), r[6], r[7], json.loads(r[8]), r[9], r[10])
                for r in rows]

    def recent_events(self, since: float, limit: int = 200) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT ts, kind, name, dst_ip, category, env, container, process FROM events WHERE ts >= ? "
                "ORDER BY ts DESC LIMIT ?", (since, limit)).fetchall()
        keys = ("ts", "kind", "name", "dst_ip", "category", "env", "container", "process")
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def prune(self, retention_days: float, now: float | None = None) -> int:
        cutoff = (now or time.time()) - retention_days * 86400
        with self.lock:
            cur = self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self.conn.execute("DELETE FROM rdap WHERE checked_ts < ?", (cutoff,))
            return cur.rowcount

    # --- first-seen ---------------------------------------------------------
    def mark_seen(self, rd: str, ts: float) -> bool:
        """Record a registered domain; True if it was never seen before (MON-10)."""
        with self.lock:
            row = self.conn.execute("SELECT count FROM seen WHERE rd = ?", (rd,)).fetchone()
            if row:
                self.conn.execute("UPDATE seen SET last_ts = max(last_ts, ?), count = count + 1 WHERE rd = ?",
                                  (ts, rd))
                return False
            self.conn.execute("INSERT INTO seen VALUES (?, ?, ?, 1)", (rd, ts, ts))
            return True

    # --- allowlist / baseline -----------------------------------------------
    def allow(self, category: str, domain: str, source: str, note: str = "", ts: float | None = None) -> None:
        with self.lock:
            existing = self.conn.execute("SELECT source FROM allowlist WHERE category = ? AND domain = ?",
                                         (category, domain)).fetchone()
            if existing and existing[0] == "user" and source == "learned":
                return
            self.conn.execute("INSERT OR REPLACE INTO allowlist VALUES (?,?,?,?,?)",
                              (category, domain.lower(), source, ts or time.time(), note))

    def disallow(self, category: str | None, domain: str) -> int:
        with self.lock:
            if category:
                cur = self.conn.execute("DELETE FROM allowlist WHERE category = ? AND domain = ?",
                                        (category, domain.lower()))
            else:
                cur = self.conn.execute("DELETE FROM allowlist WHERE domain = ?", (domain.lower(),))
            return cur.rowcount

    def remove_default(self, domain: str) -> None:
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO removed_defaults VALUES (?)", (domain.lower(),))

    def restore_default(self, domain: str) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM removed_defaults WHERE domain = ?", (domain.lower(),))

    def removed_defaults(self) -> set[str]:
        with self.lock:
            return {r[0] for r in self.conn.execute("SELECT domain FROM removed_defaults")}

    def allowlist(self) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT category, domain, source, added_ts, note FROM allowlist ORDER BY category, domain"
            ).fetchall()
        return [dict(zip(("category", "domain", "source", "added_ts", "note"), r, strict=True)) for r in rows]

    def allowed_domains(self, category: str) -> set[str]:
        with self.lock:
            rows = self.conn.execute("SELECT domain FROM allowlist WHERE category IN (?, '*')", (category,))
            return {r[0] for r in rows}

    # --- findings -----------------------------------------------------------
    def get_finding(self, fid: str) -> dict | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT id, first_ts, last_ts, count, severity, score, status, data, notified FROM findings "
                "WHERE id = ? OR id LIKE ?", (fid, fid + "%")).fetchone()
        return _finding_row(row) if row else None

    def put_finding(self, f: dict) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                (f["id"], f["first_ts"], f["last_ts"], f["count"], f["severity"], f["score"], f["status"],
                 json.dumps(f["data"], sort_keys=True, default=str), int(f.get("notified", 0))),
            )

    def findings(self, status: str | None = "open", since: float = 0.0) -> list[dict]:
        sql = "SELECT id, first_ts, last_ts, count, severity, score, status, data, notified FROM findings " \
              "WHERE last_ts >= ?"
        args: list = [since]
        if status:
            sql += " AND status = ?"
            args.append(status)
        with self.lock:
            rows = self.conn.execute(sql + " ORDER BY score DESC, last_ts DESC", args).fetchall()
        return [_finding_row(r) for r in rows]

    # --- RDAP cache -----------------------------------------------------------
    def rdap_get(self, domain: str) -> tuple[str, float, str] | None:
        with self.lock:
            row = self.conn.execute("SELECT created, checked_ts, error FROM rdap WHERE domain = ?",
                                    (domain,)).fetchone()
        return (row[0], row[1], row[2]) if row else None

    def rdap_put(self, domain: str, created: str, error: str = "") -> None:
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO rdap VALUES (?,?,?,?)", (domain, created, time.time(), error))

    # --- threat feeds -----------------------------------------------------------
    def replace_feed(self, feed: str, domains: set[str]) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM feed_domains WHERE feed = ?", (feed,))
            self.conn.executemany("INSERT OR IGNORE INTO feed_domains VALUES (?, ?)",
                                  [(d, feed) for d in sorted(domains)])
            self.conn.commit()

    def feed_domains(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        with self.lock:
            for domain, feed in self.conn.execute("SELECT domain, feed FROM feed_domains"):
                out.setdefault(domain, set()).add(f"feed:{feed}")
        return out


def _finding_row(r) -> dict:
    return {"id": r[0], "first_ts": r[1], "last_ts": r[2], "count": r[3], "severity": r[4], "score": r[5],
            "status": r[6], "data": json.loads(r[7]), "notified": r[8]}
