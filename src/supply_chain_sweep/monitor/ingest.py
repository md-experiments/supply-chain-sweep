"""Import DNS history from external resolvers or captures instead of live capture (MON-4).

Formats: dnsmasq / Pi-hole logs, NextDNS CSV exports, JSON lines, and pcap files.
Resolver logs carry no process information, so their events are category
"unknown" unless the caller says which category the client belongs to.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from .capture import Tracker
from .packets import read_pcap
from .store import Event

_DNSMASQ_QUERY = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+[\d:]+)\s+(?:\S+\s+)?dnsmasq\[\d+\]:\s+(?:\d+\s+[\d.:a-f]+/\d+\s+)?"
    r"query\[(?P<qtype>\w+)\]\s+(?P<name>\S+)\s+from\s+(?P<client>\S+)"
)
_DNSMASQ_REPLY = re.compile(
    r"dnsmasq\[\d+\]:\s+(?:\d+\s+[\d.:a-f]+/\d+\s+)?(?:reply|cached)\s+(?P<name>\S+)\s+is\s+(?P<value>\S+)"
)


def _open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def _syslog_ts(text: str, year: int) -> float:
    try:
        return datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return 0.0


def _proc(client: str, category: str) -> dict:
    return {"name": client, "category": category} if client else {"category": category}


def parse_dnsmasq(lines, category: str = "unknown", year: int | None = None) -> Iterator[Event]:
    year = year or datetime.now(UTC).year
    pending: dict[str, Event] = {}
    for line in lines:
        m = _DNSMASQ_QUERY.search(line)
        if m:
            name = m.group("name").lower()
            if name in pending:
                yield pending.pop(name)
            pending[name] = Event(_syslog_ts(m.group("ts"), year), "dns", name, m.group("qtype"), "NOERROR",
                                  process=_proc(m.group("client"), category), source="dnsmasq")
            continue
        r = _DNSMASQ_REPLY.search(line)
        if r:
            ev = pending.get(r.group("name").lower())
            value = r.group("value")
            if ev is not None:
                if value in ("NXDOMAIN", "NODATA", "NODATA-IPv6", "NXDOMAIN-IPv6"):
                    ev.rcode = value.split("-")[0]
                elif re.match(r"^[\d.]+$|^[0-9a-f:]+$", value):
                    ev.answers.append(value)
    yield from pending.values()


def parse_nextdns_csv(text: str, category: str = "unknown") -> Iterator[Event]:
    for row in csv.DictReader(io.StringIO(text)):
        name = (row.get("domain") or "").lower()
        if not name:
            continue
        try:
            ts = datetime.fromisoformat((row.get("timestamp") or "").replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        client = row.get("device_name") or row.get("client_name") or row.get("client_ip") or ""
        status = (row.get("status") or "").lower()
        yield Event(ts, "dns", name, row.get("query_type") or "A", "BLOCKED" if status == "blocked" else "NOERROR",
                    process=_proc(client, category), source="nextdns")


def parse_jsonl(lines, category: str = "unknown") -> Iterator[Event]:
    """One JSON object per line: {"ts"|"timestamp", "name"|"domain"|"query", "type", "answers", "client",
    "process": {...}} - the shape `sweep monitor export` writes."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = (d.get("name") or d.get("domain") or d.get("query") or "").lower().rstrip(".")
        ts = d.get("ts") or d.get("timestamp") or 0
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except ValueError:
                ts = 0
        proc = d.get("process") if isinstance(d.get("process"), dict) else _proc(str(d.get("client") or ""), category)
        proc.setdefault("category", category)
        if name:
            yield Event(float(ts), "dns", name, d.get("type") or d.get("qtype") or "A", d.get("rcode") or "NOERROR",
                        list(d.get("answers") or []), process=proc, source="jsonl")
        elif d.get("dst_ip"):
            yield Event(float(ts), "conn", dst_ip=d["dst_ip"], dst_port=int(d.get("dst_port") or 0), process=proc,
                        source="jsonl")


def detect_format(path: Path) -> str:
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    with _open_text(path) as fh:
        first = fh.readline()
    if first.lstrip().startswith("{"):
        return "jsonl"
    if "timestamp" in first and "domain" in first and "," in first:
        return "nextdns"
    return "dnsmasq"


def ingest_file(path: Path, fmt: str = "auto", category: str = "unknown") -> Iterator[Event]:
    fmt = detect_format(path) if fmt == "auto" else fmt
    if fmt == "pcap":
        tracker = Tracker(resolve=lambda *_a: None)
        for pkt in read_pcap(path):
            for ev in tracker.feed(pkt):
                ev.source = "pcap"
                ev.process = {"category": category}
                yield ev
        for ev in tracker.expire(float("inf")):
            ev.source, ev.process = "pcap", {"category": category}
            yield ev
        return
    with _open_text(path) as fh:
        if fmt == "nextdns":
            yield from parse_nextdns_csv(fh.read(), category)
        elif fmt == "jsonl":
            yield from parse_jsonl(fh, category)
        elif fmt == "dnsmasq":
            yield from parse_dnsmasq(fh, category)
        else:
            raise ValueError(f"unknown log format: {fmt}")
