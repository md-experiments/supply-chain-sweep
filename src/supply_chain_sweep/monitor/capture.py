"""Live capture backends (MON-1, MON-2, MON-3, MON-NFR-5, MON-NFR-7).

Linux: an AF_PACKET socket with a kernel BPF filter. Only DNS packets (UDP port
53) and the headers of outgoing TCP SYNs ever reach user space, so ordinary
traffic and payloads are never copied. The socket only observes: resolution
is never proxied or delayed.

macOS (experimental): Apple's tcpdump on the `pktap` pseudo-interface, which
labels each packet with the sending process.
"""

from __future__ import annotations

import ctypes
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from .packets import PROTO_TCP, PROTO_UDP, DnsMessage, Packet, parse_ip
from .procinfo import ContainerMap, Process, ProcessResolver, classify
from .store import Event

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
PACKET_OUTGOING = 4
DNS_SNAPLEN = 4096
SYN_SNAPLEN = 128

# --- classic BPF ------------------------------------------------------------

LDB_ABS, LDH_ABS, LDB_IND, LDH_IND, LDXB_MSH = 0x30, 0x28, 0x50, 0x48, 0xB1
AND_K, JEQ_K, JSET_K, RET_K = 0x54, 0x15, 0x45, 0x06


def _assemble(program: list[tuple]) -> list[tuple[int, int, int, int]]:
    """Tiny assembler: (op, k, true_label, false_label) or (label,) entries; jumps resolved to offsets."""
    labels, pos = {}, 0
    for ins in program:
        if len(ins) == 1:
            labels[ins[0]] = pos
        else:
            pos += 1
    out, pos = [], 0
    for ins in program:
        if len(ins) == 1:
            continue
        op, k, jt, jf = (*ins, None, None)[:4]
        jt_off = labels[jt] - pos - 1 if isinstance(jt, str) else 0
        jf_off = labels[jf] - pos - 1 if isinstance(jf, str) else 0
        out.append((op, jt_off, jf_off, k))
        pos += 1
    return out


def dns_and_syn_filter() -> list[tuple[int, int, int, int]]:
    """BPF for SOCK_DGRAM packet sockets (offset 0 is the IP header):
    accept UDP to/from port 53 (whole packet) and TCP SYN without ACK (headers only)."""
    return _assemble([
        (LDB_ABS, 0), (AND_K, 0xF0), (JEQ_K, 0x40, "v4", "chk6"),
        ("chk6",), (JEQ_K, 0x60, "v6", "drop"),
        ("v4",), (LDH_ABS, 6), (JSET_K, 0x1FFF, "drop", "v4ok"),
        ("v4ok",), (LDB_ABS, 9), (JEQ_K, PROTO_UDP, "v4udp", "v4tcp?"),
        ("v4tcp?",), (JEQ_K, PROTO_TCP, "v4tcp", "drop"),
        ("v4udp",), (LDXB_MSH, 0), (LDH_IND, 0), (JEQ_K, 53, "dns", "v4dport"),
        ("v4dport",), (LDH_IND, 2), (JEQ_K, 53, "dns", "drop"),
        ("v4tcp",), (LDXB_MSH, 0), (LDB_IND, 13), (AND_K, 0x12), (JEQ_K, 0x02, "syn", "drop"),
        ("v6",), (LDB_ABS, 6), (JEQ_K, PROTO_UDP, "v6udp", "v6tcp?"),
        ("v6tcp?",), (JEQ_K, PROTO_TCP, "v6tcp", "drop"),
        ("v6udp",), (LDH_ABS, 40), (JEQ_K, 53, "dns", "v6dport"),
        ("v6dport",), (LDH_ABS, 42), (JEQ_K, 53, "dns", "drop"),
        ("v6tcp",), (LDB_ABS, 53), (AND_K, 0x12), (JEQ_K, 0x02, "syn", "drop"),
        ("dns",), (RET_K, DNS_SNAPLEN),
        ("syn",), (RET_K, SYN_SNAPLEN),
        ("drop",), (RET_K, 0),
    ])


def attach_filter(sock: socket.socket, program: list[tuple[int, int, int, int]]) -> None:
    blob = b"".join(struct.pack("HBBI", *ins) for ins in program)
    buf = ctypes.create_string_buffer(blob)
    fprog = struct.pack("HL", len(program), ctypes.addressof(buf))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


# --- turning packets into events -----------------------------------------------

@dataclass
class _Pending:
    ts: float
    process: dict
    msg: DnsMessage
    dst: str = ""


@dataclass
class Tracker:
    """Pairs DNS queries with responses, remembers resolved IPs, and spots direct-IP connections.

    Attribution: /proc at the moment the packet is seen, then (if configured) the kernel
    attributor, which may lag the packet slightly; unattributed events wait up to `grace`.
    """

    resolve: Callable[..., Process | None]
    containers: ContainerMap | None = None
    local_ips: set[str] = field(default_factory=set)
    kernel_lookup: Callable[[str, str, int, float], dict | None] | None = None
    pending: dict[tuple, _Pending] = field(default_factory=dict)
    resolved: dict[str, float] = field(default_factory=dict)  # ip -> expiry
    held: list[tuple[float, Event, tuple[str, str, int]]] = field(default_factory=list)
    timeout: float = 5.0
    grace: float = 0.5
    stats: dict[str, int] = field(default_factory=lambda: {"packets": 0, "dns": 0, "syn": 0, "events": 0,
                                                           "attributed": 0})

    def _attribute(self, proto: str, ip: str, port: int) -> dict:
        proc = None
        container = self.containers.by_ip(ip) if self.containers is not None and ip not in self.local_ips else None
        if container is not None:
            proc = self.resolve(proto, port, ip, container.pid) if container.pid else None
            proc = proc or Process(name="", category="container")
            proc.category, proc.container, proc.image = "container", container.name, container.image
        else:
            proc = self.resolve(proto, port, ip)
        return proc.to_dict() if proc is not None else {"category": "unknown"}

    def _emit(self, ev: Event, proto: str, dst: str, dport: int, now: float) -> list[Event]:
        if ev.category != "unknown" or self.kernel_lookup is None:
            return [self._count(ev)]
        self.held.append((now + self.grace, ev, (proto, dst, dport)))
        return self.poll(now)

    def _count(self, ev: Event) -> Event:
        if ev.category != "unknown":
            self.stats["attributed"] += 1
        return ev

    def poll(self, now: float) -> list[Event]:
        """Events whose attribution is settled: found by the kernel attributor, or out of time."""
        out, keep = [], []
        for deadline, ev, (proto, dst, dport) in self.held:
            proc = self.kernel_lookup(proto, dst, dport, ev.ts) if self.kernel_lookup else None
            if proc:
                ev.process = proc
                out.append(self._count(ev))
            elif now >= deadline:
                out.append(ev)
            else:
                keep.append((deadline, ev, (proto, dst, dport)))
        self.held = keep
        return out

    def feed(self, pkt: Packet) -> list[Event]:
        self.stats["packets"] += 1
        out: list[Event] = []
        now = pkt.ts
        if pkt.dns is not None:
            self.stats["dns"] += 1
            msg = pkt.dns
            if not msg.is_response and pkt.dport in (53, 5353):
                key = (msg.id, msg.name, msg.qtype, pkt.src, pkt.sport)
                # The same query seen again on another interface (bridge, NAT) keeps the first attribution.
                dup = any(k[:3] == key[:3] and now - p.ts < 2 for k, p in self.pending.items())
                if not dup:
                    self.pending[key] = _Pending(now, self._attribute("udp", pkt.src, pkt.sport), msg, pkt.dst)
            elif msg.is_response:
                key = (msg.id, msg.name, msg.qtype, pkt.dst, pkt.dport)
                pend = self.pending.pop(key, None)
                if pend is None:  # response for a NAT'd copy: match without the client address
                    k = next((k for k in self.pending if k[:3] == key[:3]), None)
                    pend = self.pending.pop(k) if k else None
                if pend is not None:
                    expiry = now + max(msg.ttl, 300) + 3600
                    for ip in msg.answers:
                        self.resolved[ip] = expiry
                    ev = Event(pend.ts, "dns", msg.name, msg.qtype, msg.rcode, msg.answers, process=pend.process)
                    out += self._emit(ev, "udp", pend.dst, 53, now)
        elif pkt.is_syn and pkt.dport != 53:
            self.stats["syn"] += 1
            if pkt.dst not in self.local_ips and self.resolved.get(pkt.dst, 0) < now:
                ev = Event(now, "conn", dst_ip=pkt.dst, dst_port=pkt.dport,
                           process=self._attribute("tcp", pkt.src, pkt.sport))
                out += self._emit(ev, "tcp", pkt.dst, pkt.dport, now)
        out += self.expire(now)
        self.stats["events"] += len(out)
        return out

    def expire(self, now: float) -> list[Event]:
        out = []
        for key in [k for k, p in self.pending.items() if now - p.ts > self.timeout]:
            p = self.pending.pop(key)
            ev = Event(p.ts, "dns", p.msg.name, p.msg.qtype, "NORESPONSE", [], process=p.process)
            out += self._emit(ev, "udp", p.dst, 53, now)
        if len(self.resolved) > 200000:
            self.resolved = {ip: exp for ip, exp in self.resolved.items() if exp > now}
        return out


def local_addresses() -> set[str]:
    ips = {"127.0.0.1", "::1"}
    try:
        with open("/proc/net/if_inet6", encoding="ascii") as fh:
            for line in fh:
                raw = line.split()[0]
                if len(raw) == 32:
                    ips.add(socket.inet_ntop(socket.AF_INET6, bytes.fromhex(raw)))
    except OSError:
        pass
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5, check=False).stdout
        ips.update(out.split())
    except OSError:
        pass
    try:
        ips.update(i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None))
    except OSError:
        pass
    return ips


# --- backends -------------------------------------------------------------------

class LinuxCapture:
    name = "linux-af_packet"

    def __init__(self, interfaces: list[str] | None = None) -> None:
        self.interfaces = interfaces or []
        self.socks: list[socket.socket] = []

    def open(self) -> None:
        program = dns_and_syn_filter()
        targets = self.interfaces or [""]
        for iface in targets:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
            attach_filter(s, program)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
            if iface:
                s.bind((iface, 0))
            self.socks.append(s)

    def packets(self, stop: Callable[[], bool], tick: Callable[[], None]) -> Iterator[Packet]:
        if not self.socks:
            self.open()
        while not stop():
            ready, _, _ = select.select(self.socks, [], [], 1.0)
            tick()
            now = time.time()
            for s in ready:
                data, addr = s.recvfrom(DNS_SNAPLEN)
                # Loopback packets are seen twice (outgoing and incoming copy): keep the outgoing one.
                if addr[0] == "lo" and addr[2] != PACKET_OUTGOING:
                    continue
                pkt = parse_ip(data, now)
                if pkt is not None:
                    yield pkt

    def close(self) -> None:
        for s in self.socks:
            s.close()
        self.socks = []


_TCPDUMP_PROC = re.compile(r"\bproc ([^:,()]+):(\d+)")


class MacCapture:
    """Experimental: `tcpdump -k NP -i pktap,all` prints the process name and pid for each packet."""

    name = "macos-pktap"

    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None

    def events(self, stop: Callable[[], bool], tick: Callable[[], None]) -> Iterator[Event]:
        exe = shutil.which("tcpdump") or "/usr/sbin/tcpdump"
        self.proc = subprocess.Popen(
            [exe, "-n", "-l", "-k", "NP", "-i", "pktap,all", "-s", "512", "udp port 53"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        pending: dict[str, tuple[float, dict, str, str]] = {}
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            tick()
            if stop():
                break
            ev = parse_tcpdump_line(line, pending)
            if ev is not None:
                yield ev
        self.close()

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


_TD_QUERY = re.compile(r"\s(\d+)\+?\s+(A|AAAA|HTTPS|CNAME|TXT|MX|SRV|PTR|ANY)\?\s+(\S+?)\.?\s")
_TD_REPLY = re.compile(r"\s(\d+)(?:\*|-|\$|\|)*\s+(\d+)/\d+/\d+\s+(.*)\(\d+\)\s*$")
_TD_ADDR = re.compile(r"\b(?:A|AAAA)\s+([0-9a-fA-F:.]+)")


def parse_tcpdump_line(line: str, pending: dict[str, tuple[float, dict, str, str]]) -> Event | None:
    """Parse a tcpdump DNS line; queries are held until their reply (or dropped after a while)."""
    m_proc = _TCPDUMP_PROC.search(line)
    q = _TD_QUERY.search(line)
    if q and " > " in line and ".53:" in line.split(" > ", 1)[1][:60]:
        process = {"name": m_proc.group(1), "pid": int(m_proc.group(2))} if m_proc else {}
        from .procinfo import classify

        if process:
            process["category"] = classify(process["name"], "", [process["name"]])
        else:
            process["category"] = "unknown"
        pending[q.group(1)] = (time.time(), process, q.group(3).lower(), q.group(2))
        return None
    r = _TD_REPLY.search(line)
    if r and r.group(1) in pending:
        ts, process, name, qtype = pending.pop(r.group(1))
        return Event(ts, "dns", name, qtype, "NOERROR", _TD_ADDR.findall(r.group(3)), process=process,
                     source="capture")
    return None


def default_backend(interfaces: list[str] | None = None):
    if sys.platform.startswith("linux"):
        return LinuxCapture(interfaces)
    if sys.platform == "darwin":
        return MacCapture()
    raise RuntimeError(f"live capture is not supported on {sys.platform}; use `sweep monitor ingest`")


def make_tracker(proc_root: str = "/proc", kernel=None) -> Tracker:
    """A Tracker using /proc, plus a KernelAttributor (monitor.ebpf) when one is running."""
    containers = ContainerMap()
    resolver = ProcessResolver(proc_root, containers)

    def resolve(proto: str, port: int, ip: str, netns_pid: int | None = None) -> Process | None:
        return resolver.resolve(proto, port, ip, netns_pid)

    def kernel_lookup(proto: str, ip: str, port: int, ts: float) -> dict | None:
        hit = kernel.lookup(proto, ip, port, ts)
        if hit is None:
            return None
        pid, ppid, comm = hit
        proc = resolver.process(pid)
        if proc is None:  # already exited: keep what the kernel saw, and learn from the parent
            proc = Process(pid=pid, name=comm, ppid=ppid, category=classify(comm, "", [comm]))
            parent = resolver.process(ppid) if ppid > 1 else None
            if parent is not None:
                proc.parent = parent.exe or parent.name
                if proc.category == "other" and parent.category in ("package_manager", "interpreter"):
                    proc.category, proc.via, proc.env = parent.category, parent.exe or parent.name, parent.env
                proc.container, proc.image = parent.container, parent.image
                if parent.container and proc.category not in ("package_manager", "interpreter"):
                    proc.category = "container"
        return proc.to_dict()

    return Tracker(resolve=resolve, containers=containers, local_ips=local_addresses(),
                   kernel_lookup=kernel_lookup if kernel is not None else None)

