"""Header parsing for IP, UDP, TCP and DNS, plus a pcap reader.

Only headers and DNS messages are decoded. Nothing beyond the fields returned
here is kept: application payloads are never stored (MON-NFR-5).
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
          64: "SVCB", 65: "HTTPS", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

TCP_SYN, TCP_ACK = 0x02, 0x10
PROTO_TCP, PROTO_UDP = 6, 17


@dataclass
class DnsMessage:
    id: int
    is_response: bool
    rcode: str
    name: str
    qtype: str
    answers: list[str] = field(default_factory=list)  # A/AAAA addresses
    cnames: list[str] = field(default_factory=list)
    ttl: int = 0


@dataclass
class Packet:
    ts: float
    src: str
    dst: str
    proto: int
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    dns: DnsMessage | None = None

    @property
    def is_syn(self) -> bool:
        return self.proto == PROTO_TCP and bool(self.tcp_flags & TCP_SYN) and not self.tcp_flags & TCP_ACK


class DnsError(ValueError):
    pass


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    jumps = 0
    end = None
    while True:
        if off >= len(buf):
            raise DnsError("name runs past end of message")
        length = buf[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise DnsError("truncated pointer")
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | buf[off + 1]
            jumps += 1
            if jumps > 32:
                raise DnsError("compression loop")
            continue
        if length == 0:
            off += 1
            break
        off += 1
        labels.append(buf[off:off + length].decode("ascii", "replace"))
        off += length
        if len(labels) > 127:
            raise DnsError("too many labels")
    return ".".join(labels).lower(), (end if end is not None else off)


def parse_dns(buf: bytes) -> DnsMessage:
    if len(buf) < 12:
        raise DnsError("short DNS header")
    msg_id, flags, qd, an = struct.unpack("!HHHH", buf[:8])
    if qd < 1:
        raise DnsError("no question")
    name, off = _read_name(buf, 12)
    if off + 4 > len(buf):
        raise DnsError("truncated question")
    qtype = struct.unpack("!H", buf[off:off + 2])[0]
    off += 4
    for _ in range(qd - 1):  # skip any extra questions
        _, off = _read_name(buf, off)
        off += 4
    msg = DnsMessage(msg_id, bool(flags & 0x8000), RCODES.get(flags & 0xF, str(flags & 0xF)), name,
                     QTYPES.get(qtype, str(qtype)))
    ttls = []
    for _ in range(an if msg.is_response else 0):
        _, off = _read_name(buf, off)
        if off + 10 > len(buf):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        rdata = buf[off:off + rdlen]
        if rtype == 1 and rdlen == 4:
            msg.answers.append(str(ipaddress.IPv4Address(rdata)))
            ttls.append(ttl)
        elif rtype == 28 and rdlen == 16:
            msg.answers.append(str(ipaddress.IPv6Address(rdata)))
            ttls.append(ttl)
        elif rtype == 5:
            msg.cnames.append(_read_name(buf, off)[0])
        off += rdlen
    msg.ttl = min(ttls) if ttls else 0
    return msg


def parse_ip(data: bytes, ts: float = 0.0) -> Packet | None:
    """Parse an IP packet (no link-layer header). Returns None for anything not TCP/UDP."""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        proto = data[9]
        if struct.unpack("!H", data[6:8])[0] & 0x1FFF:  # non-first fragment
            return None
        src, dst = str(ipaddress.IPv4Address(data[12:16])), str(ipaddress.IPv4Address(data[16:20]))
        body = data[ihl:]
    elif version == 6:
        if len(data) < 40:
            return None
        proto = data[6]
        src, dst = str(ipaddress.IPv6Address(data[8:24])), str(ipaddress.IPv6Address(data[24:40]))
        body = data[40:]
        for _ in range(8):  # walk extension headers
            if proto in (0, 43, 60) and len(body) >= 8:
                proto, body = body[0], body[(body[1] + 1) * 8:]
            elif proto == 44 and len(body) >= 8:
                proto, body = body[0], body[8:]
            else:
                break
    else:
        return None
    if proto == PROTO_UDP and len(body) >= 8:
        sport, dport = struct.unpack("!HH", body[:4])
        pkt = Packet(ts, src, dst, proto, sport, dport)
        if 53 in (sport, dport) or 5353 in (sport, dport):
            try:
                pkt.dns = parse_dns(body[8:])
            except (DnsError, struct.error, ValueError):
                pass
        return pkt
    if proto == PROTO_TCP and len(body) >= 14:
        sport, dport = struct.unpack("!HH", body[:4])
        return Packet(ts, src, dst, proto, sport, dport, tcp_flags=body[13])
    return None


# --- pcap ------------------------------------------------------------------

_LINK_OFFSETS = {0: 4, 1: 14, 12: 0, 101: 0, 113: 16, 276: 20, 228: 0, 229: 0}


def _strip_link(linktype: int, frame: bytes) -> bytes | None:
    if linktype == 1:  # Ethernet, possibly VLAN-tagged
        off, ethertype = 14, struct.unpack("!H", frame[12:14])[0] if len(frame) >= 14 else 0
        while ethertype in (0x8100, 0x88A8) and len(frame) >= off + 4:
            ethertype = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
        return frame[off:] if ethertype in (0x0800, 0x86DD) else None
    if linktype not in _LINK_OFFSETS:
        return None
    return frame[_LINK_OFFSETS[linktype]:]


def read_pcap(path: Path) -> Iterator[Packet]:
    """Packets from a classic pcap file (e.g. `tcpdump -w`). pcapng is not supported."""
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            return
        magic = header[:4]
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<",
                  b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
        if endian is None:
            raise ValueError(f"{path}: not a pcap file (pcapng is not supported; convert with editcap -F pcap)")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(endian + "IIII", rec)
            frame = fh.read(incl)
            ip = _strip_link(linktype, frame)
            if ip is None:
                continue
            pkt = parse_ip(ip, sec + frac / (1e9 if nano else 1e6))
            if pkt is not None:
                yield pkt
