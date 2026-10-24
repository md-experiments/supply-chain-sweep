"""Builders for synthetic DNS / IP packets and pcap files used by the monitor tests."""

import socket
import struct


def dns_query(name: str, qid: int = 0x1234, qtype: int = 1) -> bytes:
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)


def dns_response(name: str, ips: list[str], qid: int = 0x1234, ttl: int = 60, rcode: int = 0) -> bytes:
    q = dns_query(name, qid)
    body = bytearray(q)
    body[2:4] = struct.pack("!H", 0x8180 | rcode)
    body[6:8] = struct.pack("!H", len(ips))
    for ip in ips:
        if ":" in ip:
            body += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, ttl, 16) + socket.inet_pton(socket.AF_INET6, ip)
        else:
            body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
    return bytes(body)


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    return ipv4(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


def tcp_syn(src: str, dst: str, sport: int, dport: int) -> bytes:
    return ipv4(src, dst, 6, struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x02, 65535, 0, 0))


def write_pcap(path, packets: list[tuple[float, bytes]]) -> None:
    """Classic pcap with Ethernet framing."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, ip in packets:
            frame = b"\x00" * 12 + b"\x08\x00" + ip
            fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame)
