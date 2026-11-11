#!/usr/bin/env python3
"""Tiny offline DNS responder used as a controlled recursion fixture.

It answers one known A name inside one dedicated zone. Responses deliberately
have AA clear so a conditional-forwarder query through Technitium proves
recursion, not an authoritative local zone answer. Only the Python standard
library is required, and it listens on loopback by default.

This is an acceptance fixture, not a general-purpose DNS server. It supports
UDP queries for A/AAAA on the configured name and returns NXDOMAIN for other
names inside the zone and REFUSED outside it.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct

QTYPE_A = 1
QTYPE_AAAA = 28
QCLASS_IN = 1

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5


def _normal_name(value: str) -> str:
    return value.strip().rstrip(".").lower()


def parse_question(packet: bytes) -> tuple[str, int, int, int]:
    """Return (qname, qtype, qclass, end_offset) for one DNS question."""
    if len(packet) < 12:
        raise ValueError("packet is shorter than a DNS header")
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount != 1:
        raise ValueError("fixture supports exactly one question")

    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated question name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed question names are not supported")
        if offset + length > len(packet):
            raise ValueError("truncated question label")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length

    if offset + 4 > len(packet):
        raise ValueError("truncated question type/class")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return ".".join(labels).rstrip(".").lower(), qtype, qclass, offset + 4


def build_response(
    packet: bytes,
    zone: str,
    name: str,
    answer: str,
    ttl: int = 60,
) -> bytes | None:
    """Build a response with AA clear for the configured fixture name."""
    if len(packet) < 12:
        return None
    request_id = struct.unpack("!H", packet[:2])[0]
    request_flags = struct.unpack("!H", packet[2:4])[0]
    recursion_desired = request_flags & 0x0100

    try:
        qname, qtype, qclass, question_end = parse_question(packet)
    except ValueError:
        return None

    zone = _normal_name(zone)
    name = _normal_name(name)
    inside_zone = qname == zone or qname.endswith("." + zone)

    answer_count = 0
    rdata = b""
    if not inside_zone:
        rcode = RCODE_REFUSED
    elif qname != name:
        rcode = RCODE_NXDOMAIN
    elif qtype == QTYPE_A and qclass == QCLASS_IN:
        rcode = RCODE_NOERROR
        answer_count = 1
        rdata = socket.inet_aton(answer)
    elif qtype == QTYPE_AAAA and qclass == QCLASS_IN:
        # NODATA for the fixture's IPv4-only name.
        rcode = RCODE_NOERROR
    else:
        rcode = RCODE_NXDOMAIN

    # QR + copied RD + RA, never AA, plus the selected RCODE.
    response_flags = 0x8000 | recursion_desired | 0x0080 | rcode
    header = struct.pack(
        "!HHHHHH",
        request_id,
        response_flags,
        1,
        answer_count,
        0,
        0,
    )
    response = bytearray(header)
    response += packet[12:question_end]

    if answer_count:
        response += b"\xc0\x0c"
        response += struct.pack("!HHIH", QTYPE_A, QCLASS_IN, ttl, 4)
        response += rdata
    return bytes(response)


def serve(
    listen: str,
    port: int,
    zone: str,
    name: str,
    answer: str,
    ttl: int,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen, port))
    print(
        f"microlab dns fixture: {name} A {answer} in {zone} "
        f"on {listen}:{port}/udp (AA clear)",
        flush=True,
    )
    while True:
        packet, peer = sock.recvfrom(4096)
        response = build_response(packet, zone, name, answer, ttl)
        if response:
            sock.sendto(response, peer)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--zone", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--answer", required=True)
    parser.add_argument("--ttl", type=int, default=60)
    args = parser.parse_args()

    zone = _normal_name(args.zone)
    name = _normal_name(args.name)
    if not zone or not name:
        parser.error("zone and name must be non-empty")
    if name != zone and not name.endswith("." + zone):
        parser.error("name must be inside zone")
    try:
        address = ipaddress.IPv4Address(args.answer)
    except ipaddress.AddressValueError as exc:
        parser.error(f"answer must be an IPv4 address: {exc}")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.ttl < 0:
        parser.error("ttl must not be negative")

    try:
        serve(args.listen, args.port, zone, name, str(address), args.ttl)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
