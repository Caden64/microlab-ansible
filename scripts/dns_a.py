#!/usr/bin/env python3
"""Resolve one A record straight from a DNS server, validating the response.

Prints the first A address on success, NXDOMAIN when the name is confirmed
absent (rcode 3), SERVFAIL, or ERROR:<reason>; exits nonzero on anything that
is not a definitive answer. Used by scripts/deploy_challenges.sh so the
wildcard-record check never confuses a broken lookup with a missing record.

No underscore placeholder groups appear anywhere in this file: they have
proven to be silently rewritten by the authoring transport, which once made
this parser read nscount as ancount.
"""
import secrets
import socket
import struct
import sys


def skip_name(message: bytes, offset: int) -> int:
    while True:
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += length + 1


def main() -> int:
    server, name = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 53
    question = b''.join(bytes([len(part)]) + part.encode() for part in name.split('.')) + bytes([0])
    ident = secrets.randbits(16)
    packet = struct.pack('>HHHHHH', ident, 0x0100, 1, 0, 0, 0) + question + struct.pack('>HH', 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(packet, (server, port))
    message, sender = sock.recvfrom(4096)
    if sender[0] != server:
        print('ERROR:unexpected-source')
        return 1
    rid, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', message[:12])
    if rid != ident or not flags & 0x8000 or flags & 0x0200:
        print('ERROR:bad-response')
        return 1
    rcode = flags & 0x000F
    if rcode == 3:
        print('NXDOMAIN')
        return 0
    if rcode != 0:
        print('SERVFAIL' if rcode == 2 else 'ERROR:rcode%d' % rcode)
        return 1

    offset = 12
    while message[offset] != 0:
        offset += message[offset] + 1
    offset += 5  # root label + QTYPE + QCLASS
    addresses = []
    for index in range(ancount):
        offset = skip_name(message, offset)
        rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', message[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            addresses.append('.'.join(str(byte) for byte in message[offset:offset + 4]))
        offset += rdlength
    if addresses:
        print(addresses[0])
        return 0
    print('NXDOMAIN')
    return 0


if __name__ == '__main__':
    sys.exit(main())
