#!/usr/bin/env python3
"""Perform one real DNS-over-TLS A query with strict certificate validation.

This exists so the MicroLab verify role does not depend on kdig. It uses only
the Python standard library, validates the server certificate and hostname with
the supplied CA root, and checks the returned A record.

The probe never treats a transport failure as a DNS answer. It classifies the
outcome into a stable category and, with --status-file, writes a small JSON
document that callers can inspect. Negative ACL acceptance requires a positive
DNS REFUSED response; a refusal to connect, a timeout, a TLS error, a malformed
response, or a wrong answer is not evidence that an ACL denied the client.
"""

import argparse
import ipaddress
import json
import random
import socket
import ssl
import struct
import sys

EXIT_OK = 0
EXIT_INTERNAL = 2

EXIT_TLS_CERTIFICATE = 10
EXIT_TLS_HANDSHAKE = 11
EXIT_TCP_REFUSED = 12
EXIT_TCP_CONNECT_TIMEOUT = 13
EXIT_TCP_UNREACHABLE = 14
EXIT_PROTOCOL = 15
EXIT_DNS_REFUSED = 16
EXIT_DNS_RCODE = 17
EXIT_WRONG_ANSWER = 18
EXIT_NO_ANSWER = 19
EXIT_TLS_TIMEOUT = 20
EXIT_RESPONSE_TIMEOUT = 21
EXIT_SOURCE_INVALID = 22
EXIT_SOURCE_UNAVAILABLE = 23
EXIT_SOURCE_MISMATCH = 24

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def encode_name(name):
    labels = name.rstrip(".").split(".")
    if not labels or any((not label) or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS name")
    wire = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels)
    return wire + b"\x00"


def skip_name(message, offset):
    while True:
        if offset >= len(message):
            raise ValueError("truncated DNS name")
        length = message[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS compression pointer")
            return offset + 2
        if length & 0xC0:
            raise ValueError("unsupported DNS label encoding")
        offset += 1 + length


def parse_a_records(message, qdcount, ancount):
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(message, offset) + 4
    addresses = []
    for _ in range(ancount):
        offset = skip_name(message, offset)
        if offset + 10 > len(message):
            raise ValueError("truncated DNS answer header")
        rtype, rclass, _ttl, rdlength = struct.unpack(
            "!HHIH", message[offset:offset + 10]
        )
        offset += 10
        if offset + rdlength > len(message):
            raise ValueError("truncated DNS answer data")
        rdata = message[offset:offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            addresses.append(socket.inet_ntoa(rdata))
    return addresses


def write_status(path, **status):
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(status, handle, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        print("DoT probe could not write status file: {}".format(exc), file=sys.stderr)


OBSERVED = {}


def canonical_ip(value):
    return str(ipaddress.ip_address(value.split("%", 1)[0]))


def open_connection(args):
    """Open the TCP connection, bound to --source-address when given.

    Without a source the kernel picks one from the default route. With a
    source, the socket is created for the source's address family, bound to
    (source, 0) before connect, and the connected socket's local address is
    read back. Every source problem gets its own category; none of them is a
    DNS answer or ACL evidence.
    """
    if not args.source_address:
        return socket.create_connection(
            (args.connect_host, args.port), timeout=args.timeout
        ), None
    try:
        source = ipaddress.ip_address(args.source_address)
    except ValueError:
        return None, (
            "source_invalid",
            EXIT_SOURCE_INVALID,
            "source address {!r} is not an IP literal".format(args.source_address),
        )
    family = socket.AF_INET6 if source.version == 6 else socket.AF_INET
    try:
        infos = socket.getaddrinfo(
            args.connect_host, args.port, family, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        return None, (
            "source_family",
            EXIT_SOURCE_INVALID,
            "connect host {!r} has no IPv{} address for source {}: {}".format(
                args.connect_host, source.version, source, exc
            ),
        )
    sockaddr = infos[0][4]
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(args.timeout)
        try:
            sock.bind((str(source), 0))
        except OSError as exc:
            sock.close()
            return None, (
                "source_unavailable",
                EXIT_SOURCE_UNAVAILABLE,
                "cannot bind source address {}: {}".format(source, exc),
            )
        sock.connect(sockaddr)
    except BaseException:
        sock.close()
        raise
    return sock, None


def finish(args, category, exit_code, detail, addresses=None):
    status = {
        "category": category,
        "exit_code": exit_code,
        "detail": detail,
        "name": args.name,
        "connect_host": args.connect_host,
        "port": args.port,
        "server_name": args.server_name,
        "expected": args.expect,
        "requested_source": args.source_address,
        "observed_source": OBSERVED.get("source", ""),
        "observed_peer": OBSERVED.get("peer", ""),
        "rd": not args.no_recursion_desired,
    }
    if addresses is not None:
        status["addresses"] = addresses
    write_status(args.status_file, **status)
    if exit_code != EXIT_OK:
        print("DoT probe failed [{}]: {}".format(category, detail), file=sys.stderr)
    return exit_code


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--connect-host", required=True)
    parser.add_argument("--port", type=int, default=853)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--expect", default="")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--source-address",
        default="",
        help="Bind the TCP socket to this local IP before connecting and "
        "require the connected socket to use it.",
    )
    parser.add_argument(
        "--no-recursion-desired",
        action="store_true",
        help="Clear the RD bit (default: RD=1, a recursive query).",
    )
    parser.add_argument(
        "--status-file",
        default="",
        help="Write a machine-readable JSON outcome with a stable category.",
    )
    args = parser.parse_args()

    query_id = random.randint(0, 0xFFFF)
    query = (
        struct.pack(
            "!HHHHHH",
            query_id,
            0x0000 if args.no_recursion_desired else 0x0100,
            1, 0, 0, 0,
        )
        + encode_name(args.name)
        + struct.pack("!HH", 1, 1)
    )

    try:
        context = ssl.create_default_context(cafile=args.ca_file)
    except (OSError, ssl.SSLError) as exc:
        return finish(args, "ca_error", EXIT_INTERNAL, str(exc))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        raw, source_error = open_connection(args)
    except ConnectionRefusedError as exc:
        return finish(args, "tcp_refused", EXIT_TCP_REFUSED, str(exc))
    except (socket.timeout, TimeoutError) as exc:
        return finish(
            args,
            "tcp_connect_timeout",
            EXIT_TCP_CONNECT_TIMEOUT,
            str(exc) or "TCP connect timed out",
        )
    except OSError as exc:
        return finish(args, "tcp_unreachable", EXIT_TCP_UNREACHABLE, str(exc))
    if source_error is not None:
        return finish(args, *source_error)

    try:
        OBSERVED["source"] = canonical_ip(raw.getsockname()[0])
        OBSERVED["peer"] = canonical_ip(raw.getpeername()[0])
    except (OSError, ValueError) as exc:
        raw.close()
        return finish(args, "source_mismatch", EXIT_SOURCE_MISMATCH, str(exc))
    if args.source_address and OBSERVED["source"] != canonical_ip(args.source_address):
        raw.close()
        return finish(
            args,
            "source_mismatch",
            EXIT_SOURCE_MISMATCH,
            "connected socket uses {} instead of requested source {}".format(
                OBSERVED["source"], args.source_address
            ),
        )

    try:
        tls = context.wrap_socket(raw, server_hostname=args.server_name)
    except ssl.SSLCertVerificationError as exc:
        raw.close()
        return finish(args, "tls_certificate", EXIT_TLS_CERTIFICATE, str(exc))
    except (socket.timeout, TimeoutError) as exc:
        raw.close()
        return finish(
            args,
            "tls_timeout",
            EXIT_TLS_TIMEOUT,
            str(exc) or "TLS handshake timed out",
        )
    except ssl.SSLError as exc:
        raw.close()
        return finish(args, "tls_handshake", EXIT_TLS_HANDSHAKE, str(exc))
    except OSError as exc:
        raw.close()
        return finish(args, "tcp_unreachable", EXIT_TCP_UNREACHABLE, str(exc))

    try:
        with tls:
            tls.settimeout(args.timeout)
            tls.sendall(struct.pack("!H", len(query)) + query)
            header = tls.recv(2)
            if len(header) != 2:
                return finish(
                    args,
                    "protocol",
                    EXIT_PROTOCOL,
                    "missing DNS-over-TLS length prefix",
                )
            length = struct.unpack("!H", header)[0]
            response = b""
            while len(response) < length:
                chunk = tls.recv(length - len(response))
                if not chunk:
                    return finish(
                        args,
                        "protocol",
                        EXIT_PROTOCOL,
                        "truncated DNS-over-TLS response",
                    )
                response += chunk
    except (socket.timeout, TimeoutError) as exc:
        return finish(
            args,
            "response_timeout",
            EXIT_RESPONSE_TIMEOUT,
            str(exc) or "DNS response timed out",
        )
    except ssl.SSLError as exc:
        return finish(args, "tls_handshake", EXIT_TLS_HANDSHAKE, str(exc))
    except OSError as exc:
        return finish(args, "tcp_unreachable", EXIT_TCP_UNREACHABLE, str(exc))

    if len(response) < 12:
        return finish(
            args, "protocol", EXIT_PROTOCOL, "short DNS response"
        )
    response_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", response[:12]
    )
    if response_id != query_id:
        return finish(
            args, "protocol", EXIT_PROTOCOL, "DNS transaction ID mismatch"
        )
    rcode = flags & 0x000F
    if rcode == 5:
        return finish(
            args,
            "dns_refused",
            EXIT_DNS_REFUSED,
            "server returned DNS RCODE=REFUSED",
        )
    if rcode:
        return finish(
            args,
            "dns_rcode",
            EXIT_DNS_RCODE,
            "server returned DNS RCODE={} ({})".format(
                rcode, RCODE_NAMES.get(rcode, "UNKNOWN")
            ),
        )

    try:
        addresses = parse_a_records(response, qdcount, ancount)
    except ValueError as exc:
        return finish(args, "protocol", EXIT_PROTOCOL, str(exc))

    print("DoT A {} -> {}".format(args.name, ",".join(addresses) or "(none)"))
    if not addresses:
        return finish(
            args,
            "no_answer",
            EXIT_NO_ANSWER,
            "valid DNS response contained no A records",
            addresses=addresses,
        )
    if args.expect and args.expect not in addresses:
        return finish(
            args,
            "wrong_answer",
            EXIT_WRONG_ANSWER,
            "expected {} not in answer {}".format(
                args.expect, ",".join(addresses)
            ),
            addresses=addresses,
        )
    return finish(args, "ok", EXIT_OK, "validated DoT A answer", addresses=addresses)


if __name__ == "__main__":
    sys.exit(main())
