#!/usr/bin/env python3
"""Portable DNS A-record query used when `dig` is not installed.

The harness prefers `dig` (an independent implementation) and falls back to
this script, recording which one was used in the check detail.
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import sys


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def skip_name(data: bytes, offset: int) -> int:
    while offset < len(data) and data[offset] != 0:
        if data[offset] & 0xC0 == 0xC0:
            return offset + 2
        offset += data[offset] + 1
    return offset + 1


def query(server: str, name: str, timeout: float, port: int = 53) -> list[str]:
    txid = random.randrange(0, 65536)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", 1, 1)  # A, IN
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(packet, (server, port))
    data, _ = sock.recvfrom(4096)

    if len(data) < 12:
        raise RuntimeError("short DNS response")
    rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if rid != txid:
        raise RuntimeError("DNS transaction id mismatch")
    if flags & 0x000F:
        raise RuntimeError(f"DNS rcode={flags & 0x000F}")

    offset = 12
    for _ in range(qd):
        offset = skip_name(data, offset) + 4

    answers: list[str] = []
    for _ in range(an):
        offset = skip_name(data, offset)
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype == 1 and rclass == 1 and rdlen == 4:
            answers.append(socket.inet_ntoa(rdata))
    return answers


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("name", nargs="?", default="")
    ap.add_argument("--server", required=True)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--port", type=int, default=53)
    args = ap.parse_args(argv)

    if not args.name:
        ap.error("a name to resolve is required")

    try:
        for address in query(args.server, args.name, args.timeout, args.port):
            print(address)
    except Exception as exc:
        print(f"dns_query: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
