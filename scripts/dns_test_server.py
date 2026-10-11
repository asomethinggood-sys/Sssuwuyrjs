#!/usr/bin/env python3
"""Minimal authoritative + forwarding DNS responder used by the tunnel tests.

It exists so the harness can prove that DNS traffic *actually traverses the
WireGuard tunnel* rather than being answered locally:

  * names under the configured test zone (default ``wg.internal``) are answered
    authoritatively with a fixed A record;
  * everything else is forwarded to an upstream resolver so that the
    full-tunnel egress test can resolve real names.

Only UDP is implemented; the harness never needs TCP fallback because the
records it looks up are small.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
from typing import Iterable


def parse_qname(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("truncated question name")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), offset


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def build_response(query: bytes, answer_ip: str | None, upstream: tuple[str, int] | None) -> bytes:
    if len(query) < 12:
        raise ValueError("short query")
    txid = query[:2]
    qname, offset = parse_qname(query, 12)
    qtype, qclass = struct.unpack("!HH", query[offset : offset + 4])
    question = query[12 : offset + 4]

    authoritative = answer_ip is not None and qname.lower().endswith(".wg.internal")

    if authoritative:
        if qtype == 1 and qclass == 1:
            header = txid + struct.pack("!HHHHH", 0x8580, 1, 1, 0, 0)
            answer = (
                b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, 30, 4)
                + socket.inet_aton(answer_ip)
            )
            return header + question + answer
        # AAAA / other types inside the test zone: NOERROR, no answers.
        header = txid + struct.pack("!HHHHH", 0x8580, 1, 0, 0, 0)
        return header + question

    if upstream is not None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3.0)
            s.sendto(query, upstream)
            reply, _ = s.recvfrom(4096)
            return reply

    # NXDOMAIN
    header = txid + struct.pack("!HHHHH", 0x8583, 1, 0, 0, 0)
    return header + question


def serve(listen: str, port: int, answer_ip: str | None, upstream: tuple[str, int] | None, ready_file: str | None) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen, port))
    if ready_file:
        with open(ready_file, "w", encoding="utf-8") as fh:
            fh.write("ready\n")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            break
        try:
            sock.sendto(build_response(data, answer_ip, upstream), addr)
        except Exception as exc:  # keep the responder alive; log to stderr only
            print(f"dns_test_server: dropping query from {addr}: {exc}", file=sys.stderr)


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--answer", default=None, help="A record for names under .wg.internal")
    ap.add_argument("--upstream", default="1.1.1.1:53", help="forwarder for other names")
    ap.add_argument("--no-upstream", action="store_true")
    ap.add_argument("--ready-file", default=None)
    args = ap.parse_args(list(argv) if argv is not None else None)

    upstream = None
    if not args.no_upstream:
        host, _, port_s = args.upstream.rpartition(":")
        upstream = (host, int(port_s))

    serve(args.listen, args.port, args.answer, upstream, args.ready_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
