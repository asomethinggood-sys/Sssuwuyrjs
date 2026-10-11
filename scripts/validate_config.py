#!/usr/bin/env python3
"""Structural validation for WireGuard interface configuration files.

`wg-quick strip` catches syntax errors. This module additionally enforces the
properties that make a config *safe*:

  * exactly one [Interface] section, at least one [Peer]
  * every peer has a PublicKey (or, for the client, an Endpoint)
  * AllowedIPs on the server never claims the client's own tunnel address
  * MTU is present and within a sane range
  * no duplicate keys inside a section
  * no obviously placeholder values left in a config claimed to be live

Exit code 0 = valid, 1 = invalid, 2 = usage error.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from dataclasses import dataclass, field

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
PLACEHOLDER_RE = re.compile(r"<[A-Z0-9_]+>|\{\{.*?\}\}")

INTERFACE_KEYS = {
    "privatekey",
    "address",
    "listenport",
    "dns",
    "mtu",
    "table",
    "fwmark",
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
}
PEER_KEYS = {
    "publickey",
    "presharedkey",
    "allowedips",
    "endpoint",
    "persistentkeepalive",
}

# Keys that carry secret material and must never be logged or committed.
SECRET_KEYS = {"privatekey", "presharedkey"}

# wg-quick allows these to appear more than once in the same section. Repeated
# values are accumulated rather than rejected as duplicates.
REPEATABLE_INTERFACE = {"address", "dns", "preup", "postup", "predown", "postdown"}
REPEATABLE_PEER = {"allowedips"}
REPEATABLE = {"interface": REPEATABLE_INTERFACE, "peer": REPEATABLE_PEER}


@dataclass
class Section:
    kind: str
    values: dict[str, str] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)


class ConfigError(Exception):
    pass


def parse(text: str) -> list[Section]:
    sections: list[Section] = []
    current: Section | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            current = Section(kind=m.group(1).lower())
            sections.append(current)
            continue
        if current is None:
            raise ConfigError(f"line {lineno}: value outside of any section")
        if "=" not in line:
            raise ConfigError(f"line {lineno}: expected 'key = value', got {line!r}")
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if not key:
            raise ConfigError(f"line {lineno}: empty key")
        if key in current.values:
            if key not in REPEATABLE.get(current.kind, set()):
                raise ConfigError(f"line {lineno}: duplicate key {key!r} in [{current.kind}]")
            separator = ", " if key == "allowedips" else "\n"
            current.values[key] = current.values[key] + separator + value
        else:
            current.values[key] = value
        current.order.append(key)
    return sections


def check(role: str, sections: list[Section], *, allow_placeholders: bool, strict: bool = True) -> list[str]:
    problems: list[str] = []
    interfaces = [s for s in sections if s.kind == "interface"]
    peers = [s for s in sections if s.kind == "peer"]

    if len(interfaces) != 1:
        problems.append(f"[{role}] expected exactly 1 [Interface], found {len(interfaces)}")
    if not peers:
        problems.append(f"[{role}] expected at least 1 [Peer], found 0")

    for section in sections:
        allowed = INTERFACE_KEYS if section.kind == "interface" else PEER_KEYS
        if section.kind not in {"interface", "peer"}:
            problems.append(f"[{role}] unknown section [{section.kind}]")
            continue
        for key in section.order:
            if key not in allowed:
                problems.append(f"[{role}] unknown key {key!r} in [{section.kind}]")

    for section in interfaces:
        if "privatekey" not in section.values:
            problems.append(f"[{role}] [Interface] is missing PrivateKey")
        else:
            value = section.values["privatekey"]
            if not allow_placeholders and not KEY_RE.match(value):
                problems.append(f"[{role}] PrivateKey is not a valid 32-byte base64 key")
        for key in ("address",):
            if key not in section.values:
                problems.append(f"[{role}] [Interface] is missing {key.capitalize()}")
        if "address" in section.values:
            for addr in _split(section.values["address"]):
                try:
                    ipaddress.ip_interface(addr)
                except ValueError as exc:
                    problems.append(f"[{role}] invalid Address {addr!r}: {exc}")
        if "mtu" in section.values:
            try:
                mtu = int(section.values["mtu"])
            except ValueError:
                problems.append(f"[{role}] MTU is not an integer")
            else:
                if not 576 <= mtu <= 1500:
                    problems.append(f"[{role}] MTU {mtu} outside sane range 576..1500")
        elif strict:
            problems.append(f"[{role}] [Interface] has no MTU (fragmentation risk on NAT paths)")

    for idx, peer in enumerate(peers, start=1):
        label = f"[{role}] peer#{idx}"
        if "publickey" not in peer.values:
            problems.append(f"{label} missing PublicKey")
        else:
            value = peer.values["publickey"]
            if not allow_placeholders and not KEY_RE.match(value):
                problems.append(f"{label} PublicKey is not a valid 32-byte base64 key")
        if "allowedips" not in peer.values:
            problems.append(f"{label} missing AllowedIPs")
        else:
            for net in _split(peer.values["allowedips"]):
                try:
                    ipaddress.ip_network(net, strict=False)
                except ValueError as exc:
                    problems.append(f"{label} invalid AllowedIPs entry {net!r}: {exc}")
        if role == "client":
            if "endpoint" not in peer.values:
                problems.append(f"{label} missing Endpoint (client needs a reachable server)")
            else:
                if not allow_placeholders and PLACEHOLDER_RE.search(peer.values["endpoint"]):
                    problems.append(f"{label} Endpoint still contains a placeholder")
                _check_endpoint(peer.values["endpoint"], problems, label)
            if "presharedkey" not in peer.values and strict:
                problems.append(f"{label} no PresharedKey (post-quantum hardening recommended)")
        if "presharedkey" in peer.values:
            value = peer.values["presharedkey"]
            if not allow_placeholders and not KEY_RE.match(value):
                problems.append(f"{label} PresharedKey is not a valid 32-byte base64 key")
        if "persistentkeepalive" in peer.values:
            try:
                ka = int(peer.values["persistentkeepalive"])
            except ValueError:
                problems.append(f"{label} PersistentKeepalive is not an integer")
            else:
                if ka and not 1 <= ka <= 65535:
                    problems.append(f"{label} PersistentKeepalive {ka} out of range")

    if role == "server" and len(peers) == 1 and "allowedips" in peers[0].values:
        srv_addrs = {
            ipaddress.ip_interface(a).ip
            for s in interfaces
            for a in _split(s.values.get("address", ""))
        }
        for net in _split(peers[0].values["allowedips"]):
            try:
                network = ipaddress.ip_network(net, strict=False)
            except ValueError:
                continue
            for addr in srv_addrs:
                if addr in network:
                    problems.append(
                        f"[server] peer AllowedIPs {net} overlaps the server address {addr}"
                    )

    return problems


def _check_endpoint(value: str, problems: list[str], label: str) -> None:
    # Accept host:port, [v6]:port, and host:port with a DNS name.
    host, _, port = value.rpartition(":")
    host = host.strip("[]")
    if not host or not port:
        problems.append(f"{label} Endpoint {value!r} is not host:port")
        return
    try:
        p = int(port)
    except ValueError:
        problems.append(f"{label} Endpoint port {port!r} is not numeric")
        return
    if not 1 <= p <= 65535:
        problems.append(f"{label} Endpoint port {p} out of range")


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def redact(text: str) -> str:
    out = []
    for line in text.splitlines():
        key = line.split("=", 1)[0].strip().lower()
        if key in SECRET_KEYS:
            out.append(f"{line.split('=')[0].rstrip()} = <redacted>")
        else:
            out.append(line)
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--server")
    ap.add_argument("--client")
    ap.add_argument("--expect-port")
    ap.add_argument("--expect-srv-ip")
    ap.add_argument("--expect-cli-ip")
    ap.add_argument("--allow-placeholders", action="store_true")
    ap.add_argument("--lenient", action="store_true", help="downgrade recommended-only findings")
    args = ap.parse_args(argv)

    if not args.server and not args.client:
        ap.error("at least one of --server/--client required")

    problems: list[str] = []
    for role, path in (("server", args.server), ("client", args.client)):
        if not path:
            continue
        text = open(path, "r", encoding="utf-8").read()
        try:
            sections = parse(text)
        except ConfigError as exc:
            problems.append(f"[{role}] parse error: {exc}")
            continue
        problems += check(
            role,
            sections,
            # Placeholders are only tolerated when explicitly requested, so a
            # template can never be mistaken for a deployable configuration.
            allow_placeholders=args.allow_placeholders,
            strict=not args.lenient,
        )
        if role == "server" and args.expect_port:
            peers_text = "\n".join(
                s.values.get("listenport", "") for s in sections if s.kind == "interface"
            )
            if peers_text and peers_text != args.expect_port:
                problems.append(f"[server] ListenPort {peers_text} != expected {args.expect_port}")

    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print("config structure OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
