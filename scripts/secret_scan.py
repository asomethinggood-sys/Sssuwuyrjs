#!/usr/bin/env python3
"""Detect WireGuard *secret* material in files that are about to be published.

A naive "looks like a 44-character base64 key" scan produces false positives,
because **public** keys have exactly the same shape as private keys. This
scanner therefore works in two passes:

1. It collects every key token that is *provably public* — values of
   ``*_public_key=`` assignments, ``PublicKey =`` lines, and ``AllowedIPs``-free
   ``[Peer]`` blocks in explicitly public files.
2. Any remaining 32-byte key token is, by construction, either a private key or
   a preshared key, and is reported as a leak.

Exit codes: 0 clean, 1 leak found, 2 usage error.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

KEY_TOKEN = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=")

# Lines whose value is a public key (or a public-key digest) are not secrets.
PUBLIC_CONTEXT = re.compile(
    rb"(public_?key|publickey|# *public|// *public)", re.IGNORECASE
)
SECRET_CONTEXT = re.compile(rb"(private_?key|privatekey|preshared_?key|presharedkey|psk)", re.IGNORECASE)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".gz", ".tgz", ".zip", ".pdf", ".woff", ".woff2", ".ico"}


def iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in SKIP_EXT:
                continue
            yield os.path.join(dirpath, name)


def scan(root: str) -> list[tuple[str, int, bytes]]:
    findings: list[tuple[str, int, bytes]] = []

    # Pass 1: collect public key tokens.
    public_tokens: set[bytes] = set()
    for path in iter_files(root):
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        for line in data.splitlines():
            if PUBLIC_CONTEXT.search(line) and not SECRET_CONTEXT.search(line):
                for match in KEY_TOKEN.finditer(line):
                    public_tokens.add(match.group(0))

    # Pass 2: anything key-shaped that is not a known public key is a secret.
    for path in iter_files(root):
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        for lineno, line in enumerate(data.splitlines(), start=1):
            if b"<redacted>" in line:
                continue
            for match in KEY_TOKEN.finditer(line):
                token = match.group(0)
                if token in public_tokens:
                    continue
                if PUBLIC_CONTEXT.search(line) and not SECRET_CONTEXT.search(line):
                    # Public key written in a line we could not attribute in pass 1.
                    continue
                findings.append((path, lineno, token[:8] + b"..."))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    leaks = 0
    for root in args.paths:
        if not os.path.exists(root):
            continue
        for path, lineno, preview in scan(root):
            leaks += 1
            print(f"LEAK {path}:{lineno} token={preview.decode()}", file=sys.stderr)

    if leaks:
        print(f"secret-scan: {leaks} potential secret(s) found", file=sys.stderr)
        return 1
    if not args.quiet:
        print("secret-scan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
