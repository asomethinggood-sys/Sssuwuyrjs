#!/usr/bin/env python3
"""Detect WireGuard *secret* material in files that are about to be published.

A naive "looks like a 44-character base64 key" scan produces false positives,
because **public** keys have exactly the same shape as private keys. This
scanner therefore works in two passes:

1. Provenance pass (strongest). Two sources, both free of heuristics:
   ``--secrets-from DIR`` treats every value in a directory of generated keys as
   a secret, and ``--secret-hashes FILE`` treats a key-shaped token as a secret
   when its SHA-256 appears in a manifest of digests. The hash form exists
   because the harness deliberately deletes its key directory before the final
   leak audit runs, so the audit has to be able to prove provenance from
   something that is not itself a secret.
2. Heuristic pass: it collects every key token that is *provably public* — the
   value of a ``PublicKey =`` / ``public_key=`` assignment, a key rendered after
   ``peer:`` by ``wg show``, and similar tool output. Anything key-shaped that is
   not one of those is, by construction, either a private key or a preshared key
   and is reported as a leak.

A private key can never be laundered into "public" by the heuristic pass without
also being caught by the provenance pass.

Exit codes: 0 clean, 1 leak found, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

KEY_TOKEN = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=")

# Separator used inside the compound words below: `wg show` (without `dump`)
# renders the label as "public key:", config files render it as "PublicKey =",
# and wg-quick's own helpers use "public_key". One separator class covers all
# three spellings - an earlier version only matched the underscore form, which
# made every `wg show` public key look like a leak.
_KEYWORD_SEP = r"[\s_\-]?"

# Lines whose *value* is a public key are not secrets. Each alternative is a
# shape that only ever precedes a public key; matching the bare word "public"
# anywhere on a line is deliberately avoided, because it let prose or unrelated
# tool output mark an arbitrary token as public and so suppress a real finding.
PUBLIC_CONTEXT = re.compile(
    rb"(?:"
    rb"^\s*(?:#|//)\s*public" + _KEYWORD_SEP.encode() + rb"key\s*[:=]"   # "# public key: <key>"
    # "PublicKey = <key>", "public_key = <key>", "server_public_key=<key>"
    rb"|\b[A-Za-z0-9_]*public" + _KEYWORD_SEP.encode() + rb"key\s*[:=]"
    rb"|\bpeer:\s*[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]="                 # wg show "peer: <key>"
    rb")",
    re.IGNORECASE,
)

# A line that describes itself as holding a secret is never public context, so a
# single line carrying both labels stays suspicious.
SECRET_CONTEXT = re.compile(
    rb"(private" + _KEYWORD_SEP.encode() + rb"key"
    rb"|preshared" + _KEYWORD_SEP.encode() + rb"key|\bpsk\b)",
    re.IGNORECASE,
)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".gz", ".tgz", ".zip", ".pdf", ".woff", ".woff2", ".ico"}


def iter_files(root: str, excludes: tuple[str, ...] = ()):
    if os.path.isfile(root):
        if not any(x in os.path.abspath(root) for x in excludes):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in SKIP_EXT:
                continue
            path = os.path.join(dirpath, name)
            if any(x and x in os.path.abspath(path) for x in excludes):
                continue
            yield path


def load_secret_hashes(path: str) -> set[str]:
    """Read a manifest of SHA-256 digests, one hex digest per line.

    A digest is not a secret: it cannot be reversed, and publishing it proves
    only that the scanner knew the key existed. That is what lets the audit keep
    working after 09-cleanup.sh has removed the keys themselves.
    """
    digests: set[str] = set()
    if not path or not os.path.isfile(path):
        return digests
    try:
        lines = open(path, "r", encoding="utf-8").read().splitlines()
    except OSError:
        return digests
    for line in lines:
        token = line.strip().lower()
        if len(token) == 64 and all(c in "0123456789abcdef" for c in token):
            digests.add(token)
    return digests


def load_known_secrets(directory: str) -> list[bytes]:
    """Read every file under *directory* and treat its contents as a secret.

    The harness writes generated private keys and preshared keys here. Values are
    trimmed of surrounding whitespace but otherwise compared verbatim, so a
    secret is caught even when it is embedded in a line that the heuristic pass
    would otherwise classify as public.
    """
    secrets: list[bytes] = []
    if not directory or not os.path.isdir(directory):
        return secrets
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            try:
                data = open(os.path.join(dirpath, name), "rb").read().strip()
            except OSError:
                continue
            if data:
                secrets.append(data)
    return secrets


def scan(
    root: str,
    excludes: tuple[str, ...] = (),
    known_secrets: tuple[bytes, ...] = (),
    secret_hashes: frozenset[str] = frozenset(),
) -> list[tuple[str, int, bytes]]:
    findings: list[tuple[str, int, bytes]] = []

    # Pass 0: provenance. A verbatim secret value can never be "public".
    for path in iter_files(root, excludes):
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        for secret in known_secrets:
            index = data.find(secret)
            if index < 0:
                continue
            lineno = data.count(b"\n", 0, index) + 1
            findings.append((path, lineno, secret[:8] + b"..."))

    # Pass 1: collect public key tokens.
    public_tokens: set[bytes] = set()
    for path in iter_files(root, excludes):
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        for line in data.splitlines():
            if PUBLIC_CONTEXT.search(line) and not SECRET_CONTEXT.search(line):
                for match in KEY_TOKEN.finditer(line):
                    public_tokens.add(match.group(0))

    # Pass 2: anything key-shaped that is not a known public key is a secret.
    for path in iter_files(root, excludes):
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        for lineno, line in enumerate(data.splitlines(), start=1):
            # NOTE: lines containing "<redacted>" are NOT skipped wholesale.
            # A partially redacted line (for example a wg(8) dump where only the
            # first column was masked) would otherwise hide the secret that
            # remains on the same line.
            for match in KEY_TOKEN.finditer(line):
                token = match.group(0)
                if token in known_secrets:
                    continue
                if secret_hashes and hashlib.sha256(token).hexdigest() in secret_hashes:
                    # Digests are checked before the public-key allowlist:
                    # provenance outranks any label-based excuse.
                    findings.append((path, lineno, token[:8] + b"..."))
                    continue
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
    ap.add_argument("--exclude", action="append", default=[],
                    help="substring of an absolute path to skip (repeatable)")
    ap.add_argument("--secrets-from", default=None, metavar="DIR",
                    help="directory holding generated keys; every value in it is "
                         "treated as a known secret (provenance pass)")
    ap.add_argument("--secret-hashes", default=None, metavar="FILE",
                    help="manifest of SHA-256 digests of known secrets; a "
                         "key-shaped token whose digest matches is a leak, which "
                         "keeps the provenance pass working after the key "
                         "directory has been deleted")
    args = ap.parse_args(argv)

    leaks = 0
    excludes = tuple(args.exclude)
    known = tuple(load_known_secrets(args.secrets_from)) if args.secrets_from else ()
    hashes = (frozenset(load_secret_hashes(args.secret_hashes))
              if args.secret_hashes else frozenset())
    for root in args.paths:
        if not os.path.exists(root):
            continue
        seen: set[tuple[str, int, bytes]] = set()
        for path, lineno, preview in scan(root, excludes, known, hashes):
            if (path, lineno, preview) in seen:
                continue
            seen.add((path, lineno, preview))
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
