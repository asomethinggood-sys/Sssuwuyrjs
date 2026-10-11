#!/usr/bin/env bash
# tests/run-unit-tests.sh - fast, unprivileged tests for the harness's own logic.
#
# These run on every pull request and cover the parts that can be tested without
# root, without the network, and without a WireGuard module: the config parser,
# the secret scanner, the template renderer and the DNS helpers. Anything that
# needs privileges or a kernel interface is covered by the CI harness instead.
set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

ok() {
  PASS=$(( PASS + 1 ))
  printf '  ok   %s\n' "$1"
}

not_ok() {
  FAIL=$(( FAIL + 1 ))
  printf '  FAIL %s\n' "$1"
}

expect_rc() {
  # expect_rc <wanted-rc> <label> -- <command...>
  local wanted="$1" label="$2"; shift 2
  [[ "${1:-}" == "--" ]] && shift
  local rc=0
  "$@" >"$WORK/out.txt" 2>&1 || rc=$?
  if [[ "$rc" == "$wanted" ]]; then
    ok "$label (rc=$rc)"
  else
    not_ok "$label (expected rc=$wanted, got rc=$rc)"; sed 's/^/       /' "$WORK/out.txt"
  fi
}

expect_contains() {
  local needle="$1" label="$2"
  if grep -qF -- "$needle" "$WORK/out.txt"; then ok "$label"; else
    not_ok "$label (missing: $needle)"; sed 's/^/       /' "$WORK/out.txt"
  fi
}

section() { printf '\n== %s ==\n' "$1"; }

# ---------------------------------------------------------------------------
section "validate_config.py"
# ---------------------------------------------------------------------------
VALID_SERVER="$WORK/server.conf"
VALID_CLIENT="$WORK/client.conf"
# Two distinct, structurally valid key values. The 43rd character must be one
# of AEIMQUYcgkosw048 (WireGuard keys are 32 bytes base64-encoded), so the
# all-'A' and all-'E' patterns are valid stand-ins when `wg` is unavailable.
if command -v wg >/dev/null 2>&1; then
  KEY_A="$(wg genkey)"
  KEY_B="$(wg genkey)"
else
  KEY_A="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  KEY_B="EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE="
fi

cat >"$VALID_SERVER" <<EOF
[Interface]
Address = 10.13.13.1/24
ListenPort = 51820
PrivateKey = $KEY_A
MTU = 1420
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = $KEY_B
PresharedKey = $KEY_B
AllowedIPs = 10.13.13.2/32
EOF

cat >"$VALID_CLIENT" <<EOF
[Interface]
Address = 10.13.13.2/32
PrivateKey = $KEY_B
DNS = 10.13.13.1
MTU = 1420

[Peer]
PublicKey = $KEY_A
PresharedKey = $KEY_B
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

expect_rc 0 "valid server+client configuration accepted" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --server "$VALID_SERVER" --client "$VALID_CLIENT"

# repeated PostUp/PostDown must not be treated as duplicate keys
expect_rc 0 "repeated PostUp/PostDown accepted" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --server "$VALID_SERVER"

sed 's/^PrivateKey.*//' "$VALID_SERVER" >"$WORK/no-key.conf"
expect_rc 1 "missing PrivateKey rejected" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --server "$WORK/no-key.conf"

sed 's|^AllowedIPs.*|AllowedIPs = 10.13.13.0/24|' "$VALID_SERVER" >"$WORK/overlap.conf"
expect_rc 1 "peer AllowedIPs overlapping the server address rejected" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --server "$WORK/overlap.conf"

sed 's/^MTU.*/MTU = 99999/' "$VALID_CLIENT" >"$WORK/bad-mtu.conf"
expect_rc 1 "insane MTU rejected" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --client "$WORK/bad-mtu.conf"

sed 's/^PrivateKey.*/PrivateKey = not-a-key/' "$VALID_CLIENT" >"$WORK/bad-key.conf"
expect_rc 1 "malformed PrivateKey rejected" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --client "$WORK/bad-key.conf"

sed 's/^Endpoint.*/Endpoint = <SERVER_ENDPOINT_HOST>:51820/' "$VALID_CLIENT" >"$WORK/placeholder.conf"
expect_rc 1 "placeholder Endpoint rejected in a live config" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --client "$WORK/placeholder.conf"
expect_rc 0 "placeholder Endpoint accepted in a template" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --client "$WORK/placeholder.conf" --allow-placeholders

sed 's/^ListenPort.*/ListenPort = 1234/' "$VALID_SERVER" >"$WORK/port.conf"
expect_rc 1 "unexpected ListenPort rejected" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --server "$WORK/port.conf" --expect-port 51820

printf '[Interface]\nAddress = 10.0.0.1/24\nAddress = 10.0.0.2/24\n' >"$WORK/multi-addr.conf"
expect_rc 1 "config without a peer rejected" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --server "$WORK/multi-addr.conf"

printf '[Interface]\nPrivateKey = %s\nBogusKey = 1\n' "$KEY_A" >"$WORK/unknown-key.conf"
expect_rc 1 "unknown key name rejected" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --server "$WORK/unknown-key.conf"

# ---------------------------------------------------------------------------
section "secret_scan.py"
# ---------------------------------------------------------------------------
SCAN="$WORK/scan"
mkdir -p "$SCAN"
if command -v wg >/dev/null 2>&1; then
  PRIV="$(wg genkey)"
  PUB="$(wg pubkey <<<"$PRIV")"
  PSK="$(wg genpsk)"
else
  # Same shape as a real key so the scanner's regex is still exercised.
  PRIV="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  PUB="EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE="
  PSK="IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII="
fi

printf 'server_public_key=%s\nclient_public_key=%s\n' "$PUB" "$PUB" >"$SCAN/public-keys.txt"
expect_rc 0 "public keys are not flagged as secrets" -- \
  python3 "$REPO_ROOT/scripts/secret_scan.py" "$SCAN"

printf 'PrivateKey = %s\n' "$PRIV" >"$SCAN/leak.conf"
expect_rc 1 "private key in an artifact is flagged" -- \
  python3 "$REPO_ROOT/scripts/secret_scan.py" "$SCAN"
rm "$SCAN/leak.conf"

printf 'PRESHARED_KEY=%s\n' "$PSK" >"$SCAN/leak2.txt"
expect_rc 1 "preshared key in an artifact is flagged" -- \
  python3 "$REPO_ROOT/scripts/secret_scan.py" "$SCAN"
rm "$SCAN/leak2.txt"

printf '[Peer]\nPublicKey = %s\nPrivateKey = <redacted>\nPresharedKey = <redacted>\n' "$PUB" \
  >"$SCAN/example.conf.redacted"
expect_rc 0 "redacted configuration is clean" -- \
  python3 "$REPO_ROOT/scripts/secret_scan.py" "$SCAN"

# The scanner must not be fooled by a secret that merely looks public.
printf '#   doc comment\n%s\n' "$PRIV" >"$SCAN/sneaky.conf"
expect_rc 1 "bare key token with no public context is flagged" -- \
  python3 "$REPO_ROOT/scripts/secret_scan.py" "$SCAN"
rm "$SCAN/sneaky.conf"

# ---------------------------------------------------------------------------
section "render-config.sh"
# ---------------------------------------------------------------------------
VALUES="$WORK/values.json"
cat >"$VALUES" <<EOF
{"CLIENT_TUNNEL_IP":"10.13.13.2","TUNNEL_DNS":"10.13.13.1","TUNNEL_MTU":"1420",
 "CLIENT_PRIVATE_KEY":"$PRIV","CLIENT_ALLOWED_IPS":"0.0.0.0/0",
 "CLIENT_PERSISTENT_KEEPALIVE":"25","CLIENT_NAME":"unit-test"}
EOF

expect_rc 1 "unresolved variables abort rendering" -- \
  "$REPO_ROOT/scripts/render-config.sh" \
    --template "$REPO_ROOT/examples/client.conf.template" \
    --values "$VALUES" --out "$WORK/out.conf"
expect_contains "unresolved variables:" "unresolved variables are named on stderr"

expect_rc 0 "--allow-unresolved emits a template" -- \
  "$REPO_ROOT/scripts/render-config.sh" \
    --template "$REPO_ROOT/examples/client.conf.template" \
    --values "$VALUES" --out "$WORK/template.conf" --allow-unresolved
expect_rc 1 "the emitted template is rejected as a live config" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --client "$WORK/template.conf"

cat >"$WORK/full.json" <<EOF
{"CLIENT_TUNNEL_IP":"10.13.13.2","TUNNEL_DNS":"10.13.13.1","TUNNEL_MTU":"1420",
 "CLIENT_PRIVATE_KEY":"$PRIV","CLIENT_ALLOWED_IPS":"0.0.0.0/0",
 "CLIENT_PERSISTENT_KEEPALIVE":"25","CLIENT_NAME":"unit-test",
 "SERVER_PUBLIC_KEY":"$PUB","PRESHARED_KEY":"$PSK",
 "SERVER_ENDPOINT_HOST":"203.0.113.10","SERVER_ENDPOINT_PORT":"51820"}
EOF
expect_rc 0 "fully specified values render a live config" -- \
  "$REPO_ROOT/scripts/render-config.sh" \
    --template "$REPO_ROOT/examples/client.conf.template" \
    --values "$WORK/full.json" --out "$WORK/live.conf" \
    --redact "$WORK/live.conf.redacted"
expect_rc 0 "rendered live config passes structural validation" -- \
  python3 "$REPO_ROOT/scripts/validate_config.py" --client "$WORK/live.conf"
if [[ "$(stat -c '%a' "$WORK/live.conf")" == "600" ]]; then
  ok "rendered config is mode 0600"
else
  not_ok "rendered config is mode 0600 (got $(stat -c '%a' "$WORK/live.conf"))"
fi
expect_rc 0 "redacted copy is clean" -- python3 "$REPO_ROOT/scripts/secret_scan.py" "$WORK/live.conf.redacted"
if grep -qF "$PRIV" "$WORK/live.conf.redacted"; then
  not_ok "redacted copy must not contain the private key"
else
  ok "redacted copy contains no private key"
fi

# ---------------------------------------------------------------------------
section "DNS helpers"
# ---------------------------------------------------------------------------
python3 - "$REPO_ROOT" <<'PY'
import importlib.util, pathlib, sys
root = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("dns_test_server", root / "scripts" / "dns_test_server.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

import struct
def query(name, qtype=1):
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return q

resp = mod.build_response(query("gateway.wg.internal"), "10.13.13.1", None)
assert resp[:2] == b"\x12\x34", "transaction id must be echoed"
assert b"\x0a\x0d\x0d\x01" in resp, "A record for 10.13.13.1 expected"
print("  ok   authoritative A answer is well formed")

resp = mod.build_response(query("gateway.wg.internal", 28), "10.13.13.1", None)
an = struct.unpack("!H", resp[6:8])[0]
assert an == 0, "AAAA inside the test zone must return NOERROR with no answers"
print("  ok   AAAA inside the test zone returns NOERROR/0 answers")

resp = mod.build_response(query("elsewhere.example"), None, None)
rcode = resp[3] & 0x0F
assert rcode == 3, f"expected NXDOMAIN without an upstream, got rcode={rcode}"
print("  ok   NXDOMAIN when no upstream and no authoritative data")
PY
if (( $? == 0 )); then PASS=$(( PASS + 3 )); else FAIL=$(( FAIL + 1 )); fi

# ---------------------------------------------------------------------------
section "templates"
# ---------------------------------------------------------------------------
if command -v grep >/dev/null 2>&1; then
  if grep -rhoE '\{\{ *[A-Z0-9_]+ *\}\}' "$REPO_ROOT/examples" | tr -d '{} ' | sort -u >"$WORK/vars.txt"; then :; fi
  MISSING=0
  while read -r var; do
    [[ -n "$var" ]] || continue
    grep -q -- "$var" "$REPO_ROOT/docs/CONFIGURATION.md" || { MISSING=1; printf '       undocumented: %s\n' "$var"; }
  done <"$WORK/vars.txt"
  if (( MISSING == 0 )); then ok "every template variable is documented"; else not_ok "every template variable is documented"; fi
fi

# ---------------------------------------------------------------------------
printf '\n---------------------------------------------\n'
printf 'unit tests: %d passed, %d failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
