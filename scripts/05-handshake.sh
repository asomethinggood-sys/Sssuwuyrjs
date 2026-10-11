#!/usr/bin/env bash
# 05-handshake.sh - prove a real WireGuard handshake is established.
#
# The only accepted evidence is a non-zero `latest-handshakes` timestamp read
# back from the kernel plus non-zero transfer counters. A green workflow with
# an empty handshake table is reported as FAIL, never as success.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

DIAG_DIR="${WG_ARTIFACT_DIR}/diagnostics"

ns() { ip netns exec "$@"; }

handshake_epoch() {
  # Prints the newest handshake unix time for the interface (0 if never).
  ns "$WG_CLI_NS" wg show wg0 latest-handshakes 2>/dev/null \
    | awk '{ if ($2+0 > max) max = $2+0 } END { print max+0 }'
}

# The peer is passive until traffic flows, so drive it deliberately.
poke() {
  ns "$WG_CLI_NS" ping -c 1 -W 2 "$WG_TUNNEL_SRV_IP" >/dev/null 2>&1 || true
}

main() {
  wg_init_artifacts
  wg_step "handshake: establish and verify"
  install -d -m 0755 "$DIAG_DIR"

  local before after waited=0
  before="$(handshake_epoch)"
  wg_log "handshake timestamp before traffic: $before (0 means none yet)"

  # Bounded wait: WG_HANDSHAKE_TIMEOUT seconds, checked every second.
  while (( waited < WG_HANDSHAKE_TIMEOUT )); do
    poke
    after="$(handshake_epoch)"
    if (( after > 0 )); then break; fi
    sleep 1
    waited=$(( waited + 1 ))
  done

  if (( after > 0 )); then
    wg_check "HS-01" PASS "WireGuard handshake established" \
      "latest-handshakes=${after} ($(date -u -d "@${after}" +%Y-%m-%dT%H:%M:%SZ)), waited ${waited}s"
  else
    wg_check "HS-01" FAIL "WireGuard handshake established" \
      "no handshake within ${WG_HANDSHAKE_TIMEOUT}s; run 11-diagnose.sh for a triage dump"
    diagnose
    exit 1
  fi

  # The server must also have seen the client.
  local srv_hs
  srv_hs="$(ns "$WG_SRV_NS" wg show wg0 latest-handshakes 2>/dev/null | awk '{ if ($2+0 > max) max=$2+0 } END { print max+0 }')"
  if (( srv_hs > 0 )); then
    wg_check "HS-02" PASS "Server observed the same handshake" "latest-handshakes=${srv_hs}"
  else
    wg_check "HS-02" FAIL "Server observed the same handshake" "server handshake table is empty"
    diagnose
    exit 1
  fi

  # Counters must move: proves the data path, not just the control plane.
  local rx tx
  rx="$(ns "$WG_CLI_NS" wg show wg0 transfer | awk '{rx+=$2} END {print rx+0}')"
  tx="$(ns "$WG_CLI_NS" wg show wg0 transfer | awk '{tx+=$3} END {print tx+0}')"
  if (( rx > 0 && tx > 0 )); then
    wg_check "HS-03" PASS "Encrypted data path moved bytes" "client rx=${rx}B tx=${tx}B"
  else
    wg_check "HS-03" FAIL "Encrypted data path moved bytes" "rx=${rx} tx=${tx}"
    exit 1
  fi

  # Keeping the same session key across pokes is the expected "roamed/stable"
  # state; a *new* handshake after the rekey interval is also normal.
  ns "$WG_CLI_NS" wg show wg0 dump >"${DIAG_DIR}/wg-client-dump.txt"
  ns "$WG_SRV_NS" wg show wg0 dump >"${DIAG_DIR}/wg-server-dump.txt"
  # Redact the key column of the dump before it can reach an artifact.
  sed -E 's/^([A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=)/<redacted>/' -i \
    "${DIAG_DIR}/wg-client-dump.txt" "${DIAG_DIR}/wg-server-dump.txt"
  wg_check "HS-04" PASS "Handshake state captured for audit" "diagnostics/wg-*-dump.txt (key column redacted)"
}

diagnose() {
  {
    echo "### triage dump at $(_wg_ts)"
    echo "--- wg show wg0 (client ns)"; ns "$WG_CLI_NS" wg show wg0 || true
    echo "--- wg show wg0 (server ns)"; ns "$WG_SRV_NS" wg show wg0 || true
    echo "--- client routes"; ns "$WG_CLI_NS" ip route show || true
    echo "--- transport reachability (cli -> srv transport ip)"
    ns "$WG_CLI_NS" ping -c 2 -W 2 "$WG_TRANSPORT_SRV_IP" || true
    echo "--- server listener"; ns "$WG_SRV_NS" ss -lunp 2>/dev/null || true
    echo "--- dns server log"; tail -n 20 "${DIAG_DIR}/dns-server.log" 2>/dev/null || true
  } >"${DIAG_DIR}/handshake-triage.txt" 2>&1
  wg_err "triage written to ${DIAG_DIR}/handshake-triage.txt"
  cat "${DIAG_DIR}/handshake-triage.txt" >&2 || true
}

main "$@"
