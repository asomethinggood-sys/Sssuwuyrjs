#!/usr/bin/env bash
# 08-recovery.sh - failure detection and recovery, exercised for real.
#
# Three scenarios, each asserted rather than assumed:
#   1. A broken peer (wrong preshared key) must produce NO handshake, and the
#      harness must notice within its bounded timeout instead of hanging.
#   2. Restoring the correct key must recover the tunnel without a rebuild.
#   3. An unreachable endpoint must fail fast with an actionable diagnostic.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

DIAG_DIR="${WG_ARTIFACT_DIR}/diagnostics"
ns() { ip netns exec "$@"; }

handshake_epoch() {
  ns "$WG_CLI_NS" wg show wg0 latest-handshakes 2>/dev/null \
    | awk '{ if ($2+0 > max) max = $2+0 } END { print max+0 }'
}

# Returns 0 as soon as a handshake newer than $1 is observed, 1 on timeout.
await_new_handshake() {
  local baseline="$1" budget="$2" waited=0 now
  while (( waited < budget )); do
    ns "$WG_CLI_NS" ping -c 1 -W 2 "$WG_TUNNEL_SRV_IP" >/dev/null 2>&1 || true
    now="$(handshake_epoch)"
    (( now > baseline )) && return 0
    sleep 1
    waited=$(( waited + 1 ))
  done
  return 1
}

main() {
  wg_init_artifacts
  wg_step "recovery: break the tunnel on purpose, then repair it"
  install -d -m 0755 "$DIAG_DIR"

  local baseline
  baseline="$(handshake_epoch)"
  (( baseline > 0 )) || wg_die "recovery tests need a working tunnel first (handshake absent)"

  # --- SCENARIO 1: mismatched preshared key -------------------------------
  local wrong_psk="${WG_STATE_DIR}/keys/wrong-preshared.key"
  ( umask 077; wg genpsk >"$wrong_psk" )
  chmod 0600 "$wrong_psk"

  # Apply the wrong PSK on the *client* only, and clear the session so a new
  # handshake must be negotiated.
  ns "$WG_CLI_NS" wg set wg0 \
      peer "$(wg_pubkey_of "${WG_STATE_DIR}/keys/server.key")" \
      preshared-key "$wrong_psk"
  ns "$WG_CLI_NS" wg set wg0 peer "$(wg_pubkey_of "${WG_STATE_DIR}/keys/server.key")" remove 2>/dev/null || true
  ns "$WG_CLI_NS" wg set wg0 \
      peer "$(wg_pubkey_of "${WG_STATE_DIR}/keys/server.key")" \
      preshared-key "$wrong_psk" \
      allowed-ips "0.0.0.0/0" \
      endpoint "${WG_TRANSPORT_SRV_IP}:${WG_LISTEN_PORT}" \
      persistent-keepalive 5

  local neg_ok=0
  if await_new_handshake "$baseline" 12; then
    neg_ok=0
  else
    neg_ok=1
  fi
  if (( neg_ok == 1 )); then
    wg_check "REC-01" PASS "Mismatched preshared key is refused" \
      "no handshake within 12s with a wrong PSK (fail-closed, as WireGuard specifies)"
  else
    wg_check "REC-01" FAIL "Mismatched preshared key is refused" \
      "a handshake completed with the wrong PSK - this must never happen"
    exit 1
  fi
  # The peer must be idle, not looping.
  ns "$WG_CLI_NS" wg show wg0 >"${DIAG_DIR}/recovery-broken-peer.txt" 2>&1 || true

  # --- SCENARIO 2: recovery by restoring the correct PSK -------------------
  baseline="$(handshake_epoch)"
  ns "$WG_CLI_NS" wg set wg0 \
      peer "$(wg_pubkey_of "${WG_STATE_DIR}/keys/server.key")" \
      preshared-key "${WG_STATE_DIR}/keys/preshared.key"

  if await_new_handshake "$baseline" "$WG_HANDSHAKE_TIMEOUT"; then
    wg_check "REC-02" PASS "Tunnel recovers after key repair" \
      "handshake re-established within ${WG_HANDSHAKE_TIMEOUT}s without rebuilding the interface"
  else
    wg_check "REC-02" FAIL "Tunnel recovers after key repair" "no handshake after restoring the PSK"
    exit 1
  fi

  # --- SCENARIO 3: unreachable endpoint fails fast -------------------------
  baseline="$(handshake_epoch)"
  local bad_port=1
  ns "$WG_CLI_NS" wg set wg0 \
      peer "$(wg_pubkey_of "${WG_STATE_DIR}/keys/server.key")" \
      endpoint "${WG_TRANSPORT_SRV_IP}:${bad_port}"
  local fail_out fail_rc=0
  fail_out="$(timeout --kill-after=5s 10s ip netns exec "$WG_CLI_NS" ping -c 1 -W 3 "$WG_TUNNEL_SRV_IP" 2>&1)" || fail_rc=$?
  if (( fail_rc != 0 )); then
    wg_check "REC-03" PASS "Unreachable endpoint fails fast and cleanly" \
      "ping over a dead endpoint returned rc=$fail_rc within the bounded timeout: $(printf '%s' "$fail_out" | tail -n 1)"
  else
    wg_check "REC-03" FAIL "Unreachable endpoint fails fast and cleanly" "traffic unexpectedly succeeded"
  fi

  # Restore the endpoint and confirm service is healthy again.
  #
  # Note: this asserts *reachability*, not a fresh handshake. WireGuard keeps a
  # live session for up to 180s, so after correcting the endpoint the next
  # packet may be carried by the existing session. Requiring a new handshake
  # here would be a false negative; we report which of the two happened.
  baseline="$(handshake_epoch)"
  ns "$WG_CLI_NS" wg set wg0 \
      peer "$(wg_pubkey_of "${WG_STATE_DIR}/keys/server.key")" \
      endpoint "${WG_TRANSPORT_SRV_IP}:${WG_LISTEN_PORT}"

  local recovered=0 waited_r=0
  while (( waited_r < WG_HANDSHAKE_TIMEOUT )); do
    if ns "$WG_CLI_NS" ping -c 1 -W 2 "$WG_TUNNEL_SRV_IP" >/dev/null 2>&1; then
      recovered=1
      break
    fi
    sleep 1
    waited_r=$(( waited_r + 1 ))
  done
  if (( recovered == 1 )); then
    local after_r
    after_r="$(handshake_epoch)"
    if (( after_r > baseline )); then
      wg_check "REC-04" PASS "Endpoint correction restores service" \
        "recovered in ${waited_r}s with a fresh handshake (new session)"
    else
      wg_check "REC-04" PASS "Endpoint correction restores service" \
        "recovered in ${waited_r}s reusing the existing session (no rekey needed)"
    fi
  else
    wg_check "REC-04" FAIL "Endpoint correction restores service" \
      "no connectivity within ${WG_HANDSHAKE_TIMEOUT}s after fixing the endpoint"
    exit 1
  fi

  shred -u "$wrong_psk" 2>/dev/null || rm -f "$wrong_psk"
  wg_log "recovery scenarios complete"
}

main "$@"
