#!/usr/bin/env bash
# 09-cleanup.sh - remove every artifact of a test run and prove it is gone.
#
# Idempotent: running it twice is not an error. It is registered as an EXIT
# trap by the suite so that a failed run cannot leave a tunnel or a key behind.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

VERIFY_ONLY=0
[[ "${1:-}" == "--verify-only" ]] && VERIFY_ONLY=1

kill_bg() {
  # Background responders are started with setsid, so match on the command line.
  pkill -f 'dns_test_server.py' 2>/dev/null || true
  pkill -f 'udp_echo.py' 2>/dev/null || true
  pkill -f 'http.server 8080' 2>/dev/null || true
  sleep 1
  pkill -9 -f 'dns_test_server.py' 2>/dev/null || true
  pkill -9 -f 'udp_echo.py' 2>/dev/null || true
  pkill -9 -f 'http.server 8080' 2>/dev/null || true
}

remove_networking() {
  # Delete in dependency order; every step tolerates "not found".
  ip netns del "$WG_SRV_NS" 2>/dev/null || true
  ip netns del "$WG_CLI_NS" 2>/dev/null || true
  ip netns del wgctl 2>/dev/null || true
  ip link del br-wg 2>/dev/null || true
  ip link del "$WG_VETH_SRV" 2>/dev/null || true
  ip link del "$WG_VETH_CLI" 2>/dev/null || true
  ip link del wg0 2>/dev/null || true
  rm -rf "/etc/netns/${WG_CLI_NS}" "/etc/netns/wgctl" 2>/dev/null || true
}

remove_firewall_rules() {
  command -v iptables >/dev/null 2>&1 || return 0
  local wan
  wan="$(ip route get 1.1.1.1 2>/dev/null | grep -oE 'dev [^ ]+' | awk '{print $2}' | head -1)"
  if [[ -n "$wan" ]]; then
    iptables -t nat -D POSTROUTING -s "${WG_BRIDGE_IP}/${WG_TRANSPORT_CIDR}" -o "$wan" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i br-wg -o "$wan" -j ACCEPT 2>/dev/null || true
  fi
}

shred_secrets() {
  local path
  for path in \
      "${WG_STATE_DIR}/keys/server.key" \
      "${WG_STATE_DIR}/keys/client.key" \
      "${WG_STATE_DIR}/keys/preshared.key" \
      "${WG_STATE_DIR}/keys/wrong-preshared.key" \
      "${WG_STATE_DIR}/values.json" \
      "${WG_STATE_DIR}/conf/server.conf" \
      "${WG_STATE_DIR}/conf/client.conf"; do
    if [[ -f "$path" ]]; then
      shred -u "$path" 2>/dev/null || rm -f "$path"
    fi
  done
  rm -rf "$WG_STATE_DIR"
}

verify_clean() {
  local problems=0

  for netns_name in "$WG_SRV_NS" "$WG_CLI_NS" wgctl; do
    if ip netns list 2>/dev/null | grep -qw "$netns_name"; then
      wg_err "namespace $netns_name still present"
      problems=$(( problems + 1 ))
    fi
  done

  if ip link show type wireguard 2>/dev/null | grep -q wg; then
    wg_err "a WireGuard interface still exists in the root namespace"
    problems=$(( problems + 1 ))
  fi

  if ip link show br-wg >/dev/null 2>&1; then
    wg_err "bridge br-wg still present"
    problems=$(( problems + 1 ))
  fi

  if [[ -e "$WG_STATE_DIR" ]]; then
    wg_err "state directory $WG_STATE_DIR still present"
    problems=$(( problems + 1 ))
  fi

  if pgrep -f 'dns_test_server.py|udp_echo.py|http.server 8080' >/dev/null 2>&1; then
    wg_err "test responders are still running"
    problems=$(( problems + 1 ))
  fi

  return "$problems"
}

main() {
  wg_init_artifacts
  wg_step "cleanup: tear down and verify"

  if (( VERIFY_ONLY == 0 )); then
    kill_bg
    remove_networking
    remove_firewall_rules
    shred_secrets
  fi

  if verify_clean; then
    wg_check "CLN-01" PASS "Network namespaces removed" "no ${WG_SRV_NS}/${WG_CLI_NS}/wgctl namespaces remain"
    wg_check "CLN-02" PASS "WireGuard interfaces and bridge removed" "root namespace is clean"
    wg_check "CLN-03" PASS "Key material destroyed" "state directory ${WG_STATE_DIR} removed"
    wg_check "CLN-04" PASS "Test responder processes terminated" "no orphaned DNS/UDP/HTTP servers"
  else
    wg_check "CLN-01" FAIL "Cleanup verification" "residual state detected - see errors above"
    exit 1
  fi

  wg_log "cleanup complete and verified"
}

main "$@"
