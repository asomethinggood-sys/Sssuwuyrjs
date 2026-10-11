#!/usr/bin/env bash
# 04-tunnel-up.sh - build the end-to-end WireGuard test bed.
#
# Topology (all inside one ephemeral GitHub-hosted runner VM):
#
#   root netns (the runner itself)     <- bridge + optional NAT
#     br-wg 192.168.77.1/29
#       |                    |
#     vethsrv              vethcli
#       |                    |
#   +--------------+     +--------------+
#   | netns wgsrv  |     | netns wgcli  |
#   | .2/29        |     | .3/29        |
#   | wg0 10.13.13.1| <-> | wg0 10.13.13.2|   UDP/51820 over the bridge
#   | (server role)|     | (client role)|
#   +--------------+     +--------------+
#
# This is a real WireGuard tunnel: real kernel crypto, real UDP transport, real
# routing and real netfilter. It is deliberately NOT an internet-facing tunnel,
# because GitHub-hosted runners have no inbound reachability (docs/FEASIBILITY.md).
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

KEYS_DIR="${WG_STATE_DIR}/keys"
DIAG_DIR="${WG_ARTIFACT_DIR}/diagnostics"

# `ns` runs a whole command inside a namespace. `-n` inside `ip` is not used
# anywhere, because mixing the two is a common source of "unknown object" bugs.
ns() { ip netns exec "$@"; }

teardown_topology() {
  # Idempotent: safe to call at the start of a run and during cleanup.
  ip link del dev br-wg 2>/dev/null || true
  ip netns del "$WG_SRV_NS" 2>/dev/null || true
  ip netns del "$WG_CLI_NS" 2>/dev/null || true
}

build_transport() {
  ip netns add "$WG_SRV_NS"
  ip netns add "$WG_CLI_NS"

  ip link add name br-wg type bridge
  ip addr add "${WG_BRIDGE_IP}/${WG_TRANSPORT_CIDR}" dev br-wg
  ip link set br-wg up

  ip link add "$WG_VETH_SRV" type veth peer name "${WG_VETH_SRV}-br"
  ip link set "$WG_VETH_SRV" netns "$WG_SRV_NS"
  ip link set "${WG_VETH_SRV}-br" master br-wg
  ip link set "${WG_VETH_SRV}-br" up

  ip link add "$WG_VETH_CLI" type veth peer name "${WG_VETH_CLI}-br"
  ip link set "$WG_VETH_CLI" netns "$WG_CLI_NS"
  ip link set "${WG_VETH_CLI}-br" master br-wg
  ip link set "${WG_VETH_CLI}-br" up

  ns "$WG_SRV_NS" ip link set lo up
  ns "$WG_SRV_NS" ip addr add "${WG_TRANSPORT_SRV_IP}/${WG_TRANSPORT_CIDR}" dev "$WG_VETH_SRV"
  ns "$WG_SRV_NS" ip link set "$WG_VETH_SRV" up

  ns "$WG_CLI_NS" ip link set lo up
  ns "$WG_CLI_NS" ip addr add "${WG_TRANSPORT_CLI_IP}/${WG_TRANSPORT_CIDR}" dev "$WG_VETH_CLI"
  ns "$WG_CLI_NS" ip link set "$WG_VETH_CLI" up

  # Prove the two namespaces can actually reach each other before adding crypto
  # on top: otherwise a later failure would be ambiguous.
  ns "$WG_SRV_NS" ping -c 2 -W 2 "$WG_TRANSPORT_CLI_IP" >/dev/null 2>&1 \
    || wg_die "transport bridge is not passing traffic (srv -> cli)"
}

build_tunnel() {
  local srv_pub cli_pub
  srv_pub="$(wg_pubkey_of "${KEYS_DIR}/server.key")"
  cli_pub="$(wg_pubkey_of "${KEYS_DIR}/client.key")"

  # --- server role ------------------------------------------------------
  ns "$WG_SRV_NS" ip link add wg0 type wireguard
  ns "$WG_SRV_NS" ip addr add "${WG_TUNNEL_SRV_IP}/${WG_TUNNEL_CIDR}" dev wg0
  ns "$WG_SRV_NS" ip link set wg0 mtu "$WG_MTU"
  ns "$WG_SRV_NS" wg set wg0 private-key "${KEYS_DIR}/server.key" listen-port "$WG_LISTEN_PORT"
  ns "$WG_SRV_NS" ip link set wg0 up
  ns "$WG_SRV_NS" wg set wg0 peer "$cli_pub" \
      preshared-key "${KEYS_DIR}/preshared.key" \
      allowed-ips "${WG_TUNNEL_CLI_IP}/32"

  # --- client role ------------------------------------------------------
  ns "$WG_CLI_NS" ip link add wg0 type wireguard
  ns "$WG_CLI_NS" ip addr add "${WG_TUNNEL_CLI_IP}/${WG_TUNNEL_CIDR}" dev wg0
  ns "$WG_CLI_NS" ip link set wg0 mtu "$WG_MTU"
  ns "$WG_CLI_NS" wg set wg0 private-key "${KEYS_DIR}/client.key" listen-port "$WG_CLI_LISTEN_PORT"
  ns "$WG_CLI_NS" ip link set wg0 up
  ns "$WG_CLI_NS" wg set wg0 peer "$srv_pub" \
      preshared-key "${KEYS_DIR}/preshared.key" \
      allowed-ips "0.0.0.0/0" \
      endpoint "${WG_TRANSPORT_SRV_IP}:${WG_LISTEN_PORT}" \
      persistent-keepalive 5

  # Pin the encapsulation endpoint to the physical link so that the later
  # full-tunnel /1 routes cannot create a routing loop.
  ns "$WG_CLI_NS" ip route replace "${WG_TRANSPORT_SRV_IP}/32" dev "$WG_VETH_CLI" 2>/dev/null || true
}

start_dns_server() {
  install -d -m 0755 "$DIAG_DIR"
  local ready="${WG_STATE_DIR}/dns.ready" log="${DIAG_DIR}/dns-server.log"
  rm -f "$ready"
  # Bound to the tunnel address inside the server namespace, so the client can
  # only reach it through wg0. `setsid` detaches it from this shell's process
  # group; 09-cleanup.sh terminates it by command-line match.
  setsid ip netns exec "$WG_SRV_NS" python3 "${SCRIPT_DIR}/dns_test_server.py" \
      --listen "$WG_TUNNEL_SRV_IP" \
      --port 53 \
      --answer "$WG_TUNNEL_SRV_IP" \
      --upstream 1.1.1.1:53 \
      --ready-file "$ready" \
      >>"$log" 2>&1 &
  if ! wg_wait_for 10 1 -- test -f "$ready"; then
    wg_err "DNS test responder did not start; log follows"
    tail -n 20 "$log" >&2 2>/dev/null || true
    return 1
  fi
  wg_log "DNS test responder ready on ${WG_TUNNEL_SRV_IP}:53 (inside ${WG_SRV_NS})"
}

collect_diagnostics() {
  install -d -m 0755 "$DIAG_DIR"
  {
    echo "### collected $(_wg_ts)"
    echo "--- root links";             ip -br link
    echo "--- root addresses";         ip -br addr
    echo "--- root routes";            ip route show
    echo "--- ${WG_SRV_NS} links";     ns "$WG_SRV_NS" ip -br link
    echo "--- ${WG_SRV_NS} routes";    ns "$WG_SRV_NS" ip route show
    echo "--- ${WG_SRV_NS} wg show";   ns "$WG_SRV_NS" wg show || true
    echo "--- ${WG_CLI_NS} routes";    ns "$WG_CLI_NS" ip route show
    echo "--- ${WG_CLI_NS} wg show";   ns "$WG_CLI_NS" wg show || true
  } >"${DIAG_DIR}/topology.txt" 2>&1
}

main() {
  wg_init_artifacts
  wg_step "tunnel: build isolated test bed"
  wg_require_root

  [[ -s "${KEYS_DIR}/server.key" ]] || wg_die "server key missing; run 02-keygen.sh first"

  teardown_topology
  build_transport
  build_tunnel
  # Configure forwarding/NAT before the DNS step: the test resolver forwards
  # unknown names upstream, which requires the server namespace to have a route
  # to the internet.
  wg_setup_nat || true
  collect_diagnostics

  if start_dns_server; then
    wg_check "TUN-01" PASS "DNS test responder started inside the server namespace" "${WG_TUNNEL_SRV_IP}:53"
  else
    wg_check "TUN-01" FAIL "DNS test responder started" "see diagnostics/dns-server.log"
  fi

  if ns "$WG_SRV_NS" ip -br addr show wg0 | grep -q "$WG_TUNNEL_SRV_IP"; then
    wg_check "TUN-02" PASS "Server WireGuard interface configured" "wg0 ${WG_TUNNEL_SRV_IP}/${WG_TUNNEL_CIDR} in netns ${WG_SRV_NS}"
  else
    wg_check "TUN-02" FAIL "Server WireGuard interface configured" "wg0 missing or misaddressed"
    exit 1
  fi

  if ns "$WG_CLI_NS" ip -br addr show wg0 | grep -q "$WG_TUNNEL_CLI_IP"; then
    wg_check "TUN-03" PASS "Client WireGuard interface configured" "wg0 ${WG_TUNNEL_CLI_IP}/${WG_TUNNEL_CIDR} in netns ${WG_CLI_NS}"
  else
    wg_check "TUN-03" FAIL "Client WireGuard interface configured" "wg0 missing or misaddressed"
    exit 1
  fi

  local cli_peers srv_peers
  cli_peers="$(ns "$WG_CLI_NS" wg show wg0 peers | wc -l)"
  srv_peers="$(ns "$WG_SRV_NS" wg show wg0 peers | wc -l)"
  if [[ "$cli_peers" == "1" && "$srv_peers" == "1" ]]; then
    wg_check "TUN-04" PASS "Kernel accepted the peer configuration" "1 peer configured on each side"
  else
    wg_check "TUN-04" FAIL "Kernel accepted the peer configuration" "cli=$cli_peers srv=$srv_peers"
    exit 1
  fi

  if wg_have iptables; then
    if ip netns exec "$WG_SRV_NS" iptables -t nat -S POSTROUTING 2>/dev/null | grep -q MASQUERADE; then
      wg_check "TUN-06" PASS "Forwarding and NAT configured for the server role" "MASQUERADE present in netns ${WG_SRV_NS}"
    else
      wg_check "TUN-06" FAIL "Forwarding and NAT configured for the server role" "no MASQUERADE rule"
    fi
  else
    wg_check "TUN-06" UNTESTED "Forwarding and NAT configured for the server role" "iptables is not installed"
  fi

  if command -v ss >/dev/null 2>&1; then
    if ns "$WG_SRV_NS" ss -lun 2>/dev/null | grep -q ":${WG_LISTEN_PORT}"; then
      wg_check "TUN-05" PASS "Server UDP listener bound" "0.0.0.0:${WG_LISTEN_PORT} inside netns ${WG_SRV_NS}"
    else
      wg_check "TUN-05" FAIL "Server UDP listener bound" "no listener on UDP/${WG_LISTEN_PORT}"
    fi
  else
    wg_check "TUN-05" UNTESTED "Server UDP listener bound" "ss(8) is not installed"
  fi
}

main "$@"
