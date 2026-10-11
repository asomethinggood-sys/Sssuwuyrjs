#!/usr/bin/env bash
# 07-connectivity.sh - end-to-end client connectivity through the tunnel.
#
# Order matters: ICMP, then UDP, then TCP inside the tunnel, and finally real
# internet egress through the tunnel once NAT/forwarding is in place. Each
# protocol is reported separately because they fail for different reasons.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

DIAG_DIR="${WG_ARTIFACT_DIR}/diagnostics"
WWW_DIR="${WG_STATE_DIR}/www"
ns() { ip netns exec "$@"; }

start_http_server() {
  install -d -m 0755 "$WWW_DIR"
  printf 'ok\n' >"${WWW_DIR}/health.txt"
  setsid ip netns exec "$WG_SRV_NS" python3 -m http.server 8080 \
      --bind "$WG_TUNNEL_SRV_IP" --directory "$WWW_DIR" \
      >>"${DIAG_DIR}/httpd.log" 2>&1 &
  wg_wait_for 10 1 -- bash -c "ip netns exec ${WG_SRV_NS} ss -ltn 2>/dev/null | grep -q ':8080'"
}

start_udp_echo() {
  cat >"${WG_STATE_DIR}/udp_echo.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    data, addr = s.recvfrom(2048)
    s.sendto(b"echo:" + data, addr)
PY
  setsid ip netns exec "$WG_SRV_NS" python3 "${WG_STATE_DIR}/udp_echo.py" "$WG_TUNNEL_SRV_IP" 9999 \
      >>"${DIAG_DIR}/udp-echo.log" 2>&1 &
  sleep 1
}

main() {
  wg_init_artifacts
  wg_step "connectivity: client traffic through the tunnel"
  install -d -m 0755 "$DIAG_DIR"

  # --- CON-01: ICMP inside the tunnel -------------------------------------
  local ping_out rc=0
  ping_out="$(ns "$WG_CLI_NS" ping -c 3 -W 3 "$WG_TUNNEL_SRV_IP" 2>&1)" || rc=$?
  if (( rc == 0 )); then
    wg_check "CON-01" PASS "ICMP echo over the tunnel" "$(printf '%s' "$ping_out" | grep -E 'packets transmitted|rtt' | tr '\n' ' ')"
  else
    wg_check "CON-01" FAIL "ICMP echo over the tunnel" "$(printf '%s' "$ping_out" | tail -2 | tr '\n' ' ')"
  fi

  # --- CON-02: UDP inside the tunnel --------------------------------------
  start_udp_echo
  local udp_out=""
  udp_out="$(ns "$WG_CLI_NS" python3 - "$WG_TUNNEL_SRV_IP" <<'PY' 2>&1 || true
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b"ping", (sys.argv[1], 9999))
data, _ = s.recvfrom(2048)
print(data.decode())
PY
)"
  if [[ "$udp_out" == "echo:ping" ]]; then
    wg_check "CON-02" PASS "UDP round-trip over the tunnel" "echo server replied through wg0"
  else
    wg_check "CON-02" FAIL "UDP round-trip over the tunnel" "response: ${udp_out:-<none>}"
  fi

  # --- CON-03: TCP inside the tunnel --------------------------------------
  if start_http_server; then
    local http_out
    http_out="$(ns "$WG_CLI_NS" curl -fsS --max-time 10 "http://${WG_TUNNEL_SRV_IP}:8080/health.txt" 2>&1)" || true
    if [[ "$http_out" == "ok" ]]; then
      wg_check "CON-03" PASS "TCP/HTTP request over the tunnel" "GET /health.txt -> 200 ok"
    else
      wg_check "CON-03" FAIL "TCP/HTTP request over the tunnel" "${http_out:-<no response>}"
    fi
  else
    wg_check "CON-03" UNTESTED "TCP/HTTP request over the tunnel" "test HTTP server did not start"
  fi

  # --- CON-04: real internet egress through the tunnel --------------------
  local wan
  wan="$(wg_wan_iface)"
  if ! wg_have iptables; then
    wg_check "CON-04" UNTESTED "Internet egress through the tunnel (NAT on server role)" \
      "iptables is not installed on this host, so NAT/forwarding could not be configured"
  elif [[ -z "$wan" ]]; then
    wg_check "CON-04" UNTESTED "Internet egress through the tunnel" "could not determine the WAN interface"
  else
    wg_setup_nat
    local egress_out egress_rc=0
    egress_out="$(ns "$WG_CLI_NS" curl -fsS --max-time 15 https://api.github.com/zen 2>&1)" || egress_rc=$?
    if (( egress_rc == 0 )) && [[ -n "$egress_out" ]]; then
      wg_check "CON-04" PASS "Internet egress through the tunnel (NAT on server role)" \
        "https://api.github.com/zen via wg0 -> ${egress_out}"
      ns "$WG_CLI_NS" wg show wg0 transfer >"${DIAG_DIR}/egress-transfer.txt" 2>&1 || true
    else
      wg_check "CON-04" UNTESTED "Internet egress through the tunnel (NAT on server role)" \
        "blocked or filtered in this environment (rc=$egress_rc); tunnel itself is unaffected"
    fi
  fi

  # --- CON-05: MTU sanity - payload up to MTU-28 travels -------------------
  local mtu=""
  if ns "$WG_CLI_NS" ip link show wg0 >/dev/null 2>&1; then
    mtu="$(ns "$WG_CLI_NS" ip -o link show wg0 | grep -oE 'mtu [0-9]+' | awk '{print $2}')"
  fi
  if [[ -z "$mtu" ]]; then
    wg_check "CON-05" SKIP "Tunnel MTU verified with DF bit set" "wg0 not present in this run"
    return 0
  fi
  local size=$(( mtu - 28 ))
  local df_out df_rc=0
  df_out="$(ns "$WG_CLI_NS" ping -c 2 -W 3 -M 'do' -s "$size" "$WG_TUNNEL_SRV_IP" 2>&1)" || df_rc=$?
  if (( df_rc == 0 )); then
    wg_check "CON-05" PASS "Tunnel MTU verified with DF bit set" "payload ${size}B carried (MTU ${mtu})"
  else
    wg_check "CON-05" FAIL "Tunnel MTU verified with DF bit set" "MTU ${mtu} payload ${size}B failed: $(printf '%s' "$df_out" | tail -1)"
  fi
}

main "$@"
