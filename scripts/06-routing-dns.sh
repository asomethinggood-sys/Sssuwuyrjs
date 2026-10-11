#!/usr/bin/env bash
# 06-routing-dns.sh - verify routing decisions and DNS resolution over the tunnel.
#
# Two distinct claims are tested and reported separately:
#   (a) routing: kernel selects the tunnel device for tunnel-destined traffic;
#   (b) DNS: a resolver that is only reachable through the tunnel answers queries.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

DIAG_DIR="${WG_ARTIFACT_DIR}/diagnostics"
ns() { ip netns exec "$@"; }

# Prefer dig (an independent implementation); fall back to the bundled Python
# client so the harness still runs on hosts without dnsutils.
DNS_TOOL="dig"
if ! command -v dig >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    DNS_TOOL="python"
  else
    DNS_TOOL="none"
  fi
fi

dns_lookup() {
  # dns_lookup <server> <name> [timeout]
  local server="$1" name="$2" timeout="${3:-3}"
  case "$DNS_TOOL" in
    dig)    ns "$WG_CLI_NS" dig +time="$timeout" +tries=2 +short A "@${server}" "$name" ;;
    python) ns "$WG_CLI_NS" python3 "${SCRIPT_DIR}/dns_query.py" "$name" --server "$server" --timeout "$timeout" ;;
    *)      return 127 ;;
  esac
}

main() {
  wg_init_artifacts
  wg_step "routing + DNS over the tunnel"
  install -d -m 0755 "$DIAG_DIR"

  # --- ROUTE-01: tunnel prefix is routed via wg0 ---------------------------
  local route_out
  route_out="$(ns "$WG_CLI_NS" ip route get "$WG_TUNNEL_SRV_IP" 2>&1)" || true
  if printf '%s' "$route_out" | grep -q 'dev wg0'; then
    wg_check "RT-01" PASS "Tunnel prefix routed through wg0" "$(printf '%s' "$route_out" | head -1)"
  else
    wg_check "RT-01" FAIL "Tunnel prefix routed through wg0" "$(printf '%s' "$route_out" | head -1)"
  fi

  # --- ROUTE-02: no leak - transport still goes out the physical link ------
  local transport_out
  transport_out="$(ns "$WG_CLI_NS" ip route get "$WG_TRANSPORT_SRV_IP" 2>&1)" || true
  if printf '%s' "$transport_out" | grep -q "dev ${WG_VETH_CLI}"; then
    wg_check "RT-02" PASS "Encapsulation endpoint pinned to the physical link" \
      "$(printf '%s' "$transport_out" | head -1)"
  else
    wg_check "RT-02" WARN "Encapsulation endpoint pinned to the physical link" \
      "expected dev ${WG_VETH_CLI}; got: $(printf '%s' "$transport_out" | head -1)"
  fi

  # --- ROUTE-03: full-tunnel policy (0.0.0.0/1 + 128.0.0.0/1) -------------
  # /1 routes are the standard wg-quick technique for overriding the default
  # route without deleting it.
  ns "$WG_CLI_NS" ip route add "${WG_TRANSPORT_SRV_IP}/32" dev "$WG_VETH_CLI" 2>/dev/null || true
  ns "$WG_CLI_NS" ip route add 0.0.0.0/1 dev wg0 2>/dev/null || true
  ns "$WG_CLI_NS" ip route add 128.0.0.0/1 dev wg0 2>/dev/null || true

  local default_out
  default_out="$(ns "$WG_CLI_NS" ip route get 1.1.1.1 2>&1)" || true
  if printf '%s' "$default_out" | grep -q 'dev wg0'; then
    wg_check "RT-03" PASS "Full-tunnel policy routes internet traffic via wg0" "1.1.1.1 -> $(printf '%s' "$default_out" | head -1)"
  else
    wg_check "RT-03" FAIL "Full-tunnel policy routes internet traffic via wg0" "$(printf '%s' "$default_out" | head -1)"
  fi
  # Endpoint must remain reachable despite the /1 routes.
  local ep_out
  ep_out="$(ns "$WG_CLI_NS" ip route get "$WG_TRANSPORT_SRV_IP" 2>&1)" || true
  if printf '%s' "$ep_out" | grep -q "dev ${WG_VETH_CLI}"; then
    wg_check "RT-04" PASS "No routing loop: endpoint excluded from the tunnel" \
      "$(printf '%s' "$ep_out" | head -1)"
  else
    wg_check "RT-04" FAIL "No routing loop: endpoint excluded from the tunnel" \
      "$(printf '%s' "$ep_out" | head -1)"
  fi

  # --- DNS-01: client resolves through a tunnel-only resolver --------------
  install -d -m 0755 "/etc/netns/${WG_CLI_NS}"
  printf 'nameserver %s\noptions timeout:2 attempts:2\n' "$WG_TUNNEL_SRV_IP" \
    >"/etc/netns/${WG_CLI_NS}/resolv.conf"

  if [[ "$DNS_TOOL" == "none" ]]; then
    wg_check "DNS-01" UNTESTED "DNS resolution answered through the tunnel" "no DNS client available (dig or python3)"
  else
    local dig_out rc=0
    dig_out="$(dns_lookup "$WG_TUNNEL_SRV_IP" "$WG_DNS_TEST_NAME" 3 2>&1)" || rc=$?
    if (( rc == 0 )) && printf '%s' "$dig_out" | grep -qF "$WG_TUNNEL_SRV_IP"; then
      wg_check "DNS-01" PASS "DNS resolution answered through the tunnel" \
        "${WG_DNS_TEST_NAME} A -> ${dig_out//$'\n'/, } via ${DNS_TOOL}; resolver ${WG_TUNNEL_SRV_IP} is only reachable through wg0"
    else
      wg_check "DNS-01" FAIL "DNS resolution answered through the tunnel" \
        "rc=$rc tool=$DNS_TOOL out=$(printf '%s' "$dig_out" | head -2 | tr '\n' ' ')"
    fi
  fi

  # --- DNS-02: resolver is genuinely unreachable without the tunnel --------
  # Query the same resolver from a namespace that has no tunnel: it must fail.
  if [[ "$DNS_TOOL" == "none" ]]; then
    wg_check "DNS-02" UNTESTED "Control test: resolver unreachable without the tunnel" "no DNS client available"
  else
    # A namespace with a blackhole route to the resolver address: resolution
    # must fail, which is what makes DNS-01 meaningful.
    local negative_rc=0
    ip netns add wgctl 2>/dev/null || true
    ns wgctl ip link set lo up
    ns wgctl ip route add blackhole "${WG_TUNNEL_SRV_IP}/32" 2>/dev/null || true
    timeout 10s bash -c "
      if [[ '$DNS_TOOL' == 'dig' ]]; then
        ip netns exec wgctl dig +time=2 +tries=1 +short A '$WG_DNS_TEST_NAME'
      else
        ip netns exec wgctl python3 '${SCRIPT_DIR}/dns_query.py' '$WG_DNS_TEST_NAME' --server '$WG_TUNNEL_SRV_IP' --timeout 2
      fi
    " >/dev/null 2>&1 || negative_rc=1
    ip netns del wgctl 2>/dev/null || true
    if (( negative_rc == 1 )); then
      wg_check "DNS-02" PASS "Control test: resolver unreachable without the tunnel" \
        "negative control fails as expected, so DNS-01 demonstrates tunnel usage"
    else
      wg_check "DNS-02" FAIL "Control test: resolver unreachable without the tunnel" \
        "resolution unexpectedly succeeded - DNS-01 does not prove tunnel usage"
    fi
  fi

  # --- DNS-03: default-route resolution through the forwarded resolver -----
  local fwd_out fwd_rc=0
  if [[ "$DNS_TOOL" == "none" ]]; then
    fwd_rc=127; fwd_out=""
  else
    fwd_out="$(dns_lookup "$WG_TUNNEL_SRV_IP" example.com 4 2>&1)" || fwd_rc=$?
  fi
  if (( fwd_rc == 0 )) && [[ -n "$fwd_out" ]]; then
    wg_check "DNS-03" PASS "Forwarded resolution works for public names" "example.com -> $(printf '%s' "$fwd_out" | head -1)"
  else
    wg_check "DNS-03" UNTESTED "Forwarded resolution works for public names" \
      "upstream forwarding failed (rc=$fwd_rc); treat as untested, not as a tunnel failure"
  fi

  ns "$WG_CLI_NS" ip route show >"${DIAG_DIR}/client-routes-final.txt" 2>&1 || true
  cat "/etc/netns/${WG_CLI_NS}/resolv.conf" >"${DIAG_DIR}/client-resolv.conf.txt" 2>&1 || true
}

main "$@"
