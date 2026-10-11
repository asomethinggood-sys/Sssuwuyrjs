#!/usr/bin/env bash
# 11-diagnose.sh - human-invokable triage dump.
#
# Safe to run at any time, including when nothing is configured. It only reads.
# Key columns are redacted before anything is written.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

TARGET="${1:-all}"
OUT="${WG_ARTIFACT_DIR}/diagnostics/manual-triage.txt"

redact_wg() {
  sed -E 's/([A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=)/<redacted>/g'
}

section() { printf '\n===== %s =====\n' "$*"; }

dump_interfaces() {
  section "links";      ip -br link
  section "addresses";  ip -br addr
  section "routes v4";  ip route show
  section "rules";      ip rule show
  section "wireguard interfaces"
  wg show 2>/dev/null | redact_wg || echo "wg: none or unavailable"
  section "wireguard configuration (key digests only)"
  for i in $(wg show interfaces 2>/dev/null || true); do
    echo "--- $i conf (redacted)"
    wg showconf "$i" 2>/dev/null | redact_wg || true
  done
}

dump_namespaces() {
  section "netns list"; ip netns list || true
  for ns_name in "$WG_SRV_NS" "$WG_CLI_NS"; do
    if ip netns list 2>/dev/null | grep -qw "$ns_name"; then
      section "netns $ns_name: wg show"
      ip netns exec "$ns_name" wg show 2>/dev/null | redact_wg || true
      section "netns $ns_name: routes"
      ip netns exec "$ns_name" ip route show || true
      section "netns $ns_name: listeners"
      ip netns exec "$ns_name" ss -lunpt 2>/dev/null || true
    else
      section "netns $ns_name: absent"
    fi
  done
}

dump_connectivity() {
  section "endpoint UDP reachability (generic)"
  echo "note: run \`nc -u -v <endpoint> <port>\` from the client side"
  section "outbound internet"
  curl -sS --max-time 10 -o /dev/null -w 'https://api.github.com -> %{http_code}\n' https://api.github.com || true
  section "firewall state (root)"
  iptables -t nat -S 2>/dev/null | head -40 || true
  iptables -S 2>/dev/null | head -40 || true
}

mkdir -p "$(dirname "$OUT")"
{
  echo "WireGuard harness triage - $(_wg_ts)"
  echo "kernel: $(uname -r)   host: $(hostname)"
  echo "target: $TARGET"
  case "$TARGET" in
    interfaces)  dump_interfaces ;;
    namespaces)  dump_namespaces ;;
    connectivity) dump_connectivity ;;
    all) dump_interfaces; dump_namespaces; dump_connectivity ;;
    *) echo "unknown target: $TARGET (use interfaces|namespaces|connectivity|all)" >&2; exit 2 ;;
  esac
} 2>&1 | tee "$OUT"

echo >&2
echo "triage written to $OUT" >&2
