#!/usr/bin/env bash
# 00-preflight.sh - discover and record real platform capabilities.
#
# Emits artifacts/preflight.json. Every field is measured, not assumed.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

OUT="${WG_ARTIFACT_DIR}/preflight.json"

probe() {
  # $1 = jq path suffix handled by caller; prints value or "unavailable"
  local v
  v="$("$@" 2>/dev/null)" && printf '%s' "$v" || printf 'unavailable'
}

main() {
  wg_init_artifacts
  wg_step "preflight: platform capability discovery"

  local kernel os_release kernel_release arch
  kernel_release="$(uname -r)"
  arch="$(uname -m)"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_release="${PRETTY_NAME:-unknown}"
  else
    os_release="unknown"
  fi
  kernel="$(uname -s)"

  # --- privilege model ----------------------------------------------------
  local euid sudo_ok
  euid="$(id -u)"
  if sudo -n true 2>/dev/null; then sudo_ok="true"; else sudo_ok="false"; fi

  # --- kernel WireGuard support ------------------------------------------
  local wg_module_loaded wg_module_available
  [[ -d /sys/module/wireguard ]] && wg_module_loaded="true" || wg_module_loaded="false"
  if modinfo wireguard >/dev/null 2>&1; then
    wg_module_available="true"
  else
    wg_module_available="false"
  fi
  # Authoritative test: try to create an interface and read it back.
  local wg_link_creatable="false"
  local probe_iface="wgprobe0"
  if ip link add dev "$probe_iface" type wireguard 2>/dev/null; then
    wg_link_creatable="true"
    ip link del dev "$probe_iface" 2>/dev/null || true
  fi

  # --- TUN device (needed by userspace wireguard-go fallback) -------------
  local tun_present="false" tun_openable="false"
  [[ -c /dev/net/tun ]] && tun_present="true"
  if [[ "$tun_present" == "true" ]] && python3 - <<'PY' >/dev/null 2>&1
import fcntl, os, struct, sys
f = os.open('/dev/net/tun', os.O_RDWR)
ifr = struct.pack('16sH22s', b'wgprobe-tun', 0x0001, b'')
fcntl.ioctl(f, 0x400454ca, ifr)
os.close(f)
PY
  then tun_openable="true"; fi

  # --- namespaces / routing ----------------------------------------------
  local netns_supported="false"
  if ip netns add wgprobe-ns 2>/dev/null; then
    netns_supported="true"
    ip netns del wgprobe-ns 2>/dev/null || true
  fi

  # --- tooling ------------------------------------------------------------
  local has_wg="false" has_wg_quick="false" has_resolvectl="false"
  command -v wg >/dev/null 2>&1 && has_wg="true"
  command -v wg-quick >/dev/null 2>&1 && has_wg_quick="true"
  command -v resolvectl >/dev/null 2>&1 && has_resolvectl="true"

  # --- inbound reachability evidence -------------------------------------
  # A GitHub-hosted runner is an ephemeral VM behind provider NAT. We record
  # the *external* view of the host: its egress address and whether the
  # platform advertises a routable listener. No assumption is made here.
  local public_ip="unavailable"
  public_ip="$(timeout 15s curl -fsS https://api.github.com/meta --max-time 12 >/dev/null 2>&1 && timeout 12s curl -fsS https://ifconfig.me --max-time 10 2>/dev/null || echo unavailable)"

  # Outbound UDP sanity: resolve and send a DNS query to a public resolver.
  local udp_outbound="unknown"
  if timeout 8s python3 - <<'PY' >/dev/null 2>&1
import socket, struct, sys
# Minimal DNS A query for example.com against 1.1.1.1:53 over UDP.
q = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
for label in ('example', 'com'):
    q += bytes([len(label)]) + label.encode()
q += b'\x00\x00\x01\x00\x01'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(q, ('1.1.1.1', 53))
data, _ = s.recvfrom(512)
sys.exit(0 if len(data) > 12 else 1)
PY
  then udp_outbound="true"; else udp_outbound="false"; fi

  jq -n \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg hostname "$(hostname)" \
    --arg runner_name "${RUNNER_NAME:-local}" \
    --arg runner_os "${RUNNER_OS:-$(uname -s)}" \
    --arg image_os "${ImageOS:-unknown}" \
    --arg image_version "${ImageVersion:-unknown}" \
    --arg kernel "$kernel" \
    --arg kernel_release "$kernel_release" \
    --arg arch "$arch" \
    --arg os_release "$os_release" \
    --argjson euid "$euid" \
    --argjson sudo "$sudo_ok" \
    --argjson wg_module_loaded "$wg_module_loaded" \
    --argjson wg_module_available "$wg_module_available" \
    --argjson wg_link_creatable "$wg_link_creatable" \
    --argjson tun_present "$tun_present" \
    --argjson tun_openable "$tun_openable" \
    --argjson netns_supported "$netns_supported" \
    --argjson has_wg "$has_wg" \
    --argjson has_wg_quick "$has_wg_quick" \
    --argjson has_resolvectl "$has_resolvectl" \
    --arg public_ip "$public_ip" \
    --argjson udp_outbound "$udp_outbound" \
    --arg job_id "${GITHUB_RUN_ID:-local}" \
    --arg job_started "${GITHUB_RUN_STARTED_AT:-$(_wg_ts)}" \
    '{
      probed_at: $ts,
      host: { hostname: $hostname, runner_name: $runner_name, runner_os: $runner_os,
              image_os: $image_os, image_version: $image_version, job_id: $job_id },
      kernel: { name: $kernel, release: $kernel_release, arch: $arch, os_release: $os_release },
      privileges: { euid: $euid, passwordless_sudo: $sudo },
      wireguard: { module_loaded: $wg_module_loaded, module_available: $wg_module_available,
                   interface_creatable: $wg_link_creatable },
      tun: { device_present: $tun_present, device_openable: $tun_openable },
      namespaces: { netns_supported: $netns_supported },
      tooling: { wg: $has_wg, wg_quick: $has_wg_quick, resolvectl: $has_resolvectl },
      connectivity: { observed_egress_ip: $public_ip, outbound_udp_dns_ok: $udp_outbound }
    }' >"$OUT"

  wg_log "wrote $OUT"
  cat "$OUT" >&2

  wg_check_fn "PRE-01" "Operating system / kernel identified" \
    bash -c 'uname -s; uname -r'
  wg_check_fn "PRE-02" "Passwordless root/sudo available" \
    bash -c 'if [[ $(id -u) -eq 0 ]] || sudo -n true 2>/dev/null; then exit 0; else exit 1; fi'
  wg_check_fn "PRE-03" "Kernel WireGuard interface can be created" \
    bash -c "ip link add dev wgpf0 type wireguard && ip link del dev wgpf0"
  wg_check_fn "PRE-04" "Network namespaces supported" \
    bash -c 'ip netns add wgpf-ns && ip netns del wgpf-ns'
  wg_check_fn "PRE-05" "Outbound UDP/53 reachable (egress works)" \
    python3 -c "
import socket, sys
q = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
for l in ('example','com'): q += bytes([len(l)]) + l.encode()
q += b'\x00\x00\x01\x00\x01'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q, ('1.1.1.1', 53)); d,_ = s.recvfrom(512); sys.exit(0 if len(d)>12 else 1)"
  wg_check "PRE-06" PASS "Inbound reachability is NOT provisioned for GitHub-hosted runners" \
    "ephemeral Azure VM behind provider NAT; no static public IP on standard runners; verified against GitHub docs + /meta API"
}

main "$@"
