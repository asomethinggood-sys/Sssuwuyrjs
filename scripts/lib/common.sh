#!/usr/bin/env bash
# shellcheck shell=bash
#
# common.sh - shared helpers for the WireGuard harness.
#
# Design rules enforced here:
#   * Never print secret material. Use `wg_log`/`wg_dbg` for anything that could
#     contain a key, and prefer `wg_secret "<path>"` which returns a value
#     without echoing it.
#   * Every network/install operation is bounded by a timeout and a retry budget.
#   * Diagnostics are always emitted on failure before the process exits.

# Guard against double-sourcing.
if [[ -n "${WG_COMMON_SOURCED:-}" ]]; then return 0; fi
WG_COMMON_SOURCED=1

set -o errexit
set -o nounset
set -o pipefail

# ---------------------------------------------------------------------------
# Configuration (all overridable from the environment)
# ---------------------------------------------------------------------------
WG_RUN_ID="${WG_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
WG_ARTIFACT_DIR="${WG_ARTIFACT_DIR:-${GITHUB_WORKSPACE:-$PWD}/artifacts}"
WG_STATE_DIR="${WG_STATE_DIR:-/run/wg-harness}"      # volatile, root-only
WG_LOG_DIR="${WG_LOG_DIR:-${WG_ARTIFACT_DIR}/logs}"
WG_REPORT_FILE="${WG_REPORT_FILE:-${WG_ARTIFACT_DIR}/test-report.json}"
WG_MARKDOWN_FILE="${WG_MARKDOWN_FILE:-${WG_ARTIFACT_DIR}/test-report.md}"

WG_RETRY_ATTEMPTS="${WG_RETRY_ATTEMPTS:-4}"
WG_RETRY_BASE_DELAY="${WG_RETRY_BASE_DELAY:-2}"
WG_CMD_TIMEOUT="${WG_CMD_TIMEOUT:-120}"
WG_HANDSHAKE_TIMEOUT="${WG_HANDSHAKE_TIMEOUT:-30}"

# Network layout used by the end-to-end test. Two isolated network namespaces
# are joined by a veth transport; the WireGuard tunnel rides on top of it.
WG_SRV_NS="${WG_SRV_NS:-wgsrv}"
WG_CLI_NS="${WG_CLI_NS:-wgcli}"
WG_VETH_SRV="${WG_VETH_SRV:-vethsrv}"
WG_VETH_CLI="${WG_VETH_CLI:-vethcli}"
WG_BRIDGE_IP="${WG_BRIDGE_IP:-192.168.77.1}"
WG_TRANSPORT_SRV_IP="${WG_TRANSPORT_SRV_IP:-192.168.77.2}"
WG_TRANSPORT_CLI_IP="${WG_TRANSPORT_CLI_IP:-192.168.77.3}"
WG_TRANSPORT_CIDR="${WG_TRANSPORT_CIDR:-29}"
WG_LISTEN_PORT="${WG_LISTEN_PORT:-51820}"
WG_CLI_LISTEN_PORT="${WG_CLI_LISTEN_PORT:-51821}"
WG_MTU="${WG_MTU:-1420}"
WG_TUNNEL_SRV_IP="${WG_TUNNEL_SRV_IP:-10.13.13.1}"
WG_TUNNEL_CLI_IP="${WG_TUNNEL_CLI_IP:-10.13.13.2}"
WG_TUNNEL_CIDR="${WG_TUNNEL_CIDR:-24}"
WG_BRIDGE_NAME="${WG_BRIDGE_NAME:-br-wg}"
WG_DNS_TEST_NAME="${WG_DNS_TEST_NAME:-gateway.wg.internal}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_wg_ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# All human-readable logs go to stderr and a log file, never to stdout, so that
# callers can safely capture stdout for values.
WG_LOG_FILE="${WG_LOG_FILE:-}"

_wg_emit() {
  local level="$1"; shift
  local line
  line="[$(_wg_ts)] [$level] $*"
  printf '%s\n' "$line" >&2
  if [[ -n "$WG_LOG_FILE" ]]; then
    mkdir -p "$(dirname "$WG_LOG_FILE")" 2>/dev/null || true
    printf '%s\n' "$line" >>"$WG_LOG_FILE" 2>/dev/null || true
  fi
}

wg_log()  { _wg_emit INFO  "$@"; }
wg_warn() { _wg_emit WARN  "$@"; }
wg_err()  { _wg_emit ERROR "$@"; }
wg_dbg()  { [[ "${WG_DEBUG:-0}" == "1" ]] && _wg_emit DEBUG "$@" || true; }
wg_step() { _wg_emit STEP "=== $* ==="; }

# Scrub anything that looks like WireGuard key material before it is printed.
wg_scrub() {
  sed -E 's#([A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=)#<redacted-key>#g'
}

wg_die() {
  wg_err "$*"
  exit 1
}

# ---------------------------------------------------------------------------
# Process / command helpers
# ---------------------------------------------------------------------------
wg_have() { command -v "$1" >/dev/null 2>&1; }

# Run a command with a hard timeout. Never inherits the caller's errexit state.
wg_run() {
  local timeout_s="$WG_CMD_TIMEOUT"
  if [[ "${1:-}" == "--timeout" ]]; then timeout_s="$2"; shift 2; fi
  timeout --kill-after=10s "${timeout_s}s" "$@"
}

# Bounded exponential-backoff retry. No infinite loops: the budget is explicit.
# Usage: wg_retry <label> <attempts> <base_delay> -- <cmd...>
wg_retry() {
  local label="$1" attempts="$2" base="$3"; shift 3
  [[ "${1:-}" == "--" ]] && shift
  local attempt=1 delay="$base" rc=0
  while :; do
    if "$@"; then
      [[ $attempt -gt 1 ]] && wg_log "retry: '$label' succeeded on attempt $attempt/$attempts"
      return 0
    fi
    rc=$?
    if (( attempt >= attempts )); then
      wg_err "retry: '$label' failed after $attempt/$attempts attempts (last rc=$rc)"
      return "$rc"
    fi
    wg_warn "retry: '$label' attempt $attempt/$attempts failed (rc=$rc); sleeping ${delay}s"
    sleep "$delay"
    delay=$(( delay * 2 ))
    attempt=$(( attempt + 1 ))
  done
}

# Poll until a predicate succeeds or the deadline passes. Never unbounded.
# Usage: wg_wait_for <seconds> <interval> -- <cmd...>
wg_wait_for() {
  local deadline_s="$1" interval="$2"; shift 2
  [[ "${1:-}" == "--" ]] && shift
  local start now
  start=$(date +%s)
  while :; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    now=$(date +%s)
    (( now - start >= deadline_s )) && return 1
    sleep "$interval"
  done
}

wg_require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then
      WG_SUDO="sudo -n"
    else
      wg_die "root privileges (or passwordless sudo) are required"
    fi
  else
    WG_SUDO=""
  fi
}

# Idempotent cleanup registration: handlers run LIFO on EXIT/INT/TERM.
_WG_TRAPS=()
wg_on_exit() { _WG_TRAPS+=("$1"); }

_wg_run_traps() {
  local rc=$?
  local i
  for (( i=${#_WG_TRAPS[@]}-1; i>=0; i-- )); do
    "${_WG_TRAPS[$i]}" || wg_warn "cleanup handler failed: ${_WG_TRAPS[$i]}"
  done
  return $rc
}
trap _wg_run_traps EXIT
trap 'wg_warn "interrupted"; exit 130' INT TERM

# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------
# Create a root-only secret file and return its path on stdout.
wg_secret_file() {
  local path="$1"
  install -d -m 0700 "$(dirname "$path")"
  install -m 0600 /dev/null "$path"
  printf '%s' "$path"
}

# Generate a WireGuard private key. The key is written to a 0600 file and is
# never written to stdout, the log, or any artifact.
wg_genkey() {
  local out="$1"
  [[ -n "${WG_SUDO:-}" ]] || WG_SUDO=""
  mkdir -p "$(dirname "$out")"
  ( umask 077; wg genkey >"$out" ) || wg_die "wg genkey failed"
  chmod 0600 "$out"
  [[ -s "$out" ]] || wg_die "generated private key at $out is empty"
  printf '%s' "$out"
}

wg_pubkey_of() {
  local priv="$1"
  wg pubkey <"$priv"
}

# Redact key material from `wg show <iface> dump` output.
#   interface line: private_key <TAB> public_key <TAB> listen_port <TAB> fwmark
#   peer line:      public_key  <TAB> preshared_key <TAB> endpoint <TAB> ...
# A column-0 sed is not sufficient here: the preshared key is the *second*
# field of a peer line, which is exactly the mistake this helper exists to
# prevent.
wg_redact_dump() {
  awk -F'\t' 'BEGIN { OFS="\t" }
    NF == 4 { $1 = "<redacted-private-key>"; print; next }
    NF >= 8 { $1 = "<redacted-peer-public-key>"; $2 = "<redacted-preshared-key>"; print; next }
    { print }'
}

# The egress interface of the host, used for MASQUERADE rules in the tests.
wg_wan_iface() {
  ip route get 1.1.1.1 2>/dev/null | grep -oE 'dev [^ ]+' | awk '{print $2}' | head -1
}

# Enable forwarding + NAT so the "server" namespace can act as an exit node
# for the "client" namespace. Idempotent: -C probes before every -A so repeated
# calls are safe, and 09-cleanup.sh removes each rule by exact match.
wg_setup_nat() {
  wg_have iptables || { wg_warn "iptables unavailable; NAT/egress tests will be UNTESTED"; return 1; }
  local wan
  wan="$(wg_wan_iface)"
  [[ -n "$wan" ]] || { wg_warn "could not determine the WAN interface"; return 1; }

  sysctl -qw net.ipv4.ip_forward=1
  iptables -t nat -C POSTROUTING -s "${WG_BRIDGE_IP}/${WG_TRANSPORT_CIDR}" -o "$wan" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "${WG_BRIDGE_IP}/${WG_TRANSPORT_CIDR}" -o "$wan" -j MASQUERADE
  iptables -C FORWARD -i br-wg -o "$wan" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i br-wg -o "$wan" -j ACCEPT
  iptables -C FORWARD -i "$wan" -o br-wg -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$wan" -o br-wg -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  ip netns exec "$WG_SRV_NS" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$WG_SRV_NS" ip route replace default via "$WG_BRIDGE_IP" dev "$WG_VETH_SRV"
  ip netns exec "$WG_SRV_NS" iptables -t nat -C POSTROUTING -s "${WG_TUNNEL_SRV_IP}/${WG_TUNNEL_CIDR}" \
      -o "$WG_VETH_SRV" -j MASQUERADE 2>/dev/null \
    || ip netns exec "$WG_SRV_NS" iptables -t nat -A POSTROUTING -s "${WG_TUNNEL_SRV_IP}/${WG_TUNNEL_CIDR}" \
      -o "$WG_VETH_SRV" -j MASQUERADE
  wg_log "NAT/forwarding enabled (WAN=$wan) so egress tests can run"
}

# Redact a leading key column, for `wg show <iface> transfer` and friends.
# The value replaced is a *public* key, but the repository rule is stricter than
# the protocol: no artifact carries a bare key token, so that the leak audit can
# treat any unlabelled key-shaped string as suspicious and still stay quiet.
wg_redact_leading_key() {
  awk -F'\t' 'BEGIN { OFS="\t" }
    $1 ~ /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/ { $1 = "<peer-public-key>" }
    { print }'
}

# Assert a path contains no WireGuard secret material.
#
# Uses scripts/secret_scan.py, which distinguishes public keys (not secrets)
# from private/preshared keys (secrets) instead of flagging every base64 blob.
wg_assert_no_key_material() {
  local target="$1"
  local scanner="${_WG_LIB_DIR}/../secret_scan.py"
  if [[ ! -f "$scanner" ]]; then
    wg_err "secret scanner not found at $scanner"
    return 1
  fi
  if python3 "$scanner" "$target"; then
    return 0
  fi
  return 1
}

_WG_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Result recording
# ---------------------------------------------------------------------------
# Emits NDJSON check records consumed by scripts/report.sh.
# Usage: wg_check <id> <status> <description> [detail]
WG_CHECKS_FILE="${WG_CHECKS_FILE:-}"

wg_check() {
  local id="$1" status="$2" desc="$3" detail="${4:-}"
  [[ -n "$WG_CHECKS_FILE" ]] || return 0
  jq -nc \
    --arg id "$id" \
    --arg status "$status" \
    --arg description "$desc" \
    --arg detail "$detail" \
    --arg ts "$(_wg_ts)" \
    '{id:$id,status:$status,description:$description,detail:$detail,timestamp:$ts}' \
    >>"$WG_CHECKS_FILE"
  local level="INFO"
  case "$status" in
    PASS) level="INFO" ;;
    FAIL) level="ERROR" ;;
    SKIP|UNTESTED) level="WARN" ;;
  esac
  _wg_emit "$level" "check[$status] $id: $desc${detail:+ -- $detail}"
}

# Wrap a shell function as a recorded check. A FAIL does not abort the suite.
wg_check_fn() {
  local id="$1" desc="$2"; shift 2
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  out="$(printf '%s' "$out" | wg_scrub)"
  if (( rc == 0 )); then
    wg_check "$id" PASS "$desc" "$(printf '%s' "$out" | tail -n 1)"
  else
    wg_check "$id" FAIL "$desc" "rc=$rc; $(printf '%s' "$out" | tail -n 3 | tr '\n' ' ')"
  fi
  return 0
}

wg_init_artifacts() {
  mkdir -p "$WG_ARTIFACT_DIR" "$WG_LOG_DIR"
  # A marker in the artifact tree (which cleanup does not remove) keeps the
  # check log from being truncated by later steps such as report.sh.
  if [[ ! -f "${WG_ARTIFACT_DIR}/.checks-initialized" ]]; then
    : >"${WG_ARTIFACT_DIR}/checks.ndjson"
    : >"${WG_ARTIFACT_DIR}/.checks-initialized"
  fi
  WG_CHECKS_FILE="${WG_ARTIFACT_DIR}/checks.ndjson"
  export WG_CHECKS_FILE
  # Root-only state directory for keys; never inside the artifact tree.
  install -d -m 0700 "$WG_STATE_DIR"
}
