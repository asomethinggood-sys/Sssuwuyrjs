#!/usr/bin/env bash
# 01-install.sh - install the tooling the harness needs, with bounded retries.
#
# Required tools cause a FAIL when absent. Optional tools only remove test
# coverage, and are reported as UNTESTED rather than as passing.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

REQUIRED_TOOLS=(wg ip jq python3)
OPTIONAL_TOOLS=(dig iptables ss ping curl)
APT_PKGS=(wireguard-tools iproute2 iptables dnsutils iputils-ping curl jq)

have() { command -v "$1" >/dev/null 2>&1; }

missing_from() {
  local tool
  for tool in "$@"; do
    have "$tool" || printf '%s\n' "$tool"
  done
}

apt_lock_wait() {
  local deadline=$((SECONDS + 180))
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    (( SECONDS > deadline )) && wg_die "timed out waiting for the dpkg lock"
    sleep 5
  done
}

install_pkgs() {
  export DEBIAN_FRONTEND=noninteractive
  apt_lock_wait
  apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -qq update
  apt_lock_wait
  apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -qq -y install "$@"
}

main() {
  wg_init_artifacts
  wg_step "install: dependencies"
  wg_require_root

  if [[ "${WG_SKIP_INSTALL:-0}" == "1" ]]; then
    wg_warn "WG_SKIP_INSTALL=1: package installation disabled; verifying what is already present"
    wg_check "DEP-00" UNTESTED "Package installation" "disabled by WG_SKIP_INSTALL=1; results below reflect pre-installed tools only"
  else
    if wg_retry "apt install" "$WG_RETRY_ATTEMPTS" "$WG_RETRY_BASE_DELAY" -- install_pkgs "${APT_PKGS[@]}"; then
      wg_check "DEP-01" PASS "Dependency installation" "apt-get install ${APT_PKGS[*]}"
    else
      wg_check "DEP-01" FAIL "Dependency installation" "apt-get failed after ${WG_RETRY_ATTEMPTS} attempts"
      wg_err "diagnostics: apt policy dump"
      apt-cache policy "${APT_PKGS[@]}" >&2 2>&1 || true
    fi
  fi

  local missing=()
  mapfile -t missing < <(missing_from "${REQUIRED_TOOLS[@]}")
  if (( ${#missing[@]} == 0 )); then
    wg_check "DEP-02" PASS "Required tools present" "${REQUIRED_TOOLS[*]}"
  else
    wg_check "DEP-02" FAIL "Required tools present" "missing: ${missing[*]}"
    exit 1
  fi

  local opt_missing=()
  mapfile -t opt_missing < <(missing_from "${OPTIONAL_TOOLS[@]}")
  if (( ${#opt_missing[@]} == 0 )); then
    wg_check "DEP-03" PASS "Optional tools present" "${OPTIONAL_TOOLS[*]}"
  else
    wg_check "DEP-03" UNTESTED "Optional tools present" \
      "missing: ${opt_missing[*]} - tests that depend on them will be reported UNTESTED"
  fi

  local wgver ipver
  wgver="$(wg --version 2>&1 | head -1)" || wgver="unknown"
  ipver="$(ip -V 2>&1 | head -1)" || ipver="unknown"
  {
    printf 'wg_version=%s\n' "$wgver"
    printf 'ip_version=%s\n' "$ipver"
    printf 'iptables=%s\n' "$(iptables --version 2>&1 | head -1 || echo absent)"
    printf 'dig=%s\n' "$(dig -v 2>&1 | head -1 || echo absent)"
    printf 'python3=%s\n' "$(python3 -V 2>&1)"
  } >"${WG_ARTIFACT_DIR}/tool-versions.txt"
  wg_log "wg  : $wgver"
  wg_log "ip  : $ipver"
}

main "$@"
