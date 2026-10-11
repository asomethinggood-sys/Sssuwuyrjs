#!/usr/bin/env bash
# run-suite.sh - orchestrate the whole harness.
#
# Steps run in dependency order. If a step that others depend on fails, the
# remaining dependent steps are recorded as SKIP (not as passes, and not as
# failures of code that never ran). Cleanup always runs, including on failure.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

STEP_LOG_DIR=""
CLEANUP_DONE=0

run_step() {
  # run_step <id> <script> <dependency-ok:0|1> <description>
  local id="$1" script="$2" dep_ok="$3" desc="$4"
  local log="${STEP_LOG_DIR}/${id}.log"
  if (( dep_ok == 0 )); then
    wg_check "$id" SKIP "$desc" "skipped: a prerequisite step failed"
    return 0
  fi
  wg_step "$id: $desc"
  set +o errexit
  bash "${SCRIPT_DIR}/${script}" 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}
  set -o errexit
  if (( rc == 0 )); then
    wg_log "$id completed (rc=0)"
    return 0
  fi
  wg_err "$id FAILED (rc=$rc); last 25 log lines:"
  tail -n 25 "$log" >&2 || true
  wg_check "$id" FAIL "$desc" "script rc=$rc; see logs/${id}.log"
  return 1
}

do_cleanup() {
  (( CLEANUP_DONE == 1 )) && return 0
  CLEANUP_DONE=1
  wg_step "cleanup (trap)"
  bash "${SCRIPT_DIR}/09-cleanup.sh" 2>&1 | tee "${STEP_LOG_DIR}/09-cleanup.log" || true
}

main() {
  wg_init_artifacts
  STEP_LOG_DIR="${WG_ARTIFACT_DIR}/logs"
  mkdir -p "$STEP_LOG_DIR"
  trap 'do_cleanup' EXIT
  trap 'wg_warn "interrupted"; exit 130' INT TERM

  wg_log "harness run id: $WG_RUN_ID"
  wg_log "artifacts: $WG_ARTIFACT_DIR"
  wg_log "state (root-only): $WG_STATE_DIR"

  local ok_preflight=1 ok_install=1 ok_keygen=1 ok_config=1 ok_tunnel=1

  run_step "STEP-00-preflight" "00-preflight.sh" 1 "Platform capability discovery" || ok_preflight=0
  run_step "STEP-01-install" "01-install.sh" "$ok_preflight" "Install wireguard-tools and test dependencies" || ok_install=0
  run_step "STEP-02-keygen" "02-keygen.sh" "$ok_install" "Generate and protect key material" || ok_keygen=0
  run_step "STEP-03-config" "03-config-validate.sh" "$ok_keygen" "Render templates and validate config syntax" || ok_config=0
  run_step "STEP-04-tunnel-up" "04-tunnel-up.sh" "$ok_config" "Build namespaces and bring up the tunnel" || ok_tunnel=0

  local ok_hs=1
  run_step "STEP-05-handshake" "05-handshake.sh" "$ok_tunnel" "Establish and verify a real WireGuard handshake" || ok_hs=0
  run_step "STEP-06-routing-dns" "06-routing-dns.sh" "$ok_hs" "Verify routing decisions and DNS over the tunnel" || true
  run_step "STEP-07-connectivity" "07-connectivity.sh" "$ok_hs" "End-to-end client connectivity (ICMP/UDP/TCP/egress)" || true
  run_step "STEP-08-recovery" "08-recovery.sh" "$ok_hs" "Failure injection, detection and recovery" || true

  do_cleanup

  run_step "STEP-10-leak-audit" "10-leak-audit.sh" "$ok_config" "Secret-leak audit of all publishable surfaces" || true
  run_step "STEP-11-report" "report.sh" 1 "Compose the test report" || true

  # The suite's exit status is driven by the recorded checks, so that a failure
  # inside a step is never softened.
  local failed
  failed="$(jq -s '[.[] | select(.status=="FAIL")] | length' "${WG_ARTIFACT_DIR}/checks.ndjson" 2>/dev/null || echo 0)"
  if (( failed > 0 )); then
    wg_err "suite finished with $failed failing check(s)"
    return 1
  fi
  wg_log "suite finished with no failing checks"
}

main "$@"
