#!/usr/bin/env bash
# 10-leak-audit.sh - prove that no secret material reached a publishable surface.
#
# Surfaces audited:
#   * the git working tree (which is what a commit would publish)
#   * artifacts/ (uploaded as a workflow artifact)
#   * the workflow summary file, if present
#   * environment variables that will be exported to later steps
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

audit_path() {
  local label="$1" path="$2" check_id="$3" exclude="${4:-}"
  [[ -e "$path" ]] || { wg_check "$check_id" SKIP "Secret scan: $label" "path does not exist"; return 0; }
  local extra=()
  [[ -n "$exclude" ]] && extra+=(--exclude "$exclude")
  # Provenance pass: the harness knows exactly which keys it generated, so a
  # verbatim copy of one of them is a leak no heuristic can explain away.
  [[ -d "${WG_STATE_DIR}/keys" ]] && extra+=(--secrets-from "${WG_STATE_DIR}/keys")
  if python3 "${SCRIPT_DIR}/secret_scan.py" "$path" "${extra[@]+"${extra[@]}"}"; then
    wg_check "$check_id" PASS "Secret scan: $label" "no private/preshared key material detected"
  else
    wg_check "$check_id" FAIL "Secret scan: $label" "secret material detected - see errors above"
    return 1
  fi
}

main() {
  wg_init_artifacts
  wg_step "audit: secret-leak scan"
  local rc=0

  # SEC-01 answers "what would a commit publish?" - so the artifact tree, which
  # is covered separately by SEC-02, is excluded rather than scanned twice.
  audit_path "working tree" "$REPO_ROOT" "SEC-01" "$WG_ARTIFACT_DIR" || rc=1
  audit_path "workflow artifacts" "$WG_ARTIFACT_DIR" "SEC-02" || rc=1

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -f "${GITHUB_STEP_SUMMARY}" ]]; then
    audit_path "job summary" "$GITHUB_STEP_SUMMARY" "SEC-03" || rc=1
  else
    wg_check "SEC-03" SKIP "Secret scan: job summary" "no summary file in this context"
  fi

  # Verify that no secret-bearing variable is exported to subsequent steps.
  local leaked=0 v
  for v in SERVER_PRIVATE_KEY CLIENT_PRIVATE_KEY PRESHARED_KEY WG_SERVER_PRIVATE_KEY WG_CLIENT_PRIVATE_KEY; do
    if [[ -n "${!v:-}" ]]; then
      wg_err "environment variable $v is set and would be inherited by later steps"
      leaked=1
    fi
  done
  if (( leaked == 0 )); then
    wg_check "SEC-04" PASS "No key material in the process environment" "no secret variables exported"
  else
    wg_check "SEC-04" FAIL "No key material in the process environment" "see errors"
    rc=1
  fi

  # Workflow files must pin every third-party action to a full commit SHA.
  local unpinned=0 line
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ (uses:)[[:space:]]*([^[:space:]#]+) ]] || continue
    local uses="${BASH_REMATCH[2]}"
    [[ "$uses" == ./* ]] && continue
    if [[ ! "$uses" =~ @[0-9a-f]{40}$ ]]; then
      wg_err "unpinned action reference: $uses"
      unpinned=1
    fi
  done < <(grep -rh 'uses:' "${REPO_ROOT}/.github/workflows" 2>/dev/null || true)
  if (( unpinned == 0 )); then
    wg_check "SEC-05" PASS "All GitHub Actions pinned to full commit SHAs" "no floating tags"
  else
    wg_check "SEC-05" FAIL "All GitHub Actions pinned to full commit SHAs" "see errors"
    rc=1
  fi

  (( rc == 0 )) || exit 1
}

main "$@"
