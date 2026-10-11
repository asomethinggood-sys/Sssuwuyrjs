#!/usr/bin/env bash
# tests/check-workflows.sh - supply-chain and injection checks for the workflows.
#
# These are the review criteria that a human reviewer would otherwise have to
# apply by hand on every change:
#   1. every third-party action is pinned to a full 40-hex commit SHA;
#   2. every workflow declares least-privilege `permissions`;
#   3. `pull_request_target` is never used;
#   4. no untrusted event context is interpolated into a `run:` block
#      (the classic GitHub Actions script-injection path);
#   5. secrets are never echoed;
#   6. every job has a timeout.
set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WF_DIR="$REPO_ROOT/.github/workflows"

PASS=0
FAIL=0
ok()     { PASS=$(( PASS + 1 )); printf '  ok   %s\n' "$1"; }
not_ok() { FAIL=$(( FAIL + 1 )); printf '  FAIL %s\n' "$1"; }

shopt -s nullglob
FILES=("$WF_DIR"/*.yml)
if (( ${#FILES[@]} == 0 )); then
  echo "no workflow files found in $WF_DIR" >&2
  exit 2
fi

echo "== pinned actions =="
UNPINNED=0
while IFS= read -r ref; do
  [[ -n "$ref" ]] || continue
  if [[ ! "$ref" =~ @[0-9a-f]{40}$ ]]; then
    printf '       unpinned: %s\n' "$ref"
    UNPINNED=1
  fi
done < <(grep -rhoE 'uses:[[:space:]]*[^[:space:]#]+' "${FILES[@]}" \
         | sed -E 's/uses:[[:space:]]*//' | grep -v '^\./' | sort -u)
if (( UNPINNED == 0 )); then ok "all actions pinned to commit SHAs"; else not_ok "all actions pinned to commit SHAs"; fi

echo "== least privilege =="
for f in "${FILES[@]}"; do
  if grep -qE '^permissions:' "$f"; then
    ok "$(basename "$f") declares top-level permissions"
  else
    not_ok "$(basename "$f") declares top-level permissions"
  fi
  if grep -qE '^[[:space:]]*permissions:[[:space:]]*write-all' "$f"; then
    not_ok "$(basename "$f") must not use write-all"
  fi
done

echo "== dangerous patterns =="
if grep -rq 'pull_request_target' "${FILES[@]}"; then
  not_ok "pull_request_target must not be used"
else
  ok "pull_request_target is not used"
fi

# Untrusted contexts: anything from github.event.* that originates with a
# contributor. These must never be expanded inside a run: block.
INJECT=0
for f in "${FILES[@]}"; do
  while IFS= read -r line; do
    case "$line" in
      *'github.event.issue.title'*|*'github.event.issue.body'*|*'github.event.pull_request.title'*|*'github.event.pull_request.body'*|*'github.head_ref'*|*'github.event.comment.body'*|*'github.event.review.body'*)
        printf '       %s: %s\n' "$(basename "$f")" "$line"
        INJECT=1
        ;;
    esac
  done <"$f"
done
if (( INJECT == 0 )); then ok "no untrusted event context in workflow expressions"; else not_ok "no untrusted event context in workflow expressions"; fi

echo "== no secret echoing =="
if grep -rnE '(echo|printf|cat)[^\n]*\$\{\{[[:space:]]*secrets\.' "${FILES[@]}" >/dev/null 2>&1; then
  not_ok "workflows must not echo secrets"
else
  ok "workflows do not echo secrets"
fi

echo "== job timeouts =="
for f in "${FILES[@]}"; do
  JOBS=$(grep -cE '^[[:space:]]+runs-on:' "$f" || true)
  TIMEOUTS=$(grep -cE '^[[:space:]]+timeout-minutes:' "$f" || true)
  if (( JOBS > 0 && TIMEOUTS >= JOBS )); then
    ok "$(basename "$f") every job has a timeout ($TIMEOUTS/$JOBS)"
  else
    not_ok "$(basename "$f") every job has a timeout ($TIMEOUTS/$JOBS)"
  fi
done

echo "== trigger sanity =="
for f in "${FILES[@]}"; do
  if grep -qE '^on:' "$f"; then ok "$(basename "$f") has an explicit trigger"; else not_ok "$(basename "$f") has an explicit trigger"; fi
done

printf '\n---------------------------------------------\n'
printf 'workflow checks: %d passed, %d failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
