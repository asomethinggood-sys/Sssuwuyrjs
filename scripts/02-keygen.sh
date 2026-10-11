#!/usr/bin/env bash
# 02-keygen.sh - generate key material and store it outside the artifact tree.
#
# Security properties asserted by this script:
#   * private keys are created with umask 077 and verified to be mode 0600
#   * private keys never appear on stdout, in the log, or in artifacts
#   * the state directory is root-only (0700) and is removed by 09-cleanup.sh
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

KEYS_DIR="${WG_STATE_DIR}/keys"
PUBLIC_KEYS_FILE="${WG_ARTIFACT_DIR}/public-keys.txt"

main() {
  wg_init_artifacts
  wg_step "keygen: WireGuard key material"

  install -d -m 0700 "$KEYS_DIR"

  local srv_priv cli_priv psk
  srv_priv="$(wg_genkey "${KEYS_DIR}/server.key")"
  cli_priv="$(wg_genkey "${KEYS_DIR}/client.key")"
  ( umask 077; wg genpsk >"${KEYS_DIR}/preshared.key" )
  chmod 0600 "${KEYS_DIR}/preshared.key"
  psk="${KEYS_DIR}/preshared.key"

  local srv_pub cli_pub
  srv_pub="$(wg_pubkey_of "$srv_priv")"
  cli_pub="$(wg_pubkey_of "$cli_priv")"

  # A manifest of SHA-256 digests of the secrets. Digests are one-way, so this
  # file is safe to publish, and it lets the leak audit prove provenance even
  # after 09-cleanup.sh has deleted the keys themselves - which is exactly the
  # order the suite runs in.
  ( umask 022
    : >"${WG_ARTIFACT_DIR}/secret-hashes.txt"
    for f in server.key client.key preshared.key; do
      [[ -f "${KEYS_DIR}/${f}" ]] || continue
      # The file holds a 44-character key plus no trailing newline in some
      # builds; tr strips any whitespace before hashing so the digest matches
      # what the scanner computes over a token it finds in a file.
      digest="$(tr -d '\r\n' <"${KEYS_DIR}/${f}" | sha256sum | awk '{print $1}')"
      printf '%s\n' "$digest" >>"${WG_ARTIFACT_DIR}/secret-hashes.txt"
    done
  ) || true

  # Public keys are safe to record.
  {
    printf 'server_public_key=%s\n' "$srv_pub"
    printf 'client_public_key=%s\n' "$cli_pub"
    printf 'generated_at=%s\n' "$(_wg_ts)"
  } >"$PUBLIC_KEYS_FILE"

  wg_check "KEY-01" PASS "Server keypair generated" "public=${srv_pub:0:8}... (private key never logged)"
  wg_check "KEY-02" PASS "Client keypair generated" "public=${cli_pub:0:8}... (private key never logged)"
  wg_check "KEY-03" PASS "Preshared key generated" "32-byte PSK stored at 0600"

  # --- enforcement checks -------------------------------------------------
  local mode
  for f in "$srv_priv" "$cli_priv" "$psk"; do
    mode="$(stat -c '%a' "$f")"
    if [[ "$mode" != "600" ]]; then
      wg_check "KEY-04" FAIL "Private key file permissions" "$f is mode $mode"
      wg_die "refusing to continue: $f is not 0600"
    fi
  done
  wg_check "KEY-04" PASS "Private key file permissions enforced" "all 0600"

  # Distinctness: the two keys must differ.
  if [[ "$srv_priv" == "$cli_priv" ]] || cmp -s "$srv_priv" "$cli_priv"; then
    wg_check "KEY-05" FAIL "Key distinctness" "server and client private keys are identical"
    wg_die "key generation produced identical keys"
  fi
  wg_check "KEY-05" PASS "Key distinctness" "server/client keys differ"

  # Private keys must not be reachable from the artifact directory.
  if wg_assert_no_key_material "$WG_ARTIFACT_DIR"; then
    wg_check "KEY-06" PASS "No key material in artifact directory" "scan clean"
  else
    wg_check "KEY-06" FAIL "No key material in artifact directory" "key material detected"
    wg_die "secret leak detected in artifacts"
  fi

  wg_log "key material stored under $KEYS_DIR (mode 0700, removed by cleanup)"
  printf '%s' "$KEYS_DIR" >"${WG_STATE_DIR}/keys_dir.path"
}

main "$@"
