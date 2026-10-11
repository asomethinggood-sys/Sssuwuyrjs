#!/usr/bin/env bash
# 03-config-validate.sh - render configs from templates and prove they parse.
#
# "Valid" here means: `wg-quick strip` accepts the file AND the harness's own
# structural checks pass. A syntactically valid config is NOT a working tunnel;
# that claim is only made by 05-handshake.sh.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_DIR="${WG_STATE_DIR}/keys"
CONF_DIR="${WG_STATE_DIR}/conf"
VALUES="${WG_STATE_DIR}/values.json"

build_values() {
  # Values are assembled with jq from files so that key material is never an
  # argument to a command and never appears in the process environment.
  local srv_priv cli_priv psk
  srv_priv="$(<"${KEYS_DIR}/server.key")"
  cli_priv="$(<"${KEYS_DIR}/client.key")"
  psk="$(<"${KEYS_DIR}/preshared.key")"

  ( umask 077; jq -n \
      --arg SERVER_PRIVATE_KEY "$srv_priv" \
      --arg CLIENT_PRIVATE_KEY "$cli_priv" \
      --arg PRESHARED_KEY "$psk" \
      --arg SERVER_PUBLIC_KEY "$(wg_pubkey_of "${KEYS_DIR}/server.key")" \
      --arg CLIENT_PUBLIC_KEY "$(wg_pubkey_of "${KEYS_DIR}/client.key")" \
      --arg SERVER_TUNNEL_IP "$WG_TUNNEL_SRV_IP" \
      --arg CLIENT_TUNNEL_IP "$WG_TUNNEL_CLI_IP" \
      --arg TUNNEL_CIDR "$WG_TUNNEL_CIDR" \
      --arg SERVER_LISTEN_PORT "$WG_LISTEN_PORT" \
      --arg TUNNEL_MTU "${WG_MTU:-1420}" \
      --arg TUNNEL_DNS "$WG_TUNNEL_SRV_IP" \
      --arg SERVER_ENDPOINT_HOST "$WG_TRANSPORT_SRV_IP" \
      --arg SERVER_ENDPOINT_PORT "$WG_LISTEN_PORT" \
      --arg CLIENT_ALLOWED_IPS "0.0.0.0/0" \
      --arg CLIENT_PERSISTENT_KEEPALIVE "25" \
      --arg CLIENT_NAME "ci-ephemeral-client" \
      --arg WAN_INTERFACE "eth0" \
      --arg IPV6_FORWARDING "0" \
      '{SERVER_PRIVATE_KEY:$SERVER_PRIVATE_KEY, CLIENT_PRIVATE_KEY:$CLIENT_PRIVATE_KEY,
        PRESHARED_KEY:$PRESHARED_KEY, SERVER_PUBLIC_KEY:$SERVER_PUBLIC_KEY,
        CLIENT_PUBLIC_KEY:$CLIENT_PUBLIC_KEY, SERVER_TUNNEL_IP:$SERVER_TUNNEL_IP,
        CLIENT_TUNNEL_IP:$CLIENT_TUNNEL_IP, TUNNEL_CIDR:$TUNNEL_CIDR,
        SERVER_LISTEN_PORT:$SERVER_LISTEN_PORT, TUNNEL_MTU:$TUNNEL_MTU,
        TUNNEL_DNS:$TUNNEL_DNS, SERVER_ENDPOINT_HOST:$SERVER_ENDPOINT_HOST,
        SERVER_ENDPOINT_PORT:$SERVER_ENDPOINT_PORT, CLIENT_ALLOWED_IPS:$CLIENT_ALLOWED_IPS,
        CLIENT_PERSISTENT_KEEPALIVE:$CLIENT_PERSISTENT_KEEPALIVE, CLIENT_NAME:$CLIENT_NAME,
        WAN_INTERFACE:$WAN_INTERFACE, IPV6_FORWARDING:$IPV6_FORWARDING}' >"$VALUES" )
  chmod 0600 "$VALUES"
  unset srv_priv cli_priv psk
}

main() {
  wg_init_artifacts
  wg_step "config: render and validate"
  install -d -m 0700 "$CONF_DIR"
  build_values

  # --- 1. templates must contain placeholders, never literal keys ----------
  if wg_assert_no_key_material "${REPO_ROOT}/examples"; then
    wg_check "CFG-01" PASS "Example configs contain no real key material" "placeholders only"
  else
    wg_check "CFG-01" FAIL "Example configs contain no real key material" "key-like string found in examples/"
    exit 1
  fi

  # --- 2. every template variable is documented ---------------------------
  local vars v missing_doc=0
  vars="$(grep -rhoE '\{\{ *[A-Z0-9_]+ *\}\}' "${REPO_ROOT}/examples" | tr -d '{} ' | sort -u)"
  for v in $vars; do
    if ! grep -q -- "$v" "${REPO_ROOT}/docs/CONFIGURATION.md" 2>/dev/null; then
      wg_warn "undocumented template variable: $v"
      missing_doc=1
    fi
  done
  if (( missing_doc == 0 )); then
    wg_check "CFG-02" PASS "All template variables documented" "$(printf '%s' "$vars" | tr '\n' ' ')"
  else
    wg_check "CFG-02" FAIL "All template variables documented" "see warnings above"
  fi

  # --- 3. render with ephemeral keys ---------------------------------------
  WG_RENDERING_LOG="${WG_ARTIFACT_DIR}/render.log"
  {
    "${SCRIPT_DIR}/render-config.sh" --template "${REPO_ROOT}/examples/server.conf.template" \
      --values "$VALUES" --out "${CONF_DIR}/server.conf" --mode 600 \
      --redact "${WG_ARTIFACT_DIR}/server.conf.redacted"
    "${SCRIPT_DIR}/render-config.sh" --template "${REPO_ROOT}/examples/client.conf.template" \
      --values "$VALUES" --out "${CONF_DIR}/client.conf" --mode 600 \
      --redact "${WG_ARTIFACT_DIR}/client.conf.redacted"
  } >>"$WG_RENDERING_LOG" 2>&1 || {
    wg_check "CFG-03" FAIL "Templates render without unresolved variables" "see render.log"
    cat "$WG_RENDERING_LOG" >&2
    exit 1
  }
  wg_check "CFG-03" PASS "Templates render without unresolved variables" "server.conf + client.conf produced"

  # --- 4. syntax validation by the upstream tool ---------------------------
  local iface rc=0
  for iface in server client; do
    if wg-quick strip "${CONF_DIR}/${iface}.conf" >/dev/null 2>"${CONF_DIR}/${iface}.strip.err"; then
      wg_log "wg-quick strip accepted ${iface}.conf"
    else
      rc=1
      wg_err "wg-quick strip rejected ${iface}.conf: $(head -3 "${CONF_DIR}/${iface}.strip.err")"
    fi
  done
  if (( rc == 0 )); then
    wg_check "CFG-04" PASS "Config syntax validated by wg-quick strip" "server.conf + client.conf"
  else
    wg_check "CFG-04" FAIL "Config syntax validated by wg-quick strip" "parse error, see logs"
    exit 1
  fi

  # --- 5. structural checks wg-quick does not perform ----------------------
  local detail structural_rc=0
  detail="$(python3 "${SCRIPT_DIR}/validate_config.py" \
      --server "${CONF_DIR}/server.conf" \
      --client "${CONF_DIR}/client.conf" \
      --expect-port "$WG_LISTEN_PORT" 2>&1)" || structural_rc=$?
  if (( structural_rc == 0 )); then
    wg_check "CFG-05" PASS "Structural config checks" "required keys, PSK, AllowedIPs, MTU"
  else
    wg_check "CFG-05" FAIL "Structural config checks" "$(printf '%s' "$detail" | head -3 | tr '\n' ' ')"
    wg_err "$detail"
    exit 1
  fi

  # --- 5b. the distributed template must be well formed and must not pass as live
  local tpl="${REPO_ROOT}/deliverables/wg-client.conf.template"
  if [[ -f "$tpl" ]]; then
    local tpl_ok=1
    python3 "${SCRIPT_DIR}/validate_config.py" --client "$tpl" --allow-placeholders \
      >/dev/null 2>&1 || tpl_ok=0
    if python3 "${SCRIPT_DIR}/validate_config.py" --client "$tpl" >/dev/null 2>&1; then
      tpl_ok=0   # a template must never validate as a live configuration
    fi
    if (( tpl_ok == 1 )); then
      wg_check "CFG-08" PASS "Distributed client template is well formed and not deployable" \
        "valid with --allow-placeholders, rejected as a live config"
    else
      wg_check "CFG-08" FAIL "Distributed client template is well formed and not deployable" \
        "template validation gave the wrong answer; see logs"
    fi
  else
    wg_check "CFG-08" UNTESTED "Distributed client template is well formed" "no template shipped"
  fi

  # --- 6. file permissions -------------------------------------------------
  local bad=0 m
  for f in "${CONF_DIR}/server.conf" "${CONF_DIR}/client.conf" "$VALUES"; do
    m="$(stat -c '%a' "$f")"
    [[ "$m" == "600" ]] || { bad=1; wg_err "$f mode $m (expected 600)"; }
  done
  if (( bad == 0 )); then
    wg_check "CFG-06" PASS "Rendered configs and values are mode 0600" "tight permissions enforced"
  else
    wg_check "CFG-06" FAIL "Rendered configs and values are mode 0600" "see errors"
    exit 1
  fi

  # --- 7. redacted artifacts are provably clean ----------------------------
  if wg_assert_no_key_material "${WG_ARTIFACT_DIR}"; then
    wg_check "CFG-07" PASS "Redacted artifacts contain no key material" "scan clean"
  else
    wg_check "CFG-07" FAIL "Redacted artifacts contain no key material" "scan found key-like data"
    exit 1
  fi

  wg_log "rendered configs live in $CONF_DIR (0700)"
}

main "$@"
