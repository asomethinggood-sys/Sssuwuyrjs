#!/usr/bin/env bash
# render-config.sh - render a WireGuard config template from a values file.
#
# SECURITY: values are read from a JSON file, never from the process
# environment, so key material does not land in /proc/*/environ. Nothing that
# is read is ever printed: only the names of missing variables are reported.
#
# Usage:
#   render-config.sh --template <tpl> --values <values.json> --out <file>
#                    [--mode 600] [--redact <file>] [--allow-unresolved]
#
# Exit codes: 0 ok, 1 unresolved/missing variables, 2 usage error.
set -o errexit
set -o nounset
set -o pipefail

TEMPLATE=""
VALUES=""
OUT=""
REDACT=""
MODE="600"
ALLOW_UNRESOLVED=0

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

while (( $# )); do
  case "$1" in
    --template) TEMPLATE="${2:-}"; shift 2 ;;
    --values)   VALUES="${2:-}";   shift 2 ;;
    --out)      OUT="${2:-}";      shift 2 ;;
    --redact)   REDACT="${2:-}";   shift 2 ;;
    --mode)     MODE="${2:-}";     shift 2 ;;
    --allow-unresolved) ALLOW_UNRESOLVED=1; shift ;;
    -h|--help)  usage ;;
    *) echo "render-config.sh: unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n "$TEMPLATE" && -n "$VALUES" && -n "$OUT" ]] || usage
[[ -r "$TEMPLATE" ]] || { echo "render-config.sh: cannot read template $TEMPLATE" >&2; exit 1; }
[[ -r "$VALUES" ]]   || { echo "render-config.sh: cannot read values $VALUES" >&2; exit 1; }

mkdir -p "$(dirname "$OUT")"

python3 - "$TEMPLATE" "$VALUES" "$OUT" "$REDACT" "$MODE" "$ALLOW_UNRESOLVED" <<'PY'
import json
import os
import re
import sys

template_path, values_path, out_path, redact_path, mode, allow_unresolved = sys.argv[1:7]
allow_unresolved = allow_unresolved == "1"

with open(values_path, "r", encoding="utf-8") as fh:
    values = json.load(fh)
if not isinstance(values, dict):
    raise SystemExit("values file must contain a JSON object")

text = open(template_path, "r", encoding="utf-8").read()
missing: list[str] = []
seen: set[str] = set()


def substitute(match: re.Match) -> str:
    name = match.group(1)
    seen.add(name)
    if name in values and values[name] != "":
        return str(values[name])
    missing.append(name)
    return f"<{name}>" if allow_unresolved else match.group(0)


rendered = re.sub(r"\{\{\s*([A-Z0-9_]+)\s*\}\}", substitute, text)

if missing:
    print(
        "render-config.sh: unresolved variables: " + ", ".join(sorted(set(missing))),
        file=sys.stderr,
    )
    if not allow_unresolved:
        raise SystemExit(1)

if "{{" in rendered and not allow_unresolved:
    print("render-config.sh: output still contains placeholders; refusing to write", file=sys.stderr)
    raise SystemExit(1)

# Refuse to write a config that claims to be live but still has <PLACEHOLDER>.
unresolved_leftover = sorted(set(re.findall(r"<([A-Z0-9_]+)>", rendered)))
if unresolved_leftover and not allow_unresolved:
    raise SystemExit("placeholder left in output: " + ", ".join(unresolved_leftover))

fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, int(mode, 8))
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write(rendered)

# A variable is secret if its NAME says so. Redaction replaces the literal
# value everywhere it appears, not just after a recognisable key name, because
# a secret can also be echoed into a comment or a hook command.
SECRET_NAME = re.compile(r"(PRIVATE|PSK|PRESHARED|SECRET|TOKEN|PASSWORD)", re.IGNORECASE)

if redact_path:
    secret_values = sorted(
        {str(v) for k, v in values.items() if SECRET_NAME.search(k) and str(v).strip()},
        key=len,
        reverse=True,
    )
    redacted = rendered
    for value in secret_values:
        redacted = redacted.replace(value, "<redacted>")
    # Belt and braces: also blank any private/preshared assignment that slipped
    # through, e.g. a value supplied under a neutral variable name.
    out_lines = []
    for line in redacted.splitlines():
        key = line.split("=", 1)[0].strip().lower() if "=" in line else ""
        if key in {"privatekey", "presharedkey"} and "<redacted>" not in line:
            out_lines.append(line.split("=", 1)[0].rstrip() + " = <redacted>")
        else:
            out_lines.append(line)
    redacted = "\n".join(out_lines) + "\n"
    if SECRET_NAME.search(" ".join(values.keys())):
        pass
    fd = os.open(redact_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(redacted)

substituted = sorted(seen - set(missing))
print(f"rendered {out_path} ({len(substituted)} variables substituted)")
if missing and allow_unresolved:
    print("unresolved: " + ", ".join(sorted(set(missing))))
PY

chmod "$MODE" "$OUT"
