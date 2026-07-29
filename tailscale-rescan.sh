#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/citadel"
STATE_FILE="${CITADEL_TAILSCALE_RESCAN_STATE:-$RUNTIME_DIR/tailscale-rescan.state}"
MAX_AGE="${CITADEL_TAILSCALE_RESCAN_MAX_AGE:-300}"
SCAN_SCRIPT="${CITADEL_SCAN_SCRIPT:-$SCRIPT_DIR/scan.sh}"
TAILSCALE_STATE_FILE="${CITADEL_TAILSCALE_STATE_FILE:-$SCRIPT_DIR/tailscale.json}"

case "${CITADEL_TAILSCALE:-true}" in
    0|false|FALSE|no|NO|off|OFF)
        echo "CITADEL Tailscale reconciliation is disabled"
        exit 0
        ;;
esac

[[ "$MAX_AGE" =~ ^[0-9]+$ ]] || {
    echo "CITADEL_TAILSCALE_RESCAN_MAX_AGE must be a non-negative integer" >&2
    exit 2
}
[[ -x "$SCAN_SCRIPT" ]] || {
    echo "CITADEL scan script is not executable: $SCAN_SCRIPT" >&2
    exit 1
}
command -v ss >/dev/null 2>&1 || {
    echo "ss is required for CITADEL listener discovery" >&2
    exit 1
}
command -v tailscale >/dev/null 2>&1 || {
    echo "tailscale is required for CITADEL Tailscale reconciliation" >&2
    exit 1
}

fingerprint() {
    local listeners serve_status serve_result

    listeners="$(
        ss -H -ltn |
            awk '{ print $4 }' |
            LC_ALL=C sort -u
    )"
    if serve_status="$(tailscale serve status --json 2>&1)"; then
        serve_result="available"
    else
        serve_result="unavailable:$?"
    fi
    printf '%s\n%s\n%s\n' \
        "$listeners" \
        "$serve_result" \
        "$serve_status" |
        sha256sum |
        awk '{ print $1 }'
}

mkdir -p "$(dirname "$STATE_FILE")"
current_fingerprint="$(fingerprint)"
previous_fingerprint=""
previous_epoch=0
if [[ -f "$STATE_FILE" ]]; then
    read -r previous_fingerprint previous_epoch < "$STATE_FILE" || true
fi
[[ "$previous_epoch" =~ ^[0-9]+$ ]] || previous_epoch=0

now="$(date +%s)"
age=$((now - previous_epoch))
if [[ "$current_fingerprint" == "$previous_fingerprint" && "$age" -lt "$MAX_AGE" ]]; then
    echo "CITADEL Tailscale listeners unchanged; reconciliation skipped"
    exit 0
fi

if [[ "$current_fingerprint" != "$previous_fingerprint" ]]; then
    echo "CITADEL Tailscale listener state changed; reconciling"
else
    echo "CITADEL Tailscale reconciliation reached max age; reconciling"
fi

"$SCAN_SCRIPT" --provider tailscale

python3 - "$TAILSCALE_STATE_FILE" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"Invalid CITADEL Tailscale state: {error}")

if not isinstance(payload, dict):
    raise SystemExit("Invalid CITADEL Tailscale state: expected an object")
if not payload.get("enabled", True):
    raise SystemExit(0)
if not payload.get("running", False):
    raise SystemExit("CITADEL Tailscale reconciliation is pending: daemon unavailable")
failures = payload.get("route_failures")
if isinstance(failures, dict) and failures:
    ports = ", ".join(sorted(str(port) for port in failures))
    raise SystemExit(f"CITADEL Tailscale reconciliation is pending for ports: {ports}")
PY

current_fingerprint="$(fingerprint)"
temporary="${STATE_FILE}.tmp"
printf '%s %s\n' "$current_fingerprint" "$(date +%s)" > "$temporary"
mv -f "$temporary" "$STATE_FILE"
echo "CITADEL Tailscale reconciliation completed"
