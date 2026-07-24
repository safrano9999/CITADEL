#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$EUID" -ne 0 ]]; then
    echo "Run this command with sudo: sudo ./unroute.sh" >&2
    exit 1
fi

exec python3 "$SCRIPT_DIR/functions/unroute_tailscale.py" --root "$SCRIPT_DIR"
