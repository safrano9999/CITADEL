#!/usr/bin/env bash
set -euo pipefail

CADDY_CONFIG="/etc/caddy/Caddyfile"

# Ensure CADDYFILES import dir exists (may be empty)
mkdir -p /opt/citadel/CADDYFILES

if [[ ! -f "$CADDY_CONFIG" ]]; then
  echo "ERROR: Missing Caddy config: $CADDY_CONFIG"
  exit 1
fi

exec caddy run --config "$CADDY_CONFIG"
