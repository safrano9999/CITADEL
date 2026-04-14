#!/usr/bin/env bash
set -euo pipefail

if [[ "${CITADEL_ENABLE_TAILSCALE:-1}" != "1" ]]; then
  echo "tailscaled disabled (CITADEL_ENABLE_TAILSCALE=${CITADEL_ENABLE_TAILSCALE:-0})"
  exec sleep infinity
fi

exec /usr/sbin/tailscaled \
  --state=/var/lib/tailscale/tailscaled.state \
  --socket=/var/run/tailscale/tailscaled.sock

