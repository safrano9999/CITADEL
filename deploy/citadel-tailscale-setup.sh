#!/usr/bin/env bash
set -euo pipefail

# If tailscale is disabled, setup_extensions.py already handled everything.
if [[ "${CITADEL_ENABLE_TAILSCALE:-0}" != "1" ]]; then
  exit 0
fi

TS_SOCKET="/var/run/tailscale/tailscaled.sock"
TS_STATE_DIR="${TS_STATE_DIR:-/var/lib/tailscale}"
TS_STATE_FILE="${TS_STATE_DIR}/tailscaled.state"
TS_CERT_DIR="${TS_STATE_DIR}/certs"
CADDY_CONFIG="/etc/caddy/Caddyfile"
CITADEL_ROOT="/opt/citadel"

mkdir -p /var/run/tailscale "$TS_STATE_DIR" "$TS_CERT_DIR"

echo "=== Waiting for tailscaled socket ==="
for _ in $(seq 1 60); do
  [[ -S "$TS_SOCKET" ]] && break
  sleep 1
done

if [[ ! -S "$TS_SOCKET" ]]; then
  echo "ERROR: tailscaled socket not available"
  exit 1
fi

echo "=== Bringing up Tailscale ==="
TS_UP_ARGS=()
[[ -n "${TS_AUTHKEY:-}" ]] && TS_UP_ARGS+=(--authkey="${TS_AUTHKEY}")
[[ -n "${TS_HOSTNAME:-}" ]] && TS_UP_ARGS+=(--hostname="${TS_HOSTNAME}")

if ! tailscale up "${TS_UP_ARGS[@]}"; then
  echo "tailscale up failed; local-only Caddyfile remains."
  exit 0
fi

echo "=== Waiting for Tailscale backend ==="
for _ in $(seq 1 90); do
  if tailscale status --json 2>/dev/null | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin).get('BackendState')=='Running' else 1)" 2>/dev/null; then
    break
  fi
  sleep 2
done

TS_DOMAIN="$(tailscale status --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('Self',{}).get('DNSName','').rstrip('.'))" 2>/dev/null || true)"

if [[ -z "$TS_DOMAIN" ]]; then
  echo "No Tailscale DNS name available."
  exit 0
fi

echo "=== Tailscale DNS: ${TS_DOMAIN} ==="
echo "=== Fetching Tailscale TLS cert ==="
tailscale cert \
  --cert-file="${TS_CERT_DIR}/cert.pem" \
  --key-file="${TS_CERT_DIR}/key.pem" \
  "${TS_DOMAIN}" || true

# Append tailscale block to Caddyfile
cat >> "$CADDY_CONFIG" <<CADDYEOF

${TS_DOMAIN}:443 {
	tls ${TS_CERT_DIR}/cert.pem ${TS_CERT_DIR}/key.pem

	route {
		import ${CITADEL_ROOT}/CADDYFILES/*.caddy

		reverse_proxy 127.0.0.1:800
	}
}
CADDYEOF

# Reload caddy to pick up the new block
caddy reload --config "$CADDY_CONFIG" 2>/dev/null || true
echo "=== Tailscale setup done ==="
