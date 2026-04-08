#!/bin/bash
set -euo pipefail

TS_SOCKET="/var/run/tailscale/tailscaled.sock"
TS_STATE_DIR="${TS_STATE_DIR:-/var/lib/tailscale}"
TS_STATE_FILE="${TS_STATE_DIR}/tailscaled.state"
TS_CERT_DIR="${TS_STATE_DIR}/certs"
CADDY_TEMPLATE="/opt/citadel/deploy/Caddyfile"
CADDY_CONFIG="/etc/caddy/Caddyfile"
LOCAL_CERT_DIR="/opt/citadel/certs"

mkdir -p /var/run/tailscale "$TS_STATE_DIR" "$TS_CERT_DIR" "$LOCAL_CERT_DIR"

echo "=== Starting tailscaled ==="
tailscaled --state="${TS_STATE_FILE}" --socket="${TS_SOCKET}" &
sleep 2

echo "=== Bringing up Tailscale ==="
TS_UP_ARGS=()

if [ -n "${TS_AUTHKEY:-}" ]; then
  TS_UP_ARGS+=(--authkey="${TS_AUTHKEY}")
fi

if [ -n "${TS_HOSTNAME:-}" ]; then
  TS_UP_ARGS+=(--hostname="${TS_HOSTNAME}")
fi

tailscale up "${TS_UP_ARGS[@]}"

if [ -z "${TS_AUTHKEY:-}" ]; then
  echo "No TS_AUTHKEY set — approve login if Tailscale prints an auth URL."
fi

echo "=== Waiting for Tailscale to connect ==="
for i in $(seq 1 60); do
  if tailscale status --json 2>/dev/null | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin).get('BackendState')=='Running' else 1)" 2>/dev/null; then
    break
  fi
  sleep 2
done

TS_DOMAIN="$(tailscale status --json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('Self',{}).get('DNSName','').rstrip('.'))")"

if [ -z "$TS_DOMAIN" ]; then
  echo "ERROR: Could not determine Tailscale DNS name."
  exit 1
fi

echo "=== Tailscale DNS name: ${TS_DOMAIN} ==="

echo "=== Fetching Tailscale TLS cert for ${TS_DOMAIN} ==="
tailscale cert \
  --cert-file="${TS_CERT_DIR}/cert.pem" \
  --key-file="${TS_CERT_DIR}/key.pem" \
  "${TS_DOMAIN}"

echo "=== Rendering Caddyfile ==="
if [ ! -f "${CADDY_TEMPLATE}" ]; then
  echo "ERROR: Missing Caddy template at ${CADDY_TEMPLATE}"
  exit 1
fi

sed "s|{TS_DOMAIN}|${TS_DOMAIN}|g" "${CADDY_TEMPLATE}" > "${CADDY_CONFIG}"

echo "=== Generating self-signed cert for local access ==="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -days 3650 -nodes \
  -keyout "${LOCAL_CERT_DIR}/local-key.pem" \
  -out "${LOCAL_CERT_DIR}/local.pem" \
  -subj "/CN=citadel" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  2>/dev/null

echo "=== Starting PHP-FPM ==="
php-fpm --daemonize

echo "=== Starting Flask hello_world ==="
/opt/citadel/hello_world/venv/bin/python /opt/citadel/hello_world/app.py &

echo "=== Starting Caddy on :443 ==="
caddy start --config "${CADDY_CONFIG}"

sleep 2

echo "=== Running initial scan ==="
/opt/citadel/scan.sh || true

echo "CITADEL is live at https://${TS_DOMAIN}/"
echo "Local access: https://localhost:8443/"

wait
