#!/bin/bash
set -euo pipefail

echo "=== Starting tailscaled ==="
tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
sleep 2

echo "=== Generating hostname ==="
if [ -z "${TS_HOSTNAME:-}" ]; then
    TS_HOSTNAME="citadel-$(python3 -c "
import random
adj = ['swift','brave','calm','bold','keen','wild','warm','cool','fair','glad']
noun = ['falcon','otter','panda','raven','tiger','cedar','brook','ember','ridge','frost']
print(f'{random.choice(adj)}-{random.choice(noun)}')
")"
    echo "Generated hostname: ${TS_HOSTNAME}"
fi

echo "=== Authenticating with Tailscale ==="
tailscale up --hostname="${TS_HOSTNAME}" --authkey="${TS_AUTHKEY:-}"
if [ -z "${TS_AUTHKEY:-}" ]; then
    echo "No TS_AUTHKEY set — check logs above for the auth URL and approve in the Tailscale admin console."
fi

echo "=== Waiting for Tailscale to connect ==="
for i in $(seq 1 60); do
    if tailscale status --json 2>/dev/null | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin).get('BackendState')=='Running' else 1)" 2>/dev/null; then
        break
    fi
    sleep 2
done

TS_DOMAIN="$(tailscale status --json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('Self',{}).get('DNSName','').rstrip('.'))")"
TS_CERT_DIR="/var/lib/tailscale/certs"
mkdir -p "$TS_CERT_DIR"

echo "=== Fetching Tailscale TLS cert for ${TS_DOMAIN} ==="
tailscale cert --cert-file="$TS_CERT_DIR/cert.pem" --key-file="$TS_CERT_DIR/key.pem" "$TS_DOMAIN"

# Write Tailscale domain into Caddyfile
sed -i "s|{TS_DOMAIN}|${TS_DOMAIN}|g" /etc/caddy/Caddyfile

echo "=== Generating self-signed cert for local access ==="
LOCAL_CERT_DIR="/opt/citadel/certs"
mkdir -p "$LOCAL_CERT_DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days 3650 -nodes \
    -keyout "$LOCAL_CERT_DIR/local-key.pem" \
    -out "$LOCAL_CERT_DIR/local.pem" \
    -subj "/CN=citadel" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

echo "=== Starting PHP-FPM ==="
php-fpm --daemonize

echo "=== Starting Flask hello_world ==="
/opt/citadel/hello_world/venv/bin/python /opt/citadel/hello_world/app.py &

echo "=== Starting Caddy on :443 ==="
caddy start --config /etc/caddy/Caddyfile

sleep 2

echo "=== Running initial scan ==="
/opt/citadel/scan.sh || true

echo "CITADEL is live at https://${TS_DOMAIN}/"
echo "Local access: https://localhost:8443/"

# Keep container alive
wait
