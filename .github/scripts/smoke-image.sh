#!/usr/bin/env bash
# Source of truth: SCRIPTS/githubactions. Generated copies are overwritten.
# Runs only on the GitHub build runner, never on core/rafael.
set -euo pipefail
image="${IMAGE_REF:?}"
name="citadel-ci-${GITHUB_RUN_ID:?}"
shared="$(mktemp -d)"
cleanup() {
    status=$?
    if (( status != 0 )); then docker logs "$name" || true; fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

check_ready() {
    for attempt in $(seq 1 45); do
        if docker exec "$name" curl -fsS "$@" >/dev/null 2>&1; then return; fi
        sleep 1
    done
    docker logs "$name"
    return 1
}

start() {
    docker run --pull=never --detach --name "$name" --network=none \
        --env TS_AUTHKEY= --env CLOUDFLARE_API_TOKEN= --env CLOUDFLARE_TUNNEL_TOKEN= \
        --env CITADEL_TOKEN= "$@" "$image" >/dev/null
}

# No credentials or volumes: WebUI must still start, with an absent filter file.
start
check_ready http://127.0.0.1:11000/
# Ship callback examples, never the installation's active registration policy.
docker exec "$name" python3 -s -c 'import json; from pathlib import Path; p = Path("CLOUDFLARE_OAUTH_Whitelist.json.example"); d = json.loads(p.read_text()); assert d["allowed_redirect_uris"]; assert d["allow_localhost"] is False; assert d["allow_loopback"] is False; assert not Path("CLOUDFLARE_OAUTH_Whitelist.json").exists()'
processes="$(docker top "$name" -eo pid,comm)"
if grep -Eq '[[:space:]](tailscaled|cloudflared)$' <<< "$processes"; then
    echo 'Unexpected tunnel daemon without credentials' >&2; exit 1
fi
docker rm -f "$name" >/dev/null

# The same image, Unix mode; settings survive recreation, socket shares CADDY.
start --env CITADEL_WEBUI_TRANSPORT=unix --env CITADEL_WEBUI_SOCKET= \
    --mount "type=bind,source=$shared,target=/opt/safrano9999/CITADEL/CITADEL_DATA"
check_ready --unix-socket /opt/safrano9999/CITADEL/CITADEL_DATA/CADDY/citadel.sock http://localhost/
for attempt in $(seq 1 45); do
    if docker logs "$name" 2>&1 | grep -Fq 'initial scan finished: 0'; then break; fi
    sleep 1
done
docker logs "$name" 2>&1 | grep -Fq 'initial scan finished: 0'
docker exec "$name" sh -c 'test -f CITADEL_DATA/ports.filter.json; printf "{\"blacklist\":[45678]}\n" > CITADEL_DATA/ports.filter.json'
docker stop --time 15 "$name" >/dev/null
test ! -e "$shared/CADDY/citadel.sock"
docker rm "$name" >/dev/null
start --mount "type=bind,source=$shared,target=/opt/safrano9999/CITADEL/CITADEL_DATA"
check_ready http://127.0.0.1:11000/
docker exec "$name" grep -q 45678 CITADEL_DATA/ports.filter.json
