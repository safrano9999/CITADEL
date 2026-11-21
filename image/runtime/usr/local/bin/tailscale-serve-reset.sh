#!/bin/sh
# Wait for a usable network map before clearing persisted Serve routes.
set -eu

[ "${TAILSCALE_SERVE_RESET:-0}" = "1" ] || exit 0

for dependency in tailscale jq timeout date sleep; do
    command -v "$dependency" >/dev/null 2>&1 || {
        printf 'tailscale-serve-reset: missing dependency: %s\n' "$dependency" >&2
        exit 1
    }
done

deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if timeout 2 tailscale status --json 2>/dev/null \
        | jq -e '.BackendState == "Running"' >/dev/null 2>&1; then
        exec timeout 10 tailscale serve reset
    fi
    sleep 1
done

printf 'tailscale-serve-reset: Tailscale did not reach Running within 30 seconds; reset skipped.\n' >&2
exit 1
