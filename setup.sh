#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

print_caddy_hint() {
    cat <<'EOF'

Central Caddy export (when CITADEL_CADDY_HTTPS_START is non-zero):
  1. Mount this instance's CITADEL named volume read-only at /etc/caddy/<instance>.
  2. Add one line to the main Caddyfile: import <instance>/CADDYFILES/Caddyfile
The generated file is refreshed by every successful CITADEL scan.
Reload or restart central Caddy after that file changes.
EOF
}

if [ "$(basename "$(cd "$SCRIPT_DIR/.." && pwd -P)")" = "CONTAINER" ]; then
    "$SCRIPT_DIR/config.sh" "$@"
    print_caddy_hint
    exit 0
fi

"$SCRIPT_DIR/config.sh" --no-container "$@"
"$SCRIPT_DIR/set_daemon.sh" --render-only

printf '\nLink the rendered systemd user service:\n'
printf '  ln -sfn %q %q\n' \
    "$SCRIPT_DIR/citadel.service" \
    "$USER_UNIT_DIR/citadel.service"
print_caddy_hint
