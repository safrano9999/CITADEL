#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

"$SCRIPT_DIR/config.sh" --no-container "$@"
"$SCRIPT_DIR/set_daemon.sh" --render-only

printf '\nLink the rendered systemd user service:\n'
printf '  ln -sfn %q %q\n' \
    "$SCRIPT_DIR/citadel.service" \
    "$USER_UNIT_DIR/citadel.service"
