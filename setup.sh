#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QUADLET_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/containers/systemd"

"$SCRIPT_DIR/config.sh" "$@"

printf '\nLink the rendered Podman Quadlet:\n'
printf '  ln -sfn %q %q\n' \
    "$SCRIPT_DIR/citadel.container" \
    "$QUADLET_DIR/citadel.container"
