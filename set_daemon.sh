#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_NAME="citadel.service"
RENDER_ONLY=false

case "${1:-}" in
    "") ;;
    --render-only) RENDER_ONLY=true ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
esac

if "$RENDER_ONLY"; then
    LOCAL_UNIT_DIR="$SCRIPT_DIR"
else
    LOCAL_UNIT_DIR="$SCRIPT_DIR/.systemd"
fi
LOCAL_UNIT="$LOCAL_UNIT_DIR/$UNIT_NAME"
USER_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
USER_UNIT="$USER_UNIT_DIR/$UNIT_NAME"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"

mkdir -p "$LOCAL_UNIT_DIR"

cat > "$LOCAL_UNIT" <<EOF
[Unit]
Description=CITADEL baremetal service dashboard
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
ExecStart=$PYTHON_BIN $SCRIPT_DIR/webui.py
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

echo "  Written: $LOCAL_UNIT"

"$RENDER_ONLY" && exit 0

mkdir -p "$USER_UNIT_DIR"
ln -sfn "$LOCAL_UNIT" "$USER_UNIT"
systemctl --user daemon-reload
systemctl --user enable --now "$UNIT_NAME"

if command -v loginctl >/dev/null 2>&1 && [[ -n "${USER:-}" ]]; then
    if [[ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || true)" != "yes" ]]; then
        loginctl enable-linger "$USER" 2>/dev/null || true
    fi
fi

systemctl --user --no-pager --full status "$UNIT_NAME" --lines=5 || true
