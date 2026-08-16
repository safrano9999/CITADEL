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
CONFIG_FILE="$SCRIPT_DIR/config.conf"
[ -f "$CONFIG_FILE" ] || CONFIG_FILE="$SCRIPT_DIR/config.conf_example"
TRANSPORT="$(sed -n 's/^CITADEL_WEBUI_TRANSPORT=//p' "$CONFIG_FILE" | tail -n 1)"
SOCKET="$(sed -n 's/^CITADEL_WEBUI_SOCKET=//p' "$CONFIG_FILE" | tail -n 1)"
RUNTIME_DIRECTORY=""

case "${TRANSPORT:-tcp}" in
    tcp) EXEC_START="$PYTHON_BIN $SCRIPT_DIR/webui.py" ;;
    unix)
        case "$SOCKET" in /*|%t/*) ;; *) echo "Invalid CITADEL_WEBUI_SOCKET: $SOCKET" >&2; exit 1 ;; esac
        EXEC_START="$PYTHON_BIN -m uvicorn webui:app --uds $SOCKET --proxy-headers --forwarded-allow-ips=*"
        RUNTIME_DIRECTORY="RuntimeDirectory=citadel"
        ;;
    *) echo "Invalid CITADEL_WEBUI_TRANSPORT: $TRANSPORT" >&2; exit 1 ;;
esac

mkdir -p "$LOCAL_UNIT_DIR"

cat > "$LOCAL_UNIT" <<EOF
[Unit]
Description=CITADEL baremetal service dashboard
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
$RUNTIME_DIRECTORY
ExecStart=$EXEC_START
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
