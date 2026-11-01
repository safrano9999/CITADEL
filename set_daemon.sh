#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f -- "${BASH_SOURCE[0]}")")"
UNIT_NAME="citadel.service"
RENDER_ONLY=false

case "${1:-}" in
    "") ;;
    --render-only) RENDER_ONLY=true ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
esac

LOCAL_UNIT_DIR="$SCRIPT_DIR"
LOCAL_UNIT="$LOCAL_UNIT_DIR/$UNIT_NAME"
USER_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
USER_UNIT="$USER_UNIT_DIR/$UNIT_NAME"
# Do not accidentally capture an activated virtual environment from PATH.
PYTHON_BIN="$(command -v "${PYTHON_BIN:-/usr/bin/python3}")"
# webui.py resolves TCP/Unix from the loaded configuration at each start, just
# as it does outside systemd. Rendering needs no config parsing or socket setup.
# python_header reads this directory's config.conf and .env directly. Do not
# copy them or inject FASTAPI_HOST: injection intentionally changes the bind.
EXEC_START="$PYTHON_BIN -E $SCRIPT_DIR/webui.py"

if ! "$RENDER_ONLY"; then
    "$PYTHON_BIN" -E -c 'import dotenv, fastapi, jinja2, uvicorn' || {
        echo "Install CITADEL's system Python dependencies before installing the service (see README)." >&2
        exit 1
    }
fi

mkdir -p "$LOCAL_UNIT_DIR"

cat > "$LOCAL_UNIT" <<EOF
[Unit]
Description=CITADEL baremetal service dashboard
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
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
systemctl --user enable "$UNIT_NAME"
systemctl --user restart "$UNIT_NAME"

if command -v loginctl >/dev/null 2>&1 && [[ -n "${USER:-}" ]]; then
    if [[ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || true)" != "yes" ]]; then
        loginctl enable-linger "$USER" 2>/dev/null || true
    fi
fi

systemctl --user --no-pager --full status "$UNIT_NAME" --lines=5 || true
