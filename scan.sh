#!/bin/bash
# scan.sh — port discovery + service probing + extension provider routing.

set -euo pipefail
umask 022

usage() {
    cat >&2 <<'EOF'
Usage: ./scan.sh [--add] [--provider PROVIDER_ID]
       ./scan.sh --del PORT

Without --provider, scan listeners and reconcile every enabled provider.
With --provider, scan listeners and reconcile only that provider.
With --add, probe only unknown ports and append routes without resetting any.
With --del PORT, delete only that port's Tailscale Serve route; do not scan.
EOF
}

PROVIDER_FILTER=""
DELETE_PORT=""
export CITADEL_SCAN_ADD=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --add) export CITADEL_SCAN_ADD=1; shift ;;
        --del)
            [[ $# -ge 2 && -z "$DELETE_PORT" && "$2" =~ ^[0-9]{1,5}$ ]] || { usage; exit 2; }
            DELETE_PORT="$2"
            shift 2
            ;;
        --provider)
            [[ $# -ge 2 && -n "$2" ]] || {
                usage
                exit 2
            }
            PROVIDER_FILTER="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done
[[ -z "$PROVIDER_FILTER" || "$PROVIDER_FILTER" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
    echo "Invalid provider ID: $PROVIDER_FILTER" >&2
    exit 2
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "$DELETE_PORT" ]]; then
    [[ "$CITADEL_SCAN_ADD" == 0 && -z "$PROVIDER_FILTER" ]] || { usage; exit 2; }
    exec python3 "$SCRIPT_DIR/functions/reset_serve.py" --del "$DELETE_PORT"
fi
CACHE_DIR="$SCRIPT_DIR/cache"
DATA_DIR="$SCRIPT_DIR/CITADEL_DATA"
ICONS_DIR="$DATA_DIR/icons"
FUNCTIONS_DIR="$SCRIPT_DIR/functions"
PROVIDERS_DIR="$FUNCTIONS_DIR/providers"
EXTENSIONS_DIR="$SCRIPT_DIR/extensions"
ENABLED_EXT_DIR="$EXTENSIONS_DIR/enabled"
CONFIG="$SCRIPT_DIR/config.ini"
SS_FILE="$DATA_DIR/ss.json"
SERVICES_FILE="$DATA_DIR/services.json"
TAILSCALE_FILE="$DATA_DIR/tailscale.json"
PORT_FILTER_FILE="$DATA_DIR/ports.filter.json"
PROVIDERS_STATE_FILE="$DATA_DIR/providers_state.json"
TIMESTAMP_FILE="$DATA_DIR/last_scan.txt"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}"
SCAN_LOCK_FILE="${CITADEL_SCAN_LOCK_FILE:-$RUNTIME_DIR/citadel-scan-${UID}.lock}"
REPORT_MAX_MB="$(PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'from python_header import get_int; print(get_int("CITADEL_REPORT_MAX_MB", 5))')"
[[ "$REPORT_MAX_MB" -gt 0 ]] || { echo "CITADEL_REPORT_MAX_MB must be positive" >&2; exit 2; }
MAX_FETCH_BYTES=$((REPORT_MAX_MB * 1048576))
BLACKLIST_STATUS="$(PYTHONPATH="$SCRIPT_DIR" python3 -c '
from python_header import get
codes = [code.strip() for code in (get("CITADEL_BLACKLIST_STATUS") or "404,502").split(",")]
if any(not code.isascii() or not code.isdigit() or len(code) != 3 or not 100 <= int(code) <= 599 for code in codes):
    raise SystemExit("CITADEL_BLACKLIST_STATUS requires comma-separated HTTP status codes (100–599)")
print("," + ",".join(codes) + ",")
')"

mkdir -p "$(dirname "$SCAN_LOCK_FILE")"
exec {SCAN_LOCK_FD}>"$SCAN_LOCK_FILE"
if flock --nonblock "$SCAN_LOCK_FD"; then
    :
else
    lock_status=$?
    if [[ "$lock_status" -eq 1 ]]; then
        echo "CITADEL scan already running; skipping duplicate request"
        exit 0
    fi
    echo "CITADEL scan lock failed (status=$lock_status)" >&2
    exit "$lock_status"
fi

mkdir -p \
    "$CACHE_DIR" "$ICONS_DIR" "$FUNCTIONS_DIR" "$PROVIDERS_DIR" \
    "$ENABLED_EXT_DIR"

CA_CERT=""
if [[ -f "$CONFIG" ]]; then
    CA_CERT="$(grep '^ca_cert' "$CONFIG" 2>/dev/null | cut -d= -f2 | xargs 2>/dev/null || true)"
fi

HTTPS_ONLY_VALUE="$(PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'from python_header import get; print(get("CITADEL_HTTPS_ONLY", "0"))')"
case "${HTTPS_ONLY_VALUE,,}" in
    1|true|yes|on) HTTPS_ONLY=true ;;
    *) HTTPS_ONLY=false ;;
esac
CITADEL_USER_AGENT_VALUE="$(PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'from python_header import get; print(get("CITADEL_USER_AGENT", ""))')"
case "${CITADEL_USER_AGENT_VALUE,,}" in
    blank|null) CITADEL_USER_AGENT_VALUE="" ;;
esac
CURL_USER_AGENT_ARGS=()
[[ -n "$CITADEL_USER_AGENT_VALUE" ]] && CURL_USER_AGENT_ARGS=(--user-agent "$CITADEL_USER_AGENT_VALUE")
CITADEL_PORT_VALUE="$(PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'from python_header import get; print(get("CITADEL_WEBUI_PORT", "11000"))')"
CITADEL_HIDE_HTTP_VALUE="$(PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'from python_header import get_bool; print(str(get_bool("CITADEL_HIDE_HTTP_WEBUI_DUPE", True)).lower())')"

LOGO_PERSISTENT_VALUE="$(PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'from python_header import get; print(get("CITADEL_LOGO_PERSISTENT", "1"))')"
LOGO_PERSISTENT=false
case "${LOGO_PERSISTENT_VALUE,,}" in 1|true|yes|on) LOGO_PERSISTENT=true ;; esac

HOST_IP="${CITADEL_SUBNET_IP:-}"
HOST_IP="${HOST_IP#"${HOST_IP%%[![:space:]]*}"}"
HOST_IP="${HOST_IP%"${HOST_IP##*[![:space:]]}"}"
case "${HOST_IP,,}" in
    ""|blank|null) HOST_IP="" ;;
esac
LOCAL_SSL="-k"
[[ -n "$CA_CERT" && -f "$CA_CERT" ]] && NET_SSL="--cacert $CA_CERT" || NET_SSL="-k"

echo "=== Scanning ports (ss -tlnHp) ==="
ss -tlnHp | python3 -c "
import json
import re
import socket
import sys

ss_file, providers_dir = sys.argv[1:3]
sys.path.insert(0, providers_dir)
from atomic_io import atomic_write_json

ports = {}
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    parts = line.split()
    if len(parts) < 4:
        continue

    local = parts[3]
    m = re.search(r':(\\d+)$', local)
    if not m:
        continue

    port = int(m.group(1))
    addr = local[:local.rfind(':')]
    process = None
    pid = None
    rest = ' '.join(parts[4:])
    pm = re.search(r'users:\\(\\(\\\"([^\\\"]+)\\\"', rest)
    if pm:
        process = pm.group(1)
    pid_match = re.search(r'\bpid=(\d+)', rest)
    if pid_match:
        pid = int(pid_match.group(1))
    try:
        service = socket.getservbyport(port, 'tcp')
    except OSError:
        service = None

    entry = ports.setdefault(port, {
        'port': port,
        'addr': addr,
        'addrs': [],
        'listeners': [],
        'process': process,
        'pid': pid,
        'service': service,
    })
    if addr not in entry['addrs']:
        entry['addrs'].append(addr)
    listener = {'addr': addr, 'process': process, 'pid': pid}
    if listener not in entry['listeners']:
        entry['listeners'].append(listener)
    if entry.get('process') == 'tailscaled' and process and process != 'tailscaled':
        entry['addr'] = addr
        entry['process'] = process
    if not entry.get('process') and process:
        entry['process'] = process
    if not entry.get('pid') and pid:
        entry['pid'] = pid

atomic_write_json(ss_file, [ports[port] for port in sorted(ports)])
" "$SS_FILE" "$PROVIDERS_DIR"
echo "Ports written to ss.json"
echo

echo "=== Applying Port Filter Policy ==="
python3 -c "
import json
import os
import sys

ss_file, filter_file, providers_dir = sys.argv[1:4]
sys.path.insert(0, providers_dir)
from atomic_io import atomic_write_json

try:
    ports = json.load(open(ss_file))
except Exception:
    ports = []
if not isinstance(ports, list):
    ports = []

created_default = False
if not os.path.exists(filter_file):
    created_default = True
    atomic_write_json(filter_file, {'whitelist': [], 'blacklist': [], 'cloudflare': {}})

try:
    policy = json.load(open(filter_file))
except Exception:
    policy = {}
if not isinstance(policy, dict):
    policy = {}

def parse_spec(values):
    out = set()
    if not isinstance(values, list):
        return out
    for item in values:
        if isinstance(item, int):
            if item > 0:
                out.add(item)
            continue
        s = str(item).strip()
        if not s:
            continue
        if '-' in s:
            a, b = s.split('-', 1)
            try:
                x = int(a.strip())
                y = int(b.strip())
            except Exception:
                continue
            if x <= 0 or y <= 0:
                continue
            lo, hi = (x, y) if x <= y else (y, x)
            out.update(range(lo, hi + 1))
            continue
        try:
            p = int(s)
        except Exception:
            continue
        if p > 0:
            out.add(p)
    return out

whitelist = parse_spec(policy.get('whitelist', []))
blacklist = parse_spec(policy.get('blacklist', []))

mode = 'whitelist' if whitelist else ('blacklist' if blacklist else 'none')

filtered = []
dropped = []
for row in ports:
    if not isinstance(row, dict):
        continue
    port = row.get('port')
    if not isinstance(port, int) or port <= 0:
        continue
    if whitelist:
        allowed = (port in whitelist)
    else:
        allowed = (port not in blacklist)
    if allowed:
        filtered.append(row)
    else:
        dropped.append(port)

atomic_write_json(ss_file, sorted(filtered, key=lambda x: x.get('port', 0)))

if created_default:
    print(f'created default policy: {filter_file}')
print(f'policy mode: {mode} (whitelist={len(whitelist)} blacklist={len(blacklist)})')
print(f'ports kept: {len(filtered)}/{len(ports)}')
if dropped:
    uniq = sorted(set(dropped))
    print('dropped ports: ' + ', '.join(str(x) for x in uniq))
" "$SS_FILE" "$PORT_FILTER_FILE" "$PROVIDERS_DIR"
echo

body_is_html() {
    local url="$1" ssl="$2"
    local body
    body="$(curl -s "${CURL_USER_AGENT_ARGS[@]}" $ssl --max-time 3 --location -o - "$url" 2>/dev/null | head -c 8192)" || true
    if echo "$body" | grep -qi "<html" 2>/dev/null; then
        return 0
    fi
    return 1
}

is_openai_v1() {
    local url="$1" ssl="$2" body status
    body="$(mktemp)"
    status="$(curl -s "${CURL_USER_AGENT_ARGS[@]}" $ssl --max-time 3 -o "$body" -w "%{http_code}" "${url}/v1/models" 2>/dev/null || echo 000)"
    if [[ "$status" != "000" ]] && python3 - "$body" <<'PY'
import json
import sys

try:
    payload = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if isinstance(payload, dict) and ("data" in payload or "error" in payload) else 1)
PY
    then
        rm -f "$body"
        return 0
    fi
    rm -f "$body"
    return 1
}

root_http_status() {
    local url="$1" ssl="$2" body status
    body="$(mktemp)"
    status="$(curl -s "${CURL_USER_AGENT_ARGS[@]}" $ssl --max-time 3 \
        --max-filesize "$MAX_FETCH_BYTES" -o "$body" -w "%{http_code}" "$url/" 2>/dev/null || true)"
    # Go/Caddy rejects plaintext on a TLS listener with an HTTP 400 response.
    # That response must never turn an HTTPS-only listener into an HTTP route.
    if [[ "$url" == http://* && "$status" == "400" ]] && \
        grep -Fqi "Client sent an HTTP request to an HTTPS server" "$body"; then
        status=""
    fi
    rm -f "$body"
    printf '%s' "$status"
}

is_discoverable_status() {
    [[ "$1" =~ ^[1-5][0-9][0-9]$ && "$BLACKLIST_STATUS" != *",$1,"* ]]
}

probe_http() {
    local host="$1" port="$2" status url ssl
    [[ "$host" == "127.0.0.1" ]] && ssl="$LOCAL_SSL" || ssl="$NET_SSL"
    url="https://${host}:${port}"
    status="$(root_http_status "$url" "$ssl")"
    [[ -z "$status" || "$BLACKLIST_STATUS" != *",$status,"* ]] || return 0
    if ! is_discoverable_status "$status"; then
        url="http://${host}:${port}"
        status="$(root_http_status "$url" "$ssl")"
        is_discoverable_status "$status" || return 0
    fi
    if body_is_html "$url/" "$ssl"; then
        echo "$url|html"
    elif is_openai_v1 "$url" "$ssl"; then
        echo "$url|openai-v1"
    else
        echo "$url|http-service"
    fi
}

try_fetch_icon() {
    local url="$1" port="$2" ssl="$3"
    local tmp result status content_type ext size
    tmp="$(mktemp "$ICONS_DIR/${port}.XXXXXX")"
    if ! result="$(curl -sS "${CURL_USER_AGENT_ARGS[@]}" $ssl --max-time 5 --max-filesize "$MAX_FETCH_BYTES" \
        -o "$tmp" -w $'%{http_code}\t%{content_type}' "$url" 2>/dev/null)"; then
        rm -f "$tmp"
        echo ""
        return
    fi
    status="${result%%$'\t'*}"
    content_type="${result#*$'\t'}"
    size="$(stat -c %s "$tmp" 2>/dev/null || echo 0)"
    ext="$(PYTHONPATH="$FUNCTIONS_DIR" python3 -c \
        'from favicon_policy import icon_extension; import sys; print(icon_extension(sys.argv[1]))' \
        "$content_type")"
    if [[ "$status" == "200" && -n "$ext" && -s "$tmp" && "$size" -le "$MAX_FETCH_BYTES" ]]; then
        local dest="$ICONS_DIR/${port}${ext}"
        mv "$tmp" "$dest"
        chmod 644 "$dest"
        # A refreshed logo replaces all older formats for this exact port.
        local old_icon
        for old_icon in "$ICONS_DIR/$port".{png,svg,webp,gif,ico}; do
            [[ "$old_icon" == "$dest" ]] || rm -f -- "$old_icon"
        done
        echo "${port}${ext}"
    else
        rm -f "$tmp"
        echo ""
    fi
}

echo "=== Probing ports for HTTP/HTTPS ==="

if [[ "$CITADEL_SCAN_ADD" == 1 ]]; then
    PENDING_ADD="$(python3 "$FUNCTIONS_DIR/scan_add.py" "$SS_FILE" "$SERVICES_FILE")"
    if [[ "$PENDING_ADD" == 0 && "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$SS_FILE")" == 0 ]]; then
        echo "Add: no new listening ports; existing routes untouched"
        exit 0
    fi
fi

python3 -c "
import json
import sys
for p in json.load(open(sys.argv[1])):
    print(p['port'])
" "$SS_FILE" | while read -r PORT; do
    printf "Port %-6s " "$PORT"
    CACHE_FILE="$CACHE_DIR/${PORT}.json"

    LOCAL_PROBE="$(probe_http "127.0.0.1" "$PORT")"
    if [[ -z "$LOCAL_PROBE" ]]; then
        if [[ -f "$CACHE_FILE" ]]; then
            python3 -c "
import json
import sys
f, providers_dir = sys.argv[1:3]
sys.path.insert(0, providers_dir)
from atomic_io import atomic_write_json
d = {'scheme': None, 'network_ip': None, 'title': None, 'icon': None}
atomic_write_json(f, d)
" "$CACHE_FILE" "$PROVIDERS_DIR"
        fi
        echo "→ no HTTP service (other)"
        continue
    fi

    LOCAL_URL="${LOCAL_PROBE%%|*}"
    PROBE_KIND="${LOCAL_PROBE##*|}"
    SCHEME="${LOCAL_URL%%://*}"

    NETWORK_IP=""
    if [[ -n "$HOST_IP" ]]; then
        NET_URL="$(probe_http "$HOST_IP" "$PORT")"
        [[ -n "$NET_URL" ]] && NETWORK_IP="$HOST_IP"
    fi

    NET_LABEL=""
    [[ -n "$NETWORK_IP" ]] && NET_LABEL=" [+net ${NETWORK_IP}]"

    if [[ "$PROBE_KIND" == "openai-v1" ]]; then
        python3 -c "
import sys
sys.path.insert(0, sys.argv[5])
from atomic_io import atomic_write_json
atomic_write_json(sys.argv[4], {
        'title': 'OpenAI v1 API',
        'icon': None,
        'scheme': sys.argv[1],
        'network_ip': sys.argv[2] or None,
        'kind': sys.argv[3],
    })
" "$SCHEME" "$NETWORK_IP" "$PROBE_KIND" "$CACHE_FILE" "$PROVIDERS_DIR"
        printf "%s     OpenAI v1 API%s\n" "$SCHEME" "$NET_LABEL"
        continue
    fi

    if [[ "$PROBE_KIND" == "http-service" ]]; then
        python3 -c "
import sys
sys.path.insert(0, sys.argv[6])
from atomic_io import atomic_write_json
atomic_write_json(sys.argv[5], {
        'title': sys.argv[1],
        'icon': None,
        'scheme': sys.argv[2],
        'network_ip': sys.argv[3] or None,
        'kind': sys.argv[4],
    })
" "HTTP Service" "$SCHEME" "$NETWORK_IP" "$PROBE_KIND" "$CACHE_FILE" "$PROVIDERS_DIR"
        printf "%s     HTTP service%s\n" "$SCHEME" "$NET_LABEL"
        continue
    fi

    printf "%-8s fetching title+icons..." "$SCHEME"

    TMP_HTML="$(mktemp)"
    if ! EFFECTIVE_URL="$(curl -sS "${CURL_USER_AGENT_ARGS[@]}" $LOCAL_SSL --max-time 5 --max-filesize "$MAX_FETCH_BYTES" \
        --location "$LOCAL_URL/" -o "$TMP_HTML" -w "%{url_effective}" 2>/dev/null)"; then
        EFFECTIVE_URL="$LOCAL_URL/"
        : > "$TMP_HTML"
    fi
    HTML="$(cat "$TMP_HTML")"
    rm -f "$TMP_HTML"
    BROWSER_PAGE="$(printf '%s' "$HTML" | PYTHONPATH="$FUNCTIONS_DIR" python3 -c \
        'import sys; from scan_policy import is_browser_page; print(int(is_browser_page(sys.stdin.read())))')"
    TITLE="$(echo "$HTML" | python3 -c "
import re
import sys
html = sys.stdin.read()
m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
from html import unescape
print(unescape(m.group(1).strip()) if m else '')
" || true)"

    FAVICON_CANDIDATES="$(echo "$HTML" | python3 -c '
import re
import sys
html = sys.stdin.read()
candidates = []
for tag in re.finditer(r"<link([^>]+)>", html, re.IGNORECASE):
    attrs = tag.group(1)
    rel_m = re.search(r"rel=[\"'"'"'](.*?)[\"'"'"']", attrs, re.IGNORECASE)
    href_m = re.search(r"href=[\"'"'"'](.*?)[\"'"'"']", attrs, re.IGNORECASE)
    if rel_m and href_m and "icon" in rel_m.group(1).lower():
        href = href_m.group(1).strip()
        priority = 0 if any(x in href.lower() for x in [".png", ".svg", ".webp"]) else 1
        candidates.append((priority, href))
candidates.sort(key=lambda x: x[0])
for _, href in candidates:
    print(href)
' || true)"

    mapfile -t ICON_URLS < <(
        printf '%s\n' "$FAVICON_CANDIDATES" |
            PYTHONPATH="$FUNCTIONS_DIR" python3 -c '
import sys
from favicon_policy import safe_icon_urls

for url in safe_icon_urls(sys.argv[1], sys.argv[2], list(sys.stdin)):
    print(url)
' "$LOCAL_URL" "$EFFECTIVE_URL"
    )

    ICON_URLS+=("${LOCAL_URL}/favicon.png")
    ICON_URLS+=("${LOCAL_URL}/favicon.ico")
    ICON_URLS+=("${LOCAL_URL}/apple-touch-icon.png")

    ICON_NAME=""
    if "$LOGO_PERSISTENT"; then
        ICON_NAME="$(PYTHONPATH="$FUNCTIONS_DIR" python3 -c \
            'from scan_policy import existing_icon; import sys; print(existing_icon(sys.argv[1], int(sys.argv[2])))' \
            "$ICONS_DIR" "$PORT")"
    fi
    if [[ -z "$ICON_NAME" ]]; then
        for FAVICON_URL in "${ICON_URLS[@]}"; do
            ICON_NAME="$(try_fetch_icon "$FAVICON_URL" "$PORT" "$LOCAL_SSL")"
            [[ -n "$ICON_NAME" ]] && break
        done
    fi

    python3 -c "
import sys
sys.path.insert(0, sys.argv[6])
from atomic_io import atomic_write_json
atomic_write_json(sys.argv[5], {
        'title': sys.argv[1],
        'icon': sys.argv[2] or None,
        'scheme': sys.argv[3],
        'network_ip': sys.argv[4] or None,
        'kind': 'html',
        'browser_page': sys.argv[7] == '1',
    })
" "$TITLE" "$ICON_NAME" "$SCHEME" "$NETWORK_IP" "$CACHE_FILE" "$PROVIDERS_DIR" "$BROWSER_PAGE"

    printf " %-20s" "${ICON_NAME:-(no icon)}"
    [[ -n "$TITLE" ]] && echo "\"$TITLE\"${NET_LABEL}" || echo "(no title)${NET_LABEL}"
done

echo "=== Building services.json ==="
python3 -c "
import datetime
import json
import os
import sys

(
    ss_file,
    cache_dir,
    icons_dir,
    out_file,
    providers_dir,
    https_only_raw,
) = sys.argv[1:7]
sys.path.insert(0, providers_dir)
from atomic_io import atomic_write_json

with open(ss_file) as handle:
    ss_raw = json.load(handle)
if not isinstance(ss_raw, list):
    raise ValueError('invalid listener inventory')

# Discovery metadata is disposable; retained logos live separately in icons/.
active_ports = {str(row['port']) for row in ss_raw}
for entry in os.scandir(cache_dir):
    stem, suffix = os.path.splitext(entry.name)
    if os.environ.get('CITADEL_SCAN_ADD') != '1' and suffix == '.json' and stem.isdigit() and stem not in active_ports:
        os.unlink(entry.path)

http_services = []
other_ports = []
icon_exts = ('png', 'svg', 'webp', 'gif', 'ico')

for p in ss_raw:
    port = p.get('port')
    cache_file = os.path.join(cache_dir, f'{port}.json')
    c = {}
    if os.path.exists(cache_file):
        try:
            c = json.load(open(cache_file))
        except Exception:
            c = {}

    raw_scheme = c.get('scheme')
    if isinstance(raw_scheme, str):
        scheme = raw_scheme.strip().lower()
    else:
        scheme = None
    if scheme not in ('http', 'https'):
        scheme = None
    title = c.get('title') or None

    icon = None
    icon_name = c.get('icon')
    if icon_name and os.path.exists(os.path.join(icons_dir, icon_name)):
        icon = f'icons/{icon_name}'
    else:
        for ext in icon_exts:
            candidate = f'{port}.{ext}'
            if os.path.exists(os.path.join(icons_dir, candidate)):
                icon = f'icons/{candidate}'
                break

    if scheme:
        display_name = title or f'Port {port}'
        http_services.append({
            'port': port,
            'addr': p.get('addr'),
            'addrs': p.get('addrs') or ([p.get('addr')] if p.get('addr') else []),
            'listeners': p.get('listeners') or [],
            'process': p.get('process'),
            'service': p.get('service'),
            'title': title,
            'name': display_name,
            'icon': icon,
            'scheme': scheme,
            'network_ip': c.get('network_ip'),
            'urls': (
                {'localhost': f'{scheme}://127.0.0.1:{port}'}
                if https_only_raw != 'true' or scheme == 'https'
                else {}
            ),
        })
    else:
        other_ports.append({
            'port': port,
            'addr': p.get('addr'),
            'addrs': p.get('addrs') or ([p.get('addr')] if p.get('addr') else []),
            'listeners': p.get('listeners') or [],
            'process': p.get('process'),
            'service': p.get('service'),
        })

payload = {
    'generated_at': datetime.datetime.now().isoformat(timespec='seconds'),
    'https_only': https_only_raw == 'true',
    'http_services': http_services,
    'other_ports': other_ports,
}
if os.environ.get('CITADEL_SCAN_ADD') == '1':
    from pathlib import Path
    sys.path.insert(0, str(Path(providers_dir).parent))
    from scan_add import merge_services
    payload = merge_services(Path(out_file), payload)
atomic_write_json(out_file, payload, indent=None)
" "$SS_FILE" "$CACHE_DIR" "$ICONS_DIR" "$SERVICES_FILE" "$PROVIDERS_DIR" "$HTTPS_ONLY"
echo "services.json written"
echo

# Hide only the duplicate WebUI tile; retain its backend for route providers.
# Match this running instance, never a different container's Citadel by title.
if [[ "$CITADEL_SCAN_ADD" != 1 ]]; then
python3 "$FUNCTIONS_DIR/scan_policy.py" \
    --services "$SERVICES_FILE" \
    --http-port "$CITADEL_PORT_VALUE" \
    --hide-http "$CITADEL_HIDE_HTTP_VALUE" \
    --user-agent "$CITADEL_USER_AGENT_VALUE"
fi

if [[ -z "$PROVIDER_FILTER" ]]; then
    echo "=== Applying Cloudflare Defaults ==="
    if [[ -f "$FUNCTIONS_DIR/cloudflare_defaults.py" ]]; then
        python3 "$FUNCTIONS_DIR/cloudflare_defaults.py" \
            --root "$SCRIPT_DIR" \
            --services-file "$SERVICES_FILE" \
            --policy-file "$PORT_FILTER_FILE" || true
    else
        echo "cloudflare_defaults.py missing: $FUNCTIONS_DIR/cloudflare_defaults.py"
    fi
    echo
else
    echo "=== Cloudflare Defaults Skipped (provider=$PROVIDER_FILTER) ==="
    echo
fi

echo "=== Applying Enabled Extensions ==="
if [[ -f "$PROVIDERS_DIR/dispatch.py" ]]; then
    if [[ -n "$PROVIDER_FILTER" ]]; then
        python3 "$PROVIDERS_DIR/dispatch.py" \
            --enabled-dir "$ENABLED_EXT_DIR" \
            --services-file "$SERVICES_FILE" \
            --cache-dir "$CACHE_DIR" \
            --config-ini "$CONFIG" \
            --state-file "$PROVIDERS_STATE_FILE" \
            --tailscale-file "$TAILSCALE_FILE" \
            --provider "$PROVIDER_FILTER" \
            --strict
    else
        python3 "$PROVIDERS_DIR/dispatch.py" \
            --enabled-dir "$ENABLED_EXT_DIR" \
            --services-file "$SERVICES_FILE" \
            --cache-dir "$CACHE_DIR" \
            --config-ini "$CONFIG" \
            --state-file "$PROVIDERS_STATE_FILE" \
            --tailscale-file "$TAILSCALE_FILE" \
            --strict
    fi
else
    echo "dispatch.py missing: $PROVIDERS_DIR/dispatch.py"
    [[ -z "$PROVIDER_FILTER" ]] || exit 1
fi
echo

date '+%Y-%m-%d %H:%M:%S' > "$TIMESTAMP_FILE"
if [[ "$CITADEL_SCAN_ADD" == 1 ]]; then
    PYTHONPATH="$PROVIDERS_DIR" python3 - "$SERVICES_FILE" <<'PY'
import json
import sys
from atomic_io import atomic_write_json
with open(sys.argv[1]) as handle:
    payload = json.load(handle)
payload.pop("pending_add_ports", None)
atomic_write_json(sys.argv[1], payload)
PY
fi
echo "=== Done: $(cat "$TIMESTAMP_FILE") ==="
