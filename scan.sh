#!/bin/bash
# scan.sh — port discovery + service probing + extension provider routing.

set -euo pipefail
umask 022

usage() {
    cat >&2 <<'EOF'
Usage: ./scan.sh [--provider PROVIDER_ID]

Without --provider, scan listeners and reconcile every enabled provider.
With --provider, scan listeners and reconcile only that provider.
EOF
}

PROVIDER_FILTER=""
while [[ $# -gt 0 ]]; do
    case "$1" in
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
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
CACHE_DIR="$SCRIPT_DIR/cache"
ICONS_DIR="$SCRIPT_DIR/icons"
FUNCTIONS_DIR="$SCRIPT_DIR/functions"
PROVIDERS_DIR="$FUNCTIONS_DIR/providers"
EXTENSIONS_DIR="$SCRIPT_DIR/extensions"
ENABLED_EXT_DIR="$EXTENSIONS_DIR/enabled"
CONFIG="$SCRIPT_DIR/config.ini"
SS_FILE="$SCRIPT_DIR/ss.json"
HOST_SS_FILE="$SCRIPT_DIR/host_ss.json"
HOST_SERVICES_FILE="$SCRIPT_DIR/host_services.json"
SERVICES_FILE="$SCRIPT_DIR/services.json"
TAILSCALE_FILE="$SCRIPT_DIR/tailscale.json"
CONTAINER_ROUTES_FILE="$SCRIPT_DIR/container_routes.json"
PORT_FILTER_FILE="$SCRIPT_DIR/ports.filter.json"
PROVIDERS_STATE_FILE="$EXTENSIONS_DIR/providers_state.json"
TIMESTAMP_FILE="$SCRIPT_DIR/last_scan.txt"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}"
SCAN_LOCK_FILE="${CITADEL_SCAN_LOCK_FILE:-$RUNTIME_DIR/citadel-scan-${UID}.lock}"
SCAN_LOCK_TIMEOUT="${CITADEL_SCAN_LOCK_TIMEOUT:-300}"
MAX_FETCH_BYTES=1048576

if [[ "${CITADEL_SCAN_LOCK_HELD:-0}" != "1" ]]; then
    [[ "$SCAN_LOCK_TIMEOUT" =~ ^[0-9]+$ ]] || {
        echo "CITADEL_SCAN_LOCK_TIMEOUT must be a non-negative integer" >&2
        exit 2
    }
    mkdir -p "$(dirname "$SCAN_LOCK_FILE")"
    scan_arguments=()
    [[ -z "$PROVIDER_FILTER" ]] ||
        scan_arguments=(--provider "$PROVIDER_FILTER")
    exec flock \
        --wait "$SCAN_LOCK_TIMEOUT" \
        "$SCAN_LOCK_FILE" \
        env CITADEL_SCAN_LOCK_HELD=1 "$SCRIPT_PATH" \
        "${scan_arguments[@]}"
fi

mkdir -p "$CACHE_DIR" "$ICONS_DIR" "$FUNCTIONS_DIR" "$PROVIDERS_DIR" "$ENABLED_EXT_DIR"

CA_CERT=""
if [[ -f "$CONFIG" ]]; then
    CA_CERT="$(grep '^ca_cert' "$CONFIG" 2>/dev/null | cut -d= -f2 | xargs 2>/dev/null || true)"
fi

HOST_IP="${CITADEL_SUBNET_IP:-}"
CONTAINER_MODE="${CITADEL_CONTAINER:-0}"
CONTAINER_MAP="${CITADEL_CONTAINER_MAP:-0}"
DEDUPE_PORT="${CITADEL_DEDUPE_PORT:-}"
case "${CONTAINER_MODE,,}" in
    1|true|yes|on) CONTAINER_MODE=true ;;
    *) CONTAINER_MODE=false ;;
esac
case "${CONTAINER_MAP,,}" in
    1|true|yes|on) CONTAINER_MAP=true ;;
    *) CONTAINER_MAP=false ;;
esac
if ! "$CONTAINER_MODE"; then
    CONTAINER_MAP=false
fi
case "${DEDUPE_PORT,,}" in
    ""|blank|null) DEDUPE_PORT="" ;;
esac
if "$CONTAINER_MAP" && [[ -n "$DEDUPE_PORT" ]] && { [[ ! "$DEDUPE_PORT" =~ ^[0-9]+$ ]] || (( DEDUPE_PORT < 1 || DEDUPE_PORT > 65535 )); }; then
    echo "CITADEL_DEDUPE_PORT must be blank or a port between 1 and 65535" >&2
    exit 2
fi

LOCAL_SSL="-k"
[[ -n "$CA_CERT" && -f "$CA_CERT" ]] && NET_SSL="--cacert $CA_CERT" || NET_SSL="-k"

echo "=== Scanning ports (ss -tlnHp) ==="
ss -tlnHp | python3 -c "
import json
import os
import re
import socket
import sys

old_procs = {}
ss_file, providers_dir = sys.argv[1:3]
sys.path.insert(0, providers_dir)
from atomic_io import atomic_write_json
if os.path.exists(ss_file):
    try:
        old = json.load(open(ss_file))
        old_procs = {p['port']: p.get('process') for p in old if p.get('process')}
    except Exception:
        pass

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
    rest = ' '.join(parts[4:])
    pm = re.search(r'users:\\(\\(\\\"([^\\\"]+)\\\"', rest)
    if pm:
        process = pm.group(1)
    if not process and port in old_procs:
        process = old_procs[port]

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
        'service': service,
    })
    if addr not in entry['addrs']:
        entry['addrs'].append(addr)
    listener = {'addr': addr, 'process': process}
    if listener not in entry['listeners']:
        entry['listeners'].append(listener)
    if entry.get('process') == 'tailscaled' and process and process != 'tailscaled':
        entry['addr'] = addr
        entry['process'] = process
    if not entry.get('process') and process:
        entry['process'] = process

atomic_write_json(ss_file, [ports[port] for port in sorted(ports)])
" "$SS_FILE" "$PROVIDERS_DIR"
echo "Ports written to ss.json"
echo

if "$CONTAINER_MODE"; then
    command -v nmap >/dev/null 2>&1 || {
        echo "CITADEL_CONTAINER=1 requires nmap" >&2
        exit 2
    }
    echo "=== Scanning host.containers.internal listeners with Nmap ==="
    HOST_NMAP_FILE="$(mktemp)"
    nmap -Pn -n -sT -sV --version-light -p- --open --stats-every 15s \
        -oN /dev/null -oX "$HOST_NMAP_FILE" host.containers.internal |
        awk '/^Stats:/ || /Timing: About/ { print; fflush() }'
    PYTHONPATH="$FUNCTIONS_DIR:$PROVIDERS_DIR" python3 -c '
import sys
from pathlib import Path
from atomic_io import atomic_write_json
from container_discovery import parse_nmap_listeners

atomic_write_json(
    sys.argv[2],
    parse_nmap_listeners(Path(sys.argv[1]), "host.containers.internal"),
)
' "$HOST_NMAP_FILE" "$HOST_SS_FILE"
    rm -f "$HOST_NMAP_FILE"
    echo "Host listeners written to host_ss.json"
    echo
fi

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
    body="$(curl -s $ssl --max-time 3 --location -o - "$url" 2>/dev/null | head -c 8192)" || true
    if echo "$body" | grep -qi "<html" 2>/dev/null; then
        return 0
    fi
    return 1
}

is_openai_v1() {
    local url="$1" ssl="$2" body status
    body="$(mktemp)"
    status="$(curl -s $ssl --max-time 3 -o "$body" -w "%{http_code}" "${url}/v1/models" 2>/dev/null || echo 000)"
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

is_http_service() {
    local url="$1" ssl="$2" status
    status="$(curl -s $ssl --max-time 3 -o /dev/null -w "%{http_code}" "$url/" 2>/dev/null || true)"
    [[ "$status" =~ ^[1-5][0-9][0-9]$ ]]
}

probe_http() {
    local host="$1" port="$2"
    local ssl
    [[ "$host" == "127.0.0.1" ]] && ssl="$LOCAL_SSL" || ssl="$NET_SSL"
    if body_is_html "https://${host}:${port}/" "$ssl"; then
        echo "https://${host}:${port}|html"
    elif body_is_html "http://${host}:${port}/" "$ssl"; then
        echo "http://${host}:${port}|html"
    elif is_openai_v1 "https://${host}:${port}" "$ssl"; then
        echo "https://${host}:${port}|openai-v1"
    elif is_openai_v1 "http://${host}:${port}" "$ssl"; then
        echo "http://${host}:${port}|openai-v1"
    elif is_http_service "https://${host}:${port}" "$ssl"; then
        echo "https://${host}:${port}|http-service"
    elif is_http_service "http://${host}:${port}" "$ssl"; then
        echo "http://${host}:${port}|http-service"
    else
        echo ""
    fi
}

try_fetch_icon() {
    local url="$1" port="$2" ssl="$3"
    local tmp result status content_type ext size
    tmp="$(mktemp "$ICONS_DIR/${port}.XXXXXX")"
    if ! result="$(curl -sS $ssl --max-time 5 --max-filesize "$MAX_FETCH_BYTES" \
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
        echo "${port}${ext}"
    else
        rm -f "$tmp"
        echo ""
    fi
}

echo "=== Probing ports for HTTP/HTTPS ==="

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
try:
    d = json.load(open(f))
except Exception:
    d = {}
d['scheme'] = None
d['network_ip'] = None
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

    if [[ -f "$CACHE_FILE" ]]; then
        IFS=$'\t' read -r EXISTING_TITLE EXISTING_ICON < <(python3 -c "
import json
import sys
try:
    d = json.load(open(sys.argv[1]))
    print((d.get('title') or '') + '\\t' + (d.get('icon') or ''))
except Exception:
    print('\\t')
" "$CACHE_FILE" 2>/dev/null || printf '\t\n')

        ICON_ON_DISK=false
        [[ -n "$EXISTING_ICON" && -f "$ICONS_DIR/$EXISTING_ICON" ]] && ICON_ON_DISK=true

        if [[ -n "$EXISTING_TITLE" ]] && $ICON_ON_DISK; then
            python3 -c "
import json
import sys
f, providers_dir = sys.argv[1], sys.argv[4]
sys.path.insert(0, providers_dir)
from atomic_io import atomic_write_json
try:
    d = json.load(open(f))
except Exception:
    d = {}
d['scheme'] = sys.argv[2]
d['network_ip'] = sys.argv[3] or None
d['kind'] = 'html'
atomic_write_json(f, d)
" "$CACHE_FILE" "$SCHEME" "$NETWORK_IP" "$PROVIDERS_DIR"
            printf "%-8s cached: \"%s\"%s\n" "$SCHEME" "$EXISTING_TITLE" "$NET_LABEL"
            continue
        fi
    fi

    printf "%-8s fetching title+icons..." "$SCHEME"

    TMP_HTML="$(mktemp)"
    if ! EFFECTIVE_URL="$(curl -sS $LOCAL_SSL --max-time 5 --max-filesize "$MAX_FETCH_BYTES" \
        --location "$LOCAL_URL/" -o "$TMP_HTML" -w "%{url_effective}" 2>/dev/null)"; then
        EFFECTIVE_URL="$LOCAL_URL/"
        : > "$TMP_HTML"
    fi
    HTML="$(cat "$TMP_HTML")"
    rm -f "$TMP_HTML"
    TITLE="$(echo "$HTML" | python3 -c "
import re
import sys
html = sys.stdin.read()
m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
print(m.group(1).strip() if m else '')
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

    rm -f "$ICONS_DIR/${PORT}".*

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
    for FAVICON_URL in "${ICON_URLS[@]}"; do
        ICON_NAME="$(try_fetch_icon "$FAVICON_URL" "$PORT" "$LOCAL_SSL")"
        [[ -n "$ICON_NAME" ]] && break
    done

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
    })
" "$TITLE" "$ICON_NAME" "$SCHEME" "$NETWORK_IP" "$CACHE_FILE" "$PROVIDERS_DIR"

    printf " %-20s" "${ICON_NAME:-(no icon)}"
    [[ -n "$TITLE" ]] && echo "\"$TITLE\"${NET_LABEL}" || echo "(no title)${NET_LABEL}"
done

HOST_RESULTS_FILE=""
if "$CONTAINER_MODE"; then
    HOST_RESULTS_FILE="$(mktemp)"
    echo "=== Probing host.containers.internal listeners ==="
    python3 -c '
import json
import sys
for row in json.load(open(sys.argv[1], encoding="utf-8")):
    print(row["port"])
' "$HOST_SS_FILE" | while read -r PORT; do
        printf "Host port %-6s " "$PORT"
        HOST_PROBE="$(probe_http "host.containers.internal" "$PORT")"
        TITLE=""
        if [[ -n "$HOST_PROBE" ]]; then
            HOST_URL="${HOST_PROBE%%|*}"
            HOST_KIND="${HOST_PROBE##*|}"
            HOST_SCHEME="${HOST_URL%%://*}"
            if [[ "$HOST_KIND" == "openai-v1" ]]; then
                TITLE="OpenAI v1 API"
            elif [[ "$HOST_KIND" == "http-service" ]]; then
                TITLE="HTTP Service"
            else
                HOST_HTML="$(curl -sS $NET_SSL --max-time 5 --max-filesize "$MAX_FETCH_BYTES" \
                    --location "$HOST_URL/" 2>/dev/null || true)"
                TITLE="$(printf '%s' "$HOST_HTML" | python3 -c '
import re
import sys
html = sys.stdin.read()
match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
print(match.group(1).strip() if match else "")
')"
            fi
            python3 -c '
import json
import sys
print(json.dumps({
    "port": int(sys.argv[1]),
    "scheme": sys.argv[2],
    "kind": sys.argv[3],
    "title": sys.argv[4] or None,
}))
' "$PORT" "$HOST_SCHEME" "$HOST_KIND" "$TITLE" >> "$HOST_RESULTS_FILE"
            printf "%-8s %s\n" "$HOST_SCHEME" "${TITLE:-(no title)}"
        else
            python3 -c '
import json
import sys
print(json.dumps({"port": int(sys.argv[1]), "scheme": None, "kind": None, "title": None}))
' "$PORT" >> "$HOST_RESULTS_FILE"
            echo "→ no HTTP service (other)"
        fi
    done
fi

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
    container_mode_raw,
    host_ss_file,
    host_results_file,
    container_map_raw,
    dedupe_raw,
    container_routes_file,
    host_services_file,
) = sys.argv[1:13]
sys.path.insert(0, providers_dir)
from atomic_io import atomic_write_json
sys.path.insert(0, os.path.dirname(providers_dir))
from container_discovery import assign_host_route_ports

def int_or_none(value):
    try:
        port = int(str(value).strip())
    except Exception:
        return None
    return port if port > 0 else None

def publish_port_for(port):
    for key, value in os.environ.items():
        if not key.endswith('_PORT') or key.endswith('_PUBLISH_PORT'):
            continue
        if int_or_none(value) != port:
            continue
        publish_key = f'{key[:-5]}_PUBLISH_PORT'
        publish_port = int_or_none(os.environ.get(publish_key))
        if publish_port:
            return publish_port
    return port

try:
    ss_raw = json.load(open(ss_file))
except Exception:
    ss_raw = []

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
        publish_port = publish_port_for(port)
        display_name = title or f'Port {port}'
        http_services.append({
            'port': port,
            'publish_port': publish_port if publish_port != port else None,
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
            'urls': {
                'localhost': f'{scheme}://127.0.0.1:{publish_port}',
            },
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
    'http_services': http_services,
    'other_ports': other_ports,
    'host_http_services': [],
    'host_other_ports': [],
    'deduplicated_ports': [],
}
host_payload = {
    'generated_at': payload['generated_at'],
    'host_http_services': [],
    'host_other_ports': [],
    'deduplicated_ports': [],
    'errors': [],
}

if container_mode_raw == 'true':
    try:
        host_rows = json.load(open(host_ss_file, encoding='utf-8'))
    except Exception:
        host_rows = []
    results = {}
    if host_results_file and os.path.exists(host_results_file):
        with open(host_results_file, encoding='utf-8') as handle:
            for line in handle:
                try:
                    result = json.loads(line)
                    results[int(result['port'])] = result
                except Exception:
                    continue

    host_http_services = []
    host_other_ports = []
    for row in host_rows:
        port = int(row.get('port') or 0)
        result = results.get(port, {})
        scheme = result.get('scheme')
        if scheme in ('http', 'https'):
            title = result.get('title') or f'Host Port {port}'
            host_http_services.append({
                **row,
                'port': port,
                'origin': 'host',
                'origin_host': 'host.containers.internal',
                'origin_port': port,
                'route_port': None,
                'title': title,
                'name': title,
                'icon': None,
                'scheme': scheme,
                'kind': result.get('kind'),
                'urls': {},
            })
        else:
            host_other_ports.append({**row, 'origin': 'host'})

    try:
        previous_routes = json.load(open(container_routes_file, encoding='utf-8'))
    except Exception:
        previous_routes = {}
    previous_assignments = previous_routes.get('assignments', {}) if isinstance(previous_routes, dict) else {}
    dedupe_start = int(dedupe_raw) if container_map_raw == 'true' and dedupe_raw else None
    host_http_services, assignments, assignment_errors = assign_host_route_ports(
        http_services,
        host_http_services,
        dedupe_start,
        previous_assignments,
    )
    payload['host_http_services'] = host_http_services
    payload['host_other_ports'] = host_other_ports
    payload['container_errors'] = assignment_errors
    payload['deduplicated_ports'] = [
        {
            'origin': key,
            'origin_port': int(key.rsplit(':', 1)[1]),
            'route_port': route_port,
        }
        for key, route_port in sorted(assignments.items(), key=lambda item: item[1])
    ]
    if container_map_raw == 'true' and dedupe_start is not None:
        atomic_write_json(container_routes_file, {
            'dedupe_start': dedupe_start,
            'assignments': assignments,
        })
    host_payload = {
        'generated_at': payload['generated_at'],
        'host_http_services': host_http_services,
        'host_other_ports': host_other_ports,
        'deduplicated_ports': payload['deduplicated_ports'],
        'errors': assignment_errors,
    }

atomic_write_json(host_services_file, host_payload)
atomic_write_json(out_file, payload, indent=None)
" "$SS_FILE" "$CACHE_DIR" "$ICONS_DIR" "$SERVICES_FILE" "$PROVIDERS_DIR" \
    "$CONTAINER_MODE" "$HOST_SS_FILE" "$HOST_RESULTS_FILE" "$CONTAINER_MAP" "$DEDUPE_PORT" "$CONTAINER_ROUTES_FILE" \
    "$HOST_SERVICES_FILE"
[[ -z "$HOST_RESULTS_FILE" ]] || rm -f "$HOST_RESULTS_FILE"
echo "services.json written"
echo

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
        FILTERED_STATE_FILE="$RUNTIME_DIR/citadel-${PROVIDER_FILTER}-provider-state.json"
        python3 "$PROVIDERS_DIR/dispatch.py" \
            --enabled-dir "$ENABLED_EXT_DIR" \
            --services-file "$SERVICES_FILE" \
            --cache-dir "$CACHE_DIR" \
            --config-ini "$CONFIG" \
            --state-file "$FILTERED_STATE_FILE" \
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
            --tailscale-file "$TAILSCALE_FILE" || true
    fi
else
    echo "dispatch.py missing: $PROVIDERS_DIR/dispatch.py"
    [[ -z "$PROVIDER_FILTER" ]] || exit 1
fi
echo

date '+%Y-%m-%d %H:%M:%S' > "$TIMESTAMP_FILE"
echo "=== Done: $(cat "$TIMESTAMP_FILE") ==="
