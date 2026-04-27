#!/bin/bash
# scan.sh — port discovery + service probing + extension provider routing.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CACHE_DIR="$SCRIPT_DIR/cache"
ICONS_DIR="$SCRIPT_DIR/icons"
FUNCTIONS_DIR="$SCRIPT_DIR/functions"
PROVIDERS_DIR="$FUNCTIONS_DIR/providers"
EXTENSIONS_DIR="$SCRIPT_DIR/extensions"
ENABLED_EXT_DIR="$EXTENSIONS_DIR/enabled"
CONFIG="$SCRIPT_DIR/config.ini"
SS_FILE="$SCRIPT_DIR/ss.json"
SERVICES_FILE="$SCRIPT_DIR/services.json"
MODULES_FILE="$SCRIPT_DIR/modules.json"
TAILSCALE_FILE="$SCRIPT_DIR/tailscale.json"
PORT_FILTER_FILE="$SCRIPT_DIR/ports.filter.json"
PROVIDERS_STATE_FILE="$EXTENSIONS_DIR/providers_state.json"
CADDYFILES_DIR="$SCRIPT_DIR/CADDYFILES"
TIMESTAMP_FILE="$SCRIPT_DIR/last_scan.txt"

mkdir -p "$CACHE_DIR" "$ICONS_DIR" "$FUNCTIONS_DIR" "$PROVIDERS_DIR" "$ENABLED_EXT_DIR" "$CADDYFILES_DIR"

CA_CERT=""
if [[ -f "$CONFIG" ]]; then
    CA_CERT="$(grep '^ca_cert' "$CONFIG" 2>/dev/null | cut -d= -f2 | xargs 2>/dev/null || true)"
fi

SUBNET_CFG="$ENABLED_EXT_DIR/subnet/config.json"
HOST_IP="$(python3 -c "
import json
import sys
p = sys.argv[1]
try:
    d = json.load(open(p))
except Exception:
    d = {}
print((d.get('subnet_ip') or '').strip())
" "$SUBNET_CFG" 2>/dev/null || true)"

LOCAL_SSL="-k"
[[ -n "$CA_CERT" && -f "$CA_CERT" ]] && NET_SSL="--cacert $CA_CERT" || NET_SSL="-k"

echo "=== Discovering modules (module.toml) ==="
python3 -c "
import json
import sys
import tomllib
from pathlib import Path

saf_dir = Path(sys.argv[1])
out_file = sys.argv[2]
self_dir = Path(sys.argv[3])

modules = {}
for candidate in sorted(saf_dir.iterdir()):
    if candidate.resolve() == self_dir.resolve():
        continue
    toml_path = candidate / 'CONTAINER' / 'module.toml'
    if not toml_path.exists():
        continue
    try:
        with open(toml_path, 'rb') as f:
            cfg = tomllib.load(f)
    except Exception:
        continue

    mod = cfg.get('module', {})
    name = mod.get('name', candidate.name.lower())
    desc = mod.get('description', '')
    ports = cfg.get('ports', [])

    for p in ports:
        port = p.get('internal') or p.get('default')
        if port:
            port = int(port)
            modules[str(port)] = {
                'name': name,
                'description': desc,
                'dir': candidate.name,
                'port': port,
            }

with open(out_file, 'w') as fh:
    json.dump(modules, fh, indent=2)

print(f'Discovered {len(modules)} module port(s):')
for port, info in sorted(modules.items(), key=lambda x: int(x[0])):
    print(f'  :{port} -> {info[\"name\"]} ({info[\"description\"]})')
" "$SAF_DIR" "$MODULES_FILE" "$SCRIPT_DIR"
echo

echo "=== Scanning ports (ss -tlnHp) ==="
ss -tlnHp | python3 -c "
import json
import os
import re
import socket
import sys

old_procs = {}
ss_file = sys.argv[1]
if os.path.exists(ss_file):
    try:
        old = json.load(open(ss_file))
        old_procs = {p['port']: p.get('process') for p in old if p.get('process')}
    except Exception:
        pass

ports = []
seen = set()
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
    if port in seen:
        continue
    seen.add(port)

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

    ports.append({
        'port': port,
        'addr': addr,
        'process': process,
        'service': service,
    })

print(json.dumps(sorted(ports, key=lambda x: x['port']), indent=2))
" "$SS_FILE" > "${SS_FILE}.tmp" && mv -f "${SS_FILE}.tmp" "$SS_FILE"
echo "Ports written to ss.json"
echo

echo "=== Applying Port Filter Policy ==="
python3 -c "
import json
import os
import sys

ss_file, filter_file = sys.argv[1:3]

try:
    ports = json.load(open(ss_file))
except Exception:
    ports = []
if not isinstance(ports, list):
    ports = []

created_default = False
if not os.path.exists(filter_file):
    created_default = True
    with open(filter_file, 'w', encoding='utf-8') as fh:
        json.dump({'whitelist': [], 'blacklist': []}, fh, indent=2)

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

with open(ss_file, 'w', encoding='utf-8') as fh:
    json.dump(sorted(filtered, key=lambda x: x.get('port', 0)), fh, indent=2)

if created_default:
    print(f'created default policy: {filter_file}')
print(f'policy mode: {mode} (whitelist={len(whitelist)} blacklist={len(blacklist)})')
print(f'ports kept: {len(filtered)}/{len(ports)}')
if dropped:
    uniq = sorted(set(dropped))
    print('dropped ports: ' + ', '.join(str(x) for x in uniq))
" "$SS_FILE" "$PORT_FILTER_FILE"
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

probe_html() {
    local host="$1" port="$2"
    local ssl
    [[ "$host" == "127.0.0.1" ]] && ssl="$LOCAL_SSL" || ssl="$NET_SSL"
    if body_is_html "https://${host}:${port}/" "$ssl"; then
        echo "https://${host}:${port}"
    elif body_is_html "http://${host}:${port}/" "$ssl"; then
        echo "http://${host}:${port}"
    else
        echo ""
    fi
}

try_fetch_icon() {
    local url="$1" port="$2" ssl="$3"
    local tmp
    tmp="$(mktemp "$ICONS_DIR/${port}.XXXXXX")"
    local status
    status="$(curl -s $ssl --max-time 5 -o "$tmp" -w "%{http_code}" "$url" 2>/dev/null || echo "000")"
    if [[ "$status" == "200" ]] && [[ -s "$tmp" ]]; then
        local ext=".ico"
        case "$url" in
            *.png) ext=".png" ;;
            *.svg) ext=".svg" ;;
            *.webp) ext=".webp" ;;
            *.gif) ext=".gif" ;;
        esac
        local dest="$ICONS_DIR/${port}${ext}"
        mv "$tmp" "$dest"
        chmod 644 "$dest"
        echo "${port}${ext}"
    else
        rm -f "$tmp"
        echo ""
    fi
}

echo "=== Probing ports for HTTP/HTTPS (HTML detection) ==="

python3 -c "
import json
import sys
for p in json.load(open(sys.argv[1])):
    print(p['port'])
" "$SS_FILE" | while read -r PORT; do
    printf "Port %-6s " "$PORT"
    CACHE_FILE="$CACHE_DIR/${PORT}.json"

    LOCAL_URL="$(probe_html "127.0.0.1" "$PORT")"
    if [[ -z "$LOCAL_URL" ]]; then
        if [[ -f "$CACHE_FILE" ]]; then
            python3 -c "
import json
import sys
f = sys.argv[1]
try:
    d = json.load(open(f))
except Exception:
    d = {}
d['scheme'] = None
d['network_ip'] = None
with open(f, 'w') as fh:
    json.dump(d, fh)
" "$CACHE_FILE"
        fi
        echo "→ no HTML (other)"
        continue
    fi

    SCHEME="${LOCAL_URL%%://*}"

    NETWORK_IP=""
    if [[ -n "$HOST_IP" ]]; then
        NET_URL="$(probe_html "$HOST_IP" "$PORT")"
        [[ -n "$NET_URL" ]] && NETWORK_IP="$HOST_IP"
    fi

    NET_LABEL=""
    [[ -n "$NETWORK_IP" ]] && NET_LABEL=" [+net ${NETWORK_IP}]"

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
f = sys.argv[1]
try:
    d = json.load(open(f))
except Exception:
    d = {}
d['scheme'] = sys.argv[2]
d['network_ip'] = sys.argv[3] or None
with open(f, 'w') as fh:
    json.dump(d, fh)
" "$CACHE_FILE" "$SCHEME" "$NETWORK_IP"
            printf "%-8s cached: \"%s\"%s\n" "$SCHEME" "$EXISTING_TITLE" "$NET_LABEL"
            continue
        fi
    fi

    printf "%-8s fetching title+icons..." "$SCHEME"

    TMP_HTML="$(mktemp)"
    EFFECTIVE_URL="$(curl -s $LOCAL_SSL --max-time 5 --location "$LOCAL_URL/" -o "$TMP_HTML" -w "%{url_effective}" 2>/dev/null || echo "$LOCAL_URL/")"
    HTML="$(cat "$TMP_HTML")"
    rm -f "$TMP_HTML"
    EFFECTIVE_BASE="${EFFECTIVE_URL%/*}/"

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

    ICON_URLS=()
    while IFS= read -r href; do
        [[ -z "$href" ]] && continue
        if [[ "$href" == http* ]]; then
            ICON_URLS+=("$href")
        elif [[ "$href" == /* ]]; then
            ICON_URLS+=("${LOCAL_URL}${href}")
        else
            ICON_URLS+=("${EFFECTIVE_BASE}${href}")
        fi
    done <<< "$FAVICON_CANDIDATES"

    ICON_URLS+=("${LOCAL_URL}/favicon.png")
    ICON_URLS+=("${LOCAL_URL}/favicon.ico")
    ICON_URLS+=("${LOCAL_URL}/apple-touch-icon.png")

    ICON_NAME=""
    for FAVICON_URL in "${ICON_URLS[@]}"; do
        ICON_NAME="$(try_fetch_icon "$FAVICON_URL" "$PORT" "$LOCAL_SSL")"
        [[ -n "$ICON_NAME" ]] && break
    done

    python3 -c "
import json
import sys
with open(sys.argv[5], 'w') as f:
    json.dump({
        'title': sys.argv[1],
        'icon': sys.argv[2] or None,
        'scheme': sys.argv[3],
        'network_ip': sys.argv[4] or None,
    }, f)
" "$TITLE" "$ICON_NAME" "$SCHEME" "$NETWORK_IP" "$CACHE_FILE"

    printf " %-20s" "${ICON_NAME:-(no icon)}"
    [[ -n "$TITLE" ]] && echo "\"$TITLE\"${NET_LABEL}" || echo "(no title)${NET_LABEL}"
done

echo "=== Building services.json ==="
python3 -c "
import datetime
import json
import os
import sys

ss_file, cache_dir, icons_dir, out_file, modules_file = sys.argv[1:6]

try:
    ss_raw = json.load(open(ss_file))
except Exception:
    ss_raw = []

# Load module.toml discovery data (port -> module info)
try:
    modules = json.load(open(modules_file))
except Exception:
    modules = {}

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

    # Enrich from module.toml discovery
    mod = modules.get(str(port), {})
    mod_name = mod.get('name', '')
    mod_desc = mod.get('description', '')

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
        # Prefer HTML title, fall back to module name, then port number
        display_name = title or mod_desc or (mod_name.upper() if mod_name else f'Port {port}')
        http_services.append({
            'port': port,
            'addr': p.get('addr'),
            'process': p.get('process'),
            'service': p.get('service'),
            'title': title,
            'name': display_name,
            'module': mod_name or None,
            'icon': icon,
            'scheme': scheme,
            'network_ip': c.get('network_ip'),
            'urls': {
                'localhost': f'{scheme}://127.0.0.1:{port}',
            },
        })
    else:
        other_ports.append({
            'port': port,
            'addr': p.get('addr'),
            'process': p.get('process'),
            'service': p.get('service'),
            'module': mod_name or None,
        })

payload = {
    'generated_at': datetime.datetime.now().isoformat(timespec='seconds'),
    'http_services': http_services,
    'other_ports': other_ports,
}
with open(out_file, 'w') as fh:
    json.dump(payload, fh)
" "$SS_FILE" "$CACHE_DIR" "$ICONS_DIR" "$SERVICES_FILE" "$MODULES_FILE"
echo "services.json written"
echo

echo "=== Generating CADDYFILES ==="
python3 -c "
import json
import sys
from pathlib import Path

services_file, caddyfiles_dir = sys.argv[1:3]

try:
    payload = json.load(open(services_file))
except Exception:
    payload = {}

http_services = payload.get('http_services', [])
cdir = Path(caddyfiles_dir)

# Remove old generated snippets
for old in cdir.glob('*.caddy'):
    old.unlink()

generated = 0
for svc in http_services:
    mod = svc.get('module')
    if not mod:
        continue
    port = svc.get('port')
    if not port:
        continue

    # Generate a caddy snippet that routes /{module}/* to the service port
    snippet = (
        f'handle_path /{mod}/* {{\n'
        f'\treverse_proxy 127.0.0.1:{port}\n'
        f'}}\n'
    )
    out_path = cdir / f'{mod}.caddy'
    out_path.write_text(snippet)
    generated += 1
    print(f'  /{mod}/* -> 127.0.0.1:{port}')

print(f'{generated} caddyfile snippet(s) written to {cdir}/')
" "$SERVICES_FILE" "$CADDYFILES_DIR"
echo

echo "=== Applying Enabled Extensions ==="
if [[ -f "$PROVIDERS_DIR/dispatch.py" ]]; then
    python3 "$PROVIDERS_DIR/dispatch.py" \
        --enabled-dir "$ENABLED_EXT_DIR" \
        --services-file "$SERVICES_FILE" \
        --cache-dir "$CACHE_DIR" \
        --config-ini "$CONFIG" \
        --state-file "$PROVIDERS_STATE_FILE" \
        --tailscale-file "$TAILSCALE_FILE" || true
else
    echo "dispatch.py missing: $PROVIDERS_DIR/dispatch.py"
fi
echo

date '+%Y-%m-%d %H:%M:%S' > "$TIMESTAMP_FILE"
chmod -R a+rX "$SCRIPT_DIR"
echo "=== Done: $(cat "$TIMESTAMP_FILE") ==="
