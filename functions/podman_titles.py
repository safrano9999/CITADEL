"""Resolve dashboard titles from Podman labels and Caddy's saved route configuration."""
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
from collections import defaultdict


def root_upstreams(routes):
    """Collect upstreams of unconditional routes for a loopback request to /."""
    names = set()
    for route in routes:
        matches = route.get('match', [])
        if matches and not any(
            set(match) <= {'host'} and
            (not match.get('host') or '127.0.0.1' in match['host'] or 'localhost' in match['host'])
            for match in matches
        ):
            continue
        for handler in route.get('handle', []):
            if handler.get('handler') == 'subroute':
                names.update(root_upstreams(handler.get('routes', [])))
            elif handler.get('handler') == 'reverse_proxy':
                for remote in handler.get('upstreams', []):
                    names.add(remote.get('dial', '').rpartition(':')[0])
    return names


def proxy_titles(config, labels):
    candidates = defaultdict(set)
    for server in config.get('apps', {}).get('http', {}).get('servers', {}).values():
        upstreams = root_upstreams(server.get('routes', []))
        for address in server.get('listen', []):
            port = address.rpartition(':')[2]
            if port.isdecimal():
                candidates[int(port)].update(upstreams)
    return {port: labels[name] for port, names in candidates.items() if len(names) == 1
            for name in names if name in labels}


def podman(uid, *args):
    account = pwd.getpwuid(uid)
    runtime = f'/run/user/{uid}'
    # Provider credentials from the scan environment must stay out of other users' processes.
    env = {'HOME': account.pw_dir, 'USER': account.pw_name, 'LOGNAME': account.pw_name,
           'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'XDG_RUNTIME_DIR': runtime}
    cmd = ['podman', *args]
    if uid != os.geteuid():
        cmd = ['runuser', '-u', account.pw_name, '--', 'env', f'XDG_RUNTIME_DIR={runtime}', *cmd]
    return subprocess.check_output(cmd, text=True, env=env, stderr=subprocess.DEVNULL, timeout=8)


def published_titles(uid, ports):
    fmt = '{{.ID}}\t{{.Names}}\t{{json (.Label "citadel.title")}}'
    containers = {}
    labels = {}
    for line in podman(uid, 'ps', '--format', fmt).splitlines():
        ident, name, encoded = line.split('\t')
        containers[ident[:12]] = name
        label = json.loads(encoded)
        if isinstance(label, str) and label.strip():
            labels[name] = label.strip()
    if not labels:
        return {}
    titles = {}
    proxy_ports = {}
    for line in podman(uid, 'port', '-a').splitlines():
        entry = re.fullmatch(r'(\w+)\s+(\d+)/tcp\s+->\s+.*:(\d+)', line)
        if not entry:
            continue
        ident, internal, external = entry.groups()
        port = int(external)
        if port not in ports:
            continue
        name = containers.get(ident[:12])
        if name in labels:
            titles[port] = labels[name]
        elif name == 'caddy':
            proxy_ports[port] = int(internal)
    if proxy_ports:
        try:
            snapshot = podman(uid, 'exec', 'caddy', 'cat', '/config/caddy/autosave.json')
            mapped = proxy_titles(json.loads(snapshot), labels)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            print(f'Caddy title lookup unavailable for UID {uid}: {type(exc).__name__}', file=sys.stderr)
        else:
            titles.update({port: mapped[target] for port, target in proxy_ports.items() if target in mapped})
    return titles


def listener_titles(rows):
    # Root scans see rootless ports from multiple independent Podman users.
    owners = defaultdict(set)
    for row in rows:
        for listener in row.get('listeners', []):
            if listener.get('process') != 'rootlessport' or not isinstance(listener.get('pid'), int):
                continue
            try:
                uid = Path('/proc', str(listener['pid'])).stat().st_uid
            except OSError:
                continue
            if os.geteuid() in (0, uid):
                owners[uid].add(row['port'])
    found = defaultdict(set)
    for uid, ports in owners.items():
        try:
            for port, title in published_titles(uid, ports).items():
                found[port].add(title)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            print(f'Podman title lookup unavailable for UID {uid}: {type(exc).__name__}', file=sys.stderr)
    return {port: next(iter(titles)) for port, titles in found.items() if len(titles) == 1}
