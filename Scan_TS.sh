#!/usr/bin/env bash
# Scan_TS.sh — read-only discovery of services on online Tailscale peers.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CITADEL_TS_ROOT="$SCRIPT_DIR"

exec python3 - <<'PY'
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path(os.environ["CITADEL_TS_ROOT"])
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "functions" / "providers"))

from atomic_io import atomic_write_json
from python_header import get_bool

output_file = root / "ts.json"


def say(message: str = "") -> None:
    print(message, flush=True)


def command_json(command: list[str]) -> dict:
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail or f"{command[0]} failed")
    data = json.loads(completed.stdout)
    if not isinstance(data, dict):
        raise RuntimeError(f"{command[0]} returned invalid JSON")
    return data


def peer_ip(peer: dict) -> str:
    for value in peer.get("TailscaleIPs") or []:
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        if address.version == 4:
            return str(address)
    for value in peer.get("TailscaleIPs") or []:
        try:
            return str(ipaddress.ip_address(str(value)))
        except ValueError:
            continue
    return ""


def display_host(peer: dict, address: str) -> str:
    dns_name = str(peer.get("DNSName") or "").strip().rstrip(".")
    return dns_name or str(peer.get("HostName") or "").strip() or address


def url_host(value: str) -> str:
    try:
        return f"[{value}]" if ipaddress.ip_address(value).version == 6 else value
    except ValueError:
        return value


def probe_web(host: str, port: int, service: str, tunnel: str) -> tuple[str, str]:
    preferred = "https" if tunnel == "ssl" or "https" in service else "http"
    for scheme in (preferred, "http" if preferred == "https" else "https"):
        url = f"{scheme}://{url_host(host)}:{port}/"
        completed = subprocess.run(
            [
                "curl", "-k", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                "--connect-timeout", "2", "--max-time", "4", url,
            ],
            capture_output=True,
            text=True,
        )
        status = completed.stdout.strip()
        if completed.returncode == 0 and status.isdigit() and status != "000":
            return scheme, url
    return "", ""


def service_link(host: str, port: int, service: str) -> str:
    schemes = {
        "ssh": "ssh",
        "ftp": "ftp",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "postgres": "postgresql",
        "redis": "redis",
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
    }
    scheme = schemes.get(service, "tcp")
    return f"{scheme}://{url_host(host)}:{port}"


def service_icon(service: str, scheme: str) -> str:
    value = f"{service} {scheme}".lower()
    if "http" in value:
        return "🌐"
    if "ssh" in value:
        return "⌨️"
    if any(name in value for name in ("postgres", "mysql", "redis", "mongo", "sql")):
        return "🗄️"
    if any(name in value for name in ("smb", "netbios", "ftp", "nfs")):
        return "📁"
    if any(name in value for name in ("smtp", "imap", "pop3")):
        return "✉️"
    return "✦"


def scan_peer(peer: dict, address: str) -> list[dict]:
    name = display_host(peer, address)
    say(f"▶ {name} ({address})")
    say("  Scanning all TCP ports …")
    descriptor, xml_name = tempfile.mkstemp(prefix="citadel-ts-", suffix=".xml")
    os.close(descriptor)
    xml_path = Path(xml_name)
    try:
        completed = subprocess.run(
            [
                "nmap", "-Pn", "-n", "-sT", "-sV", "-p-", "--open",
                "--stats-every", "15s", "-oN", os.devnull, "-oX", str(xml_path),
                address,
            ],
        )
        if completed.returncode not in (0, 1):
            raise RuntimeError(f"nmap exited with {completed.returncode}")
        try:
            document = ET.parse(xml_path).getroot()
        except ET.ParseError as exc:
            raise RuntimeError(f"nmap returned invalid XML: {exc}") from exc
    finally:
        xml_path.unlink(missing_ok=True)

    services: list[dict] = []
    target = str(peer.get("DNSName") or "").strip().rstrip(".") or address
    for port_node in document.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.get("state") != "open":
            continue
        port = int(port_node.get("portid") or 0)
        protocol = str(port_node.get("protocol") or "tcp")
        service_node = port_node.find("service")
        service = str(service_node.get("name") or "unknown") if service_node is not None else "unknown"
        product = str(service_node.get("product") or "") if service_node is not None else ""
        version = str(service_node.get("version") or "") if service_node is not None else ""
        tunnel = str(service_node.get("tunnel") or "") if service_node is not None else ""
        scheme, web_url = probe_web(target, port, service, tunnel)
        link = web_url or service_link(target, port, service)
        row = {
            "port": port,
            "protocol": protocol,
            "service": service,
            "product": product or None,
            "version": version or None,
            "scheme": scheme or None,
            "url": link,
            "web": bool(web_url),
            "icon": service_icon(service, scheme),
        }
        services.append(row)
        detail = " ".join(value for value in (product, version) if value)
        web_marker = f" → {web_url}" if web_url else ""
        say(f"  ✓ :{port:<5} {service:<16} {detail}{web_marker}".rstrip())

    services.sort(key=lambda item: item["port"])
    say(f"  Found {len(services)} open service{'s' if len(services) != 1 else ''}.")
    say()
    return services


def main() -> int:
    say("=== CITADEL Tailscale Discovery ===")
    if not get_bool("CITADEL_TS_DISCOVERY", False):
        say("CITADEL_TS_DISCOVERY is disabled; nothing was scanned.")
        return 0
    for executable in ("tailscale", "nmap", "curl"):
        if not shutil.which(executable):
            say(f"ERROR: required command is missing: {executable}")
            return 2

    try:
        status = command_json(["tailscale", "status", "--json"])
    except (RuntimeError, json.JSONDecodeError) as exc:
        say(f"ERROR: cannot read Tailscale status: {exc}")
        return 1

    self_id = str((status.get("Self") or {}).get("ID") or "")
    peers = [
        peer for peer in (status.get("Peer") or {}).values()
        if isinstance(peer, dict)
        and bool(peer.get("Online"))
        and str(peer.get("ID") or "") != self_id
        and peer_ip(peer)
    ]
    peers.sort(key=lambda peer: display_host(peer, peer_ip(peer)).casefold())
    say(f"Online peers: {len(peers)} (local host excluded)")
    say()

    hosts: list[dict] = []
    errors: list[str] = []
    for index, peer in enumerate(peers, 1):
        address = peer_ip(peer)
        name = display_host(peer, address)
        say(f"[{index}/{len(peers)}]")
        try:
            services = scan_peer(peer, address)
        except RuntimeError as exc:
            message = f"{name}: {exc}"
            errors.append(message)
            say(f"  ERROR: {exc}")
            say()
            services = []
        hosts.append({
            "name": str(peer.get("HostName") or "").strip() or name,
            "dns_name": str(peer.get("DNSName") or "").strip().rstrip(".") or None,
            "ip": address,
            "os": str(peer.get("OS") or "").strip() or None,
            "services": services,
        })

    payload = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "hosts": hosts,
        "errors": errors,
    }
    atomic_write_json(output_file, payload)
    say("=== Discovery complete ===")
    say(f"Hosts scanned: {len(hosts)}")
    say(f"Services found: {sum(len(host['services']) for host in hosts)}")
    say(f"Saved: {output_file}")
    return 0 if not errors else 1


raise SystemExit(main())
PY
