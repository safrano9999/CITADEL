#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import importlib
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from common import (
    ROUTE_SCHEMA_VERSION,
    WILDCARD_ADDRESSES,
    now_iso,
    normalize_address,
    parse_bool,
    read_json,
    route_record,
    run,
    service_addresses,
    set_ini_value,
    write_json,
)


def clear_stale_tailscale(cache_dir: str, services_payload: dict) -> None:
    if os.path.isdir(cache_dir):
        for name in os.listdir(cache_dir):
            if not name.endswith(".json"):
                continue
            path = os.path.join(cache_dir, name)
            payload = read_json(path, {})
            if not isinstance(payload, dict):
                payload = {}
            payload.pop("tailscale_url", None)
            payload.pop("tailscale_path", None)
            write_json(path, payload)

    for svc in services_payload.get("http_services", []):
        urls = svc.get("urls")
        if not isinstance(urls, dict):
            urls = {}
            svc["urls"] = urls
        urls.pop("tailscale", None)


def build_tailscale_url(domain: str, port: int, scheme: str) -> str:
    return f"{scheme}://{domain}:{port}"


def serve_target(port: int, scheme: str) -> str:
    protocol = "https+insecure" if scheme == "https" else "http"
    return f"{protocol}://127.0.0.1:{port}"


def remove_serve_route(port: str | int) -> str | None:
    removed = run(["tailscale", "serve", "--yes", f"--https={port}", "off"])
    message = f"{removed.stderr}\n{removed.stdout}".strip()
    if removed.returncode == 0 or "handler does not exist" in message.lower():
        return None
    return message or "tailscale serve removal failed"


def resolve_route_mode(
    configured_mode: str,
    service: dict[str, Any],
    tailscale_ips: set[str],
) -> str:
    if configured_mode in {"direct", "proxy"}:
        return configured_mode
    if configured_mode != "auto":
        raise ValueError(f"unsupported route_mode '{configured_mode}'")

    addresses = service_addresses(service)
    if any(address in WILDCARD_ADDRESSES for address in addresses):
        return "direct"
    if any(normalize_address(address) in tailscale_ips for address in addresses):
        return "direct"
    return "proxy"


def citadel_bool(provider_dir: str, key: str, default: str = "false") -> bool:
    root = Path(provider_dir).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    header = importlib.import_module("python_header")
    return header.get_bool(key, parse_bool(default))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-dir", required=True)
    parser.add_argument("--services-file", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--config-ini", required=True)
    parser.add_argument("--routes-out", required=True)
    parser.add_argument("--tailscale-file", required=True)
    args = parser.parse_args()

    ext_cfg = read_json(f"{args.provider_dir}/extension.json", {})

    ini_cfg_path = os.path.join(args.provider_dir, "config.ini")
    ini_parser = configparser.ConfigParser()
    if os.path.exists(ini_cfg_path):
        try:
            ini_parser.read(ini_cfg_path, encoding="utf-8")
        except Exception:
            ini_parser = configparser.ConfigParser()

    def get_cfg(key: str, default: str) -> str:
        if ini_parser.has_section("provider") and ini_parser.has_option("provider", key):
            return ini_parser.get("provider", key).strip()
        return default

    services_payload = read_json(args.services_file, {})
    previous_payload = read_json(args.tailscale_file, {})
    if not isinstance(previous_payload, dict):
        previous_payload = {}

    label = get_cfg("label", str(ext_cfg.get("label") or "Tailscale"))
    fetch_enabled = parse_bool(get_cfg("fetch", "true"))
    route_mode = get_cfg("route_mode", "auto").lower()
    errors: list[str] = []
    enabled = citadel_bool(args.provider_dir, "CITADEL_TAILSCALE")

    running = False

    clear_stale_tailscale(args.cache_dir, services_payload)

    routes: dict[str, dict[str, Any]] = {}
    serve_routes: dict[str, dict[str, object]] = {}
    previous_ports = {
        str(port)
        for port in previous_payload.get("managed_ports", [])
        if str(port).isdigit()
    }
    managed_ports = set(previous_ports)
    desired_proxy_ports: set[str] = set()
    removed_ports: set[str] = set()
    domain = None

    if not enabled:
        if shutil.which("tailscale"):
            for port in sorted(previous_ports, key=int):
                removal_error = remove_serve_route(port)
                if removal_error is None:
                    managed_ports.discard(port)
                else:
                    errors.append(f"port {port}: {removal_error}")
        write_json(args.services_file, services_payload)
    elif fetch_enabled and shutil.which("tailscale"):
        status_json = run(["tailscale", "status", "--json"])
        running = status_json.returncode == 0
        if running:
            status_payload: dict[str, Any] = {}
            try:
                import json

                status_payload = json.loads(status_json.stdout)
            except Exception:
                status_payload = {}

            running = status_payload.get("BackendState") == "Running"
            tailscale_ips = {
                normalize_address(value)
                for value in status_payload.get("Self", {}).get("TailscaleIPs", [])
                if normalize_address(value)
            }
            domains = status_payload.get("CertDomains") or []
            domain = (domains[0] if domains else None) or (
                status_payload.get("Self", {}).get("DNSName", "").rstrip(".") or None
            )
            if running and domain:
                for svc in services_payload.get("http_services", []):
                    port = int(svc.get("port", 0))
                    if port <= 0:
                        continue
                    port_key = str(port)

                    scheme = str(svc.get("scheme") or "http").strip().lower()
                    if scheme not in {"http", "https"}:
                        scheme = "http"

                    try:
                        resolved_mode = resolve_route_mode(route_mode, svc, tailscale_ips)
                    except ValueError as exc:
                        errors.append(str(exc))
                        continue

                    target = None
                    owns_listener = False
                    if resolved_mode == "direct":
                        if port_key in managed_ports:
                            removal_error = remove_serve_route(port)
                            if removal_error is not None:
                                errors.append(f"port {port}: {removal_error}")
                                continue
                            managed_ports.discard(port_key)
                            removed_ports.add(port_key)
                        route_url = build_tailscale_url(domain, port, scheme)
                    else:
                        desired_proxy_ports.add(port_key)
                        target = serve_target(port, scheme)
                        applied = run(
                            ["tailscale", "serve", "--bg", "--yes", f"--https={port}", target]
                        )
                        if applied.returncode != 0:
                            errors.append(
                                f"port {port}: "
                                f"{applied.stderr.strip() or 'tailscale serve failed'}"
                            )
                            continue
                        route_url = build_tailscale_url(domain, port, "https")
                        owns_listener = True
                        managed_ports.add(port_key)
                        serve_routes[port_key] = {
                            "url": route_url,
                            "target": target,
                            "active": True,
                        }

                    routes[port_key] = route_record(
                        resolved_mode,
                        route_url,
                        target=target,
                        owns_listener=owns_listener,
                    )

                    urls = svc.get("urls")
                    if not isinstance(urls, dict):
                        urls = {}
                        svc["urls"] = urls
                    urls["tailscale"] = route_url

                    cache_file = os.path.join(args.cache_dir, f"{port}.json")
                    cache_payload = read_json(cache_file, {})
                    if not isinstance(cache_payload, dict):
                        cache_payload = {}
                    cache_payload["tailscale_url"] = route_url
                    cache_payload["tailscale_path"] = None
                    write_json(cache_file, cache_payload)

                stale_ports = previous_ports - desired_proxy_ports - removed_ports
                for stale_port in sorted(stale_ports, key=int):
                    removal_error = remove_serve_route(stale_port)
                    if removal_error is None:
                        managed_ports.discard(stale_port)
                    else:
                        errors.append(f"port {stale_port}: {removal_error}")

    set_ini_value(args.config_ini, "tailscale", "true" if running else "false")
    write_json(args.services_file, services_payload)

    payload = {
        "provider_id": "tailscale",
        "label": label,
        "considered": bool(routes),
        "available": bool(routes),
        "generated_at": now_iso(),
        "default_candidate": True,
        "enabled": enabled,
        "running": running,
        "fetch_enabled": fetch_enabled,
        "route_mode": route_mode,
        "route_schema": ROUTE_SCHEMA_VERSION,
        "config_file": ini_cfg_path if os.path.exists(ini_cfg_path) else None,
        "domain": domain,
        "services": routes,
        "serve_routes": serve_routes,
        "managed_ports": sorted(managed_ports, key=int),
        "errors": errors,
    }

    write_json(args.routes_out, payload)
    write_json(args.tailscale_file, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
