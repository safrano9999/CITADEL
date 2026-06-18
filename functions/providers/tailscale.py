#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import os
import shutil
from pathlib import Path

from common import (
    now_iso,
    parse_bool,
    read_json,
    run,
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


def build_direct_tailscale_url(domain: str, port: int, scheme: str) -> str:
    if scheme == "https" and port == 443:
        return f"https://{domain}"
    if scheme == "http" and port == 80:
        return f"http://{domain}"
    return f"{scheme}://{domain}:{port}"


def read_key_value(path: Path, key: str) -> str:
    if not path.exists():
        return ""
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name.strip() == key:
                return value.strip().strip('"').strip("'")
    except Exception:
        return ""
    return ""


def citadel_bool(provider_dir: str, key: str, default: str = "false") -> bool:
    raw = os.environ.get(key, "").strip()
    if not raw:
        root = Path(provider_dir).resolve().parents[2]
        raw = read_key_value(root / "config.conf", key)
    if not raw:
        raw = default
    return parse_bool(raw)


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

    label = get_cfg("label", str(ext_cfg.get("label") or "Tailscale"))
    fetch_enabled = parse_bool(get_cfg("fetch", "true"))
    route_mode = get_cfg("route_mode", "direct_port").lower()
    errors: list[str] = []
    enabled = citadel_bool(args.provider_dir, "CITADEL_TAILSCALE")

    running = False

    clear_stale_tailscale(args.cache_dir, services_payload)

    routes: dict[str, str] = {}
    domain = None

    if not enabled:
        write_json(args.services_file, services_payload)
    elif fetch_enabled and shutil.which("tailscale"):
        status_json = run(["tailscale", "status", "--json"])
        running = status_json.returncode == 0
        if running:
            status_payload = read_json("/dev/null", {})
            try:
                import json

                status_payload = json.loads(status_json.stdout)
            except Exception:
                status_payload = {}

            domains = status_payload.get("CertDomains") or []
            domain = (domains[0] if domains else None) or (
                status_payload.get("Self", {}).get("DNSName", "").rstrip(".") or None
            )
            if domain:
                for svc in services_payload.get("http_services", []):
                    port = int(svc.get("port", 0))
                    if port <= 0:
                        continue

                    scheme = str(svc.get("scheme") or "http").strip().lower()
                    if scheme not in {"http", "https"}:
                        scheme = "http"

                    if route_mode != "direct_port":
                        errors.append(f"unsupported route_mode '{route_mode}' (expected direct_port)")
                        continue

                    route_url = build_direct_tailscale_url(domain, port, scheme)
                    routes[str(port)] = route_url

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
        "config_file": ini_cfg_path if os.path.exists(ini_cfg_path) else None,
        "domain": domain,
        "services": routes,
        "errors": errors,
    }

    write_json(args.routes_out, payload)
    write_json(args.tailscale_file, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
