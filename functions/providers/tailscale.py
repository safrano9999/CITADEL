#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import os
import shutil

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
    require_root = parse_bool(get_cfg("require_root", "true"))
    errors: list[str] = []
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    running = False
    if require_root and not is_root:
        errors.append("skip: needs root (run scan.sh with sudo)")
    elif shutil.which("tailscale"):
        running = run(["tailscale", "status"]).returncode == 0

    set_ini_value(args.config_ini, "tailscale", "true" if running else "false")

    clear_stale_tailscale(args.cache_dir, services_payload)

    routes: dict[str, str] = {}
    domain = None

    if require_root and not is_root:
        write_json(args.services_file, services_payload)
    elif running and fetch_enabled:
        status_json = run(["tailscale", "status", "--json"])
        if status_json.returncode != 0:
            errors.append("tailscale status --json failed")
        else:
            status_payload = read_json("/dev/null", {})
            try:
                import json

                status_payload = json.loads(status_json.stdout)
            except Exception:
                status_payload = {}

            domains = status_payload.get("CertDomains") or []
            domain = domains[0] if domains else None
            if not domain:
                errors.append("Could not determine tailscale domain")
            else:
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

    write_json(args.services_file, services_payload)

    payload = {
        "provider_id": "tailscale",
        "label": label,
        "considered": True,
        "available": bool(routes),
        "generated_at": now_iso(),
        "default_candidate": True,
        "running": running,
        "require_root": require_root,
        "executed_as_root": is_root,
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
