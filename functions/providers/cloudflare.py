#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

from cloudflare_api import CloudflareAPI, CloudflareAPIError
from cloudflare_redirect import SETTING as WWW_REDIRECT_SETTING, prepare_redirect, apply_redirect
from common import (
    ROUTE_SCHEMA_VERSION,
    now_iso,
    parse_bool,
    read_json,
    routable_services,
    route_record,
    write_json,
    write_routes,
    adding,
)


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cloudflare_apply import (  # re-export existing provider helpers
    access_app_payload, access_policy_payload, ensure_one_time_pin,
    one_time_pin_enabled, prepare_tunnel, create_bindings,
)
from cloudflare_plan import browser_routes, merge_ingress


def load_project_getter(root: Path) -> Callable[[str, str], str]:
    sys.path.insert(0, str(root))
    os.chdir(root)
    module = importlib.import_module("python_header")
    return module.get



def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-dir", required=True)
    parser.add_argument("--routes-out", required=True)
    parser.add_argument("--services-file", required=True)
    parser.add_argument("--cache-dir")
    parser.add_argument("--config-ini")
    parser.add_argument("--tailscale-file")
    args = parser.parse_args()

    provider_dir = Path(args.provider_dir).resolve()
    root = provider_dir.parents[2]
    functions_dir = root / "functions"
    sys.path.insert(0, str(functions_dir))
    from cloudflare_policy import cloudflare_rules, read_policy

    get = load_project_getter(root)
    ext_cfg = read_json(f"{args.provider_dir}/extension.json", {})
    ext_cfg = ext_cfg if isinstance(ext_cfg, dict) else {}
    services = read_json(args.services_file, {})
    services = services if isinstance(services, dict) else {}

    enabled = (
        provider_dir.parent == root / "extensions" / "enabled"
        and ext_cfg.get("enabled") is not False
    )
    domain = get("CITADEL_CLOUDFLARE_DOMAIN", "").rstrip(".").lower()
    account_id = get("CITADEL_CLOUDFLARE_ACCOUNT_ID", "")
    zone_id = get("CITADEL_CLOUDFLARE_ZONE_ID", "")
    tunnel_id = get("CITADEL_CLOUDFLARE_TUNNEL_ID", "")
    origin_host = "127.0.0.1"
    token = get("CLOUDFLARE_API_TOKEN", "").strip()
    label = str(ext_cfg.get("label") or "Cloudflare")
    errors: list[str] = []
    warnings: list[str] = []
    routes: dict[str, dict[str, Any]] = {}
    running = False
    authenticated = False
    redirect_status: dict[str, Any] = {"action": "unmanaged"}

    required = {
        "CITADEL_CLOUDFLARE_DOMAIN": domain,
        "CITADEL_CLOUDFLARE_ACCOUNT_ID": account_id,
        "CITADEL_CLOUDFLARE_ZONE_ID": zone_id,
        "CITADEL_CLOUDFLARE_TUNNEL_ID": tunnel_id,
    }
    missing = [key for key, value in required.items() if not value]
    try:
        if enabled and token:
            raw = get("CITADEL_CLOUDFLARE_SERVERSIDE_PERSISTENCE", "1").lower().strip()
            raw = "1" if raw in ("", "blank") else raw
            if raw not in ("0", "1", "false", "true", "no", "yes", "off", "on"):
                raise ValueError("CITADEL_CLOUDFLARE_SERVERSIDE_PERSISTENCE must be a boolean")
            persistent = parse_bool(raw)
            api = CloudflareAPI(token)
            api.verify_token()
            authenticated = True
            if missing:
                raise CloudflareAPIError(f"Missing Cloudflare settings: {', '.join(missing)}")
            connections = api.tunnel_connections(account_id, tunnel_id)
            running = bool(connections)

            zone = api.zone(zone_id)
            zone_domain = str(zone.get("name") or "").rstrip(".").lower()
            if not zone_domain:
                raise CloudflareAPIError("Configured Cloudflare zone has no domain name")
            if domain != zone_domain and not domain.endswith(f".{zone_domain}"):
                raise CloudflareAPIError(
                    f"CITADEL_CLOUDFLARE_DOMAIN={domain} is outside zone {zone_domain}"
                )

            policy = cloudflare_rules(Path(args.services_file).parent / "ports.filter.json", strict=True)
            defaults = read_policy(Path(args.services_file).parent / "ports.filter.json").get("cloudflare_defaults", {})
            if not isinstance(defaults, dict):
                raise ValueError("Invalid Cloudflare defaults")
            default_emails = (defaults.get("emails", []) if defaults.get("whitelist") is True else []) if defaults.get("configured") else get("CLOUDFLARE_EMAIL", "").split(",")
            desired, warnings = browser_routes(
                services, policy, domain, zone_domain, default_emails, add=adding())
            redirect_plan = prepare_redirect(
                api, zone_id, tunnel_id, domain, desired,
                get(WWW_REDIRECT_SETTING, ""), add=adding())
            redirect_status = {key: redirect_plan[key] for key in ("action", "warning")
                               if key in redirect_plan}
            tunnel_config, dns, policies, apps = prepare_tunnel(
                api, account_id, zone_id, tunnel_id, desired, persistent, adding())
            if any(route["whitelist"] for route in desired.values()):
                ensure_one_time_pin(api, account_id, domain)
            create_bindings(api, account_id, zone_id, tunnel_id, desired, dns, policies, apps)
            for hostname, route in desired.items():
                routes.setdefault(
                    str(route["port"]),
                    route_record(
                        "proxy",
                        f"https://{hostname}",
                        target=(
                            f"{route['scheme']}://{route['origin_host']}:"
                            f"{route['origin_port']}"
                        ),
                    ),
                )

            updated_config = merge_ingress(tunnel_config, desired, add=adding())
            if updated_config != tunnel_config:
                api.update_tunnel_configuration(account_id, tunnel_id, updated_config)
            apply_redirect(api, zone_id, redirect_plan)
    except (CloudflareAPIError, ValueError, OSError) as exc:
        errors.append(str(exc))
        routes = {}

    all_services = services.get("http_services")
    all_services = all_services if isinstance(all_services, list) else []
    for item in all_services:
        if not isinstance(item, dict):
            continue
        if adding() and item.get("port") not in services.get("added_ports", []):
            continue
        urls = item.setdefault("urls", {})
        if isinstance(urls, dict):
            urls.pop("cloudflare", None)
            port_key = str(item.get("port") or "")
            if port_key in routes:
                urls["cloudflare"] = routes[port_key]["url"]
    if isinstance(services.get("http_services"), list):
        write_json(args.services_file, services)

    payload = {
        "provider_id": "cloudflare",
        "label": label,
        "considered": bool(enabled and authenticated),
        "available": bool(routes),
        "generated_at": now_iso(),
        "domain": domain,
        "running": running,
        "authenticated": authenticated,
        "route_schema": ROUTE_SCHEMA_VERSION,
        "origin_host": origin_host,
        "redirect_to_www": redirect_status,
        "services": routes,
        "errors": errors,
        "warnings": warnings,
    }
    write_routes(args.routes_out, payload)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
