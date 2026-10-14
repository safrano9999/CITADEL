#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
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
    route_record,
    write_json,
    write_routes,
    adding,
)


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cloudflare_apply import (  # re-export existing provider helpers
    access_app_payload, access_policy_payload, ensure_one_time_pin,
    one_time_pin_enabled, prepare_tunnel, create_bindings,
    APIReconciler, reconciliation_lock, remote_inventory,
)
from cloudflare_plan import api_routes, browser_routes, combine_routes, merge_ingress
from cloudflare_api_policy import APISettings, backend_credentials, settings as api_settings
from cloudflare_api_routes import discover as discover_api, output as api_output


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
    requested_api = provider_dir.name == "CLOUDFLARE-API"
    browser_output = (Path(args.routes_out).parent / "cloudflare-routes.json") if requested_api else Path(args.routes_out)
    api_routes_output = Path(args.routes_out) if requested_api else Path(args.routes_out).parent / "CLOUDFLARE-API-routes.json"
    if requested_api:
        provider_dir = root / "extensions/enabled/cloudflare"
    functions_dir = root / "functions"
    sys.path.insert(0, str(functions_dir))
    from cloudflare_policy import cloudflare_rules, read_policy

    get = load_project_getter(root)
    ext_cfg = read_json(provider_dir / "extension.json", {})
    ext_cfg = ext_cfg if isinstance(ext_cfg, dict) else {}
    services = read_json(args.services_file, {})
    services = services if isinstance(services, dict) else {}

    enabled = (
        provider_dir.parent == root / "extensions" / "enabled"
        and (provider_dir / "extension.json").is_file()
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
    api_config = APISettings()
    api_table = {"schema": 1, "hosts": {}}
    api_errors, api_warnings, api_diagnostics = [], [], []
    api_verified = False
    api_hint = (root / "CITADEL_DATA/cloudflare-api/runtime.json").exists()

    required = {
        "CITADEL_CLOUDFLARE_DOMAIN": domain,
        "CITADEL_CLOUDFLARE_ACCOUNT_ID": account_id,
        "CITADEL_CLOUDFLARE_ZONE_ID": zone_id,
        "CITADEL_CLOUDFLARE_TUNNEL_ID": tunnel_id,
    }
    missing = [key for key, value in required.items() if not value]
    try:
        api_config = api_settings(root, get)
        api_errors.extend(api_config.errors)
        if token and (enabled or api_hint):
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

            policy_path = Path(args.services_file).parent / "ports.filter.json"
            policy_snapshot = read_policy(policy_path, strict=True)
            policy = cloudflare_rules(policy_path, strict=True, document=policy_snapshot)
            defaults = policy_snapshot.get("cloudflare_defaults", {})
            if not isinstance(defaults, dict):
                raise ValueError("Invalid Cloudflare defaults")
            default_emails = (defaults.get("emails", []) if defaults.get("whitelist") is True else []) if defaults.get("configured") else get("CLOUDFLARE_EMAIL", "").split(",")
            browser_desired, warnings = browser_routes(
                services, policy, domain, zone_domain, default_emails, add=adding())
            redirect_plan = prepare_redirect(
                api, zone_id, tunnel_id, domain, browser_desired,
                get(WWW_REDIRECT_SETTING, ""), add=adding())
            redirect_status = {key: redirect_plan[key] for key in ("action", "warning")
                               if key in redirect_plan}
            credentials = backend_credentials(root) if api_config.modes else {}
            endpoints = discover_api(services, api_config, credentials, int(get("CITADEL_WEBUI_PORT", "11000") or "11000"))
            write_json(root / "cache/cloudflare-api-inventory.json", {"generated_at": now_iso(), "endpoints": endpoints})
            plan = api_routes(endpoints, api_config, domain)
            api_diagnostics = plan["diagnostics"]
            with reconciliation_lock(root):
                snapshot = remote_inventory(api, account_id, zone_id, tunnel_id)
                participant = APIReconciler(api, root, account_id, zone_id, tunnel_id, plan,
                                           api_config, credentials, snapshot, add=adding())
                desired = combine_routes(browser_desired, participant.plan["origins"])
                if enabled:
                    prepare_tunnel(api, account_id, zone_id, tunnel_id, desired, persistent, adding(),
                                   inventory=snapshot, preflight_only=True)
                participant.quiesce()
                participant.protect()
                desired = combine_routes(browser_desired, participant.plan["origins"])
                if enabled:
                    tunnel_config, dns, policies, apps = prepare_tunnel(
                        api, account_id, zone_id, tunnel_id, desired, persistent, adding(), inventory=snapshot)
                    if any(route["whitelist"] for route in browser_desired.values()):
                        ensure_one_time_pin(api, account_id, domain)
                    create_bindings(api, account_id, zone_id, tunnel_id, desired, dns, policies, apps)
                    updated_config = merge_ingress(tunnel_config, desired, add=adding())
                    if updated_config != tunnel_config:
                        api.update_tunnel_configuration(account_id, tunnel_id, updated_config)
                participant.publish()
                api_table = participant.table
                api_verified = True
                api_warnings.extend(participant.warnings)
                api_errors.extend(participant.errors)
                if enabled:
                    apply_redirect(api, zone_id, redirect_plan)
            for hostname, route in (browser_desired if enabled else {}).items():
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
    except (CloudflareAPIError, ValueError, OSError) as exc:
        errors.append(str(exc))
        if api_config.enabled or api_hint:
            api_errors.append(str(exc))
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
    api_payload = api_output(api_table, considered=bool(api_config.modes or api_table["hosts"]),
                             authenticated=api_verified, modes=api_config.modes,
                             errors=api_errors, warnings=api_warnings,
                             diagnostics=api_diagnostics)
    api_payload["cleanup_pending"] = bool(api_hint and not api_verified)
    if api_payload["cleanup_pending"]:
        api_payload["warnings"].append("Remote API state is unverified; cleanup requires a valid Cloudflare management token")
        payload["warnings"].extend(api_payload["warnings"])
    write_routes(browser_output, payload)
    # API Add retention is based on the authoritative Worker table, not a stale
    # local route cache. Never let write_routes merge removed/unverified links.
    write_json(api_routes_output, api_payload)
    return 0 if not errors and not api_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
