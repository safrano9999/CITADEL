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


ACCESS_APP_PREFIX = "CITADEL "
ACCESS_POLICY_PREFIX = "CITADEL email whitelist "


def load_project_getter(root: Path) -> Callable[[str, str], str]:
    sys.path.insert(0, str(root))
    os.chdir(root)
    module = importlib.import_module("python_header")
    return module.get



def access_app_payload(hostname: str, policy_id: str) -> dict[str, Any]:
    return {
        "name": f"{ACCESS_APP_PREFIX}{hostname}",
        "domain": hostname,
        "type": "self_hosted",
        "session_duration": "24h",
        "auto_redirect_to_identity": False,
        "policies": [{"id": policy_id, "precedence": 1}],
    }


def access_policy_payload(hostname: str, emails: list[str]) -> dict[str, Any]:
    return {
        "name": f"{ACCESS_POLICY_PREFIX}{hostname}",
        "decision": "allow",
        "precedence": 1,
        "include": [{"email": {"email": email}} for email in emails],
        "exclude": [],
        "require": [],
    }


def one_time_pin_enabled(providers: list[dict[str, Any]]) -> bool:
    return any(
        str(provider.get("type") or "").lower() == "onetimepin"
        for provider in providers
        if isinstance(provider, dict)
    )


def ensure_one_time_pin(
    api: CloudflareAPI,
    account_id: str,
    domain: str,
) -> list[dict[str, Any]]:
    try:
        api.access_organization(account_id)
    except CloudflareAPIError:
        auth_domain = f"citadel-{account_id[:12].lower()}.cloudflareaccess.com"
        try:
            api.create_access_organization(account_id, auth_domain, domain)
        except CloudflareAPIError as exc:
            raise CloudflareAPIError(
                "Cloudflare Access initialization failed; the token requires "
                "Access: Organizations, Identity Providers, and Groups -> Edit"
            ) from exc

    providers = api.access_identity_providers(account_id)
    if one_time_pin_enabled(providers):
        return providers
    provider = api.create_access_identity_provider(
        account_id,
        {"config": {}, "name": "One-time PIN login", "type": "onetimepin"},
    )
    return [*providers, provider]


def matching_fields(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    # Cloudflare adds metadata and may reorder email rules in its responses.
    for key, value in expected.items():
        current = actual.get(key)
        if isinstance(value, list) and isinstance(current, list):
            if key == "policies":
                if any(not isinstance(item, dict) for item in current):
                    return False
                current = [{"id": item.get("id"), "precedence": item.get("precedence")}
                           for item in current if isinstance(item, dict)]
            value = sorted(json.dumps(item, sort_keys=True) for item in value)
            current = sorted(json.dumps(item, sort_keys=True) for item in current)
        if current != value:
            return False
    return True


def prepare_tunnel(
    api: CloudflareAPI, account_id: str, zone_id: str, tunnel_id: str,
    desired: dict[str, dict[str, Any]], persistent: bool, add: bool = False,
) -> tuple[dict[str, Any], set[str], dict[str, str], set[str]]:
    """Discover remotely; retire only changed/stale bindings, or reset everything.

    DNS is removed last and recreated first, so even an interrupted run can
    discover the remaining Access objects next time without a local ID ledger.
    """
    config = api.tunnel_configuration(account_id, tunnel_id)
    ingress = config.get("ingress", [])
    if not isinstance(ingress, list) or any(not isinstance(entry, dict) for entry in ingress):
        raise CloudflareAPIError("Invalid remote tunnel configuration; reset aborted")
    records = api.dns_records(zone_id)
    apps = api.access_apps(account_id)
    policies = api.access_policies(account_id)
    tunnel_target = f"{tunnel_id}.cfargotunnel.com".lower()
    owned_records = [
        record for record in records
        if record.get("type") == "CNAME"
        and str(record.get("content", "")).rstrip(".").lower() == tunnel_target
    ]
    hostnames = set(desired) | {
        str(record.get("name", "")).rstrip(".").lower() for record in owned_records
    } | {
        str(entry.get("hostname", "")).rstrip(".").lower()
        for entry in ingress
    }
    hostnames.discard("")
    owned_apps = [
        app for app in apps
        if app.get("domain") in hostnames
        and app.get("name") == f"{ACCESS_APP_PREFIX}{app['domain']}"
    ]
    owned_policies = [
        policy for policy in policies
        if str(policy.get("name", "")).removeprefix(ACCESS_POLICY_PREFIX) in hostnames
        and str(policy.get("name", "")).startswith(ACCESS_POLICY_PREFIX)
    ]
    # Resolve every conflict before touching existing routes or access controls.
    for record in records:
        if (record.get("name") in desired and record not in owned_records
                and record.get("type") not in {"MX", "TXT"}):
            raise CloudflareAPIError(f"Foreign DNS record conflicts with {record.get('name')}")
    for app in apps:
        if app.get("domain") in desired and app not in owned_apps:
            raise CloudflareAPIError(f"Foreign Access application conflicts with {app.get('domain')}")
    policy_ids = {policy.get("id") for policy in owned_policies}
    for app in apps:
        if app not in owned_apps and any(
            policy.get("id") in policy_ids
            for policy in (app.get("policies") or []) if isinstance(policy, dict)
        ):
            raise CloudflareAPIError("Citadel policy is also used by a foreign Access application")
    for resource in [*owned_records, *owned_apps, *owned_policies]:
        if not resource.get("id"):
            raise CloudflareAPIError("Cloudflare resource is missing an ID; reset aborted")

    keep_dns: set[str] = set()
    keep_policies: dict[str, str] = {}
    keep_apps: set[str] = set()
    if persistent or add:
        for record in owned_records:
            hostname = record["name"]
            if hostname in desired and record.get("proxied") is True and record.get("ttl") == 1:
                keep_dns.add(record["id"])
        for policy in owned_policies:
            hostname = policy["name"].removeprefix(ACCESS_POLICY_PREFIX)
            route = desired.get(hostname, {})
            if not route.get("whitelist"):
                continue
            expected = access_policy_payload(hostname, route["emails"])
            # Precedence belongs to the application's policy binding, not the
            # reusable policy returned by Cloudflare's policy inventory.
            expected.pop("precedence")
            if hostname not in keep_policies and matching_fields(policy, expected):
                keep_policies[hostname] = policy["id"]
        for app in owned_apps:
            hostname = app["domain"]
            if hostname in keep_policies and matching_fields(
                    app, access_app_payload(hostname, keep_policies[hostname])):
                keep_apps.add(app["id"])

    if add:
        # Never remove/reconfigure an existing remote object in Add mode.
        # Matching remnants from an interrupted addition may be reused.
        for record in owned_records:
            if record["name"] in desired and record["id"] not in keep_dns:
                raise CloudflareAPIError("Existing DNS differs; Add will not overwrite it")
        for app in owned_apps:
            if app["domain"] in desired and app["id"] not in keep_apps:
                raise CloudflareAPIError("Existing Access app differs; Add will not overwrite it")
        for policy in owned_policies:
            hostname = policy["name"].removeprefix(ACCESS_POLICY_PREFIX)
            if hostname in desired and policy["id"] not in keep_policies.values():
                raise CloudflareAPIError("Existing Access policy differs; Add will not overwrite it")
        for entry in ingress:
            hostname = entry.get("hostname")
            if hostname in desired:
                route = desired[hostname]
                expected = {"hostname": hostname, "service": f"{route['scheme']}://{route['origin_host']}:{route['origin_port']}"}
                if route["scheme"] == "https":
                    expected["originRequest"] = {"noTLSVerify": True}
                if entry != expected:
                    raise CloudflareAPIError("Existing tunnel route differs; Add will not overwrite it")
        return (config, {r["name"] for r in owned_records if r["id"] in keep_dns},
                keep_policies, {a["domain"] for a in owned_apps if a["id"] in keep_apps})

    # Block affected hostnames BEFORE removing Access controls. Unchanged
    # routes keep serving; a partial failure cannot expose changed/private ones.
    ready_hosts = {
        hostname for hostname, route in desired.items()
        if (not route["whitelist"] or any(
            app["domain"] == hostname and app["id"] in keep_apps for app in owned_apps))
    } if persistent else set()
    retiring = {app["domain"] for app in owned_apps if app["id"] not in keep_apps}
    safe_ingress = [entry for entry in ingress
                    if entry.get("hostname") in ready_hosts - retiring]
    safe_config = {**config, "ingress": safe_ingress + [{"service": "http_status:404"}]}
    if not persistent or safe_config != config:
        api.update_tunnel_configuration(account_id, tunnel_id, safe_config)
    for app in owned_apps:
        if app["id"] not in keep_apps:
            api.delete_access_app(account_id, app["id"])
    for policy in owned_policies:
        if policy["id"] not in keep_policies.values():
            api.delete_access_policy(account_id, policy["id"])
    for record in owned_records:
        if record["id"] not in keep_dns:
            api.delete_dns_record(zone_id, record["id"])
    return (safe_config, {r["name"] for r in owned_records if r["id"] in keep_dns},
            keep_policies, {a["domain"] for a in owned_apps if a["id"] in keep_apps})


def create_bindings(
    api: CloudflareAPI, account_id: str, zone_id: str, tunnel_id: str,
    desired: dict[str, dict[str, Any]],
    dns: set[str], policies: dict[str, str], apps: set[str],
) -> None:
    # Keep all routes disabled until DNS and every requested access rule exist.
    for hostname in sorted(desired):
        if hostname not in dns:
            api.create_tunnel_dns(zone_id, hostname, tunnel_id)
    for hostname, route in desired.items():
        if route["whitelist"] and hostname not in apps:
            policy_id = policies.get(hostname)
            if not policy_id:
                policy = api.create_access_policy(
                    account_id, access_policy_payload(hostname, route["emails"]))
                policy_id = policy.get("id")
                if not policy_id:
                    raise CloudflareAPIError("Created Access policy has no ID")
            app = api.create_access_app(
                account_id, access_app_payload(hostname, policy_id))
            if not app.get("id"):
                raise CloudflareAPIError("Created Access application has no ID")


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
    from cloudflare_policy import cloudflare_rules, resolve_hostname

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
            scanned = services.get("http_services")
            if not isinstance(scanned, list):
                raise ValueError("services.json must contain an http_services list")
            for item in scanned:
                if (not isinstance(item, dict) or not isinstance(item.get("port"), int)
                        or not 1 <= item["port"] <= 65535 or item.get("scheme") not in {"http", "https"}):
                    raise ValueError("Invalid scanned service; Cloudflare reset aborted")
            desired: dict[str, dict[str, Any]] = {}
            hostnames_seen: set[str] = set()
            all_services = routable_services(services)
            for item in all_services:
                if not isinstance(item, dict):
                    continue
                port = int(item.get("port") or 0)
                if not (1 <= port <= 65535):
                    continue
                rule = policy.get(str(port), {"subdomains": [str(port)], "whitelist": False, "emails": []})
                scheme = "https" if item.get("scheme") == "https" else "http"
                for subdomain in rule["subdomains"]:
                    hostname = resolve_hostname(port, subdomain, domain, zone_domain)
                    if hostname in hostnames_seen:
                        raise CloudflareAPIError(f"Duplicate Cloudflare hostname: {hostname}")
                    hostnames_seen.add(hostname)
                    desired[hostname] = {
                        "port": port,
                        "scheme": scheme,
                        "origin_host": origin_host,
                        "origin_port": port,
                        "whitelist": bool(rule["whitelist"]),
                        "emails": list(rule["emails"]),
                    }
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
            ingress: list[dict[str, Any]] = []
            for hostname, route in desired.items():
                entry: dict[str, Any] = {
                    "hostname": hostname,
                    "service": (
                        f"{route['scheme']}://{route['origin_host']}:"
                        f"{route['origin_port']}"
                    ),
                }
                if route["scheme"] == "https":
                    entry["originRequest"] = {"noTLSVerify": True}
                ingress.append(entry)
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

            if adding():
                existing = tunnel_config.get("ingress", [])
                if existing and ("hostname" in existing[-1] or any("hostname" not in entry for entry in existing[:-1])):
                    raise CloudflareAPIError("Invalid catch-all ordering; Add aborted")
                names = {entry.get("hostname") for entry in existing}
                ingress = existing[:-1] + [entry for entry in ingress if entry["hostname"] not in names] + (existing[-1:] or [{"service": "http_status:404"}])
            else:
                ingress += [{"service": "http_status:404"}]
            updated_config = {**tunnel_config, "ingress": ingress}
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
    }
    write_routes(args.routes_out, payload)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
