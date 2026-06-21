#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable

from cloudflare_api import CloudflareAPI, CloudflareAPIError
from common import now_iso, parse_bool, read_json, write_json


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


def remove_managed_ingress(
    config: dict[str, Any],
    managed_hostnames: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    ingress = config.get("ingress")
    ingress = ingress if isinstance(ingress, list) else []
    preserved: list[dict[str, Any]] = []
    fallback: dict[str, Any] = {"service": "http_status:404"}
    for entry in ingress:
        if not isinstance(entry, dict):
            continue
        hostname = str(entry.get("hostname") or "").lower()
        if hostname and hostname in managed_hostnames:
            continue
        if not hostname and str(entry.get("service") or "").startswith("http_status:"):
            fallback = entry
            continue
        preserved.append(entry)
    return preserved, fallback


def assert_ingress_ownership(
    config: dict[str, Any],
    desired_hostnames: set[str],
    managed_hostnames: set[str],
) -> None:
    ingress = config.get("ingress")
    ingress = ingress if isinstance(ingress, list) else []
    for entry in ingress:
        if not isinstance(entry, dict):
            continue
        hostname = str(entry.get("hostname") or "").lower()
        if hostname in desired_hostnames and hostname not in managed_hostnames:
            raise CloudflareAPIError(
                f"Tunnel ingress for {hostname} exists and is not managed by CITADEL"
            )


def reconcile_access(
    api: CloudflareAPI,
    account_id: str,
    desired: dict[str, dict[str, Any]],
    previous_apps: dict[str, str],
    previous_policies: dict[str, str],
    managed_apps: dict[str, str],
    managed_policies: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    existing_apps = api.access_apps(account_id)
    apps_by_domain = {
        str(app.get("domain") or "").lower(): app
        for app in existing_apps
        if isinstance(app, dict) and app.get("domain")
    }
    apps_by_id = {
        str(app.get("id") or ""): app
        for app in existing_apps
        if isinstance(app, dict) and app.get("id")
    }
    existing_policies = api.access_policies(account_id)
    policies_by_name = {
        str(policy.get("name") or ""): policy
        for policy in existing_policies
        if isinstance(policy, dict) and policy.get("name")
    }
    policies_by_id = {
        str(policy.get("id") or ""): policy
        for policy in existing_policies
        if isinstance(policy, dict) and policy.get("id")
    }
    selected_apps: dict[str, dict[str, Any] | None] = {}
    selected_policies: dict[str, dict[str, Any] | None] = {}

    for hostname, route in desired.items():
        if not route["whitelist"]:
            continue
        previous_policy_id = previous_policies.get(hostname, "")
        named_policy = policies_by_name.get(f"{ACCESS_POLICY_PREFIX}{hostname}")
        if named_policy and str(named_policy.get("id") or "") != previous_policy_id:
            raise CloudflareAPIError(
                f"Access policy for {hostname} exists and is not managed by CITADEL"
            )
        policy = policies_by_id.get(previous_policy_id) if previous_policy_id else named_policy
        previous_app_id = previous_apps.get(hostname, "")
        domain_app = apps_by_domain.get(hostname)
        if domain_app and str(domain_app.get("id") or "") != previous_app_id:
            raise CloudflareAPIError(
                f"Access application for {hostname} exists and is not managed by CITADEL"
            )
        app = apps_by_id.get(previous_app_id) if previous_app_id else domain_app
        selected_policies[hostname] = policy
        selected_apps[hostname] = app

    for hostname, route in desired.items():
        if not route["whitelist"]:
            continue
        policy = selected_policies[hostname]
        policy_payload = access_policy_payload(hostname, route["emails"])
        if policy:
            policy_id = str(policy.get("id") or "")
            if not policy_id:
                raise CloudflareAPIError(f"Access policy for {hostname} has no id")
            api.update_access_policy(account_id, policy_id, policy_payload)
        else:
            policy = api.create_access_policy(account_id, policy_payload)
            policy_id = str(policy.get("id") or "")
            if not policy_id:
                raise CloudflareAPIError(f"Created Access policy for {hostname} has no id")
        managed_policies[hostname] = policy_id

        app = selected_apps[hostname]
        app_payload = access_app_payload(hostname, policy_id)
        if app:
            app_id = str(app.get("id") or "")
            if not app_id:
                raise CloudflareAPIError(f"Access application for {hostname} has no id")
            api.update_access_app(account_id, app_id, app_payload)
        else:
            app = api.create_access_app(account_id, app_payload)
            app_id = str(app.get("id") or "")
            if not app_id:
                raise CloudflareAPIError(f"Created Access application for {hostname} has no id")
        managed_apps[hostname] = app_id
    return managed_apps, managed_policies


def cleanup_access(
    api: CloudflareAPI,
    account_id: str,
    previous_apps: dict[str, str],
    previous_policies: dict[str, str],
    managed_apps: dict[str, str],
    managed_policies: dict[str, str],
) -> None:
    for hostname, app_id in previous_apps.items():
        if hostname not in managed_apps and app_id:
            api.delete_access_app(account_id, app_id)
    for hostname, policy_id in previous_policies.items():
        if hostname not in managed_policies and policy_id:
            api.delete_access_policy(account_id, policy_id)


def reconcile_dns(
    api: CloudflareAPI,
    zone_id: str,
    tunnel_id: str,
    hostnames: set[str],
    previous_records: dict[str, str],
) -> dict[str, str]:
    managed = {
        hostname: api.ensure_tunnel_dns(
            zone_id,
            hostname,
            tunnel_id,
            previous_records.get(hostname, ""),
        )
        for hostname in sorted(hostnames)
    }
    return managed


def cleanup_dns(
    api: CloudflareAPI,
    zone_id: str,
    previous_records: dict[str, str],
    managed_records: dict[str, str],
) -> None:
    for hostname, record_id in previous_records.items():
        if hostname not in managed_records and record_id:
            api.delete_dns_record(zone_id, record_id)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-dir", required=True)
    parser.add_argument("--routes-out", required=True)
    parser.add_argument("--services-file", required=True)
    parser.add_argument("--cache-dir")
    parser.add_argument("--config-ini")
    parser.add_argument("--tailscale-file")
    args = parser.parse_args()

    root = Path(args.provider_dir).resolve().parents[2]
    functions_dir = root / "functions"
    sys.path.insert(0, str(functions_dir))
    from cloudflare_policy import cloudflare_rules, resolve_hostname

    get = load_project_getter(root)
    ext_cfg = read_json(f"{args.provider_dir}/extension.json", {})
    previous = read_json(args.routes_out, {})
    previous = previous if isinstance(previous, dict) else {}
    previous_hostnames = [
        str(value).lower()
        for value in previous.get("managed_hostnames", [])
        if value
    ]
    previous_dns_records = previous.get("dns_records", {})
    previous_dns_records = previous_dns_records if isinstance(previous_dns_records, dict) else {}
    previous_access_apps = previous.get("access_apps", {})
    previous_access_apps = previous_access_apps if isinstance(previous_access_apps, dict) else {}
    previous_access_policies = previous.get("access_policies", {})
    previous_access_policies = (
        previous_access_policies if isinstance(previous_access_policies, dict) else {}
    )
    services = read_json(args.services_file, {})
    services = services if isinstance(services, dict) else {}

    enabled = parse_bool(get("CITADEL_CLOUDFLARE", "0"))
    domain = get("CITADEL_CLOUDFLARE_DOMAIN", "").rstrip(".").lower()
    account_id = get("CITADEL_CLOUDFLARE_ACCOUNT_ID", "")
    zone_id = get("CITADEL_CLOUDFLARE_ZONE_ID", "")
    tunnel_id = get("CITADEL_CLOUDFLARE_TUNNEL_ID", "")
    origin_host = get("CITADEL_CLOUDFLARE_ORIGIN_HOST", "127.0.0.1")
    token = get("CLOUDFLARE_API_TOKEN", "")
    default_email = get("cloudflare_email", "")
    label = str(ext_cfg.get("label") or "Cloudflare")
    errors: list[str] = []
    routes: dict[str, str] = {}
    managed_hostnames: list[str] = []
    dns_records: dict[str, str] = {}
    access_apps: dict[str, str] = {}
    access_policies: dict[str, str] = {}
    running = False
    authenticated = False

    required = {
        "CITADEL_CLOUDFLARE_DOMAIN": domain,
        "CITADEL_CLOUDFLARE_ACCOUNT_ID": account_id,
        "CITADEL_CLOUDFLARE_ZONE_ID": zone_id,
        "CITADEL_CLOUDFLARE_TUNNEL_ID": tunnel_id,
        "CLOUDFLARE_API_TOKEN": token,
        "cloudflare_email": default_email,
    }
    missing = [key for key, value in required.items() if not value]
    api = CloudflareAPI(token) if token else None
    if enabled and "cloudflare_email" in missing:
        enabled = False
        missing = [key for key in missing if key != "cloudflare_email"]
    try:
        if enabled and missing:
            raise CloudflareAPIError(f"Missing Cloudflare settings: {', '.join(missing)}")
        if enabled and not re.fullmatch(r"[A-Za-z0-9._-]+", origin_host):
            raise CloudflareAPIError("CITADEL_CLOUDFLARE_ORIGIN_HOST is invalid")
        if enabled and api:
            api.verify_token()
            connections = api.tunnel_connections(account_id, tunnel_id)
            running = bool(connections)
            authenticated = True

            zone = api.zone(zone_id)
            zone_domain = str(zone.get("name") or "").rstrip(".").lower()
            if not zone_domain:
                raise CloudflareAPIError("Configured Cloudflare zone has no domain name")
            if domain != zone_domain and not domain.endswith(f".{zone_domain}"):
                raise CloudflareAPIError(
                    f"CITADEL_CLOUDFLARE_DOMAIN={domain} is outside zone {zone_domain}"
                )

            policy = cloudflare_rules(root / "ports.filter.json", strict=True)
            desired: dict[str, dict[str, Any]] = {}
            hostnames_seen: set[str] = set()
            for item in services.get("http_services", []):
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
                        "whitelist": bool(rule["whitelist"]),
                        "emails": list(rule["emails"]),
                    }
            managed_hostnames = sorted(desired)

            if any(route["whitelist"] for route in desired.values()):
                providers = api.access_identity_providers(account_id)
                if not one_time_pin_enabled(providers):
                    raise CloudflareAPIError(
                        "Cloudflare Access One-time PIN identity provider is not enabled"
                    )

            previous_hosts = set(previous_hostnames)
            tunnel_config = api.tunnel_configuration(account_id, tunnel_id)
            assert_ingress_ownership(tunnel_config, set(desired), previous_hosts)
            preserved, fallback = remove_managed_ingress(
                tunnel_config,
                previous_hosts | set(desired),
            )
            ingress: list[dict[str, Any]] = list(preserved)
            for hostname, route in desired.items():
                entry: dict[str, Any] = {
                    "hostname": hostname,
                    "service": f"{route['scheme']}://{origin_host}:{route['port']}",
                }
                if route["scheme"] == "https":
                    entry["originRequest"] = {"noTLSVerify": True}
                ingress.append(entry)
                routes.setdefault(str(route["port"]), f"https://{hostname}")

            reconcile_access(
                api,
                account_id,
                desired,
                previous_access_apps,
                previous_access_policies,
                access_apps,
                access_policies,
            )
            dns_records = reconcile_dns(
                api,
                zone_id,
                tunnel_id,
                set(desired),
                previous_dns_records,
            )
            tunnel_config["ingress"] = ingress + [fallback]
            api.update_tunnel_configuration(account_id, tunnel_id, tunnel_config)
            cleanup_dns(api, zone_id, previous_dns_records, dns_records)
            cleanup_access(
                api,
                account_id,
                previous_access_apps,
                previous_access_policies,
                access_apps,
                access_policies,
            )
    except (CloudflareAPIError, ValueError, OSError) as exc:
        errors.append(str(exc))
        routes = {}
        managed_hostnames = sorted(set(previous_hostnames) | set(managed_hostnames))
        dns_records = {**previous_dns_records, **dns_records}
        access_apps = {**previous_access_apps, **access_apps}
        access_policies = {**previous_access_policies, **access_policies}

    for item in services.get("http_services", []):
        if not isinstance(item, dict):
            continue
        urls = item.setdefault("urls", {})
        if isinstance(urls, dict):
            urls.pop("cloudflare", None)
            port_key = str(item.get("port") or "")
            if port_key in routes:
                urls["cloudflare"] = routes[port_key]
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
        "origin_host": origin_host,
        "managed_hostnames": managed_hostnames,
        "dns_records": dns_records,
        "access_apps": access_apps,
        "access_policies": access_policies,
        "services": routes,
        "errors": errors,
    }
    write_json(args.routes_out, payload)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
