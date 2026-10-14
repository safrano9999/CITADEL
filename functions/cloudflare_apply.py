"""Remote Cloudflare reconciliation. Call only after validating the complete plan."""
from __future__ import annotations

import json
from typing import Any

from cloudflare_api import CloudflareAPI, CloudflareAPIError
from cloudflare_plan import ingress_entry

ACCESS_APP_PREFIX = "CITADEL "
ACCESS_POLICY_PREFIX = "CITADEL email whitelist "


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
    """Discover remotely, block affected routes, update and retire owned bindings.

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
    hostnames = {
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
    for resources, field in ((owned_apps, "domain"), (owned_policies, "name")):
        names = [resource[field] for resource in resources]
        if len(set(names)) != len(names):
            raise CloudflareAPIError("Ambiguous duplicate Access resources; reconciliation aborted")

    keep_dns: set[str] = set()
    keep_policies: dict[str, str] = {}
    keep_apps: set[str] = set()
    policy_updates: dict[str, dict] = {}
    app_updates: dict[str, dict] = {}
    if persistent or add:
        for record in owned_records:
            hostname = record["name"]
            if hostname in desired and record.get("proxied") is True and record.get("ttl") == 1:
                keep_dns.add(record["id"])
    # App identity and audience survive even a requested DNS/ingress reset.
    # OAuth registrations and refresh tokens must not be invalidated by scans.
    for policy in owned_policies:
        hostname = policy["name"].removeprefix(ACCESS_POLICY_PREFIX)
        route = desired.get(hostname, {})
        if not route.get("whitelist"):
            continue
        expected = access_policy_payload(hostname, route["emails"])
        expected.pop("precedence")
        if matching_fields(policy, expected):
            keep_policies[hostname] = policy["id"]
        elif not add:
            keep_policies[hostname] = policy["id"]
            policy_updates[policy["id"]] = expected
    for app in owned_apps:
        hostname = app["domain"]
        if hostname not in keep_policies:
            continue
        expected = access_app_payload(hostname, keep_policies[hostname])
        if matching_fields(app, expected):
            keep_apps.add(app["id"])
        elif not add:
            keep_apps.add(app["id"])
            app_updates[app["id"]] = expected

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
                expected = ingress_entry(hostname, route)
                if entry != expected:
                    raise CloudflareAPIError("Existing tunnel route differs; Add will not overwrite it")
        return (config, {r["name"] for r in owned_records if r["id"] in keep_dns},
                keep_policies, {a["domain"] for a in owned_apps if a["id"] in keep_apps})

    # Block affected hostnames BEFORE removing Access controls. Unchanged
    # routes keep serving; a partial failure cannot expose changed/private ones.
    ready_hosts = {
        hostname for hostname, route in desired.items()
        if (not route["whitelist"] or any(
            app["domain"] == hostname and app["id"] in keep_apps
            and app["id"] not in app_updates
            and keep_policies.get(hostname) not in policy_updates for app in owned_apps))
    } if persistent else set()
    retiring = {app["domain"] for app in owned_apps if app["id"] not in keep_apps}
    safe_ingress = [entry for entry in ingress
                    if entry.get("hostname") in ready_hosts - retiring]
    safe_config = {**config, "ingress": safe_ingress + [{"service": "http_status:404"}]}
    if not persistent or safe_config != config:
        api.update_tunnel_configuration(account_id, tunnel_id, safe_config)
    for policy_id, changes in policy_updates.items():
        api.update_access_policy(account_id, policy_id, changes)
    for app_id, changes in app_updates.items():
        api.update_access_app(account_id, app_id, changes)
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
