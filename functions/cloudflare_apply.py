"""Remote Cloudflare reconciliation. Call only after validating the complete plan."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import hmac
from cloudflare_api_access import compiled_access
from datetime import datetime, timezone
import fcntl
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
from typing import Any

from cloudflare_api import CloudflareAPI, CloudflareAPIError
from cloudflare_plan import ingress_entry
from cloudflare_api_policy import owner_id
from cloudflare_api_state import (
    access_spec, append_table, canonical, deployment, initialize_private_state,
    private_state, resource_name, save_private_state, table_from_settings, worker_name,
)

ACCESS_APP_PREFIX = "CITADEL "
ACCESS_POLICY_PREFIX = "CITADEL email whitelist "


@contextmanager
def reconciliation_lock(root: Path):
    """Also serialize direct provider calls, in addition to the normal scan lock."""
    directory = root / "cache"
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory / "cloudflare-apply.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def remote_inventory(api, account, zone, tunnel):
    return {"config": api.tunnel_configuration(account, tunnel), "records": api.dns_records(zone),
            "apps": api.access_apps(account), "policies": api.access_policies(account)}


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
    *, inventory: dict | None = None, preflight_only: bool = False,
) -> tuple[dict[str, Any], set[str], dict[str, str], set[str]]:
    """Discover remotely, block affected routes, update and retire owned bindings.

    DNS is removed last and recreated first, so even an interrupted run can
    discover the remaining Access objects next time without a local ID ledger.
    """
    snapshot = inventory if inventory is not None else remote_inventory(api, account_id, zone_id, tunnel_id)
    config = snapshot["config"]
    ingress = config.get("ingress", [])
    if not isinstance(ingress, list) or any(not isinstance(entry, dict) for entry in ingress):
        raise CloudflareAPIError("Invalid remote tunnel configuration; reset aborted")
    records, apps, policies = snapshot["records"], snapshot["apps"], snapshot["policies"]
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
        expected_name = desired.get(app.get("domain"), {}).get("external_access")
        if app.get("domain") in desired and app not in owned_apps and app.get("name") != expected_name:
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

    if preflight_only:
        return config, set(), {}, set()

    # Block affected hostnames BEFORE removing Access controls. Unchanged
    # routes keep serving; a partial failure cannot expose changed/private ones.
    ready_hosts = {
        hostname for hostname, route in desired.items()
        if (not route["whitelist"] or route.get("access_ready") or any(
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
            snapshot["records"] = [item for item in snapshot["records"] if item["id"] != record["id"]]
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
        if route["whitelist"] and not route.get("external_access") and hostname not in apps:
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


class APIReconciler:
    """API participant in the single Cloudflare apply transaction.

    Construction is read-only preflight. quiesce/protect run before the combined
    Tunnel write; publish runs afterwards. Call the whole sequence under the
    reconciliation lock, never from a second independent provider process.
    """
    def __init__(self, api, root, account, zone, tunnel, plan, settings, credentials, snapshot, *, add=False):
        self.api, self.root, self.account, self.zone, self.tunnel = api, root, account, zone, tunnel
        self.owner = owner_id(account, zone, tunnel)
        self.name = worker_name(self.owner)
        self.prefix = f"CITADEL API {self.owner} "
        self.plan, self.settings, self.credentials, self.snapshot = deepcopy(plan), settings, credentials, snapshot
        self.add, self.warnings, self.errors = add, [], []
        self.state_path, self.state = private_state(root, self.owner)
        self.needed = bool(settings.modes or self.state or any(
            str(app.get("name", "")).startswith(self.prefix) for app in snapshot["apps"]))
        self.remote, self.domains, self.tokens = None, [], []
        self.previous = {"schema": 1, "hosts": {}}
        self.table = {"schema": 1, "hosts": self.plan["hosts"]}
        self.code = (root / "workers/cloudflare-api/worker.mjs").read_bytes() if self.needed else b""
        self.service = {}
        self.specs = {}
        self.owned_apps, self.owned_policies = {}, {}
        if not self.needed:
            return
        self.state_new = not self.state
        if self.state_new:
            self.state = initialize_private_state(self.owner)
        self.access_secrets = {identity: canonical(compiled_access(identity, grant, self.state["session_key"]))
                               for identity, grant in credentials.items() if grant.bearer or grant.oauth}
        revisions = {identity: hmac.new(bytes.fromhex(self.state["session_key"]), value.encode(), hashlib.sha256).hexdigest()
                     for identity, value in self.access_secrets.items()}
        for host in self.table["hosts"].values():
            for route in host["routes"]:
                route["access_revision"] = revisions[route["id"]]
        self.remote = api.worker_settings(account, self.name)
        if self.remote is not None and f"citadel-owner:{self.owner}" not in self.remote.get("tags", []):
            raise CloudflareAPIError("Worker name is occupied by a foreign resource")
        self.previous = table_from_settings(self.remote)
        ready_ids = {route["id"] for host in self.table["hosts"].values() for route in host["routes"]}
        timed_out_ports = {row["port"] for row in self.plan["diagnostics"] if row.get("http_status") == 0}
        access_changed = any(
            route.get("access_revision") != revisions.get(route["id"])
            or host["mode"] not in settings.modes or host["port"] in settings.excluded
            or not (getattr(credentials.get(route["id"]), "bearer" if host["mode"] == "api-bearer" else "oauth", None))
            for host in self.previous["hosts"].values() for route in host["routes"])
        if not add and not access_changed and any(route["id"] not in ready_ids and host["port"] in timed_out_ports
                           for host in self.previous["hosts"].values() for route in host["routes"]):
            raise CloudflareAPIError("API discovery is incomplete; previously published routes were preserved")
        self.domains = api.worker_domains(account)
        self.tokens = api.service_tokens(account)
        self.subdomain = api.worker_subdomain(account, self.name) if self.remote is not None else None
        for kind, collection, result in (("application", snapshot["apps"], self.owned_apps),
                                         ("policy", snapshot["policies"], self.owned_policies)):
            for item in collection:
                name = str(item.get("name", ""))
                if name.startswith(self.prefix):
                    suffix = name.removeprefix(self.prefix)
                    pattern = r"(?:origin|oauth) policy ([1-9][0-9]{0,4})" if kind == "policy" else r"(?:origin|oauth) ([1-9][0-9]{0,4})"
                    match = re.fullmatch(pattern, suffix)
                    if not match or int(match[1]) > 65535:
                        raise CloudflareAPIError(f"Unrecognized API Access {kind} ownership marker")
                    if name in result or not item.get("id"):
                        raise CloudflareAPIError(f"Ambiguous API Access {kind} ownership")
                    result[name] = item
        policy_ids = {policy["id"] for policy in self.owned_policies.values()}
        for app in snapshot["apps"]:
            if app.get("name") not in self.owned_apps and any(
                policy.get("id") in policy_ids for policy in (app.get("policies") or []) if isinstance(policy, dict)
            ):
                raise CloudflareAPIError("API Access policy is also used by a foreign application")
        for domain in self.domains:
            if domain.get("hostname") in self.plan["hosts"] and not self.owns_domain(domain):
                raise CloudflareAPIError("API hostname is occupied by a foreign Worker")
        for app in snapshot["apps"]:
            patterns = [app.get("domain", ""), *(app.get("self_hosted_domains") or [])]
            patterns += [destination.get("uri", "") for destination in app.get("destinations", [])
                         if isinstance(destination, dict) and destination.get("type") == "public"]
            for hostname, host in self.plan["hosts"].items():
                expected = resource_name(self.owner, "oauth", host["port"]) if host["mode"] == "api-oauth" else None
                for pattern in patterns:
                    if isinstance(pattern, dict):
                        pattern = pattern.get("domain", "")
                    if isinstance(pattern, str) and fnmatchcase(hostname, pattern.split("/")[0].lower()) and app.get("name") != expected:
                        raise CloudflareAPIError("API hostname is covered by a foreign Access policy (including wildcard domains)")
        for record in snapshot["records"]:
            if record.get("name") in self.plan["hosts"] and not any(
                domain.get("hostname") == record["name"] and self.owns_domain(domain) for domain in self.domains
            ):
                raise CloudflareAPIError("API hostname already has a DNS record")
        wanted_tokens = [token for token in self.tokens if token.get("name") == resource_name(self.owner, "service")]
        if len(wanted_tokens) > 1:
            raise CloudflareAPIError("Ambiguous API service-token ownership")
        if wanted_tokens:
            self.service = wanted_tokens[0]
        if self.plan["origins"]:
            if self.service:
                saved = self.state.get("service", {})
                if (saved.get("id") != self.service.get("id") or saved.get("client_id") != self.service.get("client_id")
                        or not saved.get("client_secret")):
                    raise CloudflareAPIError("Restore API runtime.json: the existing origin service secret cannot be recovered")
                if self.service.get("enabled") is False:
                    raise CloudflareAPIError("Origin service token is disabled; explicit renewal is required")
                expiry = self.service.get("expires_at")
                if expiry and datetime.fromisoformat(expiry.replace("Z", "+00:00")) <= datetime.now(timezone.utc):
                    raise CloudflareAPIError("Origin service token expired; explicit renewal is required")
            elif self.remote and self.previous["hosts"]:
                raise CloudflareAPIError("Existing API origin service token is missing; explicit recovery is required")
            organization = api.access_organization(account)
            auth_domain = str(organization.get("auth_domain", "")).removeprefix("https://").rstrip("/")
            if not re.fullmatch(r"[a-z0-9-]+\.cloudflareaccess\.com", auth_domain):
                raise CloudflareAPIError("Cloudflare Access team domain is not configured")
            self.table["issuer"] = f"https://{auth_domain}"
        elif self.previous.get("issuer"):
            self.table["issuer"] = self.previous["issuer"]
        for hostname, origin in self.plan["origins"].items():
            origin["external_access"] = resource_name(self.owner, "origin", origin["port"])
            self._preflight_access("origin", origin["port"], hostname)
            app = self.owned_apps.get(origin["external_access"], {})
            if app.get("aud"):
                origin["origin_access"] = {"required": True, "teamName": self.table["issuer"].split("//")[1].split(".")[0],
                                            "audTag": [app["aud"]]}
        for hostname, host in self.plan["hosts"].items():
            if host["mode"] == "api-oauth":
                self._preflight_access("oauth", host["port"], hostname)
                app = self.owned_apps.get(resource_name(self.owner, "oauth", host["port"]), {})
                if app.get("aud"):
                    host["audience"] = app["aud"]
        if add:
            self.table, notices = append_table(self.previous, self.table)
            self.warnings.extend(notices)
            # Existing origins are preserved by Add's ingress merge. Include
            # them for Access retention even when their mode is locally off.
            for hostname, host in self.previous["hosts"].items():
                origin_host = host["origin"].removeprefix("https://")
                if origin_host not in self.plan["origins"]:
                    previous_entry = next((e for e in snapshot["config"].get("ingress", [])
                                           if e.get("hostname") == origin_host), None)
                    if previous_entry is None:
                        raise CloudflareAPIError("Add cannot repair a missing API origin; run a full scan")
        # Limits and secret formats must be checked before any remote writes.
        placeholder = {"SESSION_KEY": self.state.get("session_key", "0" * 64),
                       "ORIGIN_CLIENT_ID": "pending", "ORIGIN_CLIENT_SECRET": "pending"}
        for host in self.table["hosts"].values():
            for route in host["routes"]:
                if route["id"] in self.access_secrets:
                    placeholder[f"ACCESS_{route['id']}"] = self.access_secrets[route["id"]]
        deployment(self.owner, self.table, placeholder, self.code)

    def owns_domain(self, domain):
        return (domain.get("service") == self.name and domain.get("zone_id") == self.zone
                and domain.get("environment", "production") == "production")

    def _preflight_access(self, role, port, hostname):
        expected = resource_name(self.owner, role, port)
        for app in self.snapshot["apps"]:
            patterns = [app.get("domain", ""), *(app.get("self_hosted_domains") or [])]
            patterns += [destination.get("uri", "") for destination in app.get("destinations", [])
                         if isinstance(destination, dict) and destination.get("type") == "public"]
            for pattern in patterns:
                if isinstance(pattern, dict):
                    pattern = pattern.get("domain", "")
                if isinstance(pattern, str) and fnmatchcase(hostname, pattern.split("/")[0].lower()) and app.get("name") != expected:
                    raise CloudflareAPIError("API origin or OAuth hostname is covered by a foreign Access application")

    def _upload(self, table, secrets, *, keep=False):
        metadata, modules = deployment(self.owner, table, secrets, self.code, keep_secrets=keep)
        if keep and self.remote:
            current_names = {b["name"] for b in self.remote.get("bindings", []) if b.get("type") == "secret_text"}
            new_names = {b["name"] for b in metadata["bindings"]}
            if len(metadata["bindings"]) + len(current_names - new_names) > 64:
                raise ValueError("Retained Worker secrets exceed the binding limit")
        current_names = {b["name"] for b in (self.remote or {}).get("bindings", []) if b.get("type") == "secret_text"}
        obsolete = current_names - set(secrets) if not keep else set()
        if not (self.remote and set(metadata["tags"]).issubset(set(self.remote.get("tags", [])))):
            self.api.upload_worker(self.account, self.name, metadata, modules)
        # Cloudflare may retain omitted secret bindings on upload. Explicitly
        # retire them, even when deployment tags otherwise already match.
        for name in sorted(obsolete):
            self.api.delete_worker_secret(self.account, self.name, name)
        retained = [b for b in (self.remote or {}).get("bindings", [])
                    if keep and b.get("type") == "secret_text" and b["name"] not in secrets]
        self.remote = {**metadata, "bindings": retained + metadata["bindings"]}
        if not keep:
            verified = self.api.worker_settings(self.account, self.name)
            names = {b["name"] for b in (verified or {}).get("bindings", []) if b.get("type") == "secret_text"}
            if names != set(secrets):
                raise CloudflareAPIError("Worker secret synchronization could not be verified")

    def quiesce(self):
        if not self.needed or self.add:
            return
        # Retain only unchanged host policies and unchanged endpoint scopes.
        safe = deepcopy(self.previous)
        safe["hosts"] = {}
        for hostname, old in self.previous["hosts"].items():
            wanted = self.table["hosts"].get(hostname)
            if wanted and {k: v for k, v in wanted.items() if k != "routes"} == {k: v for k, v in old.items() if k != "routes"}:
                routes = [route for route in old["routes"] if route in wanted["routes"]]
                if routes:
                    safe["hosts"][hostname] = {**old, "routes": routes}
        if self.remote is not None and safe != self.previous:
            self._upload(safe, {}, keep=True)
        # Remove retiring/changed origins from ingress before updating Access.
        ready = set()
        for hostname, origin in self.plan["origins"].items():
            if self.service:
                app_spec, policy_spec = access_spec(self.owner, "origin", origin["port"], hostname, self.settings, self.service["id"])
                policy = self.owned_policies.get(policy_spec["name"], {})
                app = self.owned_apps.get(app_spec["name"], {})
                app_spec["policies"] = [{"id": policy.get("id"), "precedence": 1}]
                if matching_fields(policy, policy_spec) and matching_fields(app, app_spec):
                    ready.add(hostname)
        old_origins = {app.get("domain") for app in self.owned_apps.values() if " origin " in app.get("name", "")}
        config = self.snapshot["config"]
        safe_config = {**config, "ingress": [entry for entry in config.get("ingress", [])
                       if entry.get("hostname") not in old_origins - ready]}
        if safe_config != config:
            self.api.update_tunnel_configuration(self.account, self.tunnel, safe_config)
            self.snapshot["config"] = safe_config

    def _protect(self, role, port, hostname):
        app_spec, policy_spec = access_spec(self.owner, role, port, hostname, self.settings, self.service.get("id", ""),
                                            emails=self.table["hosts"].get(hostname, {}).get("emails", []))
        self.specs[app_spec["name"]] = policy_spec["name"]
        app = self.owned_apps.get(app_spec["name"])
        policy = self.owned_policies.get(policy_spec["name"])
        if self.add and app and role == "oauth":
            return app  # Existing identity settings are append-only too.
        if policy is None:
            policy = self.api.create_access_policy(self.account, policy_spec)
            if not policy.get("id"):
                raise CloudflareAPIError("Created API policy has no identity")
            policy = {**policy_spec, **policy}
            self.snapshot["policies"].append(policy)
        elif not matching_fields(policy, policy_spec):
            if self.add:
                raise CloudflareAPIError("Existing origin policy differs; Add requires a full scan")
            updated = self.api.update_access_policy(self.account, policy["id"], policy_spec)
            policy.update(updated)
        self.owned_policies[policy_spec["name"]] = policy
        app_spec["policies"] = [{"id": policy["id"], "precedence": 1}]
        if app is None:
            app = self.api.create_access_app(self.account, app_spec)
            if not app.get("id"):
                raise CloudflareAPIError("Created API app has no identity")
            app = {**app_spec, **app}
            self.snapshot["apps"].append(app)
        elif not matching_fields(app, app_spec):
            if self.add:
                raise CloudflareAPIError("Existing origin application differs; Add requires a full scan")
            updated = self.api.update_access_app(self.account, app["id"], app_spec)
            app.update(updated)
        if not isinstance(app.get("aud"), str) or not app["aud"]:
            raise CloudflareAPIError("API Access application has no audience")
        self.owned_apps[app_spec["name"]] = app
        return app

    def protect(self):
        if not self.needed:
            return
        if self.state_new:
            save_private_state(self.state_path, self.state)
            self.state_new = False
        if self.plan["origins"] and not self.service:
            try:
                self.service = self.api.create_service_token(self.account, resource_name(self.owner, "service"))
            except CloudflareAPIError as exc:
                raise CloudflareAPIError(f"Origin service-token creation failed: {exc}",
                                         status_code=exc.status_code) from exc
            self.state["service"] = {key: self.service[key] for key in ("id", "client_id", "client_secret")}
            save_private_state(self.state_path, self.state)
        otp_error = None
        if any(host["mode"] == "api-oauth" for host in self.plan["hosts"].values()):
            try:
                ensure_one_time_pin(self.api, self.account, self.name)
            except CloudflareAPIError as exc:
                otp_error = exc
        for hostname, origin in self.plan["origins"].items():
            app = self._protect("origin", origin["port"], hostname)
            origin["access_ready"] = True
            origin["origin_access"] = {"required": True, "teamName": self.table["issuer"].split("//")[1].split(".")[0],
                                        "audTag": [app["aud"]]}
        for hostname, host in list(self.plan["hosts"].items()):
            if host["mode"] == "api-oauth":
                try:
                    if otp_error:
                        raise otp_error
                    app = self._protect("oauth", host["port"], hostname)
                    self.table["hosts"][hostname]["audience"] = app["aud"]
                except CloudflareAPIError as exc:
                    # Managed OAuth can fail independently of the bearer host.
                    # Keep it unbound/denied while publishing the valid mode.
                    self.errors.append(f"OAuth preparation failed for {hostname}: {exc}")
                    self.table["hosts"].pop(hostname, None)

    def publish(self):
        if not self.needed:
            return
        secrets = {"SESSION_KEY": self.state["session_key"]}
        if self.table["hosts"]:
            service = self.state.get("service", {})
            if not service.get("client_id") or not service.get("client_secret"):
                raise CloudflareAPIError("Origin service credentials are missing")
            secrets.update(ORIGIN_CLIENT_ID=service["client_id"], ORIGIN_CLIENT_SECRET=service["client_secret"])
        for host in self.table["hosts"].values():
            for route in host["routes"]:
                if route["id"] in self.access_secrets:
                    secrets[f"ACCESS_{route['id']}"] = self.access_secrets[route["id"]]
        keep = self.add and self.remote is not None
        if keep:
            old_names = {b["name"] for b in self.remote.get("bindings", []) if b.get("type") == "secret_text"}
            secrets = {name: value for name, value in secrets.items() if name not in old_names}
            self.warnings.append("Add preserves deployed credentials; changes require a full scan")
        self._upload(self.table, secrets, keep=keep)
        if self.subdomain is None or self.subdomain.get("enabled") is not False or self.subdomain.get("previews_enabled") is not False:
            self.api.disable_worker_subdomain(self.account, self.name)
        owned_domains = {domain["hostname"]: domain for domain in self.domains if self.owns_domain(domain)}
        for hostname in self.table["hosts"]:
            if hostname not in owned_domains:
                self.api.create_worker_domain(self.account, self.zone, self.name, hostname)
        if self.add:
            return
        for hostname, domain in owned_domains.items():
            if hostname not in self.table["hosts"]:
                self.api.delete_worker_domain(self.account, domain["id"])
        for name, app in self.owned_apps.items():
            if name not in self.specs:
                self.api.delete_access_app(self.account, app["id"])
        for name, policy in self.owned_policies.items():
            if name not in self.specs.values():
                self.api.delete_access_policy(self.account, policy["id"])
        if not self.plan["origins"] and self.service:
            self.api.delete_service_token(self.account, self.service["id"])
            self.state.pop("service", None)
            save_private_state(self.state_path, self.state)
        retired_origins = {app.get("domain") for name, app in self.owned_apps.items()
                           if name not in self.specs and " origin " in name}
        for record in self.snapshot["records"]:
            if (record.get("name") in retired_origins and record.get("type") == "CNAME"
                    and record.get("content", "").rstrip(".").lower() == f"{self.tunnel}.cfargotunnel.com".lower()):
                self.api.delete_dns_record(self.zone, record["id"])
