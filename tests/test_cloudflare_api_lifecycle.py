from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))
sys.path.insert(0, str(ROOT / "functions/providers"))

from cloudflare_api import CloudflareAPIError
from cloudflare_api_policy import APISettings, route_id
from cloudflare_api_state import table_from_settings
from cloudflare_apply import APIReconciler, create_bindings, prepare_tunnel, remote_inventory
from cloudflare_plan import api_routes, combine_routes, merge_ingress


class FakeCloudflare:
    """Stateful remote API double: each new scan re-reads remote ownership."""
    def __init__(self):
        self.events = []
        self.sequence = 0
        self.config = {"ingress": [{"service": "http_status:404"}]}
        self.records, self.apps, self.policies, self.tokens, self.domains = [], [], [], [], []
        self.worker = None
        self.subdomain = {"enabled": False, "previews_enabled": False}
        self.fail = None

    def identity(self, kind):
        self.sequence += 1
        return f"{kind}-{self.sequence}"

    def event(self, kind, value):
        self.events.append((kind, deepcopy(value)))
        if kind == self.fail:
            raise CloudflareAPIError("injected failure")

    def tunnel_configuration(self, *_): return deepcopy(self.config)
    def dns_records(self, *_): return deepcopy(self.records)
    def access_apps(self, *_): return deepcopy(self.apps)
    def access_policies(self, *_): return deepcopy(self.policies)
    def service_tokens(self, *_): return deepcopy(self.tokens)
    def worker_domains(self, *_): return deepcopy(self.domains)
    def worker_subdomain(self, *_): return deepcopy(self.subdomain)
    def access_organization(self, *_): return {"auth_domain": "testing.cloudflareaccess.com"}
    def access_identity_providers(self, *_): return [{"type": "onetimepin"}]

    def worker_settings(self, *_):
        result = deepcopy(self.worker)
        if result:
            for binding in result["bindings"]:
                if binding["type"] == "secret_text":
                    binding.pop("text", None)
        return result

    def create_service_token(self, account, name):
        token = {"id": self.identity("service"), "name": name, "client_id": "service.access", "client_secret": "private-origin"}
        self.event("service_create", {"name": name})
        self.tokens.append({key: value for key, value in token.items() if key != "client_secret"})
        return token

    def delete_service_token(self, account, identity):
        self.event("service_delete", identity)
        self.tokens = [token for token in self.tokens if token["id"] != identity]

    def create_access_policy(self, account, payload):
        self.event("policy_create", payload)
        policy = {**deepcopy(payload), "id": self.identity("policy")}
        self.policies.append(policy)
        return deepcopy(policy)

    def create_access_app(self, account, payload):
        self.event("app_create", payload)
        app = {**deepcopy(payload), "id": self.identity("app"), "aud": self.identity("audience")}
        self.apps.append(app)
        return deepcopy(app)

    def update_access_policy(self, account, identity, changes):
        self.event("policy_update", changes)
        value = next(item for item in self.policies if item["id"] == identity)
        value.update(deepcopy(changes))
        return deepcopy(value)

    def update_access_app(self, account, identity, changes):
        self.event("app_update", changes)
        value = next(item for item in self.apps if item["id"] == identity)
        value.update(deepcopy(changes))
        return deepcopy(value)

    def delete_access_app(self, account, identity):
        self.event("app_delete", identity)
        self.apps = [item for item in self.apps if item["id"] != identity]

    def delete_access_policy(self, account, identity):
        self.event("policy_delete", identity)
        self.policies = [item for item in self.policies if item["id"] != identity]

    def update_tunnel_configuration(self, account, tunnel, config):
        self.event("tunnel_update", config)
        self.config = deepcopy(config)

    def create_tunnel_dns(self, zone, hostname, tunnel):
        self.event("dns_create", hostname)
        self.records.append({"id": self.identity("dns"), "name": hostname, "type": "CNAME",
                             "content": f"{tunnel}.cfargotunnel.com", "proxied": True, "ttl": 1})

    def delete_dns_record(self, zone, identity):
        self.event("dns_delete", identity)
        self.records = [item for item in self.records if item["id"] != identity]

    def upload_worker(self, account, name, metadata, modules):
        self.event("worker_upload", {"table": table_from_settings(metadata), "name": name})
        previous = self.worker or {}
        self.worker = deepcopy(metadata)
        if "secret_text" in metadata.get("keep_bindings", []):
            names = {binding["name"] for binding in metadata["bindings"]}
            self.worker["bindings"] += [deepcopy(binding) for binding in previous.get("bindings", [])
                if binding["type"] == "secret_text" and binding["name"] not in names]
        return {"id": name}

    def disable_worker_subdomain(self, *_):
        self.event("subdomain_disable", {})
        self.subdomain = {"enabled": False, "previews_enabled": False}

    def create_worker_domain(self, account, zone, name, hostname):
        self.event("domain_create", hostname)
        domain = {"id": self.identity("domain"), "hostname": hostname, "zone_id": zone,
                  "service": name, "environment": "production"}
        self.domains.append(domain)
        return deepcopy(domain)

    def delete_worker_domain(self, account, identity):
        self.event("domain_delete", identity)
        self.domains = [item for item in self.domains if item["id"] != identity]


class APILifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        target = self.root / "workers/cloudflare-api/worker.mjs"
        target.parent.mkdir(parents=True)
        target.write_bytes((ROOT / "workers/cloudflare-api/worker.mjs").read_bytes())
        self.api = FakeCloudflare()
        self.endpoint = {"id": route_id(3070, "mcp", "/mcp"), "port": 3070, "scheme": "https", "path": "/mcp",
                         "protocol": "mcp", "status": "ready", "operations": [{"path": "/mcp", "method": "POST"}]}
        self.browser = {"8000.example.com": {"port": 8000, "scheme": "https", "origin_host": "127.0.0.1",
                        "origin_port": 8000, "whitelist": True, "emails": ["owner@example.com"]}}

    def settings(self, bearer=True, oauth=True, excluded=()):
        return APISettings(True, "a" * 64 if bearer else "", oauth, frozenset(excluded), ("owner@example.com",),
                           ("https://client.example/callback",))

    def apply(self, settings=None, *, add=False):
        settings = settings if settings is not None else self.settings()
        snapshot = remote_inventory(self.api, "account", "zone", "tunnel")
        participant = APIReconciler(self.api, self.root, "account", "zone", "tunnel",
            api_routes([self.endpoint], settings, "example.com"), settings, {}, snapshot, add=add)
        desired = combine_routes(self.browser, participant.plan["origins"])
        prepare_tunnel(self.api, "account", "zone", "tunnel", desired, True, add,
                       inventory=snapshot, preflight_only=True)
        participant.quiesce()
        participant.protect()
        desired = combine_routes(self.browser, participant.plan["origins"])
        config, dns, policies, apps = prepare_tunnel(self.api, "account", "zone", "tunnel", desired, True, add, inventory=snapshot)
        create_bindings(self.api, "account", "zone", "tunnel", desired, dns, policies, apps)
        updated = merge_ingress(config, desired, add=add)
        if updated != config:
            self.api.update_tunnel_configuration("account", "tunnel", updated)
        participant.publish()
        return participant

    def test_repeat_scan_preserves_app_ids_and_performs_no_writes(self):
        self.apply()
        identities = [(app["id"], app["aud"]) for app in self.api.apps]
        self.api.events.clear()
        self.apply()
        self.assertEqual(self.api.events, [])
        self.assertEqual([(app["id"], app["aud"]) for app in self.api.apps], identities)

    def test_both_public_modes_share_one_worker_and_machine_protected_origin(self):
        participant = self.apply()
        self.assertEqual(set(table_from_settings(self.api.worker)["hosts"]), {
            "api-3070.example.com", "oauth.api-3070.example.com"})
        self.assertEqual({domain["service"] for domain in self.api.domains}, {participant.name})
        origin = next(entry for entry in self.api.config["ingress"] if entry.get("hostname", "").startswith("origin-api-"))
        self.assertTrue(origin["originRequest"]["access"]["required"])
        policy = next(policy for policy in self.api.policies if policy["decision"] == "non_identity")
        self.assertEqual(policy["include"], [{"service_token": {"token_id": self.api.tokens[0]["id"]}}])
        events = [event[0] for event in self.api.events]
        self.assertLess(events.index("app_create"), events.index("domain_create"))

    def test_ignore_removes_both_modes_and_keeps_browser_otp(self):
        self.apply()
        browser = next(app for app in self.api.apps if app["domain"] == "8000.example.com")
        self.api.events.clear()
        self.apply(self.settings(excluded=[3070]))
        self.assertEqual(table_from_settings(self.api.worker)["hosts"], {})
        self.assertEqual(self.api.domains, [])
        self.assertEqual(self.api.tokens, [])
        self.assertEqual(self.api.apps, [browser])
        self.assertEqual(self.api.config["ingress"][0]["hostname"], "8000.example.com")
        events = [event[0] for event in self.api.events]
        self.assertLess(events.index("worker_upload"), events.index("domain_delete"))
        self.assertLess(events.index("domain_delete"), events.index("app_delete"))

    def test_oauth_only_removes_bearer_secret_and_preserves_oauth_identity(self):
        self.apply()
        oauth = next(app for app in self.api.apps if app["domain"].startswith("oauth."))
        self.apply(self.settings(bearer=False))
        self.assertEqual(set(table_from_settings(self.api.worker)["hosts"]), {"oauth.api-3070.example.com"})
        self.assertEqual(next(app for app in self.api.apps if app["domain"].startswith("oauth."))["id"], oauth["id"])
        self.assertNotIn("CLIENT_BEARER", {binding["name"] for binding in self.api.worker["bindings"]})

    def test_disabled_extension_cleans_resources_without_using_cached_route_ids(self):
        self.apply()
        self.apply(APISettings())
        self.assertFalse(table_from_settings(self.api.worker)["hosts"])
        self.assertFalse(self.api.domains)
        self.assertEqual(len(self.api.apps), 1)

    def test_add_preserves_excluded_routes_and_reports_pending_removal(self):
        self.apply()
        before = deepcopy(self.api.config)
        participant = self.apply(self.settings(excluded=[3070]), add=True)
        self.assertEqual(self.api.config, before)
        self.assertEqual(len(table_from_settings(self.api.worker)["hosts"]), 2)
        self.assertTrue(any("full scan" in warning for warning in participant.warnings))

    def test_failure_updating_origin_policy_leaves_origin_blocked(self):
        self.apply()
        policy = next(policy for policy in self.api.policies if policy["decision"] == "non_identity")
        policy["decision"] = "bypass"
        self.api.fail = "policy_update"
        with self.assertRaises(CloudflareAPIError):
            self.apply()
        self.assertFalse(any(entry.get("hostname", "").startswith("origin-api-") for entry in self.api.config["ingress"]))

    def test_foreign_worker_and_access_collisions_abort_before_writes(self):
        self.api.worker = {"tags": ["someone-else"], "bindings": []}
        with self.assertRaises(CloudflareAPIError):
            self.apply()
        self.assertEqual(self.api.events, [])
        self.api.worker = None
        self.api.apps = [{"id": "foreign", "name": "Other installation", "domain": "oauth.api-3070.example.com"}]
        with self.assertRaises(CloudflareAPIError):
            self.apply()
        self.assertEqual(self.api.events, [])

    def test_oauth_failure_does_not_publish_unprotected_oauth_or_disable_valid_bearer(self):
        original = self.api.create_access_app

        def create(account, payload):
            if payload["domain"].startswith("oauth."):
                raise CloudflareAPIError("Managed OAuth unavailable")
            return original(account, payload)

        with patch.object(self.api, "create_access_app", side_effect=create):
            participant = self.apply()
        self.assertEqual(set(table_from_settings(self.api.worker)["hosts"]), {"api-3070.example.com"})
        self.assertEqual([domain["hostname"] for domain in self.api.domains], ["api-3070.example.com"])
        self.assertTrue(participant.errors)


if __name__ == "__main__":
    unittest.main()
