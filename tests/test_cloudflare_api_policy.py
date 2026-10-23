from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))

from cloudflare_api_policy import (
    OAUTH, OAUTH_GRANT_DURATION, OAUTH_WHITELIST, credential_headers, endpoint_path,
    excluded_ports, hostnames, route_id, settings,
)
from cloudflare_api_access import parse_entries
from cloudflare_plan import api_routes, browser_routes, combine_routes, merge_ingress
from cloudflare_policy import cloudflare_rules


class APIPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("cloudflare", "CLOUDFLARE-API"):
            self.write(f"extensions/enabled/{name}/extension.json", {"enabled": True})
        self.write("CLOUDFLARE-API_ignore.json", {"ports": []})
        self.write(OAUTH_WHITELIST, {
            "allowed_redirect_uris": ["https://client.example/callback"]})
        self.config = {"CLOUDFLARE_EMAIL": "owner@example.com"}

    def write(self, name, payload):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload))
        return path

    def test_enabled_extension_scans_without_global_client_secret(self):
        for oauth, expected in (("0", ("api-bearer",)), ("1", ("api-bearer", "api-oauth"))):
            self.config[OAUTH] = oauth
            policy = settings(self.root, self.config.get)
            self.assertEqual(policy.modes, expected)
            self.assertFalse(policy.allow_localhost)
            self.assertFalse(policy.allow_loopback)
        self.config["CITADEL_CLOUDFLARE_API_BEARER"] = "ignored-legacy-value"
        self.assertEqual(settings(self.root, self.config.get).modes, ("api-bearer", "api-oauth"))

    def test_keep_mcp_routes_defaults_to_one_and_accepts_explicit_zero(self):
        for value, expected in ((None, True), ("", True), ("1", True), ("0", False)):
            if value is None:
                self.config.pop("CITADEL_KEEP_API_MCP_ROUTES", None)
            else:
                self.config["CITADEL_KEEP_API_MCP_ROUTES"] = value
            self.assertEqual(settings(self.root, self.config.get).keep_mcp_routes, expected)
        self.config["CITADEL_KEEP_API_MCP_ROUTES"] = "wrong"
        with self.assertRaisesRegex(ValueError, "CITADEL_KEEP_API_MCP_ROUTES"):
            settings(self.root, self.config.get)

    def test_extension_dependency_and_disable(self):
        self.config[OAUTH] = "1"
        for name in ("cloudflare", "CLOUDFLARE-API"):
            with self.subTest(name=name):
                self.write(f"extensions/enabled/{name}/extension.json", {"enabled": False})
                self.assertEqual(settings(self.root, self.config.get).modes, ())
                self.write(f"extensions/enabled/{name}/extension.json", {"enabled": True})

    def test_oauth_only_mode_requires_oauth_and_preserves_backend_mapping(self):
        from cloudflare_api_access import parse_entries, probe_credentials
        self.config.update(CITADEL_CLOUDFLARE_API_MODE="oauth", CITADEL_CLOUDFLARE_API_OAUTH="1")
        self.assertEqual(settings(self.root, self.config.get).modes, ("api-oauth",))
        access = parse_entries("user@example.com;backend-token")
        self.assertEqual(probe_credentials({"route": access})["route"]["authorization"], "Bearer backend-token")
        self.config[OAUTH] = "0"
        self.assertEqual(settings(self.root, self.config.get).modes, ())
        self.config["CITADEL_CLOUDFLARE_API_MODE"] = "invalid"
        with self.assertRaises(ValueError):
            settings(self.root, self.config.get)

    def test_invalid_boolean_fails(self):
        with self.assertRaises(ValueError):
            settings(self.root, {OAUTH: "yes"}.get)

    def test_missing_oauth_policy_never_falls_back_to_public(self):
        self.config[OAUTH] = "1"
        (self.root / OAUTH_WHITELIST).unlink()
        policy = settings(self.root, self.config.get)
        self.assertEqual(policy.modes, ("api-bearer",))
        self.assertTrue(policy.errors)
        self.write(OAUTH_WHITELIST, {"allow_loopback": True})
        self.assertEqual(settings(self.root, self.config.get).modes, ("api-bearer", "api-oauth"))

    def test_new_oauth_grant_duration_default_override_and_validation(self):
        from cloudflare_api_state import access_spec
        self.config[OAUTH] = "1"
        for configured, expected in ((None, "24h"), ("", "24h"), ("24h", "24h"), ("720h", "720h")):
            if configured is None:
                self.config.pop(OAUTH_GRANT_DURATION, None)
            else:
                self.config[OAUTH_GRANT_DURATION] = configured
            policy = settings(self.root, self.config.get)
            app, _ = access_spec("a" * 24, "oauth", 3005, "oauth.api-3005.example.com",
                                 policy, emails=["owner@example.com"])
            self.assertEqual(app["oauth_configuration"]["grant"], {
                "access_token_lifetime": "5m", "session_duration": expected})
        for invalid in ("0h", "721h", "-1h", "024h", "30d", "forever", "1h;bad"):
            self.config[OAUTH_GRANT_DURATION] = invalid
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, OAUTH_GRANT_DURATION):
                settings(self.root, self.config.get)

    def test_whitelist_is_authoritative_and_applies_to_every_oauth_app(self):
        from cloudflare_api_state import access_spec
        self.config[OAUTH] = "1"
        self.write("CITADEL_DATA/cloudflare-api/policy.json", {"oauth": {
            "allowed_redirect_uris": ["https://old.example/callback"],
            "allow_localhost": True}})
        uris = ["https://client.example/callback", "https://client.example/connector/oauth/*"]
        self.write(OAUTH_WHITELIST, {"allowed_redirect_uris": uris + uris,
                                    "allow_loopback": True})
        for port in (3005, 4000):
            policy = settings(self.root, self.config.get)
            app, _ = access_spec("a" * 24, "oauth", port, f"oauth.api-{port}.example.com",
                                 policy, emails=["owner@example.com"])
            dcr = app["oauth_configuration"]["dynamic_client_registration"]
            self.assertEqual(dcr["allowed_uris"], uris)
            self.assertFalse(dcr["allow_any_on_localhost"])
            self.assertTrue(dcr["allow_any_on_loopback"])
        self.write(OAUTH_WHITELIST, {"allowed_redirect_uris": uris[1:]})
        self.assertEqual(settings(self.root, self.config.get).allowed_redirect_uris, tuple(uris[1:]))
        (self.root / OAUTH_WHITELIST).unlink()
        # An obsolete runtime policy must not silently restore removed grants.
        self.assertFalse(settings(self.root, self.config.get).oauth)

    def test_whitelist_rejects_unsafe_or_ambiguous_callbacks(self):
        self.config[OAUTH] = "1"
        for uri in ("http://client.example/callback", "https://*.example/callback",
                    "https://client.example/*", "https://client.example/call*",
                    "https://client.example/a/*/callback", "https://client.example:bad/cb",
                    "https://client.example:0/cb", "https://user@client.example/cb",
                    "https://@client.example/cb", "https://client.example/cb?next=x",
                    "https://client.example/cb#", "https://client.example/cb\x7f",
                    "https://client.example/a/../*", "https://client.example/a/%2e%2e/*",
                    "https://client.example/a//cb", "https://client.example\\\\evil/cb", None):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                self.write(OAUTH_WHITELIST, {"allowed_redirect_uris": [uri]})
                settings(self.root, self.config.get)
        for payload in ({"allowed_redirect_uris": "https://client.example/cb"},
                        {"allowed_redirect_uris": ["https://client.example/cb"] * 101},
                        {"allow_loopback": "true"}, {"allow_localhost": 1},
                        {"oauth": {}}, {"allow_all": True}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.write(OAUTH_WHITELIST, payload)
                settings(self.root, self.config.get)
        path = self.root / OAUTH_WHITELIST
        for text in ("broken", "[]", '{"allow_loopback":true,"allow_loopback":false}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                path.write_text(text)
                settings(self.root, self.config.get)
        path.unlink()
        path.symlink_to(self.write("other.json", {"allow_loopback": True}))
        with self.assertRaises(ValueError):
            settings(self.root, self.config.get)

    def test_ignore_accepts_only_whole_integer_ports(self):
        self.write("CLOUDFLARE-API_ignore.json", {"ports": [3005, 3005, 443]})
        self.assertEqual(excluded_ports(self.root), {3005, 443})
        for value in ({}, {"ports": [True]}, {"ports": ["3005"]}, {"ports": [0]},
                      {"ports": [65536]}, {"ports": [], "paths": ["/api"]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.write("CLOUDFLARE-API_ignore.json", value)
                excluded_ports(self.root)
        (self.root / "CLOUDFLARE-API_ignore.json").write_text("broken")
        with self.assertRaises(ValueError):
            excluded_ports(self.root)

    def test_paths_cannot_escape_and_ids_are_stable(self):
        for path in ("https://other/", "//other", "/a/../b", "/a/%2e%2e/b", "/a\\b", "/mcp?url=x", "/mcp\x7f"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                endpoint_path(path)
        self.assertEqual(route_id(3005, "mcp", "/mcp"), route_id(3005, "mcp", "/mcp"))
        self.assertNotEqual(route_id(3005, "mcp", "/mcp"), route_id(3006, "mcp", "/mcp"))
        self.assertEqual(hostnames(3005, "example.com")["api-oauth"], "oauth.api-3005.example.com")

    def test_reserved_backend_headers_are_rejected(self):
        for name in ("Host", "CF-Access-Jwt-Assertion", "Cookie", "X-Forwarded-Host"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                credential_headers({name: "injected"})

    def test_api_publication_matrix_and_whole_port_exclusion(self):
        endpoint = {"id": route_id(3070, "mcp", "/mcp"), "port": 3070, "scheme": "https", "path": "/mcp",
                    "protocol": "mcp", "status": "ready", "operations": [{"path": "/mcp", "method": "POST"}]}
        for csv, oauth, count in (("", "0", 0), ("client;backend", "0", 1),
                                  ("user@example.com;backend", "1", 1),
                                  ("client;backend,user@example.com;backend", "1", 2),
                                  ("user@example.com", "0", 0)):
            self.config[OAUTH] = oauth
            access = {endpoint["id"]: parse_entries(csv)}
            plan = api_routes([endpoint], settings(self.root, self.config.get), "example.com", access)
            self.assertEqual(len(plan["hosts"]), count)
            self.assertEqual(len(plan["origins"]), min(count, 1))
            self.assertNotIn("backend", json.dumps(plan))
        self.write("CLOUDFLARE-API_ignore.json", {"ports": [3070]})
        plan = api_routes([endpoint], settings(self.root, self.config.get), "example.com")
        self.assertEqual(plan["hosts"], {})
        self.assertEqual(plan["origins"], {})

    def test_unverified_candidates_never_publish(self):
        endpoint = {"id": route_id(3070, "mcp", "/mcp"), "port": 3070, "scheme": "https", "path": "/mcp",
                    "protocol": "mcp", "status": "authentication-required"}
        plan = api_routes([endpoint], settings(self.root, self.config.get), "example.com")
        self.assertEqual(plan["hosts"], {})
        self.assertEqual(plan["diagnostics"][0]["status"], "authentication-required")


class BrowserPlanTests(unittest.TestCase):
    services = {"http_services": [{"port": 3005, "scheme": "https"}]}

    def plan(self, policy=None, emails=None, **kwargs):
        return browser_routes(self.services, policy or {}, "example.com", "example.com", emails or [], **kwargs)

    def test_missing_rule_and_emails_never_publish(self):
        routes, warnings = self.plan()
        self.assertEqual(routes, {})
        self.assertEqual(len(warnings), 1)

    def test_defaults_are_protected_and_public_requires_explicit_rule(self):
        protected, _ = self.plan(emails=["user@example.com"])
        self.assertTrue(protected["3005.example.com"]["whitelist"])
        public, _ = self.plan({"3005": {"whitelist": False}})
        self.assertFalse(public["3005.example.com"]["whitelist"])

    def test_corrupt_policy_is_not_interpreted_as_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            for content in ("broken", "[]", '{"cloudflare":{"3005":null}}',
                            '{"cloudflare":{"3005":{"whitelist":"false"}}}'):
                with self.subTest(content=content), self.assertRaises(ValueError):
                    path.write_text(content)
                    cloudflare_rules(path, strict=True)

    def test_browser_aliases_select_the_scanned_origin_host_after_access_login(self):
        # Browser Access authenticates the user but does not rewrite the Host
        # sent to Caddy. Both plain HTTP and HTTPS need the verified authority.
        for port, scheme in ((8123, "http"), (8443, "https")):
            with self.subTest(scheme=scheme):
                desired, _ = browser_routes({"http_services": [{"port": port, "scheme": scheme}]},
                    {str(port): {"whitelist": True, "emails": ["owner@example.com"],
                                 "subdomains": [str(port), "dashboard"]}},
                    "example.com", "example.com", [])
                config = merge_ingress({}, desired)
                for entry in config["ingress"][:-1]:
                    self.assertEqual(entry["originRequest"]["httpHostHeader"], f"127.0.0.1:{port}")
                    self.assertEqual(entry["service"], f"{scheme}://127.0.0.1:{port}")
                    self.assertEqual(entry["originRequest"].get("noTLSVerify", False), scheme == "https")
                    self.assertNotIn("access", entry["originRequest"])
                self.assertTrue(all(row["whitelist"] for row in desired.values()))
                self.assertEqual(merge_ingress(config, desired), config)

    def test_combined_plan_retains_siblings_and_add_is_append_only(self):
        browser, _ = self.plan({"3005": {"whitelist": False}})
        origin = {"origin-api-3005.example.com": {**browser["3005.example.com"], "whitelist": True}}
        combined = combine_routes(browser, origin)
        config = merge_ingress({"warp-routing": {"enabled": False}}, combined)
        self.assertEqual(len(config["ingress"]), 3)
        self.assertFalse(config["warp-routing"]["enabled"])
        self.assertEqual(merge_ingress(config, {}, add=True), config)
        with self.assertRaises(ValueError):
            combine_routes(browser, browser)


if __name__ == "__main__":
    unittest.main()
