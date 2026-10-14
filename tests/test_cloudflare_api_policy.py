from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))

from cloudflare_api_policy import (
    BEARER, OAUTH, backend_credentials, credential_headers, endpoint_path,
    excluded_ports, hostnames, route_id, settings,
)
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
        self.write("CITADEL_DATA/cloudflare-api/policy.json", {"oauth": {
            "allowed_redirect_uris": ["https://client.example/callback"]}})
        self.config = {"CLOUDFLARE_EMAIL": "owner@example.com"}

    def write(self, name, payload):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload))
        return path

    def test_four_independent_modes(self):
        for bearer, oauth, expected in (
            ("", "0", ()), ("a" * 64, "0", ("api-bearer",)),
            ("", "1", ("api-oauth",)),
            ("a" * 64, "1", ("api-bearer", "api-oauth")),
        ):
            with self.subTest(expected=expected):
                self.config.update({BEARER: bearer, OAUTH: oauth})
                policy = settings(self.root, self.config.get)
                self.assertEqual(policy.modes, expected)
                self.assertFalse(policy.allow_localhost)
                self.assertFalse(policy.allow_loopback)
                self.assertNotIn("a" * 64, repr(policy))

    def test_extension_dependency_and_disable(self):
        self.config.update({BEARER: "a" * 64, OAUTH: "1"})
        for name in ("cloudflare", "CLOUDFLARE-API"):
            with self.subTest(name=name):
                self.write(f"extensions/enabled/{name}/extension.json", {"enabled": False})
                self.assertEqual(settings(self.root, self.config.get).modes, ())
                self.write(f"extensions/enabled/{name}/extension.json", {"enabled": True})

    def test_unrendered_secret_and_invalid_boolean_fail(self):
        for config in ({BEARER: "example:openssl rand -hex 32"},
                       {BEARER: "short"}, {OAUTH: "yes"}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                settings(self.root, config.get)

    def test_missing_oauth_policy_never_falls_back_to_public(self):
        self.config.update({BEARER: "a" * 64, OAUTH: "1"})
        (self.root / "CITADEL_DATA/cloudflare-api/policy.json").unlink()
        policy = settings(self.root, self.config.get)
        self.assertEqual(policy.modes, ("api-bearer",))
        self.assertTrue(policy.errors)
        self.write("CITADEL_DATA/cloudflare-api/policy.json", {"oauth": {"allow_loopback": True}})
        self.assertEqual(settings(self.root, self.config.get).modes, ("api-bearer", "api-oauth"))

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

    def test_backend_credentials_private_and_separate_from_client_auth(self):
        key = route_id(3005, "mcp", "/mcp")
        path = self.write("CITADEL_DATA/cloudflare-api/credentials.json", {
            "routes": {key: {"headers": {"Authorization": "Bearer backend"}}}})
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            backend_credentials(self.root)
        path.chmod(0o600)
        self.assertEqual(backend_credentials(self.root)[key], {"authorization": "Bearer backend"})
        for name in ("Host", "CF-Access-Jwt-Assertion", "Cookie", "X-Forwarded-Host"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                credential_headers({name: "injected"})

    def test_api_publication_matrix_and_whole_port_exclusion(self):
        endpoint = {"id": route_id(3070, "mcp", "/mcp"), "port": 3070, "scheme": "https", "path": "/mcp",
                    "protocol": "mcp", "status": "ready", "operations": [{"path": "/mcp", "method": "POST"}]}
        for bearer, oauth, count in (("", "0", 0), ("a" * 64, "0", 1), ("", "1", 1), ("a" * 64, "1", 2)):
            self.config.update({BEARER: bearer, OAUTH: oauth})
            plan = api_routes([endpoint], settings(self.root, self.config.get), "example.com")
            self.assertEqual(len(plan["hosts"]), count)
            self.assertEqual(len(plan["origins"]), min(count, 1))
            self.assertNotIn("a" * 64, json.dumps(plan))
        self.write("CLOUDFLARE-API_ignore.json", {"ports": [3070]})
        plan = api_routes([endpoint], settings(self.root, self.config.get), "example.com")
        self.assertEqual(plan["hosts"], {})
        self.assertEqual(plan["origins"], {})

    def test_unverified_candidates_never_publish(self):
        self.config[BEARER] = "a" * 64
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
