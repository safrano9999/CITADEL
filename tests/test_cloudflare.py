from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, create_autospec, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))
sys.path.insert(0, str(ROOT / "functions" / "providers"))

from cloudflare_policy import (  # noqa: E402
    cloudflare_rules,
    default_subdomains,
    normalize_rule,
    resolve_hostname,
    write_cloudflare_rules,
)
from cloudflare import (  # noqa: E402
    access_policy_payload,
    ensure_one_time_pin,
    one_time_pin_enabled,
)
from cloudflare_api import CloudflareAPI, CloudflareAPIError  # noqa: E402
import core  # noqa: E402
import cloudflare_defaults  # noqa: E402
import cloudflare as cloudflare_provider  # noqa: E402
import dispatch  # noqa: E402
import health  # noqa: E402


class CloudflarePolicyTests(unittest.TestCase):
    def test_resolves_label_default_and_full_hostname(self) -> None:
        self.assertEqual(
            resolve_hostname(399, "", "services.example.net", "example.net"),
            "399.services.example.net",
        )
        self.assertEqual(
            resolve_hostname(399, "citadel", "services.example.net", "example.net"),
            "citadel.services.example.net",
        )
        self.assertEqual(
            resolve_hostname(399, "citadel.example.net", "services.example.net", "example.net"),
            "citadel.example.net",
        )

    def test_rejects_hostname_outside_zone(self) -> None:
        with self.assertRaises(ValueError):
            resolve_hostname(399, "citadel.example.org", "services.example.net", "example.net")

    def test_whitelist_requires_email(self) -> None:
        with self.assertRaises(ValueError):
            normalize_rule({"whitelist": True, "emails": []})

    def test_normalizes_csv_aliases_and_legacy_subdomain(self) -> None:
        self.assertEqual(
            normalize_rule({"subdomains": "399, Citadel"}, port=399)["subdomains"],
            ["399", "citadel"],
        )
        self.assertEqual(
            normalize_rule({"subdomain": "Legacy"}, port=399)["subdomains"],
            ["legacy"],
        )
        self.assertEqual(normalize_rule({}, port=399)["subdomains"], ["399"])
        with self.assertRaises(ValueError):
            normalize_rule({"subdomains": "399,399"}, port=399)

    def test_https_hostname_switches_are_independent_and_generic(self) -> None:
        settings = {
            "CITADEL_CLOUDFLARE_WWW443": "1",
            "CITADEL_CLOUDFLARE_DOMAIN443": "1",
        }
        with patch.dict(os.environ, settings):
            self.assertEqual(default_subdomains(443), ["www", "domain"])
            self.assertEqual(normalize_rule({"subdomains": ["443"]}, port=443)["subdomains"], ["www", "domain"])
            self.assertEqual(
                resolve_hostname(443, "domain", "f24-sales.com", "f24-sales.com"),
                "f24-sales.com",
            )
        with patch.dict(os.environ, {"CITADEL_CLOUDFLARE_WWW443": "0", "CITADEL_CLOUDFLARE_DOMAIN443": "1"}):
            self.assertEqual(default_subdomains(443), ["domain"])
        with patch.dict(os.environ, {"CITADEL_CLOUDFLARE_WWW443": "0", "CITADEL_CLOUDFLARE_DOMAIN443": "0"}):
            self.assertEqual(default_subdomains(443), ["443"])

    def test_strict_policy_rejects_invalid_whitelist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ports.filter.json"
            path.write_text(
                json.dumps({"cloudflare": {"399": {"whitelist": True, "emails": []}}}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                cloudflare_rules(path, strict=True)

    def test_policy_round_trip_preserves_global_filter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ports.filter.json"
            path.write_text(
                json.dumps({"whitelist": [399], "blacklist": [400]}),
                encoding="utf-8",
            )
            write_cloudflare_rules(
                path,
                {
                    "399": {
                        "subdomains": ["399", "citadel"],
                        "whitelist": True,
                        "emails": ["USER@example.net", "user@example.net"],
                    }
                },
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["whitelist"], [399])
            self.assertEqual(payload["blacklist"], [400])
            self.assertEqual(cloudflare_rules(path)["399"]["subdomains"], ["399", "citadel"])
            self.assertEqual(
                cloudflare_rules(path)["399"]["emails"],
                ["user@example.net"],
            )


class DashboardCoreTests(unittest.TestCase):
    def test_citadel_service_is_featured_and_sorted_first(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "CITADEL_DATA").mkdir()
            enabled = base / "extensions" / "enabled"
            localhost = enabled / "localhost"
            localhost.mkdir(parents=True)
            (base / "CITADEL_DATA/services.json").write_text(
                json.dumps({
                    "http_services": [
                        {"port": 11000, "name": "CODEANALYST"},
                        {"port": 10999, "name": "CITADEL"},
                    ],
                    "other_ports": [],
                }),
                encoding="utf-8",
            )
            (localhost / "extension.json").write_text(
                json.dumps({"label": "Localhost"}),
                encoding="utf-8",
            )
            (base / "CITADEL_DATA/localhost-routes.json").write_text(
                json.dumps({
                    "considered": True,
                    "available": True,
                    "services": {
                        "10999": {
                            "mode": "direct",
                            "url": "http://127.0.0.1:10999",
                            "target": None,
                            "owns_listener": False,
                        },
                        "11000": {
                            "mode": "direct",
                            "url": "http://127.0.0.1:11000",
                            "target": None,
                            "owns_listener": False,
                        },
                    },
                }),
                encoding="utf-8",
            )
            (base / "CITADEL_DATA/providers_state.json").write_text(
                json.dumps({
                    "considered_providers": ["localhost"],
                    "available_providers": ["localhost"],
                    "errors": [],
                }),
                encoding="utf-8",
            )
            (base / "CITADEL_DATA/ports.filter.json").write_text(
                json.dumps({"cloudflare": {}}),
                encoding="utf-8",
            )

            original = {
                "SERVICES_FILE": core.SERVICES_FILE,
                "LAST_SCAN_FILE": core.LAST_SCAN_FILE,
                "ENABLED_EXT_DIR": core.ENABLED_EXT_DIR,
                "PROVIDERS_STATE_FILE": core.PROVIDERS_STATE_FILE,
                "UI_CONFIG_FILE": core.UI_CONFIG_FILE,
                "PORT_FILTER_FILE": core.PORT_FILTER_FILE,
            }
            old_port = os.environ.get("CITADEL_WEBUI_PORT")
            try:
                core.SERVICES_FILE = base / "CITADEL_DATA/services.json"
                core.LAST_SCAN_FILE = base / "CITADEL_DATA/last_scan.txt"
                core.ENABLED_EXT_DIR = enabled
                core.PROVIDERS_STATE_FILE = base / "CITADEL_DATA/providers_state.json"
                core.UI_CONFIG_FILE = base / "extensions" / "ui.json"
                core.PORT_FILTER_FILE = base / "CITADEL_DATA/ports.filter.json"
                os.environ["CITADEL_WEBUI_PORT"] = "10999"
                dashboard = core.build_dashboard()
            finally:
                for name, value in original.items():
                    setattr(core, name, value)
                if old_port is None:
                    os.environ.pop("CITADEL_WEBUI_PORT", None)
                else:
                    os.environ["CITADEL_WEBUI_PORT"] = old_port

            self.assertEqual([item["port"] for item in dashboard["http_tiles"]], [10999, 11000])
            self.assertTrue(dashboard["http_tiles"][0]["featured"])
            self.assertEqual(dashboard["http_tiles"][0]["display_name"], "⭐ CITADEL ⭐")

    def test_stale_host_discovery_is_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "CITADEL_DATA").mkdir()
            (base / "CITADEL_DATA/services.json").write_text(
                json.dumps({"http_services": [{"port": 11000}], "other_ports": []}),
                encoding="utf-8",
            )
            (base / "host_services.json").write_text(
                json.dumps({
                    "host_http_services": [{
                        "port": 8080,
                        "origin": "host",
                        "origin_port": 8080,
                        "route_port": None,
                        "scheme": "http",
                    }],
                    "host_other_ports": [{"port": 5432, "service": "postgres"}],
                    "deduplicated_ports": [],
                }),
                encoding="utf-8",
            )
            original_services = core.SERVICES_FILE
            original_enabled = core.ENABLED_EXT_DIR
            try:
                core.SERVICES_FILE = base / "CITADEL_DATA/services.json"
                core.ENABLED_EXT_DIR = base / "extensions" / "enabled"
                dashboard = core.build_dashboard()
            finally:
                core.SERVICES_FILE = original_services
                core.ENABLED_EXT_DIR = original_enabled

            self.assertEqual([item["port"] for item in dashboard["http_tiles"]], [11000])
            self.assertNotIn("host_listeners", dashboard)
            self.assertNotIn("deduplicated_ports", dashboard)


class CloudflareDefaultsTests(unittest.TestCase):
    class TTYInput(io.StringIO):
        def isatty(self) -> bool:
            return True

    def run_defaults(self, base: Path, stdin: str = "", email: str = "Admin@Example.com, ops@example.com") -> int:
        old_cloudflare_ready = cloudflare_defaults.cloudflare_ready
        old_project_get = cloudflare_defaults.project_get
        old_argv = sys.argv
        old_stdin = sys.stdin
        try:
            cloudflare_defaults.cloudflare_ready = lambda _root: (True, "test")
            cloudflare_defaults.project_get = lambda _root, key, default="": email if key == "CLOUDFLARE_EMAIL" else default
            sys.argv = [
                "cloudflare_defaults.py",
                "--root",
                str(base),
                "--services-file",
                str(base / "CITADEL_DATA/services.json"),
                "--policy-file",
                str(base / "CITADEL_DATA/ports.filter.json"),
            ]
            sys.stdin = self.TTYInput(stdin)
            return cloudflare_defaults.main()
        finally:
            cloudflare_defaults.cloudflare_ready = old_cloudflare_ready
            cloudflare_defaults.project_get = old_project_get
            sys.argv = old_argv
            sys.stdin = old_stdin

    def test_env_email_defaults_protect_new_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "CITADEL_DATA").mkdir()
            (base / "CITADEL_DATA/services.json").write_text(
                json.dumps({"http_services": [{"port": 12001}, {"port": 12002}]}),
                encoding="utf-8",
            )
            (base / "CITADEL_DATA/ports.filter.json").write_text(
                json.dumps({
                    "whitelist": [],
                    "blacklist": [],
                    "cloudflare": {
                        "12001": {
                            "subdomains": ["custom"],
                            "whitelist": False,
                            "emails": [],
                        }
                    },
                }),
                encoding="utf-8",
            )
            self.assertEqual(self.run_defaults(base), 0)
            policy = json.loads((base / "CITADEL_DATA/ports.filter.json").read_text(encoding="utf-8"))
            self.assertEqual(policy["cloudflare_defaults"]["emails"], ["admin@example.com", "ops@example.com"])
            self.assertEqual(policy["cloudflare"]["12001"]["subdomains"], ["custom"])
            self.assertFalse(policy["cloudflare"]["12001"]["whitelist"])
            self.assertEqual(policy["cloudflare"]["12002"]["subdomains"], ["12002"])
            self.assertTrue(policy["cloudflare"]["12002"]["whitelist"])
            self.assertEqual(policy["cloudflare"]["12002"]["emails"], ["admin@example.com", "ops@example.com"])

    def test_missing_env_email_skips_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "CITADEL_DATA").mkdir()
            (base / "CITADEL_DATA/services.json").write_text(
                json.dumps({"http_services": [{"port": 399}]}),
                encoding="utf-8",
            )
            (base / "CITADEL_DATA/ports.filter.json").write_text(
                json.dumps({"whitelist": [], "blacklist": [], "cloudflare": {}}),
                encoding="utf-8",
            )
            self.assertEqual(self.run_defaults(base, email=""), 0)
            policy = json.loads((base / "CITADEL_DATA/ports.filter.json").read_text(encoding="utf-8"))
            self.assertNotIn("cloudflare_defaults", policy)
            self.assertEqual(policy["cloudflare"], {})


class CloudflareActivationTests(unittest.TestCase):
    def test_redirect_permission_failure_precedes_tunnel_changes(self):
        self.settings['CITADEL_CLOUDFLARE_REDIRECT_TO_WWW'] = '1'
        self.write('CITADEL_DATA/services.json', {'http_services': [{'port': 443, 'scheme': 'https'}]})
        self.write('CITADEL_DATA/ports.filter.json', {'cloudflare': {'443': {
            'subdomains': ['www', 'domain'], 'whitelist': False, 'emails': []}}})
        self.api.request.side_effect = CloudflareAPIError('forbidden', 403)
        with patch.dict(os.environ, {'CITADEL_CLOUDFLARE_WWW443': '1',
                                     'CITADEL_CLOUDFLARE_DOMAIN443': '1'}):
            code, payload = self.run_provider()
        self.assertEqual(code, 1)
        self.assertIn('Dynamic URL Redirects', payload['errors'][0])
        self.api.tunnel_configuration.assert_not_called()
        self.assert_no_remote_mutations()

    def test_redirect_created_after_target_tunnel_routes(self):
        self.settings['CITADEL_CLOUDFLARE_REDIRECT_TO_WWW'] = '1'
        self.write('CITADEL_DATA/services.json', {'http_services': [{'port': 443, 'scheme': 'https'}]})
        self.write('CITADEL_DATA/ports.filter.json', {'cloudflare': {'443': {
            'subdomains': ['www', 'domain'], 'whitelist': False, 'emails': []}}})
        self.api.request.return_value = None
        with patch.dict(os.environ, {'CITADEL_CLOUDFLARE_WWW443': '1',
                                     'CITADEL_CLOUDFLARE_DOMAIN443': '1'}):
            code, payload = self.run_provider()
        self.assertEqual(code, 0, payload['errors'])
        self.assertEqual(payload['redirect_to_www']['action'], 'create')
        self.assertEqual(self.api.method_calls[-1][0], 'request')
        self.assertEqual(self.api.method_calls[-1].args[:2], ('POST', '/zones/zone/rulesets'))
        self.assertEqual(payload['services']['443']['url'], 'https://www.services.example.net')

    def test_add_keeps_remote_routes_access_and_dns_even_when_persistence_is_zero(self):
        self.existing_protected_route()
        self.settings["CITADEL_CLOUDFLARE_SERVERSIDE_PERSISTENCE"] = "0"
        self.write("CITADEL_DATA/ports.filter.json", {"cloudflare": {
            "8000": {"whitelist": True, "emails": ["user@example.net"]},
            "8001": {"whitelist": False}}})
        old_ingress = list(self.api.tunnel_configuration.return_value["ingress"])
        old_route = {"url": "https://8000.services.example.net"}
        self.write("cache/cloudflare-routes.json", {"services": {"8000": old_route}})
        self.write("CITADEL_DATA/services.json", {"http_services": [
            {"port": 8000, "scheme": "http", "urls": {"cloudflare": old_route["url"]}},
            {"port": 8001, "scheme": "http"}], "added_ports": [8001]})
        with patch.dict(os.environ, {"CITADEL_SCAN_ADD": "1"}):
            code, payload = self.run_provider()
        self.assertEqual(code, 0, payload["errors"])
        self.assertEqual(payload["services"]["8000"], old_route)
        self.api.delete_dns_record.assert_not_called()
        self.api.delete_access_policy.assert_not_called()
        self.api.delete_access_app.assert_not_called()
        self.api.update_tunnel_configuration.assert_called_once()
        ingress = self.api.update_tunnel_configuration.call_args.args[-1]["ingress"]
        self.assertEqual(ingress[0], old_ingress[0])
        self.assertEqual(ingress[-1], old_ingress[-1])
        self.assertEqual(ingress[1]["hostname"], "8001.services.example.net")

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(os.chdir, Path.cwd())
        self.addCleanup(sys.path.__setitem__, slice(None), list(sys.path))
        self.base = Path(temporary.name)
        self.provider_dir = self.base / "extensions/enabled/cloudflare"
        self.manifest()
        self.write("CITADEL_DATA/services.json", {"http_services": [{"port": 8000, "scheme": "http"}]})
        self.write("cache/8000.json", {"kind": "html"})
        self.write("CITADEL_DATA/ports.filter.json", {"cloudflare": {"8000": {"whitelist": False}}})
        self.write("CITADEL_DATA/providers_state.json", {"providers": {"cloudflare": {"status": "ok"}}})
        (self.base / "CITADEL_DATA/last_scan.txt").write_text("2026-10-02T12:00:00Z")
        self.settings = {
            "CLOUDFLARE_API_TOKEN": "unit-test-token",
            "CITADEL_CLOUDFLARE_SERVERSIDE_PERSISTENCE": "0",
            "CITADEL_CLOUDFLARE_DOMAIN": "services.example.net",
            "CITADEL_CLOUDFLARE_ACCOUNT_ID": "account",
            "CITADEL_CLOUDFLARE_ZONE_ID": "zone",
            "CITADEL_CLOUDFLARE_TUNNEL_ID": "tunnel",
        }
        self.getter = Mock(side_effect=lambda key, default="": self.settings.get(key, default))
        self.api = create_autospec(CloudflareAPI, instance=True)
        self.api.verify_token.return_value = None
        self.api.tunnel_connections.return_value = [{"id": "connection"}]
        self.api.zone.return_value = {"name": "example.net"}
        self.api.tunnel_configuration.return_value = {"ingress": [{"service": "http_status:404"}]}
        self.api.access_apps.return_value = []
        self.api.access_policies.return_value = []
        self.api.dns_records.return_value = []
        self.api.create_tunnel_dns.return_value = "dns-record"
        self.api.create_access_policy.return_value = {"id": "new-policy"}
        self.api.create_access_app.return_value = {"id": "new-app"}
        factory = patch.object(cloudflare_provider, "CloudflareAPI", return_value=self.api)
        self.factory = factory.start()
        self.addCleanup(factory.stop)
        for target in ("subprocess.run", "urllib.request.urlopen"):
            guard = patch(target, side_effect=AssertionError("Live processes/network forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def write(self, name, payload):
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def manifest(self, enabled=True):
        self.write("extensions/enabled/cloudflare/extension.json", {
            "provider": "cloudflare", "label": "Cloudflare", "enabled": enabled,
        })

    def run_provider(self):
        output = self.base / "cache/cloudflare-routes.json"
        with (patch.object(cloudflare_provider, "load_project_getter", return_value=self.getter),
              patch.object(sys, "argv", ["cloudflare.py", "--provider-dir", str(self.provider_dir),
                                         "--routes-out", str(output), "--services-file", str(self.base / "CITADEL_DATA/services.json")])):
            code = cloudflare_provider.main()
        return code, json.loads(output.read_text())

    def ready(self):
        with patch.dict(sys.modules, {
            "python_header": SimpleNamespace(get=self.getter),
            "cloudflare_api": SimpleNamespace(CloudflareAPI=self.factory),
        }):
            return cloudflare_defaults.cloudflare_ready(self.base)

    def assert_no_remote_mutations(self):
        mutations = [call for call in self.api.method_calls
                     if call[0].startswith(("create_", "update_", "delete_", "ensure_"))]
        self.assertEqual(mutations, [])

    def test_explicit_public_rule_activates_without_legacy_toggle_or_global_email(self):
        code, payload = self.run_provider()
        self.assertEqual(code, 0)
        self.assertTrue(payload["considered"])
        self.assertTrue(payload["available"])
        self.assertTrue(payload["authenticated"])
        self.assertEqual(payload["errors"], [])
        self.assertEqual(payload["services"]["8000"]["url"], "https://8000.services.example.net")
        self.api.verify_token.assert_called_once_with()
        self.api.tunnel_connections.assert_called_once_with("account", "tunnel")
        self.api.zone.assert_called_once_with("zone")

    def test_token_without_rule_or_emails_does_not_publish(self):
        (self.base / "CITADEL_DATA/ports.filter.json").unlink()
        code, payload = self.run_provider()
        self.assertEqual(code, 0)
        self.assertFalse(payload["available"])
        self.assertEqual(payload["services"], {})
        self.assertTrue(payload["warnings"])
        self.api.create_tunnel_dns.assert_not_called()
        self.api.create_access_app.assert_not_called()

    def test_corrupt_policy_never_clears_working_routes(self):
        self.existing_protected_route()
        (self.base / "CITADEL_DATA/ports.filter.json").write_text("{invalid")
        self.assertEqual(self.run_provider()[0], 1)
        self.assert_no_remote_mutations()

    def existing_protected_route(self):
        self.settings.pop("CITADEL_CLOUDFLARE_SERVERSIDE_PERSISTENCE", None)
        hostname = "8000.services.example.net"
        self.api.tunnel_configuration.return_value = {"ingress": [
            {"hostname": hostname, "service": "http://127.0.0.1:8000",
             "originRequest": {"httpHostHeader": "127.0.0.1:8000"}},
            {"service": "http_status:404"}]}
        self.api.dns_records.return_value = [{"id": "dns", "name": hostname,
            "type": "CNAME", "content": "tunnel.cfargotunnel.com", "proxied": True, "ttl": 1}]
        policy = {"id": "policy", **access_policy_payload(hostname, ["user@example.net"])}
        policy.pop("precedence")  # Real reusable-policy responses omit this.
        self.api.access_policies.return_value = [policy]
        self.api.access_apps.return_value = [{"id": "app",
            **cloudflare_provider.access_app_payload(hostname, "policy")}]
        self.api.access_identity_providers.return_value = [{"type": "onetimepin"}]
        self.write("CITADEL_DATA/ports.filter.json", {"cloudflare": {"8000": {
            "whitelist": True, "emails": ["user@example.net"]}}})
        return hostname

    def test_default_preserves_remote_bindings_without_any_local_routes_file(self):
        self.existing_protected_route()
        for value in (None, "", "blank", "1", "true"):
            with self.subTest(value=value):
                if value is not None:
                    self.settings["CITADEL_CLOUDFLARE_SERVERSIDE_PERSISTENCE"] = value
                self.api.reset_mock()
                (self.base / "cache/cloudflare-routes.json").unlink(missing_ok=True)
                code, payload = self.run_provider()
                self.assertEqual(code, 0, payload["errors"])
                self.assertEqual(set(payload["services"]), {"8000"})
                self.assert_no_remote_mutations()

    def test_legacy_browser_ingress_gains_host_override_once_without_access_changes(self):
        self.existing_protected_route()
        self.api.tunnel_configuration.return_value["ingress"][0].pop("originRequest")
        code, payload = self.run_provider()
        self.assertEqual(code, 0, payload["errors"])
        self.api.update_tunnel_configuration.assert_called_once()
        updated = self.api.update_tunnel_configuration.call_args.args[-1]
        self.assertEqual(updated["ingress"][0]["originRequest"], {"httpHostHeader": "127.0.0.1:8000"})
        mutations = [call[0] for call in self.api.method_calls if call[0].startswith(("create_", "update_", "delete_"))]
        self.assertEqual(mutations, ["update_tunnel_configuration"])
        self.api.tunnel_configuration.return_value = updated
        self.api.reset_mock()
        self.assertEqual(self.run_provider()[0], 0)
        self.assert_no_remote_mutations()

    def test_persistent_public_route_does_not_create_access_or_rewrite_ingress(self):
        self.existing_protected_route()
        self.write("CITADEL_DATA/ports.filter.json", {"cloudflare": {"8000": {"whitelist": False}}})
        self.api.access_apps.return_value = []
        self.api.access_policies.return_value = []
        self.assertEqual(self.run_provider()[0], 0)
        self.assert_no_remote_mutations()

    def test_changed_email_blocks_only_affected_route_and_preserves_access_ids(self):
        self.existing_protected_route()
        untouched = {"hostname": "9000.services.example.net", "service": "http://127.0.0.1:9000"}
        self.api.tunnel_configuration.return_value["ingress"].insert(1, untouched)
        self.api.dns_records.return_value.append({"id": "dns-9000", "name": untouched["hostname"],
            "type": "CNAME", "content": "tunnel.cfargotunnel.com", "proxied": True, "ttl": 1})
        self.write("CITADEL_DATA/services.json", {"http_services": [
            {"port": 8000, "scheme": "http"}, {"port": 9000, "scheme": "http"}]})
        self.write("CITADEL_DATA/ports.filter.json", {"cloudflare": {"8000": {
            "whitelist": True, "emails": ["changed@example.net"]}, "9000": {"whitelist": False}}})
        self.assertEqual(self.run_provider()[0], 0)
        self.api.delete_dns_record.assert_not_called()
        self.api.create_tunnel_dns.assert_not_called()
        self.api.delete_access_app.assert_not_called()
        self.api.delete_access_policy.assert_not_called()
        self.api.update_access_policy.assert_called_once_with("account", "policy", {
            "name": "CITADEL email whitelist 8000.services.example.net", "decision": "allow",
            "include": [{"email": {"email": "changed@example.net"}}], "exclude": [], "require": []})
        self.api.update_access_app.assert_not_called()
        first = self.api.update_tunnel_configuration.call_args_list[0].args[2]["ingress"]
        self.assertEqual(first, [untouched, {"service": "http_status:404"}])
        mutations = [call[0] for call in self.api.method_calls if call[0].startswith(("update_", "delete_", "create_"))]
        self.assertEqual(mutations[0], "update_tunnel_configuration")
        self.assertEqual(mutations[-1], "update_tunnel_configuration")

    def test_access_update_failure_leaves_changed_route_blocked(self):
        self.existing_protected_route()
        self.api.access_policies.return_value[0]["decision"] = "bypass"
        self.api.update_access_policy.side_effect = CloudflareAPIError("update denied")
        code, payload = self.run_provider()
        self.assertEqual(code, 1)
        self.assertEqual(payload["services"], {})
        self.api.update_tunnel_configuration.assert_called_once()
        self.assertEqual(self.api.update_tunnel_configuration.call_args.args[2]["ingress"],
                         [{"service": "http_status:404"}])

    def test_persistence_still_removes_disappeared_service(self):
        self.existing_protected_route()
        self.write("CITADEL_DATA/services.json", {"http_services": []})
        self.assertEqual(self.run_provider()[0], 0)
        self.api.delete_access_app.assert_called_once_with("account", "app")
        self.api.delete_access_policy.assert_called_once_with("account", "policy")
        self.api.delete_dns_record.assert_called_once_with("zone", "dns")
        self.api.update_tunnel_configuration.assert_called_once()

    def test_invalid_persistence_value_never_mutates_remote_state(self):
        self.settings["CITADEL_CLOUDFLARE_SERVERSIDE_PERSISTENCE"] = "typo"
        code, payload = self.run_provider()
        self.assertEqual(code, 1)
        self.assertIn("must be a boolean", payload["errors"][0])
        self.assert_no_remote_mutations()

    def test_legacy_toggle_values_are_never_read_or_honored(self):
        for value in ("0", "false", "1", "true", "invalid", ""):
            with self.subTest(value=value):
                self.settings["CITADEL_CLOUDFLARE"] = value
                code, payload = self.run_provider()
                self.assertEqual(code, 0)
                self.assertTrue(payload["considered"])
                self.assertTrue(self.ready()[0])
        self.assertNotIn("CITADEL_CLOUDFLARE", [call.args[0] for call in self.getter.call_args_list])

    def test_production_sources_no_longer_reference_activation_toggle(self):
        for path in (Path(cloudflare_provider.__file__), Path(cloudflare_defaults.__file__)):
            with self.subTest(path=path):
                self.assertNotIn('"CITADEL_CLOUDFLARE"', path.read_text())
                self.assertNotIn("'CITADEL_CLOUDFLARE'", path.read_text())

    def test_missing_or_blank_token_skips_provider_and_defaults(self):
        self.settings["CITADEL_CLOUDFLARE"] = "1"
        for token in (None, "", " \t\n"):
            with self.subTest(token=token):
                if token is None:
                    self.settings.pop("CLOUDFLARE_API_TOKEN", None)
                else:
                    self.settings["CLOUDFLARE_API_TOKEN"] = token
                code, payload = self.run_provider()
                self.assertEqual(code, 0)
                self.assertFalse(payload["considered"])
                self.assertFalse(payload["available"])
                self.assertEqual(payload["errors"], [])
                self.assertEqual(payload["services"], {})
                self.assertEqual(health.snapshot(self.base, ["cloudflare"])["extensions"][0]["status"], "SKIP")
                self.assertEqual(self.ready(), (False, "CLOUDFLARE_API_TOKEN is missing"))
        self.factory.assert_not_called()

    def test_invalid_token_fails_without_resource_changes(self):
        self.api.verify_token.side_effect = CloudflareAPIError("invalid token")
        code, payload = self.run_provider()
        self.assertEqual(code, 1)
        self.assertFalse(payload["considered"])
        self.assertFalse(payload["authenticated"])
        self.assertEqual(payload["errors"], ["invalid token"])
        self.api.tunnel_connections.assert_not_called()
        self.api.zone.assert_not_called()
        self.assertEqual(self.ready(), (False, "invalid token"))
        self.assert_no_remote_mutations()

    def test_manifest_disabled_skips_even_with_token_and_old_toggle(self):
        self.manifest(enabled=False)
        self.settings["CITADEL_CLOUDFLARE"] = "1"
        code, payload = self.run_provider()
        self.assertEqual(code, 0)
        self.assertFalse(payload["considered"])
        self.assertFalse(payload["available"])
        self.assertEqual(payload["errors"], [])
        self.assertEqual(self.ready(), (False, "provider is disabled"))
        self.assertEqual(health.snapshot(self.base, ["cloudflare"])["extensions"][0]["status"], "SKIP")
        self.factory.assert_not_called()

    def test_disabled_folder_skips_even_with_valid_token(self):
        disabled = self.base / "extensions/disabled/cloudflare"
        disabled.parent.mkdir()
        self.provider_dir.rename(disabled)
        self.provider_dir = disabled
        code, payload = self.run_provider()
        self.assertEqual(code, 0)
        self.assertFalse(payload["considered"])
        self.assertEqual(payload["errors"], [])
        self.assertEqual(self.ready(), (False, "provider is disabled"))
        self.assertEqual(health.snapshot(self.base, ["cloudflare"])["extensions"][0]["status"], "SKIP")
        self.factory.assert_not_called()

    def test_dispatch_does_not_execute_disabled_manifest(self):
        self.manifest(enabled=False)
        with (patch.object(sys, "argv", [
                "dispatch.py", "--enabled-dir", str(self.base / "extensions/enabled"),
                "--services-file", str(self.base / "CITADEL_DATA/services.json"), "--cache-dir", str(self.base / "cache"),
                "--config-ini", str(self.base / "config.ini"),
                "--state-file", str(self.base / "CITADEL_DATA/providers_state.json"),
                "--tailscale-file", str(self.base / "tailscale.json"), "--provider", "cloudflare", "--strict",
              ]), patch.object(dispatch.subprocess, "run") as run):
            self.assertEqual(dispatch.main(), 0)
        run.assert_not_called()
        self.factory.assert_not_called()

    def test_valid_token_is_considered_but_missing_required_settings_fail(self):
        for key in ("CITADEL_CLOUDFLARE_DOMAIN", "CITADEL_CLOUDFLARE_ACCOUNT_ID",
                    "CITADEL_CLOUDFLARE_ZONE_ID", "CITADEL_CLOUDFLARE_TUNNEL_ID"):
            with self.subTest(key=key):
                saved = self.settings.pop(key)
                code, payload = self.run_provider()
                self.settings[key] = saved
                self.assertEqual(code, 1)
                self.assertTrue(payload["considered"])
                self.assertFalse(payload["available"])
                self.assertIn(key, payload["errors"][0])
        self.api.tunnel_connections.assert_not_called()
        self.assert_no_remote_mutations()

    def test_account_or_tunnel_failure_remains_error_after_token_verification(self):
        self.api.tunnel_connections.side_effect = CloudflareAPIError("account/tunnel unavailable")
        code, payload = self.run_provider()
        self.assertEqual(code, 1)
        self.assertTrue(payload["considered"])
        self.assertFalse(payload["available"])
        self.assertEqual(payload["errors"], ["account/tunnel unavailable"])
        self.api.zone.assert_not_called()
        self.assert_no_remote_mutations()

    def test_zone_domain_validation_precedes_any_resource_mutation(self):
        for zone in ({}, {"name": "other.example.org"}):
            with self.subTest(zone=zone):
                self.api.zone.return_value = zone
                code, payload = self.run_provider()
                self.assertEqual(code, 1)
                self.assertTrue(payload["considered"])
                self.assertFalse(payload["available"])
                self.assertTrue(payload["errors"])
        self.api.tunnel_configuration.assert_not_called()
        self.assert_no_remote_mutations()

    def test_subnet_setting_does_not_change_localhost_origin(self):
        self.settings["CITADEL_SUBNET_IP"] = "invalid/origin"
        code, payload = self.run_provider()
        self.assertEqual(code, 0)
        self.assertEqual(payload["origin_host"], "127.0.0.1")
        for port, route in payload["services"].items():
            self.assertRegex(route["target"], rf"^https?://127\.0\.0\.1:{port}$")

    def test_each_scan_replaces_managed_ingress_and_removes_disappeared_ports(self):
        self.write("extensions/enabled/cloudflare/routes.json", {
            "managed_hostnames": ["9999.services.example.net"],
            "dns_records": {"9999.services.example.net": "old-dns"},
            "services": {"9999": {"url": "https://9999.services.example.net"}},
        })
        manual = {"hostname": "manual.example.net", "service": "http://other:1234"}
        self.api.tunnel_configuration.return_value = {"ingress": [
            manual,
            {"hostname": "9999.services.example.net", "service": "http://127.0.0.1:9999"},
            {"service": "http_status:404"},
        ]}
        self.api.dns_records.return_value = [{"id": "old-dns", "name": "9999.services.example.net",
            "type": "CNAME", "content": "tunnel.cfargotunnel.com"}]
        code, payload = self.run_provider()
        self.assertEqual(code, 0)
        self.assertEqual(set(payload["services"]), {"8000"})
        ingress = self.api.update_tunnel_configuration.call_args.args[2]["ingress"]
        self.assertEqual(ingress, [{
            "hostname": "8000.services.example.net", "service": "http://127.0.0.1:8000",
            "originRequest": {"httpHostHeader": "127.0.0.1:8000"}},
            {"service": "http_status:404"}])
        self.api.delete_dns_record.assert_called_once_with("zone", "old-dns")
        self.assertEqual(self.api.update_tunnel_configuration.call_args_list[0].args[2]["ingress"],
                         [{"service": "http_status:404"}])

    def test_invalid_whitelist_still_prevents_resource_mutations(self):
        self.write("CITADEL_DATA/ports.filter.json", {"cloudflare": {"8000": {"whitelist": True, "emails": []}}})
        code, payload = self.run_provider()
        self.assertEqual(code, 1)
        self.assertTrue(payload["considered"])
        self.assertTrue(payload["errors"])
        self.assert_no_remote_mutations()

    def test_reset_keeps_access_ids_and_recreates_dns_without_local_ids(self):
        hostname = "8000.services.example.net"
        self.api.dns_records.return_value = [{"id": "remote-dns", "name": hostname,
            "type": "CNAME", "content": "tunnel.cfargotunnel.com"}]
        self.api.tunnel_configuration.return_value = {"ingress": [
            {"hostname": hostname, "service": "http://127.0.0.1:8000"}, {"service": "http_status:404"}]}
        self.api.access_apps.return_value = [{"id": "remote-app", "domain": hostname,
            "name": f"CITADEL {hostname}"}]
        self.api.access_policies.return_value = [{"id": "remote-policy",
            "name": f"CITADEL email whitelist {hostname}"}]
        self.api.access_identity_providers.return_value = [{"type": "onetimepin"}]
        self.write("CITADEL_DATA/ports.filter.json", {"cloudflare": {"8000": {
            "whitelist": True, "emails": ["user@example.net"]}}})
        for contents in ("not JSON", '{"dns_records":{"unrelated":"never-delete"}}'):
            (self.provider_dir / "routes.json").write_text(contents)
            self.api.reset_mock()
            code, payload = self.run_provider()
            self.assertEqual(code, 0, payload["errors"])
            for field in ("dns_records", "access_apps", "access_policies", "managed_hostnames"):
                self.assertNotIn(field, payload)
            self.api.delete_dns_record.assert_called_once_with("zone", "remote-dns")
            self.api.delete_access_app.assert_not_called()
            self.api.delete_access_policy.assert_not_called()
            self.api.update_access_app.assert_called_once()
            self.api.update_access_policy.assert_called_once()
            self.api.create_tunnel_dns.assert_called_once_with("zone", hostname, "tunnel")
            self.api.create_access_policy.assert_not_called()
            self.api.create_access_app.assert_not_called()
            calls = [call[0] for call in self.api.method_calls]
            self.assertLess(calls.index("update_tunnel_configuration"), calls.index("update_access_policy"))
            self.assertLess(calls.index("update_access_policy"), calls.index("delete_dns_record"))
            self.assertLess(calls.index("delete_dns_record"), calls.index("create_tunnel_dns"))
            self.assertEqual(calls[-1], "update_tunnel_configuration")

    def test_empty_scan_clears_the_configured_tunnel_without_a_routes_file(self):
        self.write("CITADEL_DATA/services.json", {"http_services": []})
        self.api.tunnel_configuration.return_value = {"ingress": [
            {"hostname": "old.example.net", "service": "http://127.0.0.1:5000"},
            {"service": "http_status:404"}], "warp-routing": {"enabled": False}}
        self.api.dns_records.return_value = [{"id": "old", "name": "old.example.net",
            "type": "CNAME", "content": "tunnel.cfargotunnel.com"}]
        code, payload = self.run_provider()
        self.assertEqual(code, 0, payload["errors"])
        self.api.delete_dns_record.assert_called_once_with("zone", "old")
        self.api.create_tunnel_dns.assert_not_called()
        self.api.create_access_app.assert_not_called()
        for call in self.api.update_tunnel_configuration.call_args_list:
            self.assertEqual(call.args[2]["ingress"], [{"service": "http_status:404"}])
            self.assertEqual(call.args[2]["warp-routing"], {"enabled": False})

    def test_other_tunnel_dns_and_access_objects_are_never_deleted(self):
        self.api.dns_records.return_value = [{"id": "foreign", "name": "other.example.net",
            "type": "CNAME", "content": "another-tunnel.cfargotunnel.com"}]
        self.api.access_apps.return_value = [{"id": "foreign-app", "domain": "other.example.net",
            "name": "CITADEL other.example.net"}]
        self.api.access_policies.return_value = [{"id": "foreign-policy",
            "name": "CITADEL email whitelist other.example.net"}]
        self.assertEqual(self.run_provider()[0], 0)
        self.api.delete_dns_record.assert_not_called()
        self.api.delete_access_app.assert_not_called()
        self.api.delete_access_policy.assert_not_called()

    def test_foreign_desired_dns_or_access_conflict_aborts_before_reset(self):
        hostname = "8000.services.example.net"
        for kind in ("dns", "access"):
            with self.subTest(kind=kind):
                self.api.reset_mock()
                self.api.dns_records.return_value = ([{"id": "foreign", "name": hostname,
                    "type": "CNAME", "content": "other.cfargotunnel.com"}] if kind == "dns" else [])
                self.api.access_apps.return_value = ([{"id": "foreign", "domain": hostname,
                    "name": "Manual application"}] if kind == "access" else [])
                code, payload = self.run_provider()
                self.assertEqual(code, 1)
                self.assertTrue(payload["errors"])
                self.assert_no_remote_mutations()

    def test_delete_failure_stops_before_any_route_recreation(self):
        self.api.dns_records.return_value = [{"id": "old", "name": "old.example.net",
            "type": "CNAME", "content": "tunnel.cfargotunnel.com"}]
        self.api.delete_dns_record.side_effect = CloudflareAPIError("delete denied")
        code, payload = self.run_provider()
        self.assertEqual(code, 1)
        self.assertEqual(payload["services"], {})
        self.api.create_tunnel_dns.assert_not_called()
        self.api.update_tunnel_configuration.assert_called_once()

    def test_create_failure_keeps_the_tunnel_empty(self):
        self.api.create_tunnel_dns.side_effect = CloudflareAPIError("create denied")
        code, payload = self.run_provider()
        self.assertEqual(code, 1)
        self.assertEqual(payload["services"], {})
        self.api.update_tunnel_configuration.assert_called_once()
        self.assertEqual(self.api.update_tunnel_configuration.call_args.args[2]["ingress"],
                         [{"service": "http_status:404"}])

    def test_incomplete_remote_inventory_aborts_before_reset(self):
        self.api.dns_records.side_effect = CloudflareAPIError("page unavailable")
        self.assertEqual(self.run_provider()[0], 1)
        self.assert_no_remote_mutations()

    def test_missing_or_invalid_scan_does_not_clear_working_routes(self):
        for scan in ({}, {"http_services": None}, {"http_services": "broken"},
                     {"http_services": [{"port": 0, "scheme": "http"}]}):
            with self.subTest(scan=scan):
                self.write("CITADEL_DATA/services.json", scan)
                code, payload = self.run_provider()
                self.assertEqual(code, 1)
                self.assertTrue(payload["errors"])
                self.assert_no_remote_mutations()

    def test_readiness_only_verifies_trimmed_token(self):
        self.settings["CLOUDFLARE_API_TOKEN"] = "  unit-test-token  "
        self.assertEqual(self.ready(), (True, "API token verified"))
        self.factory.assert_called_once_with("unit-test-token")
        self.api.verify_token.assert_called_once_with()
        self.assertEqual([call[0] for call in self.api.method_calls], ["verify_token"])


class CloudflareProviderTests(unittest.TestCase):
    def test_access_update_merges_complete_get_and_keeps_oauth_configuration(self):
        api = CloudflareAPI("unused-test-token")
        current = {"id": "app-id", "aud": "unchanged-audience", "name": "old",
                   "oauth_configuration": {"enabled": True, "grant": {"access_token_lifetime": "5m"}}}
        with patch.object(api, "request", side_effect=[current, {**current, "name": "new"}]) as request:
            api.update_access_app("account", "app-id", {"name": "new"})
        self.assertEqual(request.call_args_list[0].args, ("GET", "/accounts/account/access/apps/app-id"))
        self.assertEqual(request.call_args_list[1].kwargs["payload"], {**current, "name": "new"})

    def test_access_update_rejects_identity_changes_before_put(self):
        api = CloudflareAPI("unused-test-token")
        with patch.object(api, "request", return_value={"id": "another-app"}) as request:
            with self.assertRaises(CloudflareAPIError):
                api.update_access_app("account", "app-id", {"name": "new"})
            self.assertEqual(request.call_count, 1)

    def test_access_policy_uses_exact_email_rules(self) -> None:
        payload = access_policy_payload(
            "399.example.net",
            ["one@example.net", "two@example.net"],
        )
        self.assertEqual(payload["decision"], "allow")
        self.assertEqual(
            payload["include"],
            [
                {"email": {"email": "one@example.net"}},
                {"email": {"email": "two@example.net"}},
            ],
        )

    def test_one_time_pin_detection_is_exact(self) -> None:
        self.assertTrue(one_time_pin_enabled([{"type": "onetimepin"}]))
        self.assertFalse(one_time_pin_enabled([{"type": "google"}]))

    def test_access_initialization_creates_organization_and_otp(self) -> None:
        class FakeAPI:
            def access_organization(self, _account_id):
                raise CloudflareAPIError("not initialized")

            def create_access_organization(self, account_id, auth_domain, name):
                self.organization = (account_id, auth_domain, name)
                return {"auth_domain": auth_domain, "name": name}

            def access_identity_providers(self, _account_id):
                return []

            def create_access_identity_provider(self, account_id, payload):
                self.provider = (account_id, payload)
                return {"id": "otp", **payload}

        api = FakeAPI()
        providers = ensure_one_time_pin(api, "a" * 32, "example.net")
        self.assertEqual(api.organization[1], "citadel-aaaaaaaaaaaa.cloudflareaccess.com")
        self.assertEqual(api.organization[2], "example.net")
        self.assertEqual(api.provider[1]["type"], "onetimepin")
        self.assertTrue(one_time_pin_enabled(providers))

    def test_access_initialization_reuses_existing_otp(self) -> None:
        class FakeAPI:
            def access_organization(self, _account_id):
                return {"auth_domain": "existing.cloudflareaccess.com"}

            def access_identity_providers(self, _account_id):
                return [{"id": "otp", "type": "onetimepin"}]

        self.assertTrue(one_time_pin_enabled(ensure_one_time_pin(FakeAPI(), "account", "example.net")))


    def test_delete_is_idempotent_for_missing_resource(self) -> None:
        api = CloudflareAPI("token")

        def missing(*_args, **_kwargs):
            raise CloudflareAPIError("missing", status_code=404)

        api.request = missing
        api.delete_dns_record("zone", "record")
        api.delete_access_app("account", "app")
        api.delete_access_policy("account", "policy")


class CloudflareInventoryTests(unittest.TestCase):
    def test_dns_inventory_reads_all_pages(self):
        api = CloudflareAPI("test")
        api.request = Mock(side_effect=[
            [{"id": str(number)} for number in range(100)], [{"id": "last"}]])
        self.assertEqual(len(api.dns_records("zone")), 101)
        self.assertEqual(api.request.call_args.kwargs["query"], {"page": 2, "per_page": 100})

    def test_repeated_pages_or_invalid_resource_lists_are_rejected(self):
        api = CloudflareAPI("test")
        page = [{"id": str(number)} for number in range(100)]
        api.request = Mock(side_effect=[page, page])
        with self.assertRaises(CloudflareAPIError):
            api.dns_records("zone")
        for response in ({}, [None], [{"id": ""}]):
            api.request = Mock(return_value=response)
            with self.assertRaises(CloudflareAPIError):
                api.access_apps("account")

    def test_dns_is_always_created_not_upserted(self):
        api = CloudflareAPI("test")
        api.request = Mock(return_value={"id": "new-record"})
        self.assertEqual(api.create_tunnel_dns("zone", "8000.example.net", "tunnel"), "new-record")
        self.assertEqual(api.request.call_args.args, ("POST", "/zones/zone/dns_records"))
        self.assertEqual(api.request.call_args.kwargs["payload"]["content"], "tunnel.cfargotunnel.com")


class CloudflareCoreTests(unittest.TestCase):
    def test_batch_save_is_atomic_and_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "CITADEL_DATA").mkdir()
            services = base / "CITADEL_DATA/services.json"
            policy = base / "CITADEL_DATA/ports.filter.json"
            services.write_text(
                json.dumps(
                    {
                        "http_services": [
                            {"port": 12001},
                            {"port": 12002},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            old_services = core.SERVICES_FILE
            old_policy = core.PORT_FILTER_FILE
            core.SERVICES_FILE = services
            core.PORT_FILTER_FILE = policy
            try:
                saved = core.save_all_cloudflare_rules(
                    {
                        "12001": {
                            "subdomains": ["12001", "citadel"],
                            "whitelist": True,
                            "emails": ["user@example.net"],
                        },
                        "12002": {
                            "subdomains": ["12002"],
                            "whitelist": False,
                            "emails": [],
                        },
                    }
                )
                self.assertEqual(list(saved), ["12001", "12002"])
                self.assertEqual(saved["12001"]["subdomains"], ["12001", "citadel"])
                self.assertFalse(saved["12002"]["whitelist"])
                self.assertEqual(cloudflare_rules(policy), saved)
                with self.assertRaises(ValueError):
                    core.save_all_cloudflare_rules(
                        {
                            "12001": {"subdomains": ["same"], "whitelist": False},
                            "12002": {"subdomains": ["same"], "whitelist": False},
                        }
                    )
                with self.assertRaises(ValueError):
                    core.save_all_cloudflare_rules(
                        {
                            "12001": {"subdomains": ["12001"], "whitelist": False},
                            "12002": {"subdomains": ["12001"], "whitelist": False},
                        }
                    )
                self.assertEqual(cloudflare_rules(policy), saved)
            finally:
                core.SERVICES_FILE = old_services
                core.PORT_FILTER_FILE = old_policy


if __name__ == "__main__":
    unittest.main()
