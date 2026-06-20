from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))
sys.path.insert(0, str(ROOT / "functions" / "providers"))

from cloudflare_policy import (  # noqa: E402
    cloudflare_rules,
    normalize_rule,
    resolve_hostname,
    write_cloudflare_rules,
)
from cloudflare import (  # noqa: E402
    access_policy_payload,
    assert_ingress_ownership,
    one_time_pin_enabled,
    reconcile_access,
    remove_managed_ingress,
)
from cloudflare_api import CloudflareAPI, CloudflareAPIError  # noqa: E402
import core  # noqa: E402


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
                        "subdomain": "citadel",
                        "whitelist": True,
                        "emails": ["USER@example.net", "user@example.net"],
                    }
                },
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["whitelist"], [399])
            self.assertEqual(payload["blacklist"], [400])
            self.assertEqual(
                cloudflare_rules(path)["399"]["emails"],
                ["user@example.net"],
            )


class CloudflareProviderTests(unittest.TestCase):
    def test_preserves_foreign_ingress_and_keeps_fallback(self) -> None:
        config = {
            "ingress": [
                {"hostname": "foreign.example.net", "service": "http://127.0.0.1:1"},
                {"hostname": "399.example.net", "service": "http://127.0.0.1:399"},
                {"service": "http_status:404"},
            ]
        }
        preserved, fallback = remove_managed_ingress(config, {"399.example.net"})
        self.assertEqual([item.get("hostname") for item in preserved], ["foreign.example.net"])
        self.assertEqual(fallback, {"service": "http_status:404"})

    def test_refuses_unmanaged_ingress_for_desired_hostname(self) -> None:
        config = {
            "ingress": [
                {"hostname": "399.example.net", "service": "http://other:399"},
                {"service": "http_status:404"},
            ]
        }
        with self.assertRaises(CloudflareAPIError):
            assert_ingress_ownership(config, {"399.example.net"}, set())
        assert_ingress_ownership(
            config,
            {"399.example.net"},
            {"399.example.net"},
        )

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

    def test_access_refuses_unmanaged_application(self) -> None:
        class FakeAPI:
            def access_apps(self, _account_id):
                return [{"id": "foreign", "domain": "399.example.net", "name": "Foreign"}]

            def access_policies(self, _account_id):
                return []

        with self.assertRaises(CloudflareAPIError):
            reconcile_access(
                FakeAPI(),
                "account",
                {
                    "399.example.net": {
                        "whitelist": True,
                        "emails": ["user@example.net"],
                    }
                },
                {},
                {},
                {},
                {},
            )

    def test_dns_refuses_unmanaged_record(self) -> None:
        api = CloudflareAPI("token")

        def request(method, _path, **_kwargs):
            if method == "GET":
                return [{"id": "foreign", "type": "CNAME"}]
            return {}

        api.request = request
        with self.assertRaises(CloudflareAPIError):
            api.ensure_tunnel_dns("zone", "399.example.net", "tunnel")

    def test_delete_is_idempotent_for_missing_resource(self) -> None:
        api = CloudflareAPI("token")

        def missing(*_args, **_kwargs):
            raise CloudflareAPIError("missing", status_code=404)

        api.request = missing
        api.delete_dns_record("zone", "record")
        api.delete_access_app("account", "app")
        api.delete_access_policy("account", "policy")


class CloudflareCoreTests(unittest.TestCase):
    def test_batch_save_is_atomic_and_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            services = base / "services.json"
            policy = base / "ports.filter.json"
            services.write_text(
                json.dumps(
                    {
                        "http_services": [
                            {"port": 399},
                            {"port": 440},
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
                        "399": {
                            "subdomain": "citadel",
                            "whitelist": True,
                            "emails": ["user@example.net"],
                        },
                        "440": {
                            "subdomain": "",
                            "whitelist": False,
                            "emails": [],
                        },
                    }
                )
                self.assertEqual(list(saved), ["399"])
                self.assertEqual(cloudflare_rules(policy), saved)
                with self.assertRaises(ValueError):
                    core.save_all_cloudflare_rules(
                        {
                            "399": {"subdomain": "same", "whitelist": False},
                            "440": {"subdomain": "same", "whitelist": False},
                        }
                    )
                with self.assertRaises(ValueError):
                    core.save_all_cloudflare_rules(
                        {
                            "399": {"subdomain": "", "whitelist": False},
                            "440": {"subdomain": "399", "whitelist": False},
                        }
                    )
                self.assertEqual(cloudflare_rules(policy), saved)
            finally:
                core.SERVICES_FILE = old_services
                core.PORT_FILTER_FILE = old_policy


if __name__ == "__main__":
    unittest.main()
