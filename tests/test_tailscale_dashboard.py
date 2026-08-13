from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from functions import core


class TailscaleDashboardTests(unittest.TestCase):
    def test_one_provider_state_expands_to_default_http_and_https_dropdowns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            enabled = base / "enabled"
            provider = enabled / "tailscale"
            provider.mkdir(parents=True)
            (provider / "extension.json").write_text(
                json.dumps({"label": "Tailscale"}), encoding="utf-8"
            )
            (provider / "routes.json").write_text(
                json.dumps({
                    "considered": True,
                    "available": True,
                    "domain": "node.example.ts.net",
                    "variants": {
                        "default": {
                            "considered": True,
                            "available": True,
                            "services": {
                                "11000": {
                                    "url": "https://node.example.ts.net:11000"
                                }
                            },
                        },
                        "http": {
                            "label": "Tailscale HTTP",
                            "considered": True,
                            "available": True,
                            "services": {
                                "11000": {
                                    "url": "http://node.example.ts.net:25000"
                                }
                            },
                        },
                        "https": {
                            "label": "Tailscale HTTPS",
                            "considered": True,
                            "available": True,
                            "services": {
                                "11000": {
                                    "url": "https://node.example.ts.net:35000"
                                }
                            },
                        },
                    },
                }),
                encoding="utf-8",
            )
            state = base / "providers_state.json"
            state.write_text(
                json.dumps({
                    "considered_providers": ["tailscale"],
                    "available_providers": ["tailscale"],
                    "errors": [],
                }),
                encoding="utf-8",
            )

            old_enabled = core.ENABLED_EXT_DIR
            old_state = core.PROVIDERS_STATE_FILE
            try:
                core.ENABLED_EXT_DIR = enabled
                core.PROVIDERS_STATE_FILE = state
                providers = core._load_providers()
            finally:
                core.ENABLED_EXT_DIR = old_enabled
                core.PROVIDERS_STATE_FILE = old_state

            self.assertEqual(
                providers["provider_options"],
                {
                    "tailscale-default": "Tailscale Default",
                    "tailscale-http": "Tailscale HTTP",
                    "tailscale-https": "Tailscale HTTPS",
                },
            )
            self.assertNotIn("tailscale", providers["provider_options"])
            self.assertEqual(
                providers["provider_urls_by_port"]["tailscale-default"]["11000"],
                "https://node.example.ts.net:11000",
            )
            self.assertEqual(
                providers["provider_urls_by_port"]["tailscale-http"]["11000"],
                "http://node.example.ts.net:25000",
            )
            self.assertEqual(
                providers["provider_urls_by_port"]["tailscale-https"]["11000"],
                "https://node.example.ts.net:35000",
            )
            self.assertEqual(
                providers["provider_header_meta"],
                [{"label": "Tailscale", "value": "node.example.ts.net"}],
            )

    def test_disabled_variant_is_not_a_dropdown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            provider = base / "enabled" / "tailscale"
            provider.mkdir(parents=True)
            (provider / "extension.json").write_text("{}", encoding="utf-8")
            (provider / "routes.json").write_text(
                json.dumps({
                    "variants": {
                        "default": {
                            "considered": False,
                            "available": False,
                            "services": {},
                        },
                        "http": {
                            "considered": False,
                            "available": False,
                            "services": {},
                        },
                        "https": {
                            "considered": True,
                            "available": True,
                            "services": {
                                "11000": {
                                    "url": "https://node.example.ts.net:35000"
                                }
                            },
                        },
                    }
                }),
                encoding="utf-8",
            )
            state = base / "providers_state.json"
            state.write_text("{}", encoding="utf-8")

            old_enabled = core.ENABLED_EXT_DIR
            old_state = core.PROVIDERS_STATE_FILE
            try:
                core.ENABLED_EXT_DIR = base / "enabled"
                core.PROVIDERS_STATE_FILE = state
                providers = core._load_providers()
            finally:
                core.ENABLED_EXT_DIR = old_enabled
                core.PROVIDERS_STATE_FILE = old_state

            self.assertNotIn("tailscale-default", providers["provider_options"])
            self.assertNotIn("tailscale-http", providers["provider_options"])
            self.assertIn("tailscale-https", providers["provider_options"])


if __name__ == "__main__":
    unittest.main()
