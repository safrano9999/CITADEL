from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS_DIR = ROOT / "functions"
PROVIDERS_DIR = FUNCTIONS_DIR / "providers"
sys.path.insert(0, str(FUNCTIONS_DIR))
sys.path.insert(0, str(PROVIDERS_DIR))

import core  # noqa: E402


def load_subnet_provider():
    spec = importlib.util.spec_from_file_location(
        "citadel_subnet_provider",
        PROVIDERS_DIR / "subnet.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


subnet = load_subnet_provider()


class SubnetProviderTests(unittest.TestCase):
    def _run_provider(self, base: Path, configured_ip: str) -> dict:
        provider_dir = base / "extensions" / "enabled" / "subnet"
        provider_dir.mkdir(parents=True)
        (provider_dir / "extension.json").write_text(
            json.dumps({"label": "Subnet"}),
            encoding="utf-8",
        )
        services_file = base / "services.json"
        services_file.write_text(
            json.dumps(
                {
                    "http_services": [
                        {"port": 11000, "scheme": "http", "urls": {}}
                    ]
                }
            ),
            encoding="utf-8",
        )
        routes_out = provider_dir / "routes.json"
        argv = [
            "subnet.py",
            "--provider-dir",
            str(provider_dir),
            "--services-file",
            str(services_file),
            "--routes-out",
            str(routes_out),
        ]
        real_import = subnet.importlib.import_module

        def import_module(name: str):
            if name == "python_header":
                return SimpleNamespace(
                    get=lambda key, default="": (
                        configured_ip if key == "CITADEL_SUBNET_IP" else default
                    )
                )
            return real_import(name)

        with (
            patch.object(sys, "argv", argv),
            patch.object(subnet.importlib, "import_module", side_effect=import_module),
        ):
            self.assertEqual(subnet.main(), 0)
        return json.loads(routes_out.read_text(encoding="utf-8"))

    def test_empty_or_blank_subnet_is_silently_not_considered(self) -> None:
        for value in ("", "blank", " BLANK "):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as raw:
                payload = self._run_provider(Path(raw), value)
                self.assertFalse(payload["considered"])
                self.assertFalse(payload["available"])
                self.assertFalse(payload["default_candidate"])
                self.assertEqual(payload["services"], {})
                self.assertEqual(payload["errors"], [])

    def test_configured_subnet_remains_available(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            payload = self._run_provider(Path(raw), "10.89.3.1")
        self.assertTrue(payload["considered"])
        self.assertTrue(payload["available"])
        self.assertEqual(
            payload["services"]["11000"]["url"],
            "http://10.89.3.1:11000",
        )


class SubnetDashboardTests(unittest.TestCase):
    def test_blank_config_hides_stale_subnet_state_from_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            enabled = base / "enabled"
            provider = enabled / "subnet"
            provider.mkdir(parents=True)
            (provider / "extension.json").write_text(
                json.dumps({"label": "Subnet"}),
                encoding="utf-8",
            )
            (provider / "routes.json").write_text(
                json.dumps(
                    {
                        "considered": True,
                        "available": False,
                        "subnet_ip": "",
                        "services": {},
                        "errors": ["Missing CITADEL_SUBNET_IP"],
                    }
                ),
                encoding="utf-8",
            )
            state = base / "providers_state.json"
            state.write_text(
                json.dumps(
                    {
                        "considered_providers": ["subnet"],
                        "available_providers": [],
                        "errors": [],
                    }
                ),
                encoding="utf-8",
            )

            for value in ("", "blank"):
                with (
                    self.subTest(value=value),
                    patch.object(core, "ENABLED_EXT_DIR", enabled),
                    patch.object(core, "PROVIDERS_STATE_FILE", state),
                    patch.dict(os.environ, {"CITADEL_SUBNET_IP": value}),
                ):
                    dashboard = core._load_providers()
                    self.assertNotIn("subnet", dashboard["provider_options"])
                    self.assertFalse(
                        any("CITADEL_SUBNET_IP" in alert for alert in dashboard["alerts"])
                    )
                    self.assertFalse(
                        any("[subnet]" in alert for alert in dashboard["alerts"])
                    )


if __name__ == "__main__":
    unittest.main()
