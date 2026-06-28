from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PROVIDERS_DIR = ROOT / "functions" / "providers"
sys.path.insert(0, str(PROVIDERS_DIR))

from common import route_record  # noqa: E402


def load_tailscale_provider():
    spec = importlib.util.spec_from_file_location(
        "citadel_tailscale_provider",
        PROVIDERS_DIR / "tailscale.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


tailscale = load_tailscale_provider()


class RouteSchemaTests(unittest.TestCase):
    def test_common_route_record(self) -> None:
        self.assertEqual(
            route_record(
                "proxy",
                "https://node.example.ts.net:8077",
                target="http://127.0.0.1:8077",
                owns_listener=True,
            ),
            {
                "mode": "proxy",
                "url": "https://node.example.ts.net:8077",
                "target": "http://127.0.0.1:8077",
                "owns_listener": True,
            },
        )

    def test_tailscale_auto_mode_uses_direct_for_overlapping_listeners(self) -> None:
        tailscale_ips = {"100.64.0.10", "fd7a:115c:a1e0::10"}
        self.assertEqual(
            tailscale.resolve_route_mode("auto", {"addrs": ["0.0.0.0", "::"]}, tailscale_ips),
            "direct",
        )
        self.assertEqual(
            tailscale.resolve_route_mode("auto", {"addr": "100.64.0.10"}, tailscale_ips),
            "direct",
        )
        self.assertEqual(
            tailscale.resolve_route_mode("auto", {"addr": "127.0.0.1"}, tailscale_ips),
            "proxy",
        )
        self.assertEqual(
            tailscale.resolve_route_mode(
                "auto",
                {
                    "listeners": [
                        {"addr": "127.0.0.1", "process": "python"},
                        {"addr": "100.64.0.10", "process": "tailscaled"},
                    ]
                },
                tailscale_ips,
            ),
            "proxy",
        )

    def test_tailscale_scan_removes_conflict_and_keeps_loopback_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            provider_dir = base / "extensions" / "enabled" / "tailscale"
            provider_dir.mkdir(parents=True)
            (provider_dir / "extension.json").write_text(
                json.dumps({"label": "Tailscale"}),
                encoding="utf-8",
            )
            (provider_dir / "config.ini").write_text(
                "[provider]\nlabel = Tailscale\nfetch = true\nroute_mode = auto\n",
                encoding="utf-8",
            )
            services_file = base / "services.json"
            services_file.write_text(
                json.dumps({
                    "http_services": [
                        {
                            "port": 18789,
                            "addr": "0.0.0.0",
                            "addrs": ["0.0.0.0", "::"],
                            "scheme": "http",
                            "urls": {"localhost": "http://127.0.0.1:18789"},
                        },
                        {
                            "port": 8077,
                            "addr": "127.0.0.1",
                            "addrs": ["127.0.0.1"],
                            "scheme": "http",
                            "urls": {"localhost": "http://127.0.0.1:8077"},
                        },
                    ]
                }),
                encoding="utf-8",
            )
            cache_dir = base / "cache"
            cache_dir.mkdir()
            routes_out = provider_dir / "routes.json"
            tailscale_file = base / "tailscale.json"
            tailscale_file.write_text(
                json.dumps({"managed_ports": ["18789"]}),
                encoding="utf-8",
            )
            config_ini = base / "config.ini"
            commands: list[list[str]] = []

            def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                if command[:3] == ["tailscale", "status", "--json"]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        json.dumps({
                            "BackendState": "Running",
                            "CertDomains": ["node.example.ts.net"],
                            "Self": {
                                "DNSName": "node.example.ts.net.",
                                "TailscaleIPs": ["100.64.0.10", "fd7a:115c:a1e0::10"],
                            },
                        }),
                        "",
                    )
                if command == ["tailscale", "serve", "--yes", "--https=18789", "off"]:
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        "",
                        "error: failed to remove web serve: handler does not exist",
                    )
                return subprocess.CompletedProcess(command, 0, "", "")

            argv = [
                "tailscale.py",
                "--provider-dir", str(provider_dir),
                "--services-file", str(services_file),
                "--cache-dir", str(cache_dir),
                "--config-ini", str(config_ini),
                "--routes-out", str(routes_out),
                "--tailscale-file", str(tailscale_file),
            ]
            with (
                patch.object(tailscale, "run", side_effect=fake_run),
                patch.object(tailscale, "citadel_bool", return_value=True),
                patch.object(tailscale.shutil, "which", return_value="/usr/bin/tailscale"),
                patch.object(sys, "argv", argv),
            ):
                self.assertEqual(tailscale.main(), 0)

            payload = json.loads(routes_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["route_schema"], 1)
            self.assertEqual(
                payload["services"]["18789"],
                {
                    "mode": "direct",
                    "url": "http://node.example.ts.net:18789",
                    "target": None,
                    "owns_listener": False,
                },
            )
            self.assertEqual(
                payload["services"]["8077"],
                {
                    "mode": "proxy",
                    "url": "https://node.example.ts.net:8077",
                    "target": "http://127.0.0.1:8077",
                    "owns_listener": True,
                },
            )
            self.assertEqual(payload["managed_ports"], ["8077"])
            self.assertIn(
                ["tailscale", "serve", "--yes", "--https=18789", "off"],
                commands,
            )
            self.assertIn(
                [
                    "tailscale", "serve", "--bg", "--yes", "--https=8077",
                    "http://127.0.0.1:8077",
                ],
                commands,
            )
            self.assertNotIn(
                [
                    "tailscale", "serve", "--bg", "--yes", "--https=18789",
                    "http://127.0.0.1:18789",
                ],
                commands,
            )


if __name__ == "__main__":
    unittest.main()
