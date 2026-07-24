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
    def make_fixture(
        self,
        base: Path,
        services: list[dict],
        previous_state: dict | None = None,
        *,
        route_mode: str = "auto",
    ) -> dict[str, Path]:
        provider_dir = base / "extensions" / "enabled" / "tailscale"
        provider_dir.mkdir(parents=True)
        (provider_dir / "extension.json").write_text(
            json.dumps({"label": "Tailscale"}),
            encoding="utf-8",
        )
        (provider_dir / "config.ini").write_text(
            (
                "[provider]\n"
                "label = Tailscale\n"
                "fetch = true\n"
                f"route_mode = {route_mode}\n"
            ),
            encoding="utf-8",
        )
        services_file = base / "services.json"
        services_file.write_text(
            json.dumps({"http_services": services}),
            encoding="utf-8",
        )
        cache_dir = base / "cache"
        cache_dir.mkdir()
        routes_out = provider_dir / "routes.json"
        tailscale_file = base / "tailscale.json"
        if previous_state is not None:
            tailscale_file.write_text(json.dumps(previous_state), encoding="utf-8")
        return {
            "provider_dir": provider_dir,
            "services_file": services_file,
            "cache_dir": cache_dir,
            "routes_out": routes_out,
            "tailscale_file": tailscale_file,
            "config_ini": base / "config.ini",
        }

    def run_provider(
        self,
        paths: dict[str, Path],
        serve_results: dict[tuple[str, str, str], tuple[int, str]] | None = None,
        *,
        live_serve_status: dict | None = None,
        serve_status_error: str | None = None,
        tailscale_running: bool = True,
    ) -> tuple[dict, list[list[str]]]:
        commands: list[list[str]] = []
        configured_results = serve_results or {}

        def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command[:3] == ["tailscale", "status", "--json"]:
                if not tailscale_running:
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        "",
                        "tailscale status unavailable",
                    )
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps({
                        "BackendState": "Running",
                        "CertDomains": ["node.example.ts.net"],
                        "Self": {
                            "DNSName": "node.example.ts.net.",
                            "TailscaleIPs": [
                                "100.64.0.10",
                                "fd7a:115c:a1e0::10",
                            ],
                        },
                    }),
                    "",
                )
            if command == ["tailscale", "serve", "status", "--json"]:
                if serve_status_error is not None:
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        "",
                        serve_status_error,
                    )
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(live_serve_status or {}),
                    "",
                )
            if command[:2] == ["tailscale", "serve"]:
                flag = next(
                    item
                    for item in command
                    if item.startswith("--https=") or item.startswith("--http=")
                )
                public_scheme, port = flag[2:].split("=", 1)
                action = "off" if command[-1] == "off" else "apply"
                returncode, stderr = configured_results.get(
                    (public_scheme, port, action),
                    (0, ""),
                )
                return subprocess.CompletedProcess(command, returncode, "", stderr)
            return subprocess.CompletedProcess(command, 0, "", "")

        argv = [
            "tailscale.py",
            "--provider-dir", str(paths["provider_dir"]),
            "--services-file", str(paths["services_file"]),
            "--cache-dir", str(paths["cache_dir"]),
            "--config-ini", str(paths["config_ini"]),
            "--routes-out", str(paths["routes_out"]),
            "--tailscale-file", str(paths["tailscale_file"]),
        ]
        with (
            patch.object(tailscale, "run", side_effect=fake_run),
            patch.object(tailscale, "citadel_bool", return_value=True),
            patch.object(tailscale.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(sys, "argv", argv),
        ):
            self.assertEqual(tailscale.main(), 0)

        payload = json.loads(paths["routes_out"].read_text(encoding="utf-8"))
        return payload, commands

    @staticmethod
    def live_route(
        port: int,
        public_scheme: str,
        target: str,
        *,
        handlers: dict | None = None,
    ) -> dict:
        listener = {"HTTPS": True} if public_scheme == "https" else {"HTTP": True}
        return {
            "TCP": {str(port): listener},
            "Web": {
                f"node.example.ts.net:{port}": {
                    "Handlers": handlers or {"/": {"Proxy": target}},
                },
            },
        }

    @staticmethod
    def serve_mutations(commands: list[list[str]]) -> list[list[str]]:
        return [
            command
            for command in commands
            if command[:2] == ["tailscale", "serve"]
            and command != ["tailscale", "serve", "status", "--json"]
        ]

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

    def test_new_wildcard_service_prefers_https_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            paths = self.make_fixture(
                base,
                [{
                    "port": 18789,
                    "addr": "0.0.0.0",
                    "addrs": ["0.0.0.0", "::"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:18789"},
                }],
            )
            payload, commands = self.run_provider(paths)

            self.assertEqual(payload["route_schema"], 1)
            self.assertEqual(
                payload["services"]["18789"],
                {
                    "mode": "proxy",
                    "url": "https://node.example.ts.net:18789",
                    "target": "http://127.0.0.1:18789",
                    "owns_listener": True,
                },
            )
            self.assertEqual(payload["managed_ports"], ["18789"])
            self.assertEqual(payload["managed_routes"], {"18789": "https"})
            self.assertIn(
                [
                    "tailscale", "serve", "--bg", "--yes", "--https=18789",
                    "http://127.0.0.1:18789",
                ],
                commands,
            )
            self.assertNotIn(
                [
                    "tailscale", "serve", "--bg", "--yes", "--http=18789",
                    "http://127.0.0.1:18789",
                ],
                commands,
            )

    def test_https_failure_uses_sticky_http_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            paths = self.make_fixture(
                base,
                [{
                    "port": 11000,
                    "addr": "0.0.0.0",
                    "addrs": ["0.0.0.0"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:11000"},
                }],
            )
            first_payload, first_commands = self.run_provider(
                paths,
                {("https", "11000", "apply"): (1, "certificate unavailable")},
            )

            self.assertEqual(
                first_payload["services"]["11000"],
                {
                    "mode": "proxy",
                    "url": "http://node.example.ts.net:11000",
                    "target": "http://127.0.0.1:11000",
                    "owns_listener": True,
                },
            )
            self.assertEqual(first_payload["managed_routes"], {"11000": "http"})
            self.assertEqual(first_payload["fallbacks"]["11000"]["to"], "http")
            self.assertLess(
                first_commands.index([
                    "tailscale", "serve", "--bg", "--yes", "--https=11000",
                    "http://127.0.0.1:11000",
                ]),
                first_commands.index([
                    "tailscale", "serve", "--bg", "--yes", "--http=11000",
                    "http://127.0.0.1:11000",
                ]),
            )

            second_payload, second_commands = self.run_provider(
                paths,
                {
                    ("https", "11000", "apply"): (1, "must not be called"),
                    ("http", "11000", "apply"): (1, "must not be called"),
                },
            )
            self.assertEqual(
                second_payload["services"]["11000"]["url"],
                "http://node.example.ts.net:11000",
            )
            self.assertEqual(
                [command for command in second_commands if command[:2] == ["tailscale", "serve"]],
                [],
            )

    def test_unchanged_https_route_is_not_reapplied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            previous_state = {
                "route_mode": "auto",
                "services": {
                    "8077": {
                        "mode": "proxy",
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "owns_listener": True,
                    }
                },
                "serve_routes": {
                    "8077": {
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "active": True,
                    }
                },
                "managed_ports": ["8077"],
                "managed_routes": {"8077": "https"},
                "service_signatures": {
                    "8077": {
                        "origin_scheme": "http",
                        "direct_capable": False,
                        "route_mode": "auto",
                    }
                },
            }
            paths = self.make_fixture(
                base,
                [{
                    "port": 8077,
                    "addr": "127.0.0.1",
                    "addrs": ["127.0.0.1"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:8077"},
                }],
                previous_state,
            )
            payload, commands = self.run_provider(paths)

            self.assertEqual(
                payload["services"]["8077"]["url"],
                "https://node.example.ts.net:8077",
            )
            self.assertEqual(
                [command for command in commands if command[:2] == ["tailscale", "serve"]],
                [],
            )

    def test_stale_http_listener_is_removed_with_its_public_scheme(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            paths = self.make_fixture(
                base,
                [],
                {
                    "services": {
                        "11000": {
                            "mode": "proxy",
                            "url": "http://node.example.ts.net:11000",
                            "target": "http://127.0.0.1:11000",
                            "owns_listener": True,
                        }
                    },
                    "managed_ports": ["11000"],
                    "managed_routes": {"11000": "http"},
                },
            )
            payload, commands = self.run_provider(
                paths,
                live_serve_status=self.live_route(
                    11000,
                    "http",
                    "http://127.0.0.1:11000",
                ),
            )

            self.assertIn(
                ["tailscale", "serve", "--yes", "--http=11000", "off"],
                commands,
            )
            self.assertNotIn(
                ["tailscale", "serve", "--yes", "--https=11000", "off"],
                commands,
            )
            self.assertEqual(payload["managed_ports"], [])

    def test_total_failure_for_loopback_service_is_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            paths = self.make_fixture(
                base,
                [{
                    "port": 8077,
                    "addr": "127.0.0.1",
                    "addrs": ["127.0.0.1"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:8077"},
                }],
            )
            failures = {
                ("https", "8077", "apply"): (1, "https failed"),
                ("http", "8077", "apply"): (1, "http failed"),
            }
            first_payload, _ = self.run_provider(paths, failures)
            self.assertNotIn("8077", first_payload["services"])
            self.assertIn("8077", first_payload["route_failures"])

            second_payload, second_commands = self.run_provider(paths, failures)
            self.assertNotIn("8077", second_payload["services"])
            self.assertIn("8077", second_payload["route_failures"])
            self.assertEqual(
                [command for command in second_commands if command[:2] == ["tailscale", "serve"]],
                [],
            )

    def test_legacy_direct_route_is_reused_without_upgrade_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            paths = self.make_fixture(
                base,
                [{
                    "port": 18789,
                    "addr": "0.0.0.0",
                    "addrs": ["0.0.0.0"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:18789"},
                }],
                {
                    "services": {
                        "18789": "http://node.example.ts.net:18789",
                    },
                    "managed_ports": [],
                },
            )
            payload, commands = self.run_provider(paths)

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
                [command for command in commands if command[:2] == ["tailscale", "serve"]],
                [],
            )

    def test_foreign_live_listener_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            paths = self.make_fixture(
                base,
                [{
                    "port": 40010,
                    "addr": "127.0.0.1",
                    "addrs": ["127.0.0.1"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:40010"},
                }],
            )
            payload, commands = self.run_provider(
                paths,
                live_serve_status=self.live_route(
                    40010,
                    "https",
                    "http://127.0.0.1:9999",
                ),
            )

            self.assertEqual(self.serve_mutations(commands), [])
            self.assertNotIn("40010", payload["services"])
            self.assertEqual(payload["managed_routes"], {})
            self.assertIn("not managed by CITADEL", payload["route_failures"]["40010"])
            self.assertTrue(
                payload["service_signatures"]["40010"]["pending_reconciliation"]
            )

    def test_changed_managed_listener_is_verified_then_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            previous_state = {
                "services": {
                    "8077": {
                        "mode": "proxy",
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "owns_listener": True,
                    },
                },
                "serve_routes": {
                    "8077": {
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "active": True,
                    },
                },
                "managed_routes": {"8077": "https"},
                "managed_ports": ["8077"],
                "service_signatures": {
                    "8077": {
                        "origin_scheme": "http",
                        "direct_capable": False,
                        "route_mode": "auto",
                    },
                },
            }
            paths = self.make_fixture(
                base,
                [{
                    "port": 8077,
                    "addr": "127.0.0.1",
                    "addrs": ["127.0.0.1"],
                    "scheme": "https",
                    "urls": {"localhost": "https://127.0.0.1:8077"},
                }],
                previous_state,
            )
            payload, commands = self.run_provider(
                paths,
                live_serve_status=self.live_route(
                    8077,
                    "https",
                    "http://127.0.0.1:8077",
                ),
            )

            mutations = self.serve_mutations(commands)
            self.assertLess(
                mutations.index(
                    ["tailscale", "serve", "--yes", "--https=8077", "off"]
                ),
                mutations.index([
                    "tailscale", "serve", "--bg", "--yes", "--https=8077",
                    "https+insecure://127.0.0.1:8077",
                ]),
            )
            self.assertEqual(
                payload["services"]["8077"]["target"],
                "https+insecure://127.0.0.1:8077",
            )

    def test_changed_managed_listener_releases_mismatched_live_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            previous_state = {
                "services": {
                    "8077": {
                        "mode": "proxy",
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "owns_listener": True,
                    },
                },
                "serve_routes": {
                    "8077": {
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "active": True,
                    },
                },
                "managed_routes": {"8077": "https"},
                "managed_ports": ["8077"],
                "service_signatures": {
                    "8077": {
                        "origin_scheme": "http",
                        "direct_capable": False,
                        "route_mode": "auto",
                    },
                },
            }
            paths = self.make_fixture(
                base,
                [{
                    "port": 8077,
                    "addr": "127.0.0.1",
                    "addrs": ["127.0.0.1"],
                    "scheme": "https",
                    "urls": {"localhost": "https://127.0.0.1:8077"},
                }],
                previous_state,
            )
            payload, commands = self.run_provider(
                paths,
                live_serve_status=self.live_route(
                    8077,
                    "https",
                    "http://127.0.0.1:9999",
                ),
            )

            self.assertEqual(self.serve_mutations(commands), [])
            self.assertEqual(payload["managed_routes"], {})
            self.assertNotIn("8077", payload["services"])
            self.assertIn(
                "released from CITADEL management",
                payload["route_failures"]["8077"],
            )

    def test_temporary_tailscale_outage_preserves_sticky_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            paths = self.make_fixture(
                base,
                [{
                    "port": 11000,
                    "addr": "0.0.0.0",
                    "addrs": ["0.0.0.0"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:11000"},
                }],
            )
            first_payload, _ = self.run_provider(paths)
            self.assertEqual(first_payload["managed_routes"], {"11000": "https"})

            outage_payload, outage_commands = self.run_provider(
                paths,
                tailscale_running=False,
            )
            self.assertEqual(outage_payload["services"], {})
            self.assertEqual(outage_payload["managed_routes"], {"11000": "https"})
            self.assertIn("11000", outage_payload["remembered_services"])
            self.assertEqual(self.serve_mutations(outage_commands), [])

            recovered_payload, recovered_commands = self.run_provider(paths)
            self.assertEqual(
                recovered_payload["services"]["11000"]["url"],
                "https://node.example.ts.net:11000",
            )
            self.assertEqual(
                [
                    command
                    for command in recovered_commands
                    if command[:2] == ["tailscale", "serve"]
                ],
                [],
            )

    def test_inactive_recorded_listener_is_recreated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            previous_state = {
                "services": {
                    "8077": {
                        "mode": "proxy",
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "owns_listener": True,
                    },
                },
                "serve_routes": {
                    "8077": {
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "active": False,
                    },
                },
                "managed_routes": {"8077": "https"},
                "managed_ports": ["8077"],
                "service_signatures": {
                    "8077": {
                        "origin_scheme": "http",
                        "direct_capable": False,
                        "route_mode": "auto",
                    },
                },
            }
            paths = self.make_fixture(
                base,
                [{
                    "port": 8077,
                    "addr": "127.0.0.1",
                    "addrs": ["127.0.0.1"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:8077"},
                }],
                previous_state,
            )
            payload, commands = self.run_provider(paths)

            self.assertIn(
                [
                    "tailscale", "serve", "--bg", "--yes", "--https=8077",
                    "http://127.0.0.1:8077",
                ],
                commands,
            )
            self.assertTrue(payload["serve_routes"]["8077"]["active"])

    def test_explicit_direct_mode_does_not_reuse_legacy_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            previous_state = {
                "services": {
                    "18789": {
                        "mode": "proxy",
                        "url": "https://node.example.ts.net:18789",
                        "target": "http://127.0.0.1:18789",
                        "owns_listener": True,
                    },
                },
                "serve_routes": {
                    "18789": {
                        "url": "https://node.example.ts.net:18789",
                        "target": "http://127.0.0.1:18789",
                        "active": True,
                    },
                },
                "managed_routes": {"18789": "https"},
                "managed_ports": ["18789"],
            }
            paths = self.make_fixture(
                base,
                [{
                    "port": 18789,
                    "addr": "0.0.0.0",
                    "addrs": ["0.0.0.0"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:18789"},
                }],
                previous_state,
                route_mode="direct",
            )
            payload, commands = self.run_provider(
                paths,
                live_serve_status=self.live_route(
                    18789,
                    "https",
                    "http://127.0.0.1:18789",
                ),
            )

            self.assertIn(
                ["tailscale", "serve", "--yes", "--https=18789", "off"],
                commands,
            )
            self.assertEqual(payload["services"]["18789"]["mode"], "direct")
            self.assertEqual(payload["managed_routes"], {})

    def test_failed_replacement_removal_is_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            previous_state = {
                "services": {
                    "8077": {
                        "mode": "proxy",
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "owns_listener": True,
                    },
                },
                "serve_routes": {
                    "8077": {
                        "url": "https://node.example.ts.net:8077",
                        "target": "http://127.0.0.1:8077",
                        "active": True,
                    },
                },
                "managed_routes": {"8077": "https"},
                "managed_ports": ["8077"],
                "service_signatures": {
                    "8077": {
                        "origin_scheme": "http",
                        "direct_capable": False,
                        "route_mode": "auto",
                    },
                },
            }
            paths = self.make_fixture(
                base,
                [{
                    "port": 8077,
                    "addr": "127.0.0.1",
                    "addrs": ["127.0.0.1"],
                    "scheme": "https",
                    "urls": {"localhost": "https://127.0.0.1:8077"},
                }],
                previous_state,
            )
            first_payload, first_commands = self.run_provider(
                paths,
                {("https", "8077", "off"): (1, "temporary removal failure")},
                live_serve_status=self.live_route(
                    8077,
                    "https",
                    "http://127.0.0.1:8077",
                ),
            )

            self.assertEqual(
                self.serve_mutations(first_commands),
                [["tailscale", "serve", "--yes", "--https=8077", "off"]],
            )
            self.assertTrue(
                first_payload["service_signatures"]["8077"][
                    "pending_reconciliation"
                ]
            )
            self.assertEqual(first_payload["managed_routes"], {"8077": "https"})

            second_payload, second_commands = self.run_provider(
                paths,
                live_serve_status=self.live_route(
                    8077,
                    "https",
                    "http://127.0.0.1:8077",
                ),
            )
            self.assertIn(
                ["tailscale", "serve", "--yes", "--https=8077", "off"],
                second_commands,
            )
            self.assertIn(
                [
                    "tailscale", "serve", "--bg", "--yes", "--https=8077",
                    "https+insecure://127.0.0.1:8077",
                ],
                second_commands,
            )
            self.assertNotIn(
                "pending_reconciliation",
                second_payload["service_signatures"]["8077"],
            )

    def test_serve_status_error_is_retried_instead_of_becoming_sticky(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            paths = self.make_fixture(
                base,
                [{
                    "port": 40010,
                    "addr": "127.0.0.1",
                    "addrs": ["127.0.0.1"],
                    "scheme": "http",
                    "urls": {"localhost": "http://127.0.0.1:40010"},
                }],
            )
            first_payload, first_commands = self.run_provider(
                paths,
                serve_status_error="local API unavailable",
            )
            self.assertEqual(self.serve_mutations(first_commands), [])
            self.assertTrue(
                first_payload["service_signatures"]["40010"][
                    "pending_reconciliation"
                ]
            )

            second_payload, second_commands = self.run_provider(paths)
            self.assertIn(
                [
                    "tailscale", "serve", "--bg", "--yes", "--https=40010",
                    "http://127.0.0.1:40010",
                ],
                second_commands,
            )
            self.assertIn("40010", second_payload["services"])

    def test_stale_listener_with_foreign_handler_is_left_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            paths = self.make_fixture(
                base,
                [],
                {
                    "services": {
                        "11000": {
                            "mode": "proxy",
                            "url": "https://node.example.ts.net:11000",
                            "target": "http://127.0.0.1:11000",
                            "owns_listener": True,
                        },
                    },
                    "serve_routes": {
                        "11000": {
                            "url": "https://node.example.ts.net:11000",
                            "target": "http://127.0.0.1:11000",
                            "active": True,
                        },
                    },
                    "managed_routes": {"11000": "https"},
                    "managed_ports": ["11000"],
                },
            )
            payload, commands = self.run_provider(
                paths,
                live_serve_status=self.live_route(
                    11000,
                    "https",
                    "http://127.0.0.1:11000",
                    handlers={
                        "/": {"Proxy": "http://127.0.0.1:11000"},
                        "/other": {"Proxy": "http://127.0.0.1:9999"},
                    },
                ),
            )

            self.assertEqual(self.serve_mutations(commands), [])
            self.assertEqual(payload["managed_routes"], {})
            self.assertTrue(
                any(
                    "released from CITADEL management" in error
                    for error in payload["errors"]
                )
            )


if __name__ == "__main__":
    unittest.main()
