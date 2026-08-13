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


def load_provider():
    spec = importlib.util.spec_from_file_location(
        "citadel_tailscale_provider_v2",
        PROVIDERS_DIR / "tailscale.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


tailscale = load_provider()


class TailscaleProviderV2Tests(unittest.TestCase):
    def fixture(
        self,
        base: Path,
        services: list[dict],
        previous: dict | str | None = None,
    ) -> dict[str, Path]:
        provider_dir = base / "extensions" / "enabled" / "tailscale"
        provider_dir.mkdir(parents=True)
        (provider_dir / "extension.json").write_text(
            json.dumps({"label": "Tailscale"}), encoding="utf-8"
        )
        services_file = base / "services.json"
        services_file.write_text(
            json.dumps({"http_services": services}), encoding="utf-8"
        )
        cache = base / "cache"
        cache.mkdir()
        state = base / "tailscale.json"
        if isinstance(previous, dict):
            state.write_text(json.dumps(previous), encoding="utf-8")
        elif isinstance(previous, str):
            state.write_text(previous, encoding="utf-8")
        return {
            "provider_dir": provider_dir,
            "services": services_file,
            "cache": cache,
            "routes": provider_dir / "routes.json",
            "state": state,
            "config": base / "config.ini",
        }

    @staticmethod
    def service(port: int, scheme: str = "http") -> dict:
        return {
            "port": port,
            "addr": "0.0.0.0",
            "addrs": ["0.0.0.0"],
            "scheme": scheme,
            "urls": {"localhost": f"{scheme}://127.0.0.1:{port}"},
        }

    @staticmethod
    def live_route(port: int, scheme: str, target: str) -> dict:
        tcp = {"HTTPS": True} if scheme == "https" else {"HTTP": True}
        return {
            "TCP": {str(port): tcp},
            "Web": {
                f"node.example.ts.net:{port}": {
                    "Handlers": {"/": {"Proxy": target}},
                }
            },
        }

    def run_provider(
        self,
        paths: dict[str, Path],
        *,
        starts: dict[str, str] | None = None,
        spacing: str = "100",
        live: dict | None = None,
        local: str = "",
        running: bool = True,
        enabled: bool = True,
        default_enabled: bool = False,
        failures: dict[
            tuple[str, str, str],
            tuple[int, str] | list[tuple[int, str]],
        ] | None = None,
        expect_rc: int = 0,
    ) -> tuple[dict | None, list[list[str]]]:
        commands: list[list[str]] = []
        configured_starts = starts or {"http": "15000", "https": "25000"}
        configured_failures = failures or {}

        def fake_value(_provider_dir: str, key: str, default: str = "") -> str:
            values = {
                "CITADEL_TAILSCALE": "true" if enabled else "false",
                "CITADEL_TAILSCALE_DEFAULT": "1" if default_enabled else "0",
                "CITADEL_TAILSCALE_HTTP_START": configured_starts.get("http", "0"),
                "CITADEL_TAILSCALE_HTTPS_START": configured_starts.get("https", "0"),
                "CITADEL_TAILSCALE_RANGE": spacing,
            }
            return values.get(key, default)

        def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command == ["tailscale", "status", "--json"]:
                if not running:
                    return subprocess.CompletedProcess(command, 1, "", "offline")
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
            if command == ["tailscale", "serve", "status", "--json"]:
                return subprocess.CompletedProcess(command, 0, json.dumps(live or {}), "")
            if command == ["ss", "-H", "-ltnp"]:
                return subprocess.CompletedProcess(command, 0, local, "")
            if command[:2] == ["tailscale", "serve"]:
                flag = next(
                    value
                    for value in command
                    if value.startswith("--http=") or value.startswith("--https=")
                )
                scheme, port = flag[2:].split("=", 1)
                action = "off" if command[-1] == "off" else "apply"
                outcome = configured_failures.get((scheme, port, action), (0, ""))
                if isinstance(outcome, list):
                    rc, error = outcome.pop(0) if outcome else (0, "")
                else:
                    rc, error = outcome
                return subprocess.CompletedProcess(command, rc, "", error)
            return subprocess.CompletedProcess(command, 0, "", "")

        argv = [
            "tailscale.py",
            "--provider-dir", str(paths["provider_dir"]),
            "--services-file", str(paths["services"]),
            "--cache-dir", str(paths["cache"]),
            "--config-ini", str(paths["config"]),
            "--routes-out", str(paths["routes"]),
            "--tailscale-file", str(paths["state"]),
        ]
        with (
            patch.object(tailscale, "run", side_effect=fake_run),
            patch.object(tailscale, "citadel_value", side_effect=fake_value),
            patch.object(tailscale.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(sys, "argv", argv),
        ):
            self.assertEqual(tailscale.main(), expect_rc)
        payload = (
            json.loads(paths["routes"].read_text(encoding="utf-8"))
            if paths["routes"].exists()
            else None
        )
        return payload, commands

    @staticmethod
    def mutations(commands: list[list[str]]) -> list[list[str]]:
        return [
            command
            for command in commands
            if command[:2] == ["tailscale", "serve"]
            and command != ["tailscale", "serve", "status", "--json"]
        ]

    def test_initial_dual_variants_are_sorted_and_spaced(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(
                Path(raw),
                [self.service(11000), self.service(4000), self.service(8080)],
            )
            payload, commands = self.run_provider(paths)
            assert payload is not None
            expected = {"4000": 15000, "8080": 15100, "11000": 15200}
            self.assertEqual(payload["port_assignments"]["http"], expected)
            self.assertEqual(
                payload["port_assignments"]["https"],
                {"4000": 25000, "8080": 25100, "11000": 25200},
            )
            self.assertEqual(payload["variants"]["http"]["label"], "Tailscale HTTP")
            self.assertEqual(payload["variants"]["https"]["label"], "Tailscale HTTPS")
            self.assertEqual(len(self.mutations(commands)), 6)
            self.assertTrue(
                all(route["mode"] == "proxy" for route in payload["services"].values())
            )

    def test_native_https_has_no_http_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(9443, "https")])
            payload, commands = self.run_provider(paths)
            assert payload is not None
            self.assertEqual(payload["variants"]["http"]["services"], {})
            route = payload["variants"]["https"]["services"]["9443"]
            self.assertEqual(route["target"], "https+insecure://127.0.0.1:9443")
            self.assertEqual(len(self.mutations(commands)), 1)

    def test_blank_start_disables_variant_but_preserves_assignment_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)])
            first, _ = self.run_provider(paths)
            assert first is not None
            live = self.live_route(15000, "http", "http://127.0.0.1:4000")
            second, commands = self.run_provider(
                paths,
                starts={"http": "blank", "https": "25000"},
                live=live,
            )
            assert second is not None
            self.assertFalse(second["variants"]["http"]["considered"])
            self.assertEqual(second["port_assignments"]["http"], {"4000": 15000})
            self.assertEqual(second["allocation_policy"]["last_nonblank"]["http"], 15000)
            self.assertIn(
                ["tailscale", "serve", "--yes", "--http=15000", "off"],
                commands,
            )

    def test_new_service_skips_local_and_raw_tailscale_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)])
            live = {"TCP": {"25000": {"TCPForward": "127.0.0.1:5432"}}}
            local = (
                'LISTEN 0 4096 0.0.0.0:15000 0.0.0.0:* users:(("uvicorn",pid=42,fd=3))\n'
            )
            payload, commands = self.run_provider(paths, live=live, local=local)
            assert payload is not None
            self.assertEqual(payload["port_assignments"]["http"]["4000"], 15001)
            self.assertEqual(payload["port_assignments"]["https"]["4000"], 25001)
            warnings = "\n".join(payload["warnings"])
            self.assertIn("process=uvicorn pid=42", warnings)
            self.assertIn("TCPForward", warnings)
            self.assertIn("pruefe 15001", warnings)
            self.assertNotIn("--https=25000", " ".join(" ".join(c) for c in commands))

    def test_apply_race_collision_advances_new_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)])
            payload, commands = self.run_provider(
                paths,
                starts={"http": "15000", "https": "0"},
                failures={
                    ("http", "15000", "apply"): (1, "address already in use"),
                },
            )
            assert payload is not None
            self.assertEqual(payload["port_assignments"]["http"], {"4000": 15001})
            self.assertEqual(
                payload["variants"]["http"]["services"]["4000"]["public_port"],
                15001,
            )
            self.assertIn("pruefe 15001", "\n".join(payload["warnings"]))
            self.assertIn("--http=15001", " ".join(" ".join(c) for c in commands))

    def test_persisted_foreign_collision_is_pending_and_never_moves(self) -> None:
        previous = {
            "allocation_policy": {
                "starts": {"https": 25000},
                "last_nonblank": {"https": 25000},
                "range": 100,
            },
            "port_assignments": {"http": {}, "https": {"4000": 25000}},
            "managed_routes": {},
        }
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)], previous)
            live = self.live_route(25000, "https", "http://127.0.0.1:4000")
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "25000"},
                live=live,
                expect_rc=1,
            )
            assert payload is not None
            self.assertEqual(payload["port_assignments"]["https"], {"4000": 25000})
            self.assertEqual(payload["variants"]["https"]["services"], {})
            self.assertIn("https:4000", payload["route_failures"])
            self.assertEqual(self.mutations(commands), [])

    def test_tailscaled_socket_without_serve_json_is_persisted_pending(self) -> None:
        previous = {
            "allocation_policy": {
                "last_nonblank": {"https": 25000}, "range": 100,
            },
            "port_assignments": {"http": {}, "https": {"4000": 25000}},
            "managed_routes": {},
        }
        local = (
            'LISTEN 0 4096 100.64.0.1:25000 0.0.0.0:* users:(("tailscaled",pid=9,fd=3))\n'
        )
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)], previous)
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "25000"},
                local=local,
                expect_rc=1,
            )
            assert payload is not None
            self.assertIn("tailscaled", "\n".join(payload["errors"]))
            self.assertEqual(self.mutations(commands), [])

    def test_outage_preserves_remembered_variants_and_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)])
            first, _ = self.run_provider(paths)
            assert first is not None
            second, commands = self.run_provider(paths, running=False)
            assert second is not None
            self.assertEqual(
                second["variants"]["https"]["services"],
                first["variants"]["https"]["services"],
            )
            self.assertEqual(second["managed_routes"], first["managed_routes"])
            self.assertEqual(self.mutations(commands), [])

    def test_invalid_policy_or_assignment_fails_closed(self) -> None:
        previous = {
            "allocation_policy": {
                "last_nonblank": {"https": 25000}, "range": 100,
            },
            "port_assignments": {
                "http": {},
                "https": {"4000": 25000, "8080": 25000},
            },
            "managed_routes": {"25000": "https"},
        }
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)], previous)
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "26000"},
                spacing="200",
                live=self.live_route(25000, "https", "http://127.0.0.1:4000"),
                expect_rc=1,
            )
            self.assertIsNone(payload)
            self.assertEqual(self.mutations(commands), [])

    def test_apply_failure_retains_old_exact_owned_listener(self) -> None:
        old_live = self.live_route(11000, "https", "http://127.0.0.1:4000")
        previous = {
            "allocation_policy": {
                "last_nonblank": {"https": 25000}, "range": 100,
            },
            "port_assignments": {"http": {}, "https": {}},
            "managed_routes": {"11000": "https"},
            "serve_routes": {
                "11000": {
                    "url": "https://node.example.ts.net:11000",
                    "target": "http://127.0.0.1:4000",
                    "active": True,
                }
            },
        }
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)], previous)
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "25000"},
                live=old_live,
                failures={("https", "25000", "apply"): (1, "apply failed")},
                expect_rc=1,
            )
            assert payload is not None
            self.assertEqual(payload["managed_routes"], {"11000": "https"})
            self.assertNotIn(
                ["tailscale", "serve", "--yes", "--https=11000", "off"],
                commands,
            )

    def test_same_port_replacement_failure_restores_previous_route(self) -> None:
        previous = {
            "allocation_policy": {
                "last_nonblank": {"https": 25000}, "range": 100,
            },
            "port_assignments": {"http": {}, "https": {"4000": 25000}},
            "managed_routes": {"25000": "https"},
            "serve_routes": {
                "25000": {
                    "url": "https://node.example.ts.net:25000",
                    "target": "http://127.0.0.1:4000",
                    "logical_port": 4000,
                    "public_scheme": "https",
                    "active": True,
                }
            },
        }
        replacement = self.service(5000)
        replacement.update({
            "origin": "host",
            "origin_host": "host.containers.internal",
            "origin_port": 5000,
            "route_port": 4000,
        })
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [replacement], previous)
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "25000"},
                live=self.live_route(25000, "https", "http://127.0.0.1:4000"),
                failures={
                    ("https", "25000", "apply"): [
                        (1, "apply failed"),
                        (0, ""),
                    ],
                },
                expect_rc=1,
            )
            assert payload is not None
            applies = [
                command
                for command in commands
                if command[:4] == ["tailscale", "serve", "--bg", "--yes"]
            ]
            self.assertEqual(applies[-1][-1], "http://127.0.0.1:4000")
            self.assertEqual(payload["managed_routes"], {"25000": "https"})
            self.assertEqual(
                payload["remembered_serve_routes"]["25000"]["target"],
                "http://127.0.0.1:4000",
            )

    def test_exact_owned_route_is_reused_without_mutation(self) -> None:
        previous = {
            "allocation_policy": {
                "last_nonblank": {"https": 25000}, "range": 100,
            },
            "port_assignments": {"http": {}, "https": {"4000": 25000}},
            "managed_routes": {"25000": "https"},
            "serve_routes": {
                "25000": {
                    "url": "https://node.example.ts.net:25000",
                    "target": "http://127.0.0.1:4000",
                    "logical_port": 4000,
                    "public_scheme": "https",
                    "active": True,
                }
            },
        }
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)], previous)
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "25000"},
                live=self.live_route(25000, "https", "http://127.0.0.1:4000"),
            )
            assert payload is not None
            self.assertIn("4000", payload["variants"]["https"]["services"])
            self.assertEqual(self.mutations(commands), [])

    def test_disappeared_service_removes_exact_owned_listener_but_keeps_tombstone(self) -> None:
        previous = {
            "allocation_policy": {
                "last_nonblank": {"https": 25000}, "range": 100,
            },
            "port_assignments": {"http": {}, "https": {"4000": 25000}},
            "managed_routes": {"25000": "https"},
            "serve_routes": {
                "25000": {
                    "url": "https://node.example.ts.net:25000",
                    "target": "http://127.0.0.1:4000",
                    "logical_port": 4000,
                    "public_scheme": "https",
                    "active": True,
                }
            },
        }
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [], previous)
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "25000"},
                live=self.live_route(25000, "https", "http://127.0.0.1:4000"),
            )
            assert payload is not None
            self.assertIn(
                ["tailscale", "serve", "--yes", "--https=25000", "off"],
                commands,
            )
            self.assertEqual(payload["managed_routes"], {})
            self.assertEqual(payload["port_assignments"]["https"], {"4000": 25000})

    def test_start_change_and_range_change_each_fail_closed(self) -> None:
        previous = {
            "allocation_policy": {
                "last_nonblank": {"https": 25000}, "range": 100,
            },
            "port_assignments": {"http": {}, "https": {"4000": 25000}},
            "managed_routes": {"25000": "https"},
            "serve_routes": {
                "25000": {
                    "url": "https://node.example.ts.net:25000",
                    "target": "http://127.0.0.1:4000",
                    "active": True,
                }
            },
        }
        for start, spacing, expected in (
            ("26000", "100", "HTTPS_START cannot change"),
            ("25000", "200", "RANGE cannot change"),
        ):
            with self.subTest(start=start, spacing=spacing), tempfile.TemporaryDirectory() as raw:
                paths = self.fixture(Path(raw), [self.service(4000)], previous)
                payload, commands = self.run_provider(
                    paths,
                    starts={"http": "0", "https": start},
                    spacing=spacing,
                    live=self.live_route(25000, "https", "http://127.0.0.1:4000"),
                    expect_rc=1,
                )
                self.assertIsNone(payload)
                self.assertEqual(self.mutations(commands), [])

    def test_corrupt_existing_state_returns_nonzero_and_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(4000)], "{broken")
            payload, commands = self.run_provider(paths, expect_rc=1)
            self.assertIsNone(payload)
            self.assertEqual(paths["state"].read_text(encoding="utf-8"), "{broken")
            self.assertEqual(self.mutations(commands), [])

    def test_default_maps_loopback_services_one_to_one_with_detected_scheme(self) -> None:
        http = self.service(11000)
        https = self.service(9443, "https")
        for service in (http, https):
            service["addr"] = "127.0.0.1"
            service["addrs"] = ["127.0.0.1"]
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [http, https])
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "0"},
                default_enabled=True,
            )
            assert payload is not None
            routes = payload["variants"]["default"]["services"]
            self.assertEqual(
                routes["11000"]["url"],
                "http://node.example.ts.net:11000",
            )
            self.assertEqual(
                routes["9443"]["url"],
                "https://node.example.ts.net:9443",
            )
            mutations = self.mutations(commands)
            self.assertIn(
                ["tailscale", "serve", "--bg", "--yes", "--http=11000", "http://127.0.0.1:11000"],
                mutations,
            )
            self.assertIn(
                ["tailscale", "serve", "--bg", "--yes", "--https=9443", "https+insecure://127.0.0.1:9443"],
                mutations,
            )

    def test_default_displays_wildcard_service_without_claiming_listener(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(11000)])
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "0"},
                default_enabled=True,
            )
            assert payload is not None
            route = payload["variants"]["default"]["services"]["11000"]
            self.assertEqual(route["mode"], "direct")
            self.assertFalse(route["owns_listener"])
            self.assertEqual(self.mutations(commands), [])

    def test_default_ignores_tailnet_serve_socket_and_migrates_owned_scheme(self) -> None:
        service = self.service(11000)
        service.update({
            "addr": "127.0.0.1",
            "addrs": ["127.0.0.1", "100.64.0.10"],
            "listeners": [
                {"addr": "127.0.0.1", "process": "python", "pid": 101},
                # Scanner snapshots can inherit the app process name for the
                # Tailnet listener because process lookup is port-wide.
                {"addr": "100.64.0.10", "process": "python", "pid": None},
            ],
        })
        previous = {
            "managed_routes": {"11000": "https"},
            "serve_routes": {
                "11000": {
                    "url": "https://node.example.ts.net:11000",
                    "target": "http://127.0.0.1:11000",
                    "logical_port": 11000,
                    "public_scheme": "https",
                    "variant": "default",
                    "active": True,
                }
            },
        }
        live = self.live_route(11000, "https", "http://127.0.0.1:11000")
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [service], previous)
            payload, commands = self.run_provider(
                paths,
                starts={"http": "0", "https": "0"},
                default_enabled=True,
                live=live,
            )
            assert payload is not None
            route = payload["variants"]["default"]["services"]["11000"]
            self.assertEqual(route["mode"], "proxy")
            self.assertEqual(route["public_scheme"], "http")
            self.assertTrue(route["owns_listener"])
            mutations = self.mutations(commands)
            self.assertIn(
                ["tailscale", "serve", "--yes", "--https=11000", "off"],
                mutations,
            )
            self.assertIn(
                [
                    "tailscale", "serve", "--bg", "--yes", "--http=11000",
                    "http://127.0.0.1:11000",
                ],
                mutations,
            )

    def test_default_zero_hides_default_variant(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self.fixture(Path(raw), [self.service(11000)])
            payload, _ = self.run_provider(
                paths,
                starts={"http": "0", "https": "0"},
                default_enabled=False,
            )
            assert payload is not None
            self.assertFalse(payload["variants"]["default"]["considered"])
            self.assertEqual(payload["variants"]["default"]["services"], {})


if __name__ == "__main__":
    unittest.main()
