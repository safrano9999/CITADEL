from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))


def load_unroute():
    spec = importlib.util.spec_from_file_location(
        "citadel_unroute",
        ROOT / "functions" / "unroute_tailscale.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


unroute = load_unroute()


def route(logical: int, public: int, scheme: str) -> dict:
    return {
        "mode": "proxy",
        "url": f"{scheme}://node.example.ts.net:{public}",
        "target": f"http://127.0.0.1:{logical}",
        "owns_listener": True,
        "logical_port": logical,
        "public_port": public,
        "public_scheme": scheme,
    }


def state(logical: int = 11000) -> dict:
    default = route(logical, logical, "http")
    http = route(logical, 25000, "http")
    https = route(logical, 35000, "https")
    return {
        "port_assignments": {
            "http": {str(logical): 25000, "11999": 25100},
            "https": {str(logical): 35000, "11999": 35100},
        },
        "allocation_policy": {
            "starts": {"http": 25000, "https": 35000},
            "last_nonblank": {"http": 25000, "https": 35000},
            "range": 100,
        },
        "managed_ports": [str(logical), "25000", "35000"],
        "managed_routes": {
            str(logical): "http",
            "25000": "http",
            "35000": "https",
        },
        "serve_routes": {
            str(logical): {**default, "variant": "default", "active": True},
            "25000": {**http, "active": True},
            "35000": {**https, "active": True},
        },
        "remembered_serve_routes": {
            str(logical): {**default, "variant": "default", "active": True},
            "25000": {**http, "active": True},
            "35000": {**https, "active": True},
        },
        "variants": {
            "default": {"available": True, "services": {str(logical): default}},
            "http": {"available": True, "services": {str(logical): http}},
            "https": {"available": True, "services": {str(logical): https}},
        },
        "remembered_variants": {
            "default": {"available": True, "services": {str(logical): default}},
            "http": {"available": True, "services": {str(logical): http}},
            "https": {"available": True, "services": {str(logical): https}},
        },
        "services": {str(logical): default},
        "remembered_services": {str(logical): default},
        "service_signatures": {
            f"default:{logical}": {},
            f"http:{logical}": {},
            f"https:{logical}": {},
        },
        "route_failures": {},
        "fallbacks": {},
    }


def live_config(*entries: tuple[int, str, int]) -> dict:
    tcp = {}
    web = {}
    for public, scheme, logical in entries:
        tcp[str(public)] = {scheme.upper(): True}
        web[f"node.example.ts.net:{public}"] = {
            "Handlers": {"/": {"Proxy": f"http://127.0.0.1:{logical}"}}
        }
    return {"TCP": tcp, "Web": web}


class ResolutionTests(unittest.TestCase):
    def test_logical_port_selects_default_and_both_allocated_variants(self) -> None:
        resolution = unroute.resolve_requested_port(state(), 11000)
        self.assertEqual(resolution.kind, "logical")
        self.assertEqual(
            [
                (item.variant, item.scheme, item.public_port)
                for item in resolution.listeners
            ],
            [
                ("default", "http", 11000),
                ("http", "http", 25000),
                ("https", "https", 35000),
            ],
        )

    def test_public_port_selects_only_exact_variant(self) -> None:
        resolution = unroute.resolve_requested_port(state(), 35000)
        self.assertEqual(resolution.kind, "public")
        self.assertEqual(
            [
                (item.variant, item.scheme, item.logical_port, item.public_port)
                for item in resolution.listeners
            ],
            [("https", "https", 11000, 35000)],
        )

    def test_logical_public_collision_is_fail_closed(self) -> None:
        payload = state()
        payload["port_assignments"]["http"]["35000"] = 25001
        with self.assertRaisesRegex(unroute.UnrouteError, "ambiguous"):
            unroute.resolve_requested_port(payload, 35000)

    def test_legacy_literal_listener_remains_supported(self) -> None:
        payload = {
            "managed_routes": {"11000": "https"},
            "remembered_serve_routes": {
                "11000": {
                    "url": "https://node.example.ts.net:11000",
                    "target": "http://127.0.0.1:11000",
                }
            },
        }
        resolution = unroute.resolve_requested_port(payload, 11000)
        self.assertEqual(resolution.kind, "legacy")
        self.assertEqual(resolution.listeners[0].public_port, 11000)
        self.assertTrue(resolution.listeners[0].owned)


class StatePruningTests(unittest.TestCase):
    def test_prunes_one_public_variant_but_keeps_all_assignments(self) -> None:
        payload = state()
        original_assignments = copy.deepcopy(payload["port_assignments"])
        selection = unroute.resolve_requested_port(payload, 35000).listeners[0]

        self.assertTrue(unroute.prune_listener_state(payload, selection))

        self.assertEqual(payload["port_assignments"], original_assignments)
        self.assertEqual(
            payload["managed_routes"],
            {"11000": "http", "25000": "http"},
        )
        self.assertEqual(payload["managed_ports"], ["11000", "25000"])
        self.assertNotIn("11000", payload["variants"]["https"]["services"])
        self.assertIn("11000", payload["variants"]["default"]["services"])
        self.assertIn("11000", payload["variants"]["http"]["services"])
        self.assertEqual(
            payload["services"]["11000"]["public_port"],
            11000,
        )

    def test_logical_pruning_keeps_assignment_tombstones(self) -> None:
        payload = state()
        original_assignments = copy.deepcopy(payload["port_assignments"])
        for selection in unroute.resolve_requested_port(payload, 11000).listeners:
            unroute.prune_listener_state(payload, selection)

        self.assertEqual(payload["port_assignments"], original_assignments)
        self.assertEqual(payload["managed_routes"], {})
        self.assertNotIn("11000", payload["services"])


class UnrouteIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        (self.base / "extensions/enabled/tailscale").mkdir(parents=True)
        (self.base / "cache").mkdir()
        (self.base / "icons").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_fixture(self) -> None:
        payload = state()
        for path in (
            self.base / "tailscale.json",
            self.base / "extensions/enabled/tailscale/routes.json",
        ):
            path.write_text(json.dumps(payload), encoding="utf-8")
        (self.base / "services.json").write_text(
            json.dumps({
                "http_services": [{
                    "port": 11000,
                    "scheme": "http",
                    "urls": {
                        "localhost": "http://127.0.0.1:11000",
                        "tailscale-default": "http://node.example.ts.net:11000",
                        "tailscale-http": "http://node.example.ts.net:25000",
                        "tailscale-https": "https://node.example.ts.net:35000",
                        "tailscale": "http://node.example.ts.net:11000",
                    },
                }],
                "other_ports": [{"port": 5432, "service": "postgresql"}],
            }),
            encoding="utf-8",
        )
        (self.base / "cache/11000.json").write_text(
            json.dumps({
                "title": "CITADEL",
                "tailscale_default_url": "http://node.example.ts.net:11000",
                "tailscale_http_url": "http://node.example.ts.net:25000",
                "tailscale_https_url": "https://node.example.ts.net:35000",
                "tailscale_url": "http://node.example.ts.net:11000",
                "tailscale_path": None,
            }),
            encoding="utf-8",
        )
        (self.base / "icons/11000.png").write_bytes(b"icon")

    @staticmethod
    def runner(config: dict, commands: list[list[str]]):
        def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command[-3:] == ["serve", "status", "--json"]:
                return subprocess.CompletedProcess(
                    command, 0, json.dumps(config), ""
                )
            return subprocess.CompletedProcess(command, 0, "", "")
        return run

    def test_public_unroute_removes_only_exact_listener_and_preserves_files(self) -> None:
        self.write_fixture()
        commands: list[list[str]] = []
        live = live_config(
            (11000, "http", 11000),
            (25000, "http", 11000),
            (35000, "https", 11000),
        )
        with (
            patch.object(unroute.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(unroute, "load_live_serve_config", return_value=live),
            patch.object(unroute, "release_serve_port", side_effect=lambda binary, port, scheme: commands.append([binary, "serve", "--yes", f"--{scheme}={port}", "off"])),
        ):
            self.assertEqual(unroute.unroute(self.base, [35000]), 0)

        mutations = [command for command in commands if command[-1] == "off"]
        self.assertEqual(
            mutations,
            [["/usr/bin/tailscale", "serve", "--yes", "--https=35000", "off"]],
        )
        updated = json.loads((self.base / "tailscale.json").read_text())
        self.assertEqual(updated["port_assignments"], state()["port_assignments"])
        self.assertEqual(
            updated["managed_routes"],
            {"11000": "http", "25000": "http"},
        )
        services = json.loads((self.base / "services.json").read_text())
        self.assertEqual(len(services["http_services"]), 1)
        self.assertEqual(services["other_ports"][0]["port"], 5432)
        self.assertNotIn("tailscale-https", services["http_services"][0]["urls"])
        self.assertTrue((self.base / "cache/11000.json").exists())
        self.assertTrue((self.base / "icons/11000.png").exists())
        cache = json.loads((self.base / "cache/11000.json").read_text())
        self.assertNotIn("tailscale_https_url", cache)
        self.assertEqual(
            cache["tailscale_url"], "http://node.example.ts.net:11000"
        )

    def test_foreign_listener_is_left_untouched_without_state_mutation(self) -> None:
        self.write_fixture()
        original = (self.base / "tailscale.json").read_text()
        foreign = live_config((35000, "https", 9999))
        commands: list[list[str]] = []
        runner = self.runner(foreign, commands)
        with (
            patch.object(unroute.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(unroute, "load_live_serve_config", return_value=foreign),
            patch.object(unroute, "release_serve_port") as release,
            self.assertRaisesRegex(unroute.UnrouteError, "left untouched"),
        ):
            unroute.unroute(self.base, [35000])

        release.assert_not_called()
        self.assertEqual((self.base / "tailscale.json").read_text(), original)

    def test_logical_unroute_releases_default_and_both_allocated_variants(self) -> None:
        self.write_fixture()
        commands: list[list[str]] = []
        live = live_config(
            (11000, "http", 11000),
            (25000, "http", 11000),
            (35000, "https", 11000),
        )
        with (
            patch.object(unroute.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(unroute, "load_live_serve_config", return_value=live),
            patch.object(unroute, "release_serve_port", side_effect=lambda binary, port, scheme: commands.append([binary, "serve", "--yes", f"--{scheme}={port}", "off"])),
        ):
            self.assertEqual(unroute.unroute(self.base, [11000]), 0)

        mutations = [command for command in commands if command[-1] == "off"]
        self.assertEqual(
            mutations,
            [
                ["/usr/bin/tailscale", "serve", "--yes", "--http=11000", "off"],
                ["/usr/bin/tailscale", "serve", "--yes", "--http=25000", "off"],
                ["/usr/bin/tailscale", "serve", "--yes", "--https=35000", "off"],
            ],
        )
        updated = json.loads((self.base / "tailscale.json").read_text())
        self.assertEqual(updated["port_assignments"], state()["port_assignments"])
        self.assertEqual(updated["managed_routes"], {})
        self.assertTrue((self.base / "cache/11000.json").exists())
        self.assertTrue((self.base / "icons/11000.png").exists())

    def test_foreign_default_fails_closed_before_any_variant_is_removed(self) -> None:
        self.write_fixture()
        original = (self.base / "tailscale.json").read_text()
        live = live_config(
            (11000, "http", 9999),
            (25000, "http", 11000),
            (35000, "https", 11000),
        )
        with (
            patch.object(unroute.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(unroute, "load_live_serve_config", return_value=live),
            patch.object(unroute, "release_serve_port") as release,
            self.assertRaisesRegex(unroute.UnrouteError, "left untouched"),
        ):
            unroute.unroute(self.base, [11000])

        release.assert_not_called()
        self.assertEqual((self.base / "tailscale.json").read_text(), original)

    def test_direct_default_is_never_switched_off(self) -> None:
        self.write_fixture()
        for relative in (
            Path("tailscale.json"),
            Path("extensions/enabled/tailscale/routes.json"),
        ):
            path = self.base / relative
            payload = json.loads(path.read_text())
            direct = {
                **route(11000, 11000, "http"),
                "mode": "direct",
                "target": None,
                "owns_listener": False,
            }
            payload["variants"]["default"]["services"]["11000"] = direct
            payload["remembered_variants"]["default"]["services"]["11000"] = direct
            payload["services"]["11000"] = direct
            payload["remembered_services"]["11000"] = direct
            payload["managed_ports"].remove("11000")
            payload["managed_routes"].pop("11000")
            payload["serve_routes"].pop("11000")
            payload["remembered_serve_routes"].pop("11000")
            path.write_text(json.dumps(payload), encoding="utf-8")

        commands: list[list[str]] = []
        live = live_config((25000, "http", 11000), (35000, "https", 11000))
        with (
            patch.object(unroute.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(unroute, "load_live_serve_config", return_value=live),
            patch.object(unroute, "release_serve_port", side_effect=lambda binary, port, scheme: commands.append([binary, "serve", "--yes", f"--{scheme}={port}", "off"])),
        ):
            self.assertEqual(unroute.unroute(self.base, [11000]), 0)

        self.assertEqual(
            [command for command in commands if command[-1] == "off"],
            [
                ["/usr/bin/tailscale", "serve", "--yes", "--http=25000", "off"],
                ["/usr/bin/tailscale", "serve", "--yes", "--https=35000", "off"],
            ],
        )
        updated = json.loads((self.base / "tailscale.json").read_text())
        self.assertEqual(updated["port_assignments"], state()["port_assignments"])
        self.assertIn("11000", updated["variants"]["default"]["services"])


if __name__ == "__main__":
    unittest.main()
