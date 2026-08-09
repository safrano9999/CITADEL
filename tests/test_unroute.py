from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_unroute():
    spec = importlib.util.spec_from_file_location(
        "citadel_unroute",
        ROOT / "functions" / "unroute_tailscale.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


unroute = load_unroute()


class UnrouteTests(unittest.TestCase):
    @staticmethod
    def successful_runner(commands: list[list[str]]):
        def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        return run

    def test_releases_only_configured_http_and_https_port(self) -> None:
        commands: list[list[str]] = []
        unroute.release_serve_port(
            "/usr/bin/tailscale",
            11000,
            self.successful_runner(commands),
        )
        self.assertEqual(
            commands,
            [
                [
                    "/usr/bin/tailscale",
                    "serve",
                    "--yes",
                    "--https=11000",
                    "off",
                ],
                [
                    "/usr/bin/tailscale",
                    "serve",
                    "--yes",
                    "--http=11000",
                    "off",
                ],
            ],
        )
        self.assertFalse(any("reset" in command for command in commands))

    def test_missing_handlers_are_an_idempotent_success(self) -> None:
        def missing(
            command: list[str],
            **_: object,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                command,
                1,
                "",
                "handler does not exist",
            )

        unroute.release_serve_port("/usr/bin/tailscale", 11000, missing)

    def test_failure_is_reported(self) -> None:
        def fail(
            command: list[str],
            **_: object,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, "", "permission denied")

        with self.assertRaises(unroute.UnrouteError):
            unroute.release_serve_port("/usr/bin/tailscale", 11000, fail)

    def test_clears_only_selected_port_from_all_persisted_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            provider_dir = base / "extensions" / "enabled" / "tailscale"
            provider_dir.mkdir(parents=True)
            state = {
                "managed_ports": ["11000", "18789"],
                **{
                    key: {
                        "11000": {"value": "target"},
                        "18789": {"value": "keep"},
                    }
                    for key in unroute.PORT_MAP_KEYS
                },
            }
            for path in (
                base / "tailscale.json",
                provider_dir / "routes.json",
            ):
                path.write_text(json.dumps(state), encoding="utf-8")

            (base / "services.json").write_text(
                json.dumps(
                    {
                        "http_services": [
                            {
                                "port": 11000,
                                "urls": {
                                    "localhost": "http://127.0.0.1:11000",
                                    "tailscale": "https://node.ts.net:11000",
                                },
                            },
                            {
                                "port": 18789,
                                "urls": {
                                    "tailscale": "https://node.ts.net:18789",
                                },
                            },
                        ],
                        "other_ports": [
                            {"port": 11000, "service": "stale"},
                            {"port": 5432, "service": "postgresql"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (base / "cache").mkdir()
            (base / "cache" / "11000.json").write_text(
                json.dumps(
                    {
                        "title": "CITADEL",
                        "tailscale_url": "https://node.ts.net:11000",
                        "tailscale_path": None,
                    }
                ),
                encoding="utf-8",
            )
            icons_dir = base / "icons"
            icons_dir.mkdir()
            (icons_dir / "11000.png").write_bytes(b"stale png")
            (icons_dir / "11000.ico").write_bytes(b"stale ico")
            (icons_dir / "18789.svg").write_text(
                "<svg></svg>",
                encoding="utf-8",
            )

            unroute.clear_persisted_port(base, 11000)

            for path in (
                base / "tailscale.json",
                provider_dir / "routes.json",
            ):
                updated = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(updated["managed_ports"], ["18789"])
                for key in unroute.PORT_MAP_KEYS:
                    self.assertNotIn("11000", updated[key])
                    self.assertIn("18789", updated[key])

            services = json.loads(
                (base / "services.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                [entry["port"] for entry in services["http_services"]],
                [18789],
            )
            self.assertEqual(
                [entry["port"] for entry in services["other_ports"]],
                [5432],
            )
            self.assertFalse((base / "cache" / "11000.json").exists())
            self.assertFalse((icons_dir / "11000.png").exists())
            self.assertFalse((icons_dir / "11000.ico").exists())
            self.assertTrue((icons_dir / "18789.svg").exists())

    def test_invalid_config_never_calls_tailscale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "config.conf").write_text(
                "CITADEL_WEBUI_PORT=70000\n",
                encoding="utf-8",
            )
            with (
                patch.object(unroute.shutil, "which") as which,
                self.assertRaises(unroute.UnrouteError),
            ):
                unroute.unroute(base)
            which.assert_not_called()

    def test_explicit_ports_do_not_require_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with (
                patch.object(unroute.shutil, "which", return_value="/usr/bin/tailscale"),
                patch.object(unroute, "release_serve_port") as release,
                patch.object(unroute, "clear_persisted_port") as clear,
            ):
                self.assertEqual(unroute.unroute(base, [790, 11000]), 0)
            self.assertEqual(
                [call.args[1] for call in release.call_args_list],
                [790, 11000],
            )
            self.assertEqual(
                [call.args[1] for call in clear.call_args_list],
                [790, 11000],
            )


if __name__ == "__main__":
    unittest.main()
