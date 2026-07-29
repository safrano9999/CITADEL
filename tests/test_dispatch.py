from __future__ import annotations

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

import dispatch  # noqa: E402


class DispatchFilterTests(unittest.TestCase):
    def arguments(self, base: Path, *extra: str) -> list[str]:
        return [
            "dispatch.py",
            "--enabled-dir",
            str(base / "enabled"),
            "--services-file",
            str(base / "services.json"),
            "--cache-dir",
            str(base / "cache"),
            "--config-ini",
            str(base / "config.ini"),
            "--state-file",
            str(base / "providers-state.json"),
            "--tailscale-file",
            str(base / "tailscale.json"),
            *extra,
        ]

    def provider(self, base: Path, name: str) -> None:
        directory = base / "enabled" / name
        directory.mkdir(parents=True)
        (directory / "extension.json").write_text(
            json.dumps({"provider": name, "label": name.title()}),
            encoding="utf-8",
        )

    def run_provider(
        self,
        command: list[str],
        *,
        returncode: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        routes_out = Path(command[command.index("--routes-out") + 1])
        routes_out.write_text(
            json.dumps(
                {
                    "considered": True,
                    "available": True,
                    "label": routes_out.parent.name.title(),
                    "services": {"11000": {"url": "https://example.invalid"}},
                    "errors": [],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, returncode, "", "failed")

    def test_reconciles_only_requested_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "cache").mkdir()
            (base / "services.json").write_text("{}", encoding="utf-8")
            self.provider(base, "tailscale")
            self.provider(base, "subnet")
            commands: list[list[str]] = []

            def fake_run(command: list[str], **_kwargs):
                commands.append(command)
                return self.run_provider(command)

            with (
                patch.object(
                    sys,
                    "argv",
                    self.arguments(
                        base,
                        "--provider",
                        "tailscale",
                        "--strict",
                    ),
                ),
                patch.object(dispatch.subprocess, "run", side_effect=fake_run),
            ):
                self.assertEqual(dispatch.main(), 0)

            self.assertEqual(len(commands), 1)
            self.assertTrue(commands[0][1].endswith("/tailscale.py"))
            state = json.loads(
                (base / "providers-state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(state["enabled_providers"], ["tailscale"])
            self.assertEqual(state["errors"], [])

    def test_strict_missing_provider_fails_without_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "enabled").mkdir()
            (base / "cache").mkdir()
            (base / "services.json").write_text("{}", encoding="utf-8")
            with (
                patch.object(
                    sys,
                    "argv",
                    self.arguments(
                        base,
                        "--provider",
                        "tailscale",
                        "--strict",
                    ),
                ),
                patch.object(dispatch.subprocess, "run") as run,
            ):
                self.assertEqual(dispatch.main(), 1)
            run.assert_not_called()
            state = json.loads(
                (base / "providers-state.json").read_text(encoding="utf-8")
            )
            self.assertIn(
                "Requested provider is not enabled: tailscale",
                state["errors"],
            )

    def test_strict_provider_failure_is_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "cache").mkdir()
            (base / "services.json").write_text("{}", encoding="utf-8")
            self.provider(base, "tailscale")

            def fake_run(command: list[str], **_kwargs):
                return self.run_provider(command, returncode=1)

            with (
                patch.object(
                    sys,
                    "argv",
                    self.arguments(
                        base,
                        "--provider",
                        "tailscale",
                        "--strict",
                    ),
                ),
                patch.object(dispatch.subprocess, "run", side_effect=fake_run),
            ):
                self.assertEqual(dispatch.main(), 1)


if __name__ == "__main__":
    unittest.main()
