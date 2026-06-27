from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))

from cloudflared_service import ensure_cloudflared_service  # noqa: E402


class CloudflaredServiceTests(unittest.TestCase):
    def settings(self, **overrides: str) -> dict[str, str]:
        values = {"CITADEL_CLOUDFLARE": "1", "TUNNEL_TOKEN": "configured"}
        values.update(overrides)
        return values

    def test_disabled_does_not_call_systemd(self) -> None:
        calls = []

        def runner(*args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args[0], 0, "", "")

        values = self.settings(CITADEL_CLOUDFLARE="0")
        self.assertEqual(ensure_cloudflared_service(lambda key, default="": values.get(key, default), runner), "disabled")
        self.assertEqual(calls, [])

    def test_missing_setting_does_not_call_systemd(self) -> None:
        values = self.settings(TUNNEL_TOKEN="")
        result = ensure_cloudflared_service(
            lambda key, default="": values.get(key, default),
            lambda *_args, **_kwargs: self.fail("systemd must not be called"),
        )
        self.assertEqual(result, "missing setting: TUNNEL_TOKEN")

    def test_starts_loaded_inactive_service(self) -> None:
        commands: list[list[str]] = []

        def runner(command, **_kwargs):
            commands.append(command)
            if "show" in command:
                return subprocess.CompletedProcess(command, 0, "loaded\n", "")
            if "is-active" in command:
                return subprocess.CompletedProcess(command, 3, "", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        values = self.settings()
        result = ensure_cloudflared_service(lambda key, default="": values.get(key, default), runner)
        self.assertEqual(result, "started")
        self.assertEqual(commands[-1], ["systemctl", "start", "cloudflared.service"])

    def test_keeps_active_service_running(self) -> None:
        commands: list[list[str]] = []

        def runner(command, **_kwargs):
            commands.append(command)
            if "show" in command:
                return subprocess.CompletedProcess(command, 0, "loaded\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        values = self.settings()
        result = ensure_cloudflared_service(lambda key, default="": values.get(key, default), runner)
        self.assertEqual(result, "already running")
        self.assertEqual(len(commands), 2)

    def test_missing_systemctl_does_not_break_startup(self) -> None:
        values = self.settings()

        def runner(*_args, **_kwargs):
            raise FileNotFoundError("systemctl")

        result = ensure_cloudflared_service(lambda key, default="": values.get(key, default), runner)
        self.assertEqual(result, "cloudflared.service not found")


if __name__ == "__main__":
    unittest.main()
