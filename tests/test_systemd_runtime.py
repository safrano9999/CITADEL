from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
UNIT_DIR = ROOT / "image/runtime/etc/systemd/system"


class CitadelSystemdRuntimeTests(unittest.TestCase):
    def test_tailscale_allocator_environment_reaches_runtime_units(self) -> None:
        expected = {
            "CITADEL_TAILSCALE_HTTP_START",
            "CITADEL_TAILSCALE_HTTPS_START",
            "CITADEL_TAILSCALE_RANGE",
        }
        for name in ("citadel.service", "citadel-scan.service"):
            unit = (UNIT_DIR / name).read_text(encoding="utf-8")
            pass_environment = next(
                line for line in unit.splitlines() if line.startswith("PassEnvironment=")
            )
            self.assertTrue(expected.issubset(set(pass_environment.split("=")[1].split())))

    def test_scan_coalesces_duplicate_requests_without_waiting(self) -> None:
        scan = (ROOT / "scan.sh").read_text(encoding="utf-8")
        self.assertIn("flock --nonblock", scan)
        self.assertNotIn("CITADEL_SCAN_LOCK_TIMEOUT", scan)
        self.assertNotIn("flock --wait", scan)

    def test_scan_has_only_optional_ordering_for_runtime_services(self) -> None:
        unit = (UNIT_DIR / "citadel-scan.service").read_text(encoding="utf-8")
        self.assertNotIn("CITADEL_SCAN_DELAY", unit)
        self.assertNotIn("CITADEL_SCAN_ON_START", unit)
        self.assertNotIn("/bin/sleep", unit)
        self.assertIn("TimeoutStartSec=infinity", unit)
        self.assertNotIn("Requires=", unit)
        self.assertEqual(unit.count("Wants="), 1)
        self.assertIn("Wants=network-online.target", unit)
        for service in (
            "persistainer.service",
            "cloudflared.service",
            "openclaw.service",
            "hermes.service",
            "citadel.service",
            "kachelmann-webui.service",
            "jugo.service",
            "kiwix-bridge.service",
            "napoleon.service",
            "naturalgrounding.service",
            "pvdach.service",
            "spanker-webui.service",
        ):
            self.assertIn(service, unit)
        self.assertNotIn("openclaw-ephemeral-schedule.service", unit)

    def test_web_service_waits_for_persistence_and_listener(self) -> None:
        unit = (UNIT_DIR / "citadel.service").read_text(encoding="utf-8")
        self.assertIn("Requires=persistainer.service", unit)
        self.assertIn("After=network.target persistainer.service", unit)
        self.assertIn("fedora44-wait-ready", unit)

    def test_webui_does_not_own_cloudflared_service(self) -> None:
        webui = (ROOT / "webui.py").read_text(encoding="utf-8")
        self.assertNotIn("cloudflared_service", webui)
        self.assertFalse((ROOT / "functions/cloudflared_service.py").exists())


if __name__ == "__main__":
    unittest.main()
