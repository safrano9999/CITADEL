from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
UNIT_DIR = ROOT / "image/runtime/etc/systemd/system"


class CitadelSystemdRuntimeTests(unittest.TestCase):
    def test_tailscale_state_matches_alpine_mount_path(self) -> None:
        state = "/opt/safrano9999/CITADEL/CITADEL_TAILSCALE"
        for unit in ("tailscaled.service", "tailscale-up.service"):
            dropin = UNIT_DIR / f"{unit}.d/citadel-state.conf"
            self.assertIn(f"Environment=TS_STATE_DIR={state}", dropin.read_text())
        self.assertIn(f"-tailscale:{state}:Z", (ROOT / "container.example").read_text())
        entrypoint = (ROOT / "container/entrypoint.py").read_text()
        self.assertIn('root / "CITADEL_TAILSCALE"', entrypoint)
        self.assertNotIn("/var/lib/tailscale", entrypoint)

    def test_example_uses_one_to_one_ports_without_allocated_variants(self) -> None:
        example = (ROOT / "config.conf_example").read_text(encoding="utf-8")
        values = dict(
            line.split("=", 1) for line in example.splitlines()
            if line and not line.startswith("#") and "=" in line
        )
        self.assertEqual(values["CITADEL_HTTPS_ONLY"], "0")
        self.assertEqual(values["CITADEL_HIDE_HTTP_WEBUI_DUPE"], "1")
        self.assertNotIn("CITADEL_WEBUI_HTTPS_PORT", values)
        self.assertEqual(values["CITADEL_TAILSCALE_SERVE"], "full")
        self.assertIn("#choices: off http_to_https full\n#default-preset: full\nCITADEL_TAILSCALE_SERVE=full", example)
        self.assertEqual(values["TAILSCALE_SERVE_RESET"], "0")
        self.assertNotIn("CITADEL_PERSISTENT", values)
        self.assertNotIn("#named-volume:", example)
        self.assertEqual(values["CITADEL_LOGO_PERSISTENT"], "1")
        self.assertNotIn("CITADEL_TAILSCALE", values)
        self.assertNotIn("CITADEL_CLOUDFLARE", values)
        self.assertEqual(values["CITADEL_WEBUI_TRANSPORT"], "tcp")
        self.assertEqual(values["CITADEL_WEBUI_SOCKET"], "")
        self.assertEqual(values["CADDYFILE_START"], "")
        self.assertEqual(values["CADDYFILE_STEPS"], "1")
        self.assertEqual(values["CADDYFILE_BACKEND"], "127.0.0.1")
        self.assertNotIn("CITADEL_TS_DISCOVERY", values)

    def test_current_environment_reaches_runtime_units(self) -> None:
        expected = {
            "CITADEL_HIDE_HTTP_WEBUI_DUPE",
            "CITADEL_LOGO_PERSISTENT",
            "CITADEL_TAILSCALE_SERVE",
            "CADDYFILE_START",
            "CADDYFILE_STEPS",
            "CLOUDFLARE_TUNNEL_TOKEN",
        }
        for name in ("citadel.service", "citadel-scan.service"):
            unit = (UNIT_DIR / name).read_text(encoding="utf-8")
            self.assertIn("PassEnvironment=CADDYFILE_BACKEND", unit)
            pass_environment = next(
                line for line in unit.splitlines() if line.startswith("PassEnvironment=")
            )
            self.assertTrue(expected.issubset(set(pass_environment.split("=")[1].split())))
            self.assertNotIn("CITADEL_TAILSCALE", pass_environment.split())
            self.assertNotIn("CITADEL_CLOUDFLARE", pass_environment.split())
            self.assertNotIn("TUNNEL_TOKEN", pass_environment.split("=", 1)[1].split())
            self.assertNotIn("CITADEL_PERSISTENT", pass_environment.split("=", 1)[1].split())

    def test_scan_coalesces_duplicate_requests_without_waiting(self) -> None:
        scan = (ROOT / "scan.sh").read_text(encoding="utf-8")
        example = (ROOT / "config.conf_example").read_text(encoding="utf-8")
        scan_unit = (UNIT_DIR / "citadel-scan.service").read_text(encoding="utf-8")
        self.assertIn("CITADEL_HTTPS_ONLY=0", example)
        self.assertIn("CITADEL_HTTPS_ONLY", scan_unit)
        self.assertIn("CITADEL_USER_AGENT=Mozilla/5.0 (compatible; CITADEL/1.0)", example)
        self.assertIn("CITADEL_USER_AGENT", scan_unit)
        self.assertIn('get("CITADEL_USER_AGENT", "")', scan)
        self.assertIn('CURL_USER_AGENT_ARGS=(--user-agent "$CITADEL_USER_AGENT_VALUE")', scan)
        self.assertGreaterEqual(scan.count('"${CURL_USER_AGENT_ARGS[@]}"'), 5)
        self.assertIn('--user-agent "$CITADEL_USER_AGENT_VALUE"', scan)
        self.assertIn("if https_only_raw != 'true' or scheme == 'https'", scan)
        self.assertIn("flock --nonblock", scan)
        self.assertNotIn("CITADEL_SCAN_LOCK_TIMEOUT", scan)
        self.assertNotIn("flock --wait", scan)
        self.assertNotIn("tailscale serve reset", scan)
        for name in ("CONTAINER", "DEDUPE_PORT", "CLEAR_TAILSCALE", "TAILSCALE_DEFAULT", "TAILSCALE_HTTP_START", "TAILSCALE_HTTPS_START", "TAILSCALE_RANGE", "CADDY_HTTPS_START", "TS_DISCOVERY"):
            self.assertNotIn("CITADEL_" + name, example + scan + scan_unit)

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
        self.assertIn("After=tailscale-up.service", unit)
        self.assertNotIn("tailscale-serve-reset", unit)
        self.assertNotIn("serve reset", unit)
        self.assertIn("fedora45-wait-ready", unit)

    def test_cascade_python_can_import_its_system_wide_pip_dependencies(self) -> None:
        unit = (UNIT_DIR / "citadel.service").read_text(encoding="utf-8")
        commands = [line.split("=", 1)[1] for line in unit.splitlines()
                    if line.startswith(("ExecStart=", "ExecStartPost="))]
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertTrue(command.startswith("/usr/bin/python3 -E webui.py"))
            self.assertNotIn(" -s ", command)
            self.assertNotIn(".venv", command)

    def test_webui_does_not_own_cloudflared_service(self) -> None:
        webui = (ROOT / "webui.py").read_text(encoding="utf-8")
        self.assertNotIn("cloudflared_service", webui)
        self.assertFalse((ROOT / "functions/cloudflared_service.py").exists())


if __name__ == "__main__":
    unittest.main()
