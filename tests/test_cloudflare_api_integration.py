from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))
sys.path.insert(0, str(ROOT / "functions/providers"))
import core
import dispatch
from cloudflare_api_routes import output
from health import snapshot


class APIIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, provider in (("cloudflare", "cloudflare"), ("CLOUDFLARE-API", "cloudflare_api_routes")):
            self.write(f"extensions/enabled/{name}/extension.json", {"provider": provider, "enabled": True})
        self.write("CITADEL_DATA/services.json", {"http_services": [{"port": 3070, "scheme": "https", "name": "Blender"}]})
        self.write("CITADEL_DATA/ports.filter.json", {})
        self.write("cache/3070.json", {"kind": "http-service"})
        self.write("CITADEL_DATA/providers_state.json", {"providers": {
            "cloudflare": {"status": "ok"}, "CLOUDFLARE-API": {"status": "ok"}}})
        (self.root / "CITADEL_DATA/last_scan.txt").write_text("2026-10-14T00:00:00Z")
        self.browser_payload = {"considered": True, "available": True,
            "services": {"3070": {"url": "https://3070.example.com"}}, "errors": []}
        hosts = {}
        for mode, hostname in (("api-bearer", "api-3070.example.com"), ("api-oauth", "oauth.api-3070.example.com")):
            hosts[hostname] = {"mode": mode, "port": 3070, "routes": [
                {"id": "mcp", "protocol": "mcp", "path": "/mcp"},
                {"id": "rest", "protocol": "rest", "path": "/api/v1"}]}
        self.api_payload = output({"hosts": hosts}, considered=True, authenticated=True, verify=lambda _: True)
        self.write("cache/cloudflare-routes.json", self.browser_payload)
        self.write("cache/CLOUDFLARE-API-routes.json", self.api_payload)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def test_either_provider_filter_runs_one_shared_reconciliation(self):
        for selected in ([], ["--provider", "cloudflare"], ["--provider", "CLOUDFLARE-API"]):
            calls = []

            def run(command, **_):
                calls.append(command)
                self.write("cache/cloudflare-routes.json", self.browser_payload)
                self.write("cache/CLOUDFLARE-API-routes.json", self.api_payload)
                return subprocess.CompletedProcess(command, 0, "", "")

            args = ["dispatch.py", "--enabled-dir", str(self.root / "extensions/enabled"),
                "--services-file", str(self.root / "CITADEL_DATA/services.json"), "--cache-dir", str(self.root / "cache"),
                "--config-ini", str(self.root / "config.ini"), "--state-file", str(self.root / "CITADEL_DATA/providers_state.json"),
                "--tailscale-file", str(self.root / "tailscale.json"), "--strict", *selected]
            with self.subTest(selected=selected), patch.object(sys, "argv", args), patch.object(dispatch.subprocess, "run", side_effect=run):
                self.assertEqual(dispatch.main(), 0)
                self.assertEqual(len(calls), 1)
                state = json.loads((self.root / "CITADEL_DATA/providers_state.json").read_text())
                self.assertEqual(set(state["available_providers"]), {"cloudflare", "CLOUDFLARE-API"})

    def dashboard(self):
        with patch.multiple(core, BASE_DIR=self.root, SERVICES_FILE=self.root / "CITADEL_DATA/services.json",
            LAST_SCAN_FILE=self.root / "CITADEL_DATA/last_scan.txt", ENABLED_EXT_DIR=self.root / "extensions/enabled",
            PROVIDERS_STATE_FILE=self.root / "CITADEL_DATA/providers_state.json", UI_CONFIG_FILE=self.root / "extensions/ui.json",
            PORT_FILTER_FILE=self.root / "CITADEL_DATA/ports.filter.json"):
            return core.build_dashboard()

    def test_one_extension_yields_two_modes_and_all_endpoint_links(self):
        dashboard = self.dashboard()
        self.assertEqual(set(dashboard["provider_options"]), {"cloudflare", "api-bearer", "api-oauth"})
        tile = dashboard["http_tiles"][0]
        for mode in ("api-bearer", "api-oauth"):
            self.assertEqual(len(tile["provider_endpoints"][mode]), 2)
        self.assertEqual(tile["provider_urls"]["cloudflare"], "https://3070.example.com")
        from jinja2 import Environment, FileSystemLoader
        page = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=True).get_template("index.html").render(data=dashboard)
        self.assertIn('value="api-bearer"', page)
        self.assertIn('value="api-oauth"', page)
        self.assertIn("oauth.api-3070.example.com/mcp", page)
        self.assertIn("oauth.api-3070.example.com/api/v1", page)

    def test_health_keeps_both_modes_and_does_not_claim_authenticated_protocol_success(self):
        result = snapshot(self.root, ["CLOUDFLARE-API"])
        self.assertEqual(result["status"], "PASS")
        endpoints = result["extensions"][0]["services"]
        self.assertEqual(len(endpoints), 4)
        self.assertEqual({endpoint["provider"] for endpoint in endpoints}, {"api-bearer", "api-oauth"})
        self.assertTrue(all("NOT_TESTED" in endpoint["detail"] for endpoint in endpoints))

    def test_inactive_mode_hidden_and_disabled_extension_reports_pending_cleanup(self):
        self.api_payload["views"].pop("api-bearer")
        self.write("cache/CLOUDFLARE-API-routes.json", self.api_payload)
        self.assertNotIn("api-bearer", self.dashboard()["provider_options"])
        disabled = self.root / "extensions/disabled"
        disabled.mkdir()
        (self.root / "extensions/enabled/CLOUDFLARE-API").rename(disabled / "CLOUDFLARE-API")
        self.write("cache/CLOUDFLARE-API-routes.json", {"cleanup_pending": True})
        dashboard = self.dashboard()
        self.assertNotIn("api-oauth", dashboard["provider_options"])
        self.assertTrue(any("cleanup is pending" in alert for alert in dashboard["alerts"]))


if __name__ == "__main__":
    unittest.main()
