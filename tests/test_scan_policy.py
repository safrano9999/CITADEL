from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))
sys.path.insert(0, str(ROOT / "functions/providers"))
import scan_policy
from scan_policy import existing_icon, hide_webui_http, is_browser_page
from providers.common import routable_services
import core


class ScanPolicyTests(unittest.TestCase):
    def setUp(self):
        self.listeners = [
            {"port": port, "scheme": "https" if port == 2000 else "http"}
            for port in (2000, 4096, 11000)
        ]
        self.instance = "a" * 32

    def test_explicit_discovery_page_marker_keeps_real_web_interfaces(self):
        self.assertFalse(is_browser_page("<html><head><meta content='mcp-discovery' name='citadel-page-role'></head></html>"))
        self.assertTrue(is_browser_page("<html><title>Vikunja</title><body>Web app and MCP endpoint</body></html>"))
        self.assertTrue(is_browser_page("<html><title>MCP dashboard</title><body>Real browser UI</body></html>"))
        self.assertTrue(is_browser_page("<!-- <meta name='citadel-page-role' content='mcp-discovery'> --><html>App</html>"))

    def test_same_instance_https_hides_tile_not_backend(self):
        with patch.object(scan_policy, "probe_webui_instance", return_value=self.instance):
            rows, hidden = hide_webui_http(self.listeners, 11000)
        self.assertEqual(hidden, [11000])
        self.assertTrue(rows[0]["citadel_webui"])
        self.assertTrue(rows[2]["hide_webui_http"])
        self.assertNotIn("hide_webui_http", rows[1])
        self.assertEqual(len(routable_services({"http_services": rows})), 3)
        self.assertNotIn("hide_webui_http", self.listeners[2])

    def test_failed_https_restores_http_on_the_next_scan(self):
        with patch.object(scan_policy, "probe_webui_instance", return_value=self.instance):
            rows, _ = hide_webui_http(self.listeners, 11000)
        with patch.object(scan_policy, "probe_webui_instance", side_effect=[self.instance, ""]):
            restored, hidden = hide_webui_http(rows, 11000)
        self.assertEqual(hidden, [])
        self.assertNotIn("hide_webui_http", restored[2])

    def test_another_containers_citadel_is_not_the_same_instance(self):
        with patch.object(scan_policy, "probe_webui_instance", side_effect=[self.instance, "b" * 32]):
            rows, hidden = hide_webui_http(self.listeners, 11000)
        self.assertEqual(hidden, [])
        self.assertNotIn("hide_webui_http", rows[2])

    def test_missing_backend_marker_does_not_hide_by_port_or_title(self):
        self.listeners[0]["title"] = "CITADEL"
        with patch.object(scan_policy, "probe_webui_instance", return_value="") as probe:
            rows, hidden = hide_webui_http(self.listeners, 11000)
        self.assertEqual(hidden, [])
        probe.assert_called_once_with("http", 11000, "")

    def test_disabled_absent_or_https_backend_does_not_probe(self):
        for rows, enabled in (
            (self.listeners, False),
            ([row for row in self.listeners if row["port"] != 2000], True),
            ([row for row in self.listeners if row["port"] != 11000], True),
            ([dict(row, scheme="https") for row in self.listeners], True),
        ):
            with self.subTest(rows=rows, enabled=enabled):
                with patch.object(scan_policy, "probe_webui_instance") as probe:
                    self.assertEqual(hide_webui_http(rows, 11000, enabled), (rows, []))
                probe.assert_not_called()

    def test_only_successful_local_probe_with_valid_marker_is_accepted(self):
        response = MagicMock()
        response.__enter__.return_value = response
        opener = MagicMock()
        opener.open.return_value = response
        for status, marker, expected in (
            (200, self.instance, self.instance), (302, self.instance, ""),
            (500, self.instance, ""), (200, "", ""), (200, "CITADEL", ""),
        ):
            response.status = status
            response.headers = {"X-Citadel-Instance": marker}
            with patch.object(scan_policy, "build_opener", return_value=opener):
                self.assertEqual(scan_policy.probe_webui_instance("https", 2000, "test-agent"), expected)
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://127.0.0.1:2000/")
            self.assertEqual(request.get_header("User-agent"), "test-agent")
        opener.open.side_effect = HTTPError("https://127.0.0.1:2000/", 302, "redirect", {}, None)
        with patch.object(scan_policy, "build_opener", return_value=opener):
            self.assertEqual(scan_policy.probe_webui_instance("https", 2000), "")
        self.assertIsNone(scan_policy.NoRedirects().redirect_request(None, None, 302, "", {}, "http://elsewhere/"))

    def test_scan_marks_visibility_before_dispatch_without_caddy_dependency(self):
        scan = (ROOT / "scan.sh").read_text()
        self.assertNotIn("caddy_export.py", scan)
        self.assertLess(scan.index('"$FUNCTIONS_DIR/scan_policy.py"'), scan.index("dispatch.py"))
        self.assertIn("CITADEL_HIDE_HTTP_WEBUI_DUPE", scan)
        self.assertNotIn("CITADEL_WEBUI_HTTPS_PORT", scan)

    def test_https_dashboard_keeps_featured_tile_without_a_port_setting(self):
        with patch.dict("os.environ", {"CITADEL_WEBUI_PORT": "11000"}):
            self.assertTrue(core._is_citadel_service({"port": 2000, "citadel_webui": True}))
            self.assertTrue(core._is_citadel_service({"port": 11000}))
            self.assertFalse(core._is_citadel_service({"port": 4096}))

    def test_dashboard_hides_only_explicit_duplicate(self):
        services = {"http_services": [dict(row) for row in self.listeners]}
        services["http_services"][2]["hide_webui_http"] = True
        def read(path, default):
            return services if path == core.SERVICES_FILE else default
        providers = dict(provider_order=[], provider_options={}, provider_urls_by_port={},
                         provider_header_meta=[], alerts=[], cloudflare_available=False)
        with patch.object(core, "_read_json", side_effect=read), patch.object(core, "_load_providers", return_value=providers):
            dashboard = core.build_dashboard()
        self.assertEqual([row["port"] for row in dashboard["http_tiles"]], [2000, 4096])

    def test_logo_lookup_does_not_depend_on_old_metadata(self):
        with tempfile.TemporaryDirectory() as raw:
            Path(raw, "4096.svg").write_text("<svg/>")
            self.assertEqual(existing_icon(raw, 4096), "4096.svg")
            self.assertEqual(existing_icon(raw, 2000), "")


if __name__ == "__main__":
    unittest.main()
