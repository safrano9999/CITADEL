import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import webui
from health import snapshot

spec = importlib.util.spec_from_file_location("checker", Path(__file__).resolve().parents[1] / "functions/citadel-health-check.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.write("CITADEL_DATA/services.json", {"http_services": [{"port": 8000, "name": "Example", "urls": {"tailscale": "https://test.ts.net:8000"}}]})
        self.write("cache/8000.json", {"kind": "html"})
        self.write("CITADEL_DATA/providers_state.json", {"providers": {"tailscale": {"status": "ok"}}})
        self.write("extensions/enabled/tailscale/extension.json", {"enabled": True})
        self.write("CITADEL_DATA/tailscale-routes.json", {"considered": True, "available": True, "services": {"8000": {"url": "https://test.ts.net:8000"}}})
        (self.base / "CITADEL_DATA/last_scan.txt").write_text("2026-09-16 18:27:03")

    def write(self, name, data):
        p = self.base / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data))

    def test_read_only_selected_extensions(self):
        before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in self.base.rglob("*") if p.is_file()}
        with patch("subprocess.run", side_effect=AssertionError("No processes")), patch("urllib.request.urlopen", side_effect=AssertionError("No network")):
            data = snapshot(self.base, ["tailscale", "cloudflare"])
        self.assertEqual(data["status"], "PASS")
        self.assertEqual([e["status"] for e in data["extensions"]], ["PASS", "SKIP"])
        after = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in self.base.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_only_absent_extensions_never_pass(self):
        self.assertEqual(snapshot(self.base, ["cloudflare"])["status"], "NOT_TESTED")

    def test_missing_cache_fails(self):
        (self.base / "cache/8000.json").unlink()
        self.assertEqual(snapshot(self.base, ["tailscale"])["status"], "FAIL")

    def test_missing_index_means_not_tested(self):
        (self.base / "CITADEL_DATA/services.json").write_text("not json")
        result = snapshot(self.base, ["tailscale"])
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["extensions"][0]["status"], "NOT_TESTED")

    def test_missing_assigned_route_fails(self):
        self.write("CITADEL_DATA/tailscale-routes.json", {"considered": True, "available": True, "services": {}})
        self.assertEqual(snapshot(self.base, ["tailscale"])["status"], "FAIL")

    def test_provider_failure_is_not_skip(self):
        self.write("CITADEL_DATA/providers_state.json", {"providers": {"tailscale": {"status": "error"}}})
        self.assertEqual(snapshot(self.base, ["tailscale"])["extensions"][0]["status"], "FAIL")

    def test_no_path_traversal(self):
        with self.assertRaises(ValueError):
            snapshot(self.base, ["../../other"])

    def test_health_has_one_route_per_provider_and_port(self):
        services = snapshot(self.base)["extensions"][0]["services"]
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["provider"], "tailscale")

    def test_web_routes_and_html_escape(self):
        with patch.object(webui.core, "BASE_DIR", self.base):
            self.assertEqual(webui.health_json("tailscale")["status"], "PASS")
            page = webui.health_page("tailscale")
            self.assertIn("Saved index state", page)
            self.assertIn("✅", page)
            with self.assertRaises(webui.HTTPException) as error:
                webui.health_json("../bad")
            self.assertEqual(error.exception.status_code, 400)
        script = webui.health_checker()
        self.assertTrue(Path(script.path).is_file())
        paths = {route.path for route in webui.app.routes}
        self.assertTrue({"/healthz", "/api/health", "/healthz/check.py"}.issubset(paths))

    def test_cli_queries_only_selected_extensions(self):
        data = snapshot(self.base, ["tailscale"])
        with patch.object(checker, "fetch", side_effect=[(200, "https://citadel/", b"ok"), (200, "https://citadel/api/health", json.dumps(data).encode()), (200, "https://test.ts.net:8000", b"ok")]) as fetch:
            result = checker.check("https://citadel", ["tailscale"])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(fetch.call_count, 3)
        self.assertIn("extensions=tailscale", fetch.call_args_list[1].args[0])

    def test_self_failure_stops_without_retry(self):
        with patch.object(checker, "fetch", return_value=(503, "https://citadel", b"bad")) as fetch:
            result = checker.check("https://citadel", ["tailscale", "cloudflare"])
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(all(e["status"] == "NOT_TESTED" for e in result["extensions"]))

    def test_cloudflare_login_is_enough(self):
        body = b'<form action="/cdn-cgi/access/verify-code/example"><input type="email"></form>'
        url = "https://team.cloudflareaccess.com/cdn-cgi/access/login/example?secret=hidden"
        with patch.object(checker, "fetch", return_value=(200, url, body)) as fetch:
            result = checker.probe("cloudflare", {"port": 8000, "url": "https://example/"}, 5)
        self.assertEqual(result["status"], "PASS")
        self.assertNotIn("hidden", json.dumps(result))
        self.assertEqual(fetch.call_count, 1)

    def test_arbitrary_200_and_fake_cloudflare_do_not_pass(self):
        for url, body in [("https://team.cloudflareaccess.com/cdn-cgi/access/login/a", b"error"), ("https://cloudflareaccess.com.evil.test/cdn-cgi/access/login/a", b'<form action="/cdn-cgi/access/verify-code/a"><input type="password"></form>')]:
            with self.subTest(url=url), patch.object(checker, "fetch", return_value=(200, url, body)):
                self.assertEqual(checker.probe("cloudflare", {"port": 8000, "url": "https://example"}, 5)["status"], "FAIL")

    def test_unrequested_extension_is_rejected_before_probing(self):
        data = snapshot(self.base, ["tailscale"])
        with patch.object(checker, "fetch", side_effect=[(200, "https://citadel/", b"ok"), (200, "https://citadel/api/health", json.dumps(data).encode())]) as fetch:
            result = checker.check("https://citadel", ["cloudflare"])
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(result["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
