import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import MagicMock, patch

from functions import availability


class Routes(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/": (200, {}),
            "/access": (302, {"Location": "https://team.cloudflareaccess.com/cdn-cgi/access/login/firefly"}),
            "/unrelated": (302, {"Location": "https://example.org/"}),
            "/challenge": (403, {"cf-mitigated": "challenge"}),
            "/auth": (401, {"WWW-Authenticate": 'Bearer realm="fixture"'}),
            "/down": (503, {}),
            "/start": (302, {"Location": "/login", "Set-Cookie": "visit=1; Path=/"}),
            "/login": (200, {}) if self.headers.get("Cookie") == "visit=1" else (302, {"Location": "/login"}),
        }
        code, headers = routes[self.path]
        self.send_response(code)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()

    def log_message(self, *_):
        pass


class AvailabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Routes)
        cls.url = f"http://127.0.0.1:{server.server_port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(server.server_close)
        cls.addClassCleanup(server.shutdown)

    def test_hover_details_and_access_boundaries(self):
        for path, state, detail in [
            ("/", "up", "HTTP 200 OK"), ("/access", "auth", "Cloudflare Access"),
            ("/unrelated", "down", "redirect outside"), ("/auth", "auth", "Bearer"),
            ("/challenge", "auth", "Cloudflare browser challenge"), ("/down", "down", "503 Service Unavailable"),
        ]:
            with self.subTest(path=path):
                actual, tooltip = availability.probe(self.url + path)
                self.assertEqual(actual, state)
                self.assertIn(detail, tooltip)

    def test_redirect_cookies_are_limited_to_one_probe(self):
        self.assertEqual(availability.probe(self.url + "/start")[0], "up")
        self.assertEqual(availability.probe(self.url + "/login"), ("down", "Redirect limit exceeded"))

    def test_https_upgrade_uses_final_response_and_rejects_downgrade(self):
        def response(code, headers):
            obj = MagicMock(status=code, headers=headers, reason="fixture")
            obj.__enter__.return_value = obj
            return obj
        with patch.object(availability, "build_opener") as build:
            opener = build.return_value
            upgrade = response(308, {"Location": "https://example.com/p?q=1"})
            for code, state in [(200, "up"), (503, "down")]:
                opener.open.side_effect = [upgrade, response(code, {})]
                self.assertEqual(availability.probe("http://example.com/p?q=1")[0], state)
                self.assertEqual(opener.open.call_args.args[0].full_url, "https://example.com/p?q=1")
            opener.open.side_effect = [upgrade, response(302, {"Location": "http://example.com/"})]
            self.assertIn("outside", availability.probe("http://example.com/")[1])

    def test_only_requested_indexed_tiles_and_active_link_are_checked(self):
        dashboard = {"http_tiles": [
            {"port": 10, "provider_urls": {"local": self.url + "/down"}},
            {"port": 11, "provider_urls": {}, "interface_links": {"local": [{"url": self.url + "/"}]}},
            {"port": 12, "provider_urls": {"local": self.url + "/access"}},
        ]}
        async def collect():
            targets = availability.tile_urls(dashboard, "local", {"10", "11", "999"})
            return [chunk async for chunk in availability.stream(targets)]
        events = asyncio.run(collect())
        self.assertTrue(events[-1].startswith("event: done"))
        results = {row["port"]: row["state"] for row in (json.loads(e[6:]) for e in events[:-1])}
        self.assertEqual(results, {"10": "down", "11": "up"})
