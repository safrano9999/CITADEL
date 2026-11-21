import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest

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
