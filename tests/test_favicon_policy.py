import base64
import json
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


FUNCTIONS_DIR = Path(__file__).resolve().parents[1] / "functions"
sys.path.insert(0, str(FUNCTIONS_DIR))

from favicon_policy import mcp_icon_sources, discover_icon, icon_extension, safe_icon_urls, scan_icon


class FaviconPolicyTests(unittest.TestCase):
    def test_accepts_relative_and_same_endpoint_urls(self):
        urls = safe_icon_urls(
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080/app/",
            ["/favicon.ico", "icon.png", "https://127.0.0.1:8080/secure.webp"],
        )
        self.assertEqual(
            urls,
            [
                "http://127.0.0.1:8080/favicon.ico",
                "http://127.0.0.1:8080/app/icon.png",
                "https://127.0.0.1:8080/secure.webp",
            ],
        )

    def test_rejects_foreign_link_local_and_other_ports(self):
        urls = safe_icon_urls(
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080/",
            [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:9090/favicon.ico",
                "https://example.net/favicon.ico",
                "file:///etc/passwd",
            ],
        )
        self.assertEqual(urls, [])

    def test_foreign_redirect_base_is_ignored(self):
        urls = safe_icon_urls(
            "http://127.0.0.1:8080",
            "http://example.net/redirected/",
            ["relative.png"],
        )
        self.assertEqual(urls, ["http://127.0.0.1:8080/relative.png"])

    def test_goaccess_inline_icon_and_size_limit(self):
        url = "https://127.0.0.1:1234"
        ico = bytes.fromhex("000001000100") + bytes(18)
        encoded = base64.b64encode(ico).decode()
        html = f'<link rel="shortcut ICON" href="data:image/x-icon;base64,{encoded}">'
        self.assertEqual(discover_icon(html, url, url, self.fail, 128), (".ico", ico))
        missing = lambda path: (b"", path)
        self.assertIsNone(discover_icon(html, url, url, missing, 4))

    def test_invalid_inline_candidate_and_percent_encoded_svg(self):
        url = "http://localhost:8080"
        html = ('<link rel=icon href="data:image/png;base64,!!!">'
                '<link rel=icon href="data:image/svg+xml,%3Csvg%2F%3E">')
        self.assertEqual(discover_icon(html, url, url, self.fail, 100), (".svg", b"<svg/>"))

    def test_injected_favicon_without_html(self):
        url = "http://localhost:8080"
        def fetch(path):
            body = b"<svg/>" if path == url + "/favicon.svg" else b"<html/>"
            return body, path
        self.assertEqual(discover_icon("", url, url, fetch, 100), (".svg", b"<svg/>"))

    def test_manifest_and_html_base(self):
        url = "http://localhost:8080"
        html = '<base href="/app/"><link rel=manifest href="manifest.json">'
        resources = {
            url + "/app/manifest.json": (b'{"icons":[{"src":"icon.svg"}]}', url + "/static/site.json"),
            url + "/static/icon.svg": (b"<svg/>", url + "/static/icon.svg"),
        }
        self.assertEqual(discover_icon(html, url, url, resources.__getitem__, 100), (".svg", b"<svg/>"))

    def test_injected_file_with_generic_mime_and_redirect(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"/>'
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                requests.append(self.path)
                if self.path == "/favicon.svg":
                    self.send_response(302)
                    self.send_header("Location", "/injected/logo.svg")
                elif self.path == "/injected/logo.svg":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.end_headers()
                    self.wfile.write(svg)
                    return
                else:
                    self.send_response(404)
                self.end_headers()

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with tempfile.TemporaryDirectory() as directory:
                    port = server.server_port
                    url = f"http://127.0.0.1:{port}"
                    filename = scan_icon("", url, url, Path(directory), port, 2048, "")
                    self.assertEqual(filename, f"{port}.svg")
                    self.assertEqual((Path(directory) / filename).read_bytes(), svg)
                    self.assertIn("/injected/logo.svg", requests)
            finally:
                server.shutdown()
                thread.join()

    def test_external_base_and_malformed_links_do_not_prevent_fallback(self):
        url = "http://localhost:8080"
        html = ('<base href="https://elsewhere.example/"><link rel=icon href="icon.svg">'
                '<link rel=icon href="http://["><link rel=icon href="file:///tmp/logo.png">')
        requested = []
        def fetch(path):
            requested.append(path)
            return b"<svg/>", path
        self.assertEqual(discover_icon(html, url, url, fetch, 100), (".svg", b"<svg/>"))
        self.assertEqual(requested, [url + "/favicon.png"])

    def test_mcp_initialize_icon_replaces_cached_favicon_and_closes_session(self):
        from api_discovery import Probe, LocalProbes
        from cloudflare_api_policy import route_id

        port = 4242
        url = f"https://127.0.0.1:{port}"
        key = route_id(port, "mcp", "/api/mcp")
        svg = b"<svg/>"
        src = "data:image/svg+xml;base64," + base64.b64encode(svg).decode()
        result = {"protocolVersion": "2025-11-25", "capabilities": {},
                  "serverInfo": {"icons": [{"src": src}]}}
        event = "data: " + json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}) + "\n\n"
        def initialize(_self, path, method, payload, headers):
            self.assertEqual(method, "POST")
            self.assertEqual(payload["method"], "initialize")
            if path != "/api/mcp":
                self.assertFalse(headers)
                return Probe(404, {}, b"")
            self.assertEqual(headers.get("authorization"), "Bearer fixture")
            return Probe(200, {"content-type": "text/event-stream", "mcp-session-id": "session"}, event.encode())

        with tempfile.TemporaryDirectory() as tmp, patch.object(LocalProbes, "__call__", initialize), \
                patch("urllib.request.OpenerDirector.open") as close_session:
            directory = Path(tmp)
            access = directory / "CLOUDFLARE-API_access.json"
            access.write_text(json.dumps({"routes": {key: "client;fixture"}}))
            access.chmod(0o600)
            old_name = f"{port}.png"
            (directory / old_name).write_bytes(b"old")
            name = scan_icon("", url, url, directory, port, 2048, "",
                             mcp_sources=mcp_icon_sources("https", port, directory), cached=old_name)
            self.assertEqual(name, f"{port}.svg")
            self.assertEqual((directory / name).read_bytes(), svg)
            self.assertFalse((directory / old_name).exists())
            request = close_session.call_args.args[0]
            self.assertEqual((request.method, request.full_url), ("DELETE", url + "/api/mcp"))

    def test_invalid_mcp_icon_falls_back_to_http_or_retained_icon(self):
        url = "https://127.0.0.1:4242"
        sources = [("/mcp", ["data:image/png;base64,@@@@", "https://other.example/icon.png"])]
        def fetch(path):
            self.assertEqual(path, url + "/favicon.png")
            return b"<svg/>", path
        self.assertEqual(discover_icon("", url, url, fetch, 2048, mcp_sources=sources), (".svg", b"<svg/>"))
        self.assertIsNone(discover_icon("", url, url, self.fail, 2048, mcp_sources=sources, cached="4242.png"))

    def test_only_passive_supported_image_types_are_accepted(self):
        self.assertEqual(icon_extension("image/png; charset=binary"), ".png")
        self.assertEqual(icon_extension("image/jpeg"), ".jpeg")
        self.assertEqual(icon_extension("IMAGE/JPEG; charset=binary"), ".jpeg")
        self.assertEqual(icon_extension("image/x-icon"), ".ico")
        self.assertEqual(icon_extension("image/svg+xml"), ".svg")
        self.assertEqual(icon_extension("text/html"), "")


if __name__ == "__main__":
    unittest.main()
