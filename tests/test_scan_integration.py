from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ScanIntegrationTests(unittest.TestCase):
    def test_fresh_titles_and_routes_with_independent_logo_reuse(self):
        fixture = {"title": "First", "icon_requests": 0}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if fixture.get("reject_http"):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Client sent an HTTP request to an HTTPS server.\n")
                    return
                icon = self.path == "/icon.svg"
                if icon:
                    fixture["icon_requests"] += 1
                body = ("<svg xmlns='http://www.w3.org/2000/svg'/>" if icon else
                        f'<html><head><title>{fixture["title"]}</title><link rel="icon" href="/icon.svg"></head></html>').encode()
                if not icon:
                    body += b' ' * fixture.get('padding', 0)
                self.send_response(200 if icon else fixture.get("status", 200))
                self.send_header("Content-Type", "image/svg+xml" if icon else "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_port
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            for filename in ("scan.sh", "python_header.py"):
                shutil.copy2(ROOT / filename, base / filename)
            shutil.copytree(ROOT / "functions", base / "functions", ignore=shutil.ignore_patterns("__pycache__"))
            ext = base / "extensions/enabled/localhost"
            ext.mkdir(parents=True)
            (ext / "extension.json").write_text('{"provider":"localhost"}')
            (base / "config.conf").write_text("CITADEL_LOGO_PERSISTENT=1\nCITADEL_HIDE_HTTP_WEBUI_DUPE=1\nCITADEL_HTTPS_ONLY=0\nCITADEL_SUBNET_IP=\nCITADEL_REPORT_MAX_MB=\n")
            bin_dir = base / "bin"
            bin_dir.mkdir()
            ss = bin_dir / "ss"
            ss.write_text('#!/bin/sh\ncat "$SCAN_LISTENERS"\n')
            ss.chmod(0o755)
            listeners = base / "listeners.txt"
            listeners.write_text(f'LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:* users:(("fixture",pid=1,fd=1))\n')
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CITADEL_", "CLOUDFLARE_", "TUNNEL_"))}
            env.update(PATH=f"{bin_dir}:{os.environ['PATH']}", PYTHONNOUSERSITE="1",
                       XDG_RUNTIME_DIR=raw, SCAN_LISTENERS=str(listeners),
                       CITADEL_SCAN_LOCK_FILE=str(base / "scan.lock"))

            def scan(*args):
                result = subprocess.run(["bash", "scan.sh", "--provider", "localhost", *args],
                                        cwd=base, env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads((base / "CITADEL_DATA/services.json").read_text())

            first = scan()
            self.assertEqual(first["http_services"][0]["title"], "First")
            self.assertEqual(fixture["icon_requests"], 1)
            logo = base / f"CITADEL_DATA/icons/{port}.svg"
            before = (logo.read_bytes(), logo.stat().st_mtime_ns)
            fixture["title"] = "Changed"
            # Add is a no-op for known listeners, including absent/offline ones.
            self.assertEqual(scan("--add"), first)
            self.assertEqual(fixture["icon_requests"], 1)
            added_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=added_server.serve_forever, daemon=True).start()
            self.addCleanup(added_server.server_close)
            self.addCleanup(added_server.shutdown)
            new_port = added_server.server_port
            # The old service is absent from discovery but must remain unchanged.
            listeners.write_text(f'LISTEN 0 128 127.0.0.1:{new_port} 0.0.0.0:*\n')
            added = scan("--add")
            self.assertEqual(next(row for row in added["http_services"] if row["port"] == port), first["http_services"][0])
            self.assertEqual(added["added_ports"], [new_port])
            self.assertNotIn("pending_add_ports", added)
            routes = json.loads((base / "CITADEL_DATA/localhost-routes.json").read_text())
            self.assertEqual(set(routes["services"]), {str(port), str(new_port)})
            self.assertEqual((logo.read_bytes(), logo.stat().st_mtime_ns), before)
            self.assertEqual(scan("--add"), added)
            fixture["icon_requests"] = 1
            # Return to the single-service fixture for the full-scan assertions.
            (base / "CITADEL_DATA/services.json").write_text(json.dumps(first))
            listeners.write_text("")
            self.assertEqual(scan("--add"), first)
            listeners.write_text(f'LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:*\n')
            # Reuse must work without any old cache metadata at all.
            (base / f"cache/{port}.json").unlink()
            second = scan()
            service = second["http_services"][0]
            self.assertEqual(service["title"], "Changed")
            self.assertEqual(service["urls"]["localhost"], f"http://127.0.0.1:{port}")
            self.assertEqual(fixture["icon_requests"], 1)
            self.assertEqual((logo.read_bytes(), logo.stat().st_mtime_ns), before)
            env["CITADEL_LOGO_PERSISTENT"] = "0"
            scan()
            self.assertEqual(fixture["icon_requests"], 2)
            fixture['padding'] = 2 * 1048576
            fixture['title'] = 'Large report with default limit'
            self.assertEqual(scan()['http_services'][0]['title'], fixture['title'])
            fixture['padding'] = 6 * 1048576
            fixture['title'] = 'Large report &amp; configured limit'
            env['CITADEL_REPORT_MAX_MB'] = '15'
            self.assertEqual(scan()['http_services'][0]['title'], 'Large report & configured limit')
            fixture['padding'] = 0
            # A live proxy with a missing backend must not retain a web route.
            for status in (404, 502):
                fixture['status'] = status
                self.assertEqual(scan()['http_services'], [])
                self.assertEqual(json.loads((base / 'CITADEL_DATA/localhost-routes.json').read_text())['services'], {})
            # The configured CSV replaces the default; auth responses still count.
            env['CITADEL_BLACKLIST_STATUS'] = ' 404 , 503 '
            self.assertEqual(scan()['http_services'][0]['port'], port)
            fixture['status'] = 401
            self.assertEqual(scan()['http_services'][0]['port'], port)
            fixture['status'] = 503
            self.assertEqual(scan()['http_services'], [])
            fixture['status'] = 200
            fixture["reject_http"] = True
            rejected = scan()
            self.assertEqual(rejected["http_services"], [])
            self.assertEqual(rejected["other_ports"][0]["port"], port)
            listeners.write_text("")
            self.assertEqual(scan()["http_services"], [])
            self.assertEqual(json.loads((base / "CITADEL_DATA/localhost-routes.json").read_text())["services"], {})
            self.assertFalse((base / f"cache/{port}.json").exists())
            self.assertTrue(logo.is_file())
