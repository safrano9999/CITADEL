from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))

from api_discovery import (
    GRAPHQL_QUERY, MAX_REQUESTS, MISSING_PATH, TOOLS_INVOKE_PATH, LocalProbes, Probe, discover_service, documentation_links,
    json_message, openapi_operations,
)
from cloudflare_api_policy import route_id


def reply(data, status=200):
    return Probe(status, {"content-type": "application/json"}, json.dumps(data).encode())


class DiscoveryTests(unittest.TestCase):
    service = {"port": 3070, "scheme": "https", "title": "Blender bridge"}

    def discover(self, responses, credentials=None):
        self.calls = []

        def probe(path, method="GET", payload=None, headers=None, **kwargs):
            self.calls.append((path, method, payload, headers, kwargs))
            return responses.get((method, path), responses.get(path, Probe(404, {}, b"")))

        return discover_service(self.service, credentials or {}, probe=probe)

    def test_initialize_json_and_sse_detect_same_protocol_without_tool_execution(self):
        message = {"jsonrpc": "2.0", "id": 1, "result": {
            "protocolVersion": "2025-06-18", "serverInfo": {"name": "bridge"}, "capabilities": {}}}
        for response in (reply(message), Probe(200, {"content-type": "text/event-stream"},
                 b'event: message\r\ndata: ' + json.dumps(message).encode() + b'\r\n\r\n')):
            with self.subTest(headers=response.headers):
                rows = self.discover({"/mcp": response})
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["status"], "ready")
                self.assertEqual(rows[0]["protocol"], "mcp")
                self.assertTrue(rows[0]["detected"])
                self.assertTrue(all(call[2]["method"] == "initialize" for call in self.calls if call[1] == "POST"))
                self.assertLessEqual(len(self.calls), MAX_REQUESTS)

    def test_html_and_auth_status_are_not_protocol_proof(self):
        rows = self.discover({"/mcp": Probe(200, {"content-type": "text/html"}, b"<html>Login</html>"),
                              "/api/mcp": reply({"error": "Unauthorized"}, 401)})
        self.assertFalse(any(row["status"] == "ready" for row in rows))
        self.assertFalse(any(row["detected"] for row in rows))
        self.assertEqual(rows[0]["status"], "authentication-required")

    def test_legacy_sse_is_reported_unsupported_without_following_its_endpoint(self):
        response = Probe(200, {"content-type": "text/event-stream"},
                         b"event: endpoint\ndata: https://other.example/messages\n\n")
        rows = self.discover({"/sse": response})
        self.assertEqual(rows[0]["status"], "unsupported")
        self.assertTrue(rows[0]["detected"])
        self.assertFalse(any("other.example" in call[0] for call in self.calls))
        probe = LocalProbes("http", 3070)
        stream = Mock(code=200, headers=response.headers)
        stream.read1.side_effect = [response.body, AssertionError("must not wait on legacy stream")]
        with patch.object(probe.opener, "open", return_value=stream):
            self.assertEqual(probe("/sse").body, response.body)
        stream.close.assert_called_once()

    def test_backend_secret_only_sent_to_matching_candidate_and_not_in_inventory(self):
        key = route_id(3070, "mcp", "/mcp")
        rows = self.discover({"/mcp": reply({}, 401)}, {key: {"authorization": "Bearer private-backend"}})
        self.assertEqual(self.calls[0][3], {"authorization": "Bearer private-backend"})
        self.assertTrue(all(not call[3] for call in self.calls[1:]))
        self.assertNotIn("private-backend", json.dumps(rows))
        self.assertEqual(rows[0]["credential_ref"], key)

    def test_openapi_lists_exact_methods_and_auth_requirements(self):
        document = {"openapi": "3.1.0", "servers": [{"url": "/api/v1"}], "security": [{"token": []}],
                    "paths": {"/tasks/{id}": {"get": {}, "delete": {}}, "/health": {"get": {"security": []}}}}
        rows = self.discover({"/openapi.json": reply(document)})
        api = next(row for row in rows if row["path"] == "/api/v1")
        self.assertEqual(api["status"], "authentication-required")
        self.assertTrue(api["detected"])
        self.assertEqual(api["operations"][0], {"path": "/api/v1/tasks/{id}", "method": "GET", "requires_auth": True})
        key = api["id"]
        rows = self.discover({"/openapi.json": reply(document)}, {key: {"authorization": "Bearer test"}})
        self.assertEqual(next(row for row in rows if row["id"] == key)["status"], "ready")

    def test_external_targets_and_ambiguous_paths_are_rejected(self):
        for document in (
            {"openapi": "3.1.0", "servers": [{"url": "https://other.example/api"}], "paths": {"/a": {"get": {}}}},
            {"swagger": "2.0", "paths": {"/api/%2e%2e/admin": {"get": {}}}},
            {"openapi": "3.1.0", "paths": {"/a": {"$ref": "https://other.example/spec"}}},
        ):
            with self.subTest(document=document), self.assertRaises(ValueError):
                openapi_operations(document, "https://127.0.0.1:3070/openapi.json")

    def test_unsupported_openapi_map_is_detected_without_publishing_operations(self):
        document = {"openapi": "3.1.0", "paths": {
            "/items": {"get": {}}, "/proxy/{path:path}": {"post": {}}}}
        rows = self.discover({"/openapi.json": reply(document)})
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["detected"])
        self.assertEqual(rows[0]["status"], "unsupported")
        self.assertEqual(rows[0]["path"], "/openapi.json")
        self.assertEqual(rows[0]["operations"], [])
        self.assertFalse(any(row["detected"] for row in self.discover({"/api": reply({"status": "ok"})})))

    def test_multiple_documents_merge_operations_and_later_root_probe_does_not_erase_them(self):
        first = {"openapi": "3.1.0", "servers": [{"url": "/api"}],
                 "paths": {"/one": {"get": {}}, "/shared": {"get": {}}}}
        second = {"openapi": "3.1.0", "servers": [{"url": "/api"}], "security": [{"token": []}],
                  "paths": {"/two": {"get": {}}, "/shared": {"get": {}}}}
        rows = self.discover({"/openapi.json": reply(first), "/swagger.json": reply(second), "/api": reply({"status": "ok"})})
        api = next(row for row in rows if row["path"] == "/api")
        self.assertEqual(api["status"], "authentication-required")
        self.assertEqual({op["path"] for op in api["operations"]}, {"/api/one", "/api/two", "/api/shared"})
        self.assertTrue(next(op for op in api["operations"] if op["path"] == "/api/shared")["requires_auth"])

    def test_graphql_uses_only_read_only_query(self):
        rows = self.discover({"/graphql": reply({"data": {"__typename": "Query"}})})
        self.assertEqual(rows[0]["status"], "ready")
        call = next(call for call in self.calls if call[0] == "/graphql")
        self.assertEqual(call[1], "GET")
        self.assertEqual(call[4]["query"], {"query": GRAPHQL_QUERY})

    def test_invocation_api_detected_without_token_and_without_tool_execution(self):
        rows = self.discover({TOOLS_INVOKE_PATH: Probe(405, {"allow": "POST"}, b""),
            ("POST", TOOLS_INVOKE_PATH): reply({"error": {"type": "unauthorized"}}, 401)})
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["protocol"], rows[0]["status"]), ("rpc", "authentication-required"))
        self.assertTrue(rows[0]["detected"])
        self.assertEqual(rows[0]["operations"], [{"path": TOOLS_INVOKE_PATH, "method": "POST", "requires_auth": True}])
        self.assertEqual(next(call[2] for call in self.calls if call[:2] == (TOOLS_INVOKE_PATH, "POST")), {})
        self.assertLessEqual(len(self.calls), MAX_REQUESTS)
        from cloudflare_api_policy import APISettings
        from cloudflare_plan import api_routes
        from cloudflare_api_access import parse_entries
        self.assertEqual(api_routes(rows, APISettings(enabled=True), "example.com", {row["id"]: parse_entries("client;backend") for row in rows})["hosts"], {})

    def test_invocation_validation_proves_readiness_only_after_authentication(self):
        key = route_id(3070, "rpc", TOOLS_INVOKE_PATH)
        rows = self.discover({TOOLS_INVOKE_PATH: Probe(405, {"allow": "POST"}, b""),
            ("POST", TOOLS_INVOKE_PATH): reply({"ok": False, "error": {
                "type": "invalid_request", "message": "tools.invoke requires name"}}, 400)},
            {key: {"authorization": "Bearer private"}})
        self.assertEqual(rows[0]["status"], "ready")
        self.assertEqual(rows[0]["credential_ref"], key)
        self.assertEqual(next(call[3] for call in self.calls if call[0] == MISSING_PATH), None)
        self.assertNotIn("private", json.dumps(rows))
        from cloudflare_api_policy import APISettings
        from cloudflare_plan import api_routes
        from cloudflare_api_access import parse_entries
        plan = api_routes(rows, APISettings(enabled=True), "example.com", {row["id"]: parse_entries("client;backend") for row in rows})
        route = plan["hosts"]["api-3070.example.com"]["routes"][0]
        self.assertEqual(route["operations"], [{"path": TOOLS_INVOKE_PATH, "method": "POST"}])
        self.assertEqual(route["access_ref"], key)

    def test_invocation_probe_rejects_global_method_auth_and_html_responses(self):
        for responses in (
            {TOOLS_INVOKE_PATH: reply({"error": "unauthorized"}, 401)},
            {TOOLS_INVOKE_PATH: Probe(405, {"allow": "POST"}, b""), MISSING_PATH: Probe(405, {"allow": "POST"}, b"")},
            {TOOLS_INVOKE_PATH: Probe(405, {"allow": "GET"}, b"")},
            {TOOLS_INVOKE_PATH: Probe(405, {"allow": "POST"}, b""), ("POST", TOOLS_INVOKE_PATH): Probe(401, {"content-type": "text/html"}, b"Login")},
        ):
            with self.subTest(responses=responses):
                self.assertFalse(any(row.get("detected") for row in self.discover(responses)))

    def test_additional_schema_locations_are_discovered(self):
        for path in ("/api-doc/openapi.json", "/api/schema/", "/doc"):
            with self.subTest(path=path):
                rows = self.discover({path: reply({"openapi": "3.0.3", "paths": {"/api/items": {"get": {}}}})})
                self.assertTrue(any(row["detected"] and row["protocol"] == "rest" for row in rows))

    def test_admin_listener_never_probed(self):
        probe = Mock(side_effect=AssertionError("Admin API must not be discovered"))
        for service, ports in ((self.service, [3070]), ({**self.service, "citadel_webui": True}, []),
                               ({**self.service, "title": "Citadel"}, [])):
            self.assertEqual(discover_service(service, {}, probe=probe, admin_ports=ports), [])

    def test_only_same_origin_document_links_followed(self):
        response = reply({"openapi_url": "/docs/spec.json", "swagger_url": "https://evil.example/spec.json"})
        self.assertEqual(documentation_links(response, "https://127.0.0.1:3070/api"), ["/docs/spec.json"])
        rows = self.discover({"/api": response, "/docs/spec.json": reply({
            "openapi": "3.1.0", "paths": {"/api/tasks": {"get": {}}}})})
        self.assertTrue(any(row["status"] == "ready" for row in rows))
        self.assertTrue(all("evil" not in call[0] for call in self.calls))

    def test_transport_rejects_mutating_queries_and_arbitrary_targets(self):
        probe = LocalProbes("https", 3070)
        with patch.object(probe.opener, "open") as open_request:
            for path, kwargs in (("https://other/mcp", {}), ("/mcp", {"method": "POST", "payload": {"method": "tools/call"}}),
                                 (TOOLS_INVOKE_PATH, {"method": "POST", "payload": {"tool": "exec", "args": {}}}),
                                 (TOOLS_INVOKE_PATH, {"method": "POST", "payload": {"method": "initialize", "tool": "exec"}}),
                                 ("/unrelated", {"method": "POST", "payload": {}}),
                                 ("/graphql", {"query": {"query": "mutation { deleteAll }"}})):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    probe(path, **kwargs)
            open_request.assert_not_called()

    def test_sse_transport_stops_after_result_without_waiting_for_eof(self):
        probe = LocalProbes("http", 3070)
        response = Mock(code=200, headers={"content-type": "text/event-stream"})
        response.read1.side_effect = [b'data: {"jsonrpc":"2.0","id":1,"result":{}}\n\n', AssertionError("must not wait")]
        with patch.object(probe.opener, "open", return_value=response):
            result = probe("/mcp", "POST", {"method": "initialize"})
        self.assertEqual(json_message(result)["id"], 1)
        response.close.assert_called_once()

    def test_mcp_initialize_accepts_delayed_bridge_startup(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading

        delay = threading.Event()

        class Bridge(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.end_headers()
                self.wfile.flush()
                delay.wait(1.2)
                self.wfile.write(b'data: {"jsonrpc":"2.0","id":1,"result":{}}\n\n')

            def log_message(self, *args):
                pass

        with HTTPServer(('127.0.0.1', 0), Bridge) as server:
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            try:
                probe = LocalProbes('http', server.server_port)
                result = probe('/mcp', 'POST', {'method': 'initialize'})
                self.assertEqual(result.status, 200)
                self.assertEqual(json_message(result)['id'], 1)
            finally:
                delay.set()
                thread.join(timeout=3)

    def test_empty_invocation_transport_reads_only_bounded_error_response(self):
        import io
        probe = LocalProbes("http", 3070)
        response = Mock(code=401, headers={"content-type": "application/json"})
        response.read1.side_effect = io.BytesIO(b'{"error":{"type":"unauthorized"}}').read1
        with patch.object(probe.opener, "open", return_value=response) as opened:
            result = probe(TOOLS_INVOKE_PATH, "POST", {})
            self.assertEqual(opened.call_args.args[0].data, b"{}")
        self.assertEqual(json_message(result)["error"]["type"], "unauthorized")
        response.read1.side_effect = io.BytesIO(b"x" * 16385).read1
        with patch.object(probe.opener, "open", return_value=response):
            self.assertEqual(probe(TOOLS_INVOKE_PATH, "POST", {}).status, 0)

    def test_large_openapi_document_is_read_with_a_bounded_body(self):
        import io
        from api_discovery import MAX_BODY
        body = json.dumps({"openapi": "3.1.0", "info": {"description": "x" * (600 * 1024)},
                           "paths": {"/api/items": {"get": {}}}}).encode()
        probe = LocalProbes("http", 3070)
        response = Mock(code=200, headers={"content-type": "application/json"})
        response.read1.side_effect = io.BytesIO(body).read1
        with patch.object(probe.opener, "open", return_value=response):
            result = probe("/openapi.json")
        self.assertEqual(result.status, 200)
        self.assertEqual(len(openapi_operations(json_message(result), probe.base)[1]), 1)
        response.read1.side_effect = io.BytesIO(b"x" * (MAX_BODY + 1)).read1
        with patch.object(probe.opener, "open", return_value=response):
            self.assertEqual(probe("/openapi.json").status, 0)


if __name__ == "__main__":
    unittest.main()
