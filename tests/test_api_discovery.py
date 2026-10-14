from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))

from api_discovery import (
    GRAPHQL_QUERY, LocalProbes, Probe, discover_service, documentation_links,
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
            return responses.get(path, Probe(404, {}, b""))

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
                self.assertTrue(all(call[2]["method"] == "initialize" for call in self.calls if call[1] == "POST"))
                self.assertLessEqual(len(self.calls), 20)

    def test_html_and_auth_status_are_not_protocol_proof(self):
        rows = self.discover({"/mcp": Probe(200, {"content-type": "text/html"}, b"<html>Login</html>"),
                              "/api/mcp": reply({"error": "Unauthorized"}, 401)})
        self.assertFalse(any(row["status"] == "ready" for row in rows))
        self.assertEqual(rows[0]["status"], "authentication-required")

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


if __name__ == "__main__":
    unittest.main()
