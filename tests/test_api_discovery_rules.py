from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))
sys.path.insert(0, str(ROOT / "functions/providers"))
from api_discovery import Probe, discover_service
from api_discovery_rules import FILENAME, load_rules
from cloudflare_api_policy import APISettings, route_id
from cloudflare_plan import api_routes
from providers.cloudflare_api_routes import discover


class LocalDiscoveryRulesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.document = json.loads((ROOT / (FILENAME + ".example")).read_text())
        self.rule = self.document["routes"][0]
        self.service = {"port": 3070, "scheme": "https", "title": "Blender Bridge"}

    def load(self):
        (self.root / FILENAME).write_text(json.dumps(self.document))
        return load_rules(self.root)

    def run_discovery(self, response, *, credentials=None, service=None):
        self.calls = []
        def probe(path, method="GET", payload=None, headers=None, **kwargs):
            self.calls.append((path, method, payload, headers))
            return response if path == "/api/status" else Probe(404, {}, b"")
        return discover_service(service or self.service, credentials or {}, rules=self.load(), probe=probe)

    def test_optional_file_and_invalid_configuration(self):
        self.assertEqual(load_rules(self.root), ())
        original = deepcopy(self.document)
        bad_rules = [
            {**self.rule, "port": True}, {**self.rule, "title": ""},
            {**self.rule, "headers": {"Authorization": "secret"}},
            {**self.rule, "probe": {"path": "https://evil.example/api", "json_type": "object"}},
            {**self.rule, "probe": {"path": "/other", "json_type": "object"}},
            {**self.rule, "probe": {"path": "/api/status", "json_type": "object", "method": "POST"}},
            {**self.rule, "operations": [{"path": "/apiary/secret", "method": "GET", "requires_auth": False}]},
            {**self.rule, "operations": [{"path": "/api/{path:path}", "method": "GET", "requires_auth": False}]},
            {**self.rule, "operations": [{"path": "/api/status", "method": "GET"}]},
        ]
        for rule in bad_rules:
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                self.document = {"routes": [rule]}
                self.load()
        self.document = {"routes": original["routes"] * 2}
        with self.assertRaises(ValueError):
            self.load()
        (self.root / FILENAME).write_text("{")
        with self.assertRaises(ValueError):
            load_rules(self.root)

    def test_verified_rule_has_exact_scope_and_never_executes_declared_operation(self):
        response = Probe(200, {"content-type": "application/json"}, b'{"status":"ok","version":"1"}')
        rows = self.run_discovery(response)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "authentication-required")
        self.assertTrue(rows[0]["detected"])
        self.assertFalse(any(call[0] == "/api/render" for call in self.calls))
        key = route_id(3070, "rest", "/api")
        rows = self.run_discovery(response, credentials={key: {"authorization": "Bearer private"}})
        self.assertEqual(rows[0]["status"], "ready")
        self.assertEqual(self.calls[0][3], {"authorization": "Bearer private"})
        self.assertTrue(all(not call[3] for call in self.calls[1:] if call[0] != "/api"))
        self.assertNotIn("private", json.dumps(rows))
        plan = api_routes(rows, APISettings(enabled=True, bearer="a" * 64), "example.com")
        route = plan["hosts"]["api-3070.example.com"]["routes"][0]
        self.assertEqual(route["operations"], [{"method": "GET", "path": "/api/status"},
                                              {"method": "POST", "path": "/api/render"}])

    def test_unverified_or_changed_service_does_not_publish(self):
        for response in (Probe(401, {"content-type": "application/json"}, b'{"error":"unauthorized"}'),
                         Probe(200, {"content-type": "text/html"}, b"login"),
                         Probe(200, {"content-type": "application/json"}, b'{"wrong":"api"}'),
                         Probe(302, {"location": "https://evil.example"}, b""), Probe(0, {}, b"")):
            with self.subTest(response=response):
                rows = self.run_discovery(response)
                self.assertFalse(any(row["detected"] for row in rows))
                self.assertEqual(api_routes(rows, APISettings(enabled=True, bearer="a" * 64), "example.com")["hosts"], {})
        self.run_discovery(Probe(200, {"content-type": "application/json"}, b"{}"),
                           service={**self.service, "title": "Another service"})
        self.assertFalse(any(call[0] == "/api/status" for call in self.calls))

    def test_excluded_and_admin_ports_are_never_probed_even_with_rules(self):
        rules = self.load()
        for settings, port in ((APISettings(enabled=True, bearer="a" * 64, excluded=frozenset([3070])), 2000),
                               (APISettings(enabled=True, bearer="a" * 64), 3070)):
            with patch("api_discovery.LocalProbes", side_effect=AssertionError("must not probe")):
                self.assertEqual(discover({"http_services": [self.service]}, settings, {}, port, rules=rules), [])

    def test_local_and_openapi_operations_merge_without_weakening_auth(self):
        document = {"openapi": "3.1.0", "servers": [{"url": "/api"}], "paths": {"/render": {"post": {}}}}
        def probe(path, *args, **kwargs):
            data = {"version": "1", "status": "ok"} if path == "/api/status" else document if path == "/openapi.json" else None
            return Probe(200, {"content-type": "application/json"}, json.dumps(data).encode()) if data else Probe(404, {}, b"")
        rows = discover_service(self.service, {}, rules=self.load(), probe=probe)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "authentication-required")
        self.assertEqual(len(rows[0]["operations"]), 2)
        self.assertTrue(next(op for op in rows[0]["operations"] if op["method"] == "POST")["requires_auth"])


if __name__ == "__main__":
    unittest.main()
