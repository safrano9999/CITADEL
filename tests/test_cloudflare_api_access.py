from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "functions"))
from cloudflare_api_access import (FILENAME, parse_entries, compiled_access, load_access,
    scaffold, save_access, revision, mark_applied, management_view, probe_credentials)
from cloudflare_api_policy import route_id


class AccessRegistryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.row = {"id": route_id(3070, "mcp", "/mcp"), "port": 3070, "path": "/mcp",
                    "protocol": "mcp", "status": "authentication-required"}
        scaffold(self.root, [self.row])
        self.key = self.row["id"]

    def test_all_four_forms_and_case_normalized_email(self):
        grant = parse_entries("Foo@bar.de;inner,outer;backend,single,other@bar.de")
        self.assertEqual(grant.oauth, {"foo@bar.de": "inner", "other@bar.de": None})
        self.assertEqual(grant.bearer, {"outer": "backend", "single": "single"})
        self.assertNotIn("backend", repr(grant))

    def test_invalid_ambiguous_and_oversized_entries_never_echo_secrets(self):
        for value in ("outer;inner;third", "outer;", ";inner", "outer,", "has space",
                      "outer,outer;other", "User@bar.de,user@bar.de;secret", "bad@@bar.de",
                      "outer;secret-with-newline\ninside", "x;" + "b" * 4097,
                      ",".join(f"token{i}" for i in range(65)), "x;" + "b" * 3000 + ",y;" + "c" * 3000):
            with self.subTest(kind=value[:10]):
                with self.assertRaises(ValueError) as failure:
                    parse_entries(value)
                self.assertNotIn(value, str(failure.exception))

    def test_scan_scaffold_preserves_user_entries_and_does_not_invent_credentials(self):
        self.assertEqual(load_access(self.root), {self.key: ""})
        before = revision(load_access(self.root))
        save_access(self.root, {self.key: "outer;inner"}, before)
        scaffold(self.root, [])
        scaffold(self.root, [self.row])
        self.assertEqual(load_access(self.root), {self.key: "outer;inner"})
        self.assertEqual(stat.S_IMODE((self.root / FILENAME).stat().st_mode), 0o600)

    def test_save_is_pending_until_successful_scan_marks_exact_snapshot(self):
        empty = load_access(self.root)
        mark_applied(self.root, empty)
        self.assertFalse(management_view(self.root)["pending"])
        first = save_access(self.root, {self.key: "outer;inner"}, revision(empty))
        self.assertTrue(management_view(self.root)["pending"])
        mark_applied(self.root, first)
        self.assertFalse(management_view(self.root)["pending"])
        save_access(self.root, {self.key: "outer;changed"}, revision(first))
        mark_applied(self.root, first)  # A concurrent scan can only acknowledge its own snapshot.
        self.assertTrue(management_view(self.root)["pending"])

    def test_stale_editor_and_unknown_route_rejected_without_overwrite(self):
        original = revision(load_access(self.root))
        save_access(self.root, {self.key: "outer;first"}, original)
        with self.assertRaises(FileExistsError):
            save_access(self.root, {self.key: "outer;stale"}, original)
        with self.assertRaises(ValueError):
            save_access(self.root, {route_id(9999, "mcp", "/mcp"): "token"}, revision(load_access(self.root)))
        self.assertEqual(load_access(self.root)[self.key], "outer;first")

    def test_insecure_symlink_duplicate_and_invalid_files_fail_closed(self):
        path = self.root / FILENAME
        path.chmod(0o644)
        with self.assertRaises(ValueError): load_access(self.root)
        path.chmod(0o600)
        for raw in ('{}', '{"routes":{},"routes":{}}', '[]'):
            path.write_text(raw)
            with self.assertRaises(ValueError): load_access(self.root)
        path.unlink()
        path.symlink_to(self.root / "missing")
        with self.assertRaises(ValueError): load_access(self.root)

    def test_worker_verifiers_are_route_bound_and_single_token_is_not_stored(self):
        grant = parse_entries("single,outer;backend,owner@example.com;user-backend,guest@example.com")
        result = compiled_access(self.key, grant, "c" * 64)
        expected = hmac.new(bytes.fromhex("c" * 64), (self.key + "\0single").encode(), hashlib.sha256).hexdigest()
        self.assertIn({"hash": expected, "backend": None}, result["bearer"])
        self.assertNotIn("single", json.dumps(result))
        self.assertNotEqual(result, compiled_access(route_id(3071, "mcp", "/mcp"), grant, "c" * 64))
        self.assertEqual(result["oauth"]["guest@example.com"], None)
        self.assertEqual(probe_credentials({self.key: parse_entries("outer;backend")}),
                         {self.key: {"authorization": "Bearer backend"}})


class AccessWebUiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import webui
        self.webui = webui
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key = route_id(3070, "mcp", "/mcp")
        scaffold(self.root, [{"port": 3070, "path": "/mcp", "protocol": "mcp", "status": "ready"}])
        self.enterContext(patch.object(webui.core, "BASE_DIR", self.root))
        self.token = self.enterContext(patch.object(webui, "_configured_edit_token", return_value="admin-secret"))
        self.enterContext(patch.object(webui, "_edit_token_guard", webui.EditTokenGuard()))

    async def call(self, method="GET", payload=None, token="admin-secret", extra=(), path="/api/cloudflare/access"):
        body = json.dumps(payload).encode() if payload is not None else b""
        messages = []
        async def receive(): return {"type": "http.request", "body": body, "more_body": False}
        async def send(message): messages.append(message)
        await self.webui.app({"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
            "query_string": b"", "root_path": "", "server": ("localhost", 80), "client": ("test", 1),
            "headers": [(b"x-citadel-token", token.encode()), *extra]}, receive, send)
        start = next(message for message in messages if message["type"] == "http.response.start")
        data = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
        self.assertEqual(dict(start["headers"])[b"cache-control"], b"no-store")
        return start["status"], data

    async def test_read_and_write_require_token_and_unset_config_fails_closed(self):
        for method in ("GET", "PUT"):
            self.assertEqual((await self.call(method, token=""))[0], 401)
        self.token.return_value = ""
        self.assertEqual((await self.call())[0], 503)

    async def test_login_shell_contains_no_route_credentials(self):
        save_access(self.root, {self.key: "private-client;private-backend"}, revision(load_access(self.root)))
        status, body = await self.call(path="/cloudflare-api", token="")
        self.assertEqual(status, 200)
        self.assertNotIn(b"private-client", body)
        self.assertNotIn(self.key.encode(), body)

    async def test_authenticated_save_only_stages_and_stale_save_conflicts(self):
        mark_applied(self.root, load_access(self.root))
        status, body = await self.call()
        self.assertEqual(status, 200)
        data = json.loads(body)
        payload = {"routes": {self.key: "outer;inner"}, "revision": data["revision"]}
        status, body = await self.call("PUT", payload)
        self.assertEqual(status, 200)
        self.assertNotIn(b"inner", body)
        self.assertEqual(json.loads(body)["applies_on"], "next_scan")
        self.assertTrue(management_view(self.root)["pending"])
        self.assertEqual((await self.call("PUT", payload))[0], 409)

    async def test_cross_site_and_invalid_payloads_rejected_without_secret_echo(self):
        self.assertEqual((await self.call(extra=[(b"sec-fetch-site", b"cross-site")]))[0], 403)
        for routes in ({self.key: "secret;"}, None, ["secret"]):
            status, body = await self.call("PUT", {"revision": revision(load_access(self.root)), "routes": routes})
            self.assertEqual(status, 400)
            self.assertNotIn(b"secret;", body)
