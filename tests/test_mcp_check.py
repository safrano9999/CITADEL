import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "functions"))
from mcp_check import CheckError, MCPCheck


class ConnectionCheckTests(unittest.TestCase):
    def response(self, identity, result=None, *, sse=False, status=200):
        payload = {"jsonrpc": "2.0", "id": identity, "result": result or {}}
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "text/event-stream" if sse else "application/json", "Mcp-Session-Id": "opaque-session"}
        stream = io.BytesIO(b"data: " + body + b"\n\n" if sse else body)
        return Mock(status=status, getheader=lambda name, default=None: headers.get(name, default), read1=stream.read1)

    def test_json_and_sse_session_with_tool_pagination_never_calls_tools(self):
        for sse in (False, True):
            responses = [self.response(1, {"protocolVersion": "2025-06-18", "serverInfo": {}, "capabilities": {}}, sse=sse),
                         self.response(None, status=202), self.response(2, {"tools": [{}], "nextCursor": "page2"}, sse=sse),
                         self.response(3, {"tools": [{}]}, sse=sse)]
            connections = [Mock(getresponse=Mock(return_value=response)) for response in responses]
            with patch("mcp_check.http.client.HTTPSConnection", side_effect=connections):
                self.assertEqual(MCPCheck("https://api-3070.example.com/mcp", "client-token").run()["tools"], 2)
            methods = [json.loads(conn.request.call_args.kwargs["body"])["method"] for conn in connections]
            self.assertEqual(methods, ["initialize", "notifications/initialized", "tools/list", "tools/list"])
            for conn in connections[1:]:
                self.assertEqual(conn.request.call_args.kwargs["headers"]["Mcp-Session-Id"], "opaque-session")
            self.assertTrue(all(conn.close.call_count == 1 for conn in connections))

    def test_invalid_auth_redirects_and_tool_calls_fail_without_following(self):
        checker = MCPCheck("https://oauth.api-3070.example.com/mcp", "oauth:opaque")
        with self.assertRaises(CheckError):
            checker.rpc("tools/call", 1, {})
        for status in (302, 401, 403):
            conn = Mock(getresponse=Mock(return_value=self.response(1, status=status)))
            with patch("mcp_check.http.client.HTTPSConnection", return_value=conn), self.assertRaises(CheckError):
                checker.run()
            conn.request.assert_called_once()

    def test_rejects_html_login_and_mismatched_result(self):
        checker = MCPCheck("https://api-3070.example.com/mcp", "client-token")
        response = self.response(1)
        response.getheader = lambda *args: "text/html"
        with patch("mcp_check.http.client.HTTPSConnection", return_value=Mock(getresponse=Mock(return_value=response))), self.assertRaises(CheckError):
            checker.run()
        with self.assertRaises(CheckError):
            checker.result({"jsonrpc": "2.0", "id": 999, "result": {}}, 1)
