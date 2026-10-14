#!/usr/bin/env python3
"""Explicit read-only remote MCP check. Never run application tools."""
from __future__ import annotations

import argparse
import getpass
import http.client
import json
from pathlib import Path
import stat
import time
from urllib.parse import urlsplit

MAX_BODY = 1024 * 1024
VERSIONS = {"2025-03-26", "2025-06-18", "2025-11-25"}


class CheckError(Exception):
    pass


class MCPCheck:
    def __init__(self, url, token):
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or parsed.query):
            raise CheckError("Use an HTTPS endpoint without credentials, query or fragment")
        if not token or len(token) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise CheckError("A valid client bearer or OAuth access token is required")
        self.target = parsed
        self.token = token
        self.session = None
        self.version = "2025-06-18"
        self.deadline = time.monotonic() + 30

    def rpc(self, method, identity=None, params=None):
        if method not in {"initialize", "notifications/initialized", "tools/list"}:
            raise CheckError("Only initialization and listing tools are permitted")
        if time.monotonic() >= self.deadline:
            raise CheckError("Connection check time budget exhausted")
        body = {"jsonrpc": "2.0", "method": method}
        if identity is not None:
            body["id"] = identity
        if params is not None:
            body["params"] = params
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": self.version}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        connection = http.client.HTTPSConnection(self.target.hostname, self.target.port,
            timeout=min(5, self.deadline - time.monotonic()))
        try:
            connection.request("POST", self.target.path or "/", body=json.dumps(body), headers=headers)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise CheckError(f"{method}: HTTP {response.status}; redirects are not followed")
            session = response.getheader("Mcp-Session-Id")
            if session:
                if not 1 <= len(session) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in session):
                    raise CheckError("Invalid MCP session header")
                self.session = session
            if identity is None:
                return None
            kind = response.getheader("Content-Type", "").split(";")[0].lower()
            if kind not in {"application/json", "text/event-stream"}:
                raise CheckError("Expected MCP JSON or SSE, not an HTML login page")
            data = bytearray()
            consumed = 0
            while consumed <= MAX_BODY and time.monotonic() < self.deadline:
                chunk = response.read1(min(16384, MAX_BODY + 1 - consumed))
                consumed += len(chunk)
                if consumed > MAX_BODY:
                    break
                data.extend(chunk)
                if kind == "text/event-stream":
                    data[:] = data.replace(b"\r\n", b"\n")
                    while b"\n\n" in data:
                        event, _, rest = data.partition(b"\n\n")
                        data[:] = rest
                        value = b"\n".join(line[5:].lstrip() for line in event.split(b"\n") if line.startswith(b"data:"))
                        if value:
                            message = json.loads(value)
                            if isinstance(message, dict) and message.get("id") == identity:
                                return self.result(message, identity)
                if not chunk:
                    if kind == "application/json":
                        return self.result(json.loads(data), identity)
                    break
            raise CheckError("MCP response missing or response/time limit exceeded")
        except (OSError, http.client.HTTPException, ValueError):
            # Backend responses, URLs and credentials must not enter error logs.
            raise CheckError("MCP transport or response validation failed") from None
        finally:
            connection.close()

    @staticmethod
    def result(message, identity):
        if (not isinstance(message, dict) or message.get("jsonrpc") != "2.0"
                or message.get("id") != identity or not isinstance(message.get("result"), dict)
                or "error" in message):
            raise CheckError("MCP returned an error or invalid result")
        return message["result"]

    def run(self):
        initialized = self.rpc("initialize", 1, {"protocolVersion": self.version, "capabilities": {},
            "clientInfo": {"name": "citadel-read-only-check", "version": "1"}})
        if (initialized.get("protocolVersion") not in VERSIONS or not isinstance(initialized.get("serverInfo"), dict)
                or not isinstance(initialized.get("capabilities"), dict)):
            raise CheckError("Unsupported MCP initialize result")
        self.version = initialized["protocolVersion"]
        self.rpc("notifications/initialized")
        cursor, seen, count = None, set(), 0
        for page in range(10):
            result = self.rpc("tools/list", page + 2, {"cursor": cursor} if cursor else {})
            if not isinstance(result.get("tools"), list):
                raise CheckError("Invalid tools/list result")
            count += len(result["tools"])
            cursor = result.get("nextCursor")
            if not cursor:
                return {"protocol_version": self.version, "tools": count, "tools_called": 0}
            if not isinstance(cursor, str) or len(cursor) > 8192 or cursor in seen:
                raise CheckError("Invalid or repeated tools/list cursor")
            seen.add(cursor)
        raise CheckError("Tool-list page limit exceeded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--token-file", type=Path, help="Optional private file containing only the client access token")
    args = parser.parse_args()
    try:
        if args.token_file:
            info = args.token_file.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 8193:
                raise CheckError("Token file must be a regular private file (mode 0600), at most 8193 bytes")
            token = args.token_file.read_text().strip()
        else:
            token = getpass.getpass("Client bearer / OAuth access token (hidden): ")
        result = MCPCheck(args.url, token).run()
        print(json.dumps({"status": "PASS", **result}))
        return 0
    except (CheckError, OSError, ValueError) as exc:
        print(f"FAIL: {exc}" if isinstance(exc, CheckError) else "FAIL: Cannot read client token")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
