"""Small, per-scan rules; never rewrite the user's persistent port policy."""

from __future__ import annotations

import argparse
import json
import re
import ssl
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from providers.atomic_io import atomic_write_json


class _PageRoleParser(HTMLParser):
    discovery_page = False

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            return
        attrs = dict(attrs)
        if (attrs.get("name", "").lower() == "citadel-page-role"
                and attrs.get("content", "").lower() == "mcp-discovery"):
            self.discovery_page = True


def is_browser_page(html: str) -> bool:
    """Hide explicitly marked discovery pages; preserve real web interfaces."""
    parser = _PageRoleParser()
    parser.feed(html)
    return not parser.discovery_page


def existing_icon(directory: str | Path, port: int) -> str:
    """Logos survive independently of ephemeral scan metadata."""
    for extension in ("png", "svg", "webp", "gif", "ico"):
        name = f"{port}.{extension}"
        if (Path(directory) / name).is_file():
            return name
    return ""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe_webui_instance(scheme: str, port: int, user_agent: str = "") -> str:
    """Compare local proxy endpoints, not public certificate trust or titles."""
    if scheme not in ("http", "https") or not 1 <= port <= 65535:
        return ""
    # As in local discovery, loopback certificates may name the real host rather
    # than 127.0.0.1. No public URL or certificate is inferred from this probe.
    opener = build_opener(ProxyHandler({}), NoRedirects(),
                          HTTPSHandler(context=ssl._create_unverified_context()))
    headers = {"User-Agent": user_agent} if user_agent else {}
    try:
        with opener.open(Request(f"{scheme}://127.0.0.1:{port}/", headers=headers), timeout=2) as response:
            value = response.headers.get("X-Citadel-Instance", "")
            if 200 <= response.status < 300 and re.fullmatch(r"[a-f0-9]{32}", value):
                return value
    except HTTPError as exc:
        exc.close()
    except (OSError, URLError, ValueError):
        pass
    return ""


def hide_webui_http(
    listeners: list[dict[str, Any]],
    http_port: int,
    enabled: bool = True,
    user_agent: str = "",
) -> tuple[list[dict[str, Any]], list[int]]:
    """Keep all backends; hide only this instance's duplicate HTTP tile."""
    rows = [dict(row) for row in listeners]
    for row in rows:
        row.pop("hide_webui_http", None)
        row.pop("citadel_webui", None)
    backend = next((row for row in rows if row.get("port") == http_port and row.get("scheme") == "http"), None)
    if not enabled or backend is None or not 1 <= http_port <= 65535:
        return rows, []
    frontends = [row for row in rows if row.get("scheme") == "https"]
    if not frontends:
        return rows, []
    instance = probe_webui_instance("http", http_port, user_agent)
    if not instance:
        return rows, []
    backend["citadel_webui"] = True
    found = False
    for row in frontends:
        port = row.get("port")
        if isinstance(port, int) and probe_webui_instance("https", port, user_agent) == instance:
            row["citadel_webui"] = True
            found = True
    if found:
        backend["hide_webui_http"] = True
    return rows, [http_port] if found else []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--services", type=Path, required=True)
    parser.add_argument("--http-port", type=int, required=True)
    parser.add_argument("--hide-http", choices=("true", "false"), default="true")
    parser.add_argument("--user-agent", default="")
    args = parser.parse_args()
    payload = json.loads(args.services.read_text())
    rows, hidden = hide_webui_http(
        payload.get("http_services", []), args.http_port,
        args.hide_http == "true", args.user_agent,
    )
    payload["http_services"] = rows
    payload["hidden_webui_http_ports"] = hidden
    atomic_write_json(args.services, payload)
    if hidden:
        print(f"hide WebUI HTTP tile {args.http_port}: the same instance is reachable over HTTPS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
