from __future__ import annotations

import base64
import binascii
import http.client
import json
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote_to_bytes, urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree

MAX_ICON_CANDIDATES = 16
ALLOWED_ICON_TYPES = {
    "image/gif": ".gif",
    "image/jpeg": ".jpeg",
    "image/png": ".png",
    "image/svg+xml": ".svg",
    "image/vnd.microsoft.icon": ".ico",
    "image/webp": ".webp",
    "image/x-icon": ".ico",
    "image/ico": ".ico",
}


def _endpoint(url: str) -> tuple[str, int] | None:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.hostname.casefold(), port


def safe_icon_urls(local_url: str, effective_url: str, hrefs: list[str]) -> list[str]:
    """Resolve icon links while keeping every request on the scanned endpoint."""
    endpoint = _endpoint(local_url)
    if endpoint is None:
        return []

    base = effective_url if _endpoint(effective_url) == endpoint else f"{local_url.rstrip('/')}/"
    urls: list[str] = []
    for href in hrefs:
        if len(href) > 8192 or any(ord(char) < 32 for char in href):
            continue
        try:
            candidate = urljoin(base, href.strip())
        except ValueError:
            continue
        if _endpoint(candidate) != endpoint:
            continue
        parsed = urlsplit(candidate)
        clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if clean not in urls:
            urls.append(clean)
        if len(urls) >= MAX_ICON_CANDIDATES:
            break
    return urls


def icon_extension(content_type: str) -> str:
    normalized = content_type.split(";", 1)[0].strip().casefold()
    return ALLOWED_ICON_TYPES.get(normalized, "")


FALLBACK_PATHS = ("/favicon.png", "/favicon.ico", "/favicon.svg", "/favicon.webp",
                  "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png")


class IconLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.base = ""
        self.icons = []
        self.touch_icons = []
        self.manifest = ""

    def handle_starttag(self, tag, attrs):
        if tag not in {"base", "link"}:
            return
        attrs = dict(attrs)
        href = (attrs.get("href") or "").strip()
        if not href:
            return
        if tag == "base":
            if not self.base:
                self.base = href
            return
        rel = set((attrs.get("rel") or "").lower().split())
        if "icon" in rel:
            targets = self.icons
        elif rel & {"apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon"}:
            targets = self.touch_icons
        elif "manifest" in rel and not self.manifest:
            self.manifest = href
            return
        else:
            return
        if len(targets) < MAX_ICON_CANDIDATES and href not in targets:
            targets.append(href)


def inline_image(url, limit):
    header, sep, payload = url[5:].partition(",")
    parts = header.lower().split(";")
    if not sep or not icon_extension(parts[0]):
        return b""
    data = unquote_to_bytes(payload)
    if "base64" in parts[1:]:
        encoded = b"".join(data.split())
        try:
            data = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), validate=True)
        except binascii.Error:
            return b""
    return data if len(data) <= limit else b""


def image_extension(data):
    # Some static servers label all mounted files as application/octet-stream.
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\x00\x00\x01\x00"):
        return ".ico"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpeg"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return ".webp"
    if data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<"):
        try:
            root = ElementTree.fromstring(data)
        except (ElementTree.ParseError, LookupError, ValueError):
            return ""
        if root.tag in {"svg", "{http://www.w3.org/2000/svg}svg"}:
            return ".svg"
    return ""


def fetch_resource(url, local_url, limit, user_agent, temporary):
    """Bound each transfer and validate the destination before following a redirect."""
    for _ in range(4):
        args = ["curl", "-ksS", "--globoff", "--proto", "=http,https", "--max-time", "5",
                "--max-filesize", str(limit), "-o", str(temporary), "-w",
                "%{http_code}\\n%{redirect_url}"]
        if user_agent:
            args.extend(["--user-agent", user_agent])
        result = subprocess.run([*args, "--", url], capture_output=True)
        if result.returncode:
            break
        status, _, target = result.stdout.decode(errors="replace").partition("\n")
        if status == "200" and temporary.stat().st_size <= limit:
            return temporary.read_bytes(), url
        if status not in {"301", "302", "303", "307", "308"} or not target:
            break
        targets = safe_icon_urls(local_url, url, [target])
        if not targets:
            break
        url = targets[0]
    return b"", url


def discover_icon(html, local_url, effective_url, fetch, limit, *, mcp_sources=()):
    links = IconLinks()
    try:
        links.feed(html)
        links.close()
    except (AssertionError, ValueError):
        pass  # Keep usable links parsed before malformed markup.
    page = effective_url if _endpoint(effective_url) == _endpoint(local_url) else local_url + "/"
    try:
        base = urljoin(page, links.base)
    except ValueError:
        base = page

    def resolve(href, relative_to):
        try:
            absolute = urljoin(relative_to, href)
        except ValueError:
            return []
        return safe_icon_urls(local_url, local_url, [absolute])

    seen = set()

    def first_image(hrefs, relative_to):
        for href in hrefs:
            if href.lower().startswith("data:"):
                if href in seen:
                    continue
                seen.add(href)
                data = inline_image(href, limit)
            else:
                urls = resolve(href, relative_to)
                if not urls or urls[0] in seen:
                    continue
                seen.add(urls[0])
                data, _ = fetch(urls[0])
            ext = image_extension(data)
            if ext:
                return ext, data
        return None

    for path, sources in mcp_sources:
        image = first_image(sources, urljoin(local_url, path))
        if image:
            return image

    image = first_image(links.icons + links.touch_icons, base)
    if image:
        return image
    if links.manifest:
        manifests = resolve(links.manifest, base)
        if manifests:
            body, manifest_url = fetch(manifests[0])
            try:
                manifest = json.loads(body)
            except (ValueError, RecursionError):
                manifest = None
            icons = manifest.get("icons") if isinstance(manifest, dict) else None
            if isinstance(icons, list):
                sources = [item["src"] for item in icons[:MAX_ICON_CANDIDATES]
                           if isinstance(item, dict) and isinstance(item.get("src"), str)]
                image = first_image(sources, manifest_url)
                if image:
                    return image
    return first_image(FALLBACK_PATHS, local_url)


def mcp_icon_sources(scheme, port, root, *, timeout=8):
    from api_discovery import MCP_PATHS, LocalProbes, initialize_mcp
    from cloudflare_api_access import load_access, parse_entries, probe_credentials
    from cloudflare_api_policy import route_id

    try:
        access = load_access(root)
    except (OSError, ValueError):
        access = {}
    probe = LocalProbes(scheme, port, seconds=timeout, initialize_timeout=timeout)
    for path in MCP_PATHS:
        key = route_id(port, "mcp", path)
        try:
            headers = probe_credentials({key: parse_entries(access.get(key, ""))}).get(key, {})
        except ValueError:
            headers = {}
        try:
            response, info = initialize_mcp(probe, path, headers)
        except http.client.HTTPException:
            return
        icons = info.get("icons") if info else None
        if isinstance(icons, list):
            yield path, [icon["src"] for icon in icons[:MAX_ICON_CANDIDATES]
                         if isinstance(icon, dict) and isinstance(icon.get("src"), str)]

        if response.status in {401, 403}:
            page = probe(path, headers={"Accept": "text/html"})
            mime = page.headers.get("content-type", "").partition(";")[0].strip().lower()
            if page.status == 200 and mime == "text/html":
                links = IconLinks()
                try:
                    links.feed(page.body.decode("utf-8", errors="replace"))
                    links.close()
                    base = urljoin(path, links.base)
                except (AssertionError, ValueError):
                    continue
                yield base, links.icons + links.touch_icons


def scan_icon(html, local_url, effective_url, directory, port, limit, user_agent, *, mcp_sources=()):
    with tempfile.TemporaryDirectory(dir=directory, prefix=f".{port}.") as staging:
        temporary = Path(staging) / "icon"

        def fetch(url):
            return fetch_resource(url, local_url, limit, user_agent, temporary)

        image = discover_icon(html, local_url, effective_url, fetch, limit, mcp_sources=mcp_sources)
        if not image:
            return ""
        ext, data = image
        destination = directory / f"{port}{ext}"
        temporary.write_bytes(data)
        temporary.chmod(0o644)
        temporary.replace(destination)
    for suffix in set(ALLOWED_ICON_TYPES.values()) | {".jpg"}:
        if suffix != ext:
            (directory / f"{port}{suffix}").unlink(missing_ok=True)
    return destination.name


if __name__ == "__main__":
    local_url, effective_url, icons_dir, port_text, limit_text, user_agent = sys.argv[1:7]
    directory = Path(icons_dir)
    port = int(port_text)
    page_seconds = int(sys.argv[7]) if len(sys.argv) > 7 and sys.argv[7].isdecimal() else 0
    sources = mcp_icon_sources(urlsplit(local_url).scheme, port, Path(__file__).resolve().parents[1],
                               timeout=max(8, page_seconds))
    print(scan_icon(sys.stdin.buffer.read().decode(errors="replace"), local_url, effective_url,
                    directory, port, int(limit_text), user_agent, mcp_sources=sources))
