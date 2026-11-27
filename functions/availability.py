"""Read-only availability checks for the URLs shown on Citadel's dashboard."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPException
from http.cookiejar import CookieJar
import json
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


_workers = ThreadPoolExecutor(max_workers=6, thread_name_prefix="citadel-availability")


def tile_urls(dashboard, mode, ports):
    for tile in dashboard["http_tiles"]:
        port = str(tile["port"])
        if port not in ports:
            continue
        links = tile.get("interface_links", {}).get(mode, [])
        url = links[0]["url"] if links else tile["provider_urls"].get(mode)
        if url:
            yield port, url


def probe(url):
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()), NoRedirect())
    try:
        initial = urlsplit(url)
        if initial.scheme not in {"https", "http"} or not initial.hostname or initial.username is not None:
            return "down", "Invalid indexed service URL"
        for _ in range(6):
            request = Request(url, headers={"User-Agent": "CITADEL-Availability/1", "Accept": "*/*"})
            try:
                response = opener.open(request, timeout=4)
            except HTTPError as error:
                response = error
            with response:
                code = response.status
                detail = f"HTTP {code} {response.reason or ''}".rstrip()
                if response.headers.get("cf-mitigated", "").lower() == "challenge":
                    return "auth", f"{detail} — Cloudflare browser challenge. Backend behind challenge was not checked."
                if code in (301, 302, 303, 307, 308) and response.headers.get("Location"):
                    current = urlsplit(url)
                    url = urljoin(url, response.headers["Location"])
                    target = urlsplit(url)
                    if target.scheme == "https" and (target.hostname or "").endswith(".cloudflareaccess.com") and target.path.startswith("/cdn-cgi/access/login/") and target.username is None:
                        return "auth", f"{detail} — Cloudflare Access login at {target.hostname}. Backend behind login was not checked."
                    upgrade = (current.scheme == "http" and target.scheme == "https"
                               and target.hostname == current.hostname and target.username is None
                               and ((current.port or 80) == 80 and (target.port or 443) == 443
                                    or current.port is not None and current.port == target.port))
                    if not upgrade and (target.scheme, target.netloc) != (current.scheme, current.netloc):
                        return "down", f"{detail} — redirect outside the indexed service"
                    continue
                if code == 401 and response.headers.get("WWW-Authenticate"):
                    method = response.headers["WWW-Authenticate"].split()[0]
                    return "auth", f"{detail} — {method} authentication required"
                if code == 200:
                    path = urlsplit(url).path.rstrip("/").lower().split("/")[-1]
                    if path in {"login", "signin", "sign-in", "access"} and "text/html" in response.headers.get("Content-Type", ""):
                        sample = response.read(16384).lower()
                        if b'password' in sample and b'<form' in sample:
                            return "auth", f"{detail} — login form"
                    return "up", detail
                return "down", detail
        return "down", "Redirect limit exceeded"
    except (URLError, OSError, HTTPException, ValueError) as error:
        reason = getattr(error, "reason", error)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return "down", f"TLS certificate error: {reason.verify_message}"
        if isinstance(reason, socket.gaierror):
            return "down", f"DNS lookup failed: {reason.strerror}"
        if isinstance(reason, TimeoutError):
            return "down", "Connection or response timed out (4 s)"
        return "down", f"{type(reason).__name__}: {reason}"


async def stream(targets):
    loop = asyncio.get_running_loop()
    pending = {}
    targets = iter(targets)
    try:
        while True:
            while len(pending) < 4:
                target = next(targets, None)
                if target is None:
                    break
                port, url = target
                pending[loop.run_in_executor(_workers, probe, url)] = port
            if not pending:
                break
            ready, _ = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for future in ready:
                state, detail = future.result()
                result = {"port": pending.pop(future), "state": state, "detail": detail}
                yield "data: " + json.dumps(result) + "\n\n"
        yield "event: done\ndata: {}\n\n"
    finally:
        for future in pending:
            future.cancel()
