from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit


MAX_ICON_CANDIDATES = 16
ALLOWED_ICON_TYPES = {
    "image/gif": ".gif",
    "image/png": ".png",
    "image/svg+xml": ".svg",
    "image/vnd.microsoft.icon": ".ico",
    "image/webp": ".webp",
    "image/x-icon": ".ico",
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
        candidate = urljoin(base, href.strip())
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
