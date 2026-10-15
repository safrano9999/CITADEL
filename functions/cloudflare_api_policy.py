"""Validated local policy for the optional Cloudflare API extension.

No network calls and no credential values in public inventory. These functions
are shared by the scanner, planner and configuration commands.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Callable
from urllib.parse import urlsplit

from cloudflare_policy import normalize_hostname

EXTENSION = "CLOUDFLARE-API"
OAUTH = "CITADEL_CLOUDFLARE_API_OAUTH"
OAUTH_WHITELIST = "CLOUDFLARE_OAUTH_Whitelist.json"
MODE_LABELS = {"api-bearer": "API-Bearer", "api-oauth": "API-OAuth"}
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
FORBIDDEN_HEADERS = {
    "host", "connection", "content-length", "transfer-encoding", "upgrade",
    "cookie", "set-cookie", "forwarded", "proxy-authorization",
    "mcp-session-id", "mcp-protocol-version", "origin",
}


def read_object(path: Path, *, missing: bool = True, private: bool = False) -> dict:
    if path.is_symlink():
        raise ValueError(f"Policy must not be a symlink: {path.name}")
    try:
        info = path.stat()
    except FileNotFoundError:
        if missing:
            return {}
        raise ValueError(f"Required policy is missing: {path.name}") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ValueError(f"Invalid policy file: {path.name}")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(f"Secret file must be private (mode 0600): {path.name}")
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON field in {path.name}")
            result[key] = value
        return result
    try:
        result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_fields)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON in {path.name}") from exc
    if not isinstance(result, dict):
        raise ValueError(f"Expected JSON object in {path.name}")
    return result


def extension_enabled(root: Path, name: str) -> bool:
    directory = root / "extensions" / "enabled" / name
    if not directory.is_dir():
        return False
    if not directory.resolve().is_relative_to((root / "extensions" / "enabled").resolve()):
        raise ValueError("Extension escapes enabled directory")
    manifest = read_object(directory / "extension.json", missing=False)
    return manifest.get("enabled") is not False


def excluded_ports(root: Path) -> frozenset[int]:
    data = read_object(root / "CLOUDFLARE-API_ignore.json", missing=False)
    if set(data) != {"ports"} or not isinstance(data["ports"], list):
        raise ValueError("CLOUDFLARE-API_ignore.json must contain only a ports list")
    if any(type(p) is not int or not 1 <= p <= 65535 for p in data["ports"]):
        raise ValueError("Ignored ports must be integers between 1 and 65535")
    return frozenset(data["ports"])


def endpoint_path(value: str, *, template: bool = False) -> str:
    # Deny ambiguous paths rather than permitting downstream double decoding.
    if (not isinstance(value, str) or not value.startswith("/") or "//" in value
            or any(c in value for c in "%\\?#") or any(ord(c) < 33 or ord(c) > 126 for c in value)
            or any(part in {".", ".."} for part in value.split("/"))):
        raise ValueError("Invalid API endpoint path")
    parts = value.split("/")
    for part in parts:
        if "{" in part or "}" in part:
            if not template or not re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_.-]*\}", part):
                raise ValueError("Invalid OpenAPI path parameter")
    return value


def route_id(port: int, protocol: str, path: str) -> str:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid route port")
    if protocol not in {"mcp", "rest", "graphql", "rpc"}:
        raise ValueError("Unsupported API protocol")
    endpoint_path(path)
    digest = hashlib.sha256(f"{port}:{protocol}:{path}".encode()).hexdigest()[:20]
    return f"p{port}_{digest}"


def owner_id(account: str, zone: str, tunnel: str) -> str:
    if not all((account, zone, tunnel)):
        raise ValueError("Account, zone and dedicated Tunnel are required")
    return hashlib.sha256(f"{account}:{zone}:{tunnel}".encode()).hexdigest()[:24]


def hostnames(port: int, domain: str) -> dict[str, str]:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid route port")
    domain = normalize_hostname(domain)
    return {"api-bearer": normalize_hostname(f"api-{port}.{domain}"),
            "api-oauth": normalize_hostname(f"oauth.api-{port}.{domain}"),
            "origin": normalize_hostname(f"origin-api-{port}.{domain}")}


def credential_headers(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 16:
        raise ValueError("Backend headers must be a small JSON object")
    result = {}
    for key, secret in value.items():
        name = key.lower() if isinstance(key, str) else ""
        if (not HEADER_NAME.fullmatch(name) or name in FORBIDDEN_HEADERS
                or name.startswith(("cf-", "x-forwarded-"))):
            raise ValueError("Reserved or invalid backend credential header")
        if (not isinstance(secret, str) or not secret or len(secret) > 8192
                or any(ord(c) < 32 or ord(c) == 127 for c in secret)):
            raise ValueError("Invalid backend credential value")
        if name in result:
            raise ValueError("Duplicate backend credential header")
        result[name] = secret
    return result


@dataclass(frozen=True)
class APISettings:
    enabled: bool = False
    oauth: bool = False
    excluded: frozenset[int] = frozenset()
    allowed_redirect_uris: tuple[str, ...] = ()
    allow_localhost: bool = False
    allow_loopback: bool = False
    errors: tuple[str, ...] = ()

    @property
    def modes(self) -> tuple[str, ...]:
        if not self.enabled:
            return ()
        return ("api-bearer",) + (("api-oauth",) if self.oauth else ())


def settings(root: Path, get: Callable[[str, str], str]) -> APISettings:
    if not extension_enabled(root, "cloudflare") or not extension_enabled(root, EXTENSION):
        return APISettings()
    raw_oauth = get(OAUTH, "0").strip()
    if raw_oauth not in {"", "blank", "0", "1"}:
        raise ValueError(f"{OAUTH} must be 0 or 1")
    oauth = raw_oauth == "1"
    excluded = excluded_ports(root)
    options = read_object(root / OAUTH_WHITELIST) if oauth else {}
    if not isinstance(options, dict) or set(options) - {
        "allowed_redirect_uris", "allow_localhost", "allow_loopback",
    }:
        raise ValueError(f"Invalid OAuth registration policy in {OAUTH_WHITELIST}")
    uris = options.get("allowed_redirect_uris", [])
    if not isinstance(uris, list) or len(uris) > 100:
        raise ValueError("OAuth callback addresses must be a list")
    for uri in uris:
        if (not isinstance(uri, str) or len(uri) > 2048
                or any(ord(c) < 33 or ord(c) > 126 for c in uri)
                or any(c in uri for c in "\\?#")):
            raise ValueError("Invalid OAuth callback address")
        parsed = urlsplit(uri)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.port == 0):
            raise ValueError("OAuth callbacks must be HTTPS URLs without credentials")
        normalize_hostname(parsed.hostname)
        endpoint_path(parsed.path or "/")
        # Cloudflare supports a final /* for variable callback IDs. Require
        # a specific path prefix; never allow wildcard hosts or an entire site.
        if "*" in uri and (uri.count("*") != 1 or not parsed.path.endswith("/*")
                           or parsed.path == "/*"):
            raise ValueError("OAuth callback wildcards require a specific path ending in /*")
    local = options.get("allow_localhost", False)
    loopback = options.get("allow_loopback", False)
    if type(local) is not bool or type(loopback) is not bool:
        raise ValueError("OAuth loopback options must be JSON booleans")
    errors = []
    if oauth and not (uris or local or loopback):
        errors.append(f"OAuth requires client callbacks in {OAUTH_WHITELIST}")
        oauth = False
    return APISettings(enabled=True, oauth=oauth, excluded=excluded,
                       allowed_redirect_uris=tuple(dict.fromkeys(uris)),
                       allow_localhost=local, allow_loopback=loopback, errors=tuple(errors))
