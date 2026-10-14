"""Validated local policy for the optional Cloudflare API extension.

No network calls and no credential values in public inventory. These functions
are shared by the scanner, planner and configuration commands.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Callable
from urllib.parse import urlsplit

from cloudflare_policy import normalize_emails, normalize_hostname

EXTENSION = "CLOUDFLARE-API"
BEARER = "CITADEL_CLOUDFLARE_API_BEARER"
OAUTH = "CITADEL_CLOUDFLARE_API_OAUTH"
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
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
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
    if protocol not in {"mcp", "rest", "graphql"}:
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
    bearer: str = field(default="", repr=False)
    oauth: bool = False
    excluded: frozenset[int] = frozenset()
    emails: tuple[str, ...] = ()
    allowed_redirect_uris: tuple[str, ...] = ()
    allow_localhost: bool = False
    allow_loopback: bool = False
    errors: tuple[str, ...] = ()

    @property
    def modes(self) -> tuple[str, ...]:
        if not self.enabled:
            return ()
        return (("api-bearer",) if self.bearer else ()) + (("api-oauth",) if self.oauth else ())


def settings(root: Path, get: Callable[[str, str], str]) -> APISettings:
    if not extension_enabled(root, "cloudflare") or not extension_enabled(root, EXTENSION):
        return APISettings()
    bearer = get(BEARER, "").strip()
    if bearer.lower() == "blank":
        bearer = ""
    if bearer and (bearer.startswith("example:") or len(bearer) < 32
                   or any(ord(c) < 33 or ord(c) > 126 for c in bearer)):
        raise ValueError("API bearer must be a rendered secret of at least 32 characters")
    raw_oauth = get(OAUTH, "0").strip()
    if raw_oauth not in {"", "blank", "0", "1"}:
        raise ValueError(f"{OAUTH} must be 0 or 1")
    oauth = raw_oauth == "1"
    excluded = excluded_ports(root) if (bearer or oauth) else frozenset()
    policy = read_object(root / "CITADEL_DATA" / "cloudflare-api" / "policy.json") if oauth else {}
    if set(policy) - {"oauth"}:
        raise ValueError("Unknown API policy field")
    options = policy.get("oauth", {})
    if not isinstance(options, dict) or set(options) - {
        "allowed_redirect_uris", "allow_localhost", "allow_loopback",
    }:
        raise ValueError("Invalid OAuth registration policy")
    uris = options.get("allowed_redirect_uris", [])
    if not isinstance(uris, list) or len(uris) > 100:
        raise ValueError("OAuth callback addresses must be a list")
    for uri in uris:
        if not isinstance(uri, str):
            raise ValueError("Invalid OAuth callback address")
        parsed = urlsplit(uri)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.fragment or parsed.query or "*" in uri
                or any(ord(c) < 33 for c in uri)):
            raise ValueError("OAuth callbacks must be explicit HTTPS URLs without wildcards")
    local = options.get("allow_localhost", False)
    loopback = options.get("allow_loopback", False)
    if type(local) is not bool or type(loopback) is not bool:
        raise ValueError("OAuth loopback options must be JSON booleans")
    errors = []
    emails = ()
    if oauth:
        try:
            emails = tuple(normalize_emails(get("CLOUDFLARE_EMAIL", "").split(",")))
        except ValueError:
            errors.append("OAuth requires a valid email allowlist")
        if not emails or not (uris or local or loopback):
            errors.append("OAuth requires allowed emails and explicit client callback configuration")
        if errors:
            oauth = False
    return APISettings(True, bearer, oauth, excluded, emails, tuple(dict.fromkeys(uris)),
                       local, loopback, tuple(errors))


def backend_credentials(root: Path) -> dict[str, dict]:
    data = read_object(root / "CITADEL_DATA" / "cloudflare-api" / "credentials.json", private=True)
    if not data:
        return {}
    if set(data) != {"routes"} or not isinstance(data["routes"], dict):
        raise ValueError("Backend credentials must contain a routes object")
    result = {}
    for key, entry in data["routes"].items():
        if (not re.fullmatch(r"p[0-9]{1,5}_[a-f0-9]{20}", key)
                or not isinstance(entry, dict) or set(entry) - {"headers", "identities", "fallback"}):
            raise ValueError("Invalid backend credential route")
        # Reserve the shape for identity-specific credentials; do not silently
        # grant the shared token when the operator requested per-user isolation.
        if entry.get("identities") or entry.get("fallback") is False:
            raise ValueError("Per-identity backend credentials are not supported yet")
        result[key] = credential_headers(entry.get("headers", {}))
    return result
