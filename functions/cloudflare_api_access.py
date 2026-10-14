"""Explicit, route-scoped API grants. Saving never deploys to Cloudflare."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re

from cloudflare_api_policy import read_object, route_id
from cloudflare_policy import normalize_emails
from providers.atomic_io import atomic_write_json

FILENAME = "CLOUDFLARE-API_access.json"
ROUTE_ID = re.compile(r"p[0-9]{1,5}_[a-f0-9]{20}")
TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+=*")


@dataclass
class RouteAccess:
    bearer: dict[str, str] = field(default_factory=dict, repr=False)
    oauth: dict[str, str | None] = field(default_factory=dict, repr=False)


def parse_entries(value: str) -> RouteAccess:
    if not isinstance(value, str) or len(value) > 65536:
        raise ValueError("Access entries must be a CSV string of at most 64 KiB")
    result = RouteAccess()
    if not value.strip():
        return result
    entries = value.split(",")
    if len(entries) > 64:
        raise ValueError("At most 64 access entries are allowed per route")
    for index, entry in enumerate(entries, 1):
        parts = [part.strip() for part in entry.split(";")]
        # Never include a supplied value in an error: it may be a credential.
        if len(parts) not in {1, 2} or any(not part for part in parts):
            raise ValueError(f"Entry {index}: expected a value or a pair separated by a semicolon")
        identity = parts[0]
        email = "@" in identity
        if email:
            try:
                normalized = normalize_emails([identity])
                if len(normalized) != 1:
                    raise ValueError()
                identity = normalized[0]
            except ValueError:
                raise ValueError(f"Entry {index}: invalid email address") from None
        for token in parts[1:] if email else parts:
            if len(token) > 4096 or not TOKEN.fullmatch(token):
                raise ValueError(f"Entry {index}: invalid bearer token format")
        target = result.oauth if email else result.bearer
        if identity in target:
            raise ValueError(f"Entry {index}: duplicate identity in this route")
        target[identity] = parts[1] if len(parts) == 2 else None if email else identity
    # Check the actual per-route Worker binding size before saving or scanning.
    compiled_access("p1_" + "0" * 20, result, "0" * 64)
    return result


def validate_document(data: dict) -> dict[str, str]:
    if set(data) != {"routes"} or not isinstance(data["routes"], dict) or len(data["routes"]) > 2000:
        raise ValueError("Access JSON must contain a routes object (at most 2000 routes)")
    for identity, csv in data["routes"].items():
        if not ROUTE_ID.fullmatch(identity):
            raise ValueError("Invalid access route ID; use an ID from the scan inventory")
        parse_entries(csv)
    return dict(data["routes"])


def load_access(root: Path) -> dict[str, str]:
    data = read_object(root / FILENAME, private=True)
    return validate_document(data) if (root / FILENAME).exists() else {}


def revision(routes: dict[str, str]) -> str:
    # Empty scaffold rows do not constitute a change in granted access.
    active = {key: value for key, value in routes.items() if value.strip()}
    return hashlib.sha256(json.dumps(active, sort_keys=True).encode()).hexdigest()


@contextmanager
def access_lock(root: Path):
    directory = root / "cache"
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory / "cloudflare-access.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def scaffold(root: Path, inventory: list[dict]) -> None:
    """Add empty candidates, preserving all user edits and vanished routes."""
    with access_lock(root):
        routes = load_access(root)
        before = dict(routes)
        for row in inventory:
            if row.get("detected") or row.get("status") in {"ready", "authentication-required"}:
                identity = route_id(row["port"], row["protocol"], row["path"])
                routes.setdefault(identity, "")
        if routes != before or not (root / FILENAME).exists():
            atomic_write_json(root / FILENAME, {"routes": routes}, mode=0o600)


def save_access(root: Path, routes: dict, expected_revision: str) -> dict[str, str]:
    routes = validate_document({"routes": routes})
    if len(json.dumps({"routes": routes}, indent=2).encode()) > 1024 * 1024:
        raise ValueError("Access configuration exceeds the 1 MiB file limit")
    with access_lock(root):
        current = load_access(root)
        if not isinstance(expected_revision, str) or expected_revision != revision(current):
            raise FileExistsError("Access configuration changed; reload before saving")
        # The UI cannot invent target addresses or unknown route IDs.
        if set(routes) - set(current):
            raise ValueError("Unknown access route; run a scan first")
        atomic_write_json(root / FILENAME, {"routes": routes}, mode=0o600)
    return routes


def probe_credentials(access: dict[str, RouteAccess]) -> dict[str, dict]:
    """Use only explicitly configured, route-scoped backend credentials."""
    result = {}
    for identity, grant in access.items():
        tokens = [*grant.bearer.values(), *(v for v in grant.oauth.values() if v)]
        if tokens:
            result[identity] = {"authorization": "Bearer " + tokens[0]}
    return result


def compiled_access(identity: str, grant: RouteAccess, key: str) -> dict:
    secret = bytes.fromhex(key)
    result = {"bearer": [
        {"hash": hmac.new(secret, (identity + "\0" + client).encode(), hashlib.sha256).hexdigest(),
         "backend": None if client == backend else backend}
        for client, backend in sorted(grant.bearer.items())], "oauth": dict(sorted(grant.oauth.items()))}
    if len(json.dumps(result, separators=(",", ":")).encode()) > 5000:
        raise ValueError("Access entries exceed the Worker secret limit of 5 KB per route")
    return result


def mark_applied(root: Path, routes: dict[str, str]) -> None:
    path = root / "CITADEL_DATA/cloudflare-api/access-applied.json"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_write_json(path, {"revision": revision(routes)}, mode=0o600)


def management_view(root: Path) -> dict:
    with access_lock(root):
        routes = load_access(root)
    applied = read_object(root / "CITADEL_DATA/cloudflare-api/access-applied.json", private=True)
    inventory = read_object(root / "cache/cloudflare-api-inventory.json").get("endpoints", [])
    known = {row["id"]: row for row in inventory if isinstance(row, dict) and "id" in row}
    return {"revision": revision(routes), "pending": applied.get("revision") != revision(routes),
            "applies_on": "next_scan", "routes": [
                {"id": identity, "entries": csv,
                 **{key: known.get(identity, {}).get(key) for key in ("port", "protocol", "path", "status", "evidence", "detected")}}
                for identity, csv in sorted(routes.items())]}
