"""Private credential state and deterministic Cloudflare API resource metadata."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets

from cloudflare_api_policy import APISettings, read_object
from providers.atomic_io import atomic_write_json


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def worker_name(owner: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{24}", owner):
        raise ValueError("Invalid Cloudflare installation identity")
    return f"citadel-api-{owner}"


def resource_name(owner: str, role: str, port: int | None = None, *, policy=False) -> str:
    worker_name(owner)
    if role not in {"origin", "oauth", "service"}:
        raise ValueError("Invalid API resource role")
    return f"CITADEL API {owner} {role}" + (" policy" if policy else "") + (f" {port}" if port else "")


def private_state(root: Path, owner: str) -> tuple[Path, dict]:
    path = root / "CITADEL_DATA" / "cloudflare-api" / "runtime.json"
    if path.parent.is_symlink():
        raise ValueError("API credential directory must not be a symlink")
    state = read_object(path, private=True)
    if state and (state.get("owner") != owner or not re.fullmatch(r"[a-f0-9]{64}", state.get("session_key", ""))):
        raise ValueError("API private state belongs to a different installation or is invalid")
    return path, state


def save_private_state(path: Path, state: dict) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("API credentials must use direct private files")
    read_object(path, private=True)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_write_json(path, state, mode=0o600)


def initialize_private_state(owner: str) -> dict:
    return {"owner": owner, "session_key": secrets.token_hex(32)}


def access_spec(owner: str, role: str, port: int, hostname: str, settings: APISettings,
                service_id: str = "") -> tuple[dict, dict]:
    app = {"name": resource_name(owner, role, port), "domain": hostname, "type": "self_hosted",
           "session_duration": "24h", "auto_redirect_to_identity": False}
    policy = {"name": resource_name(owner, role, port, policy=True), "exclude": [], "require": []}
    if role == "origin":
        if not service_id:
            raise ValueError("Origin protection requires a service-token identity")
        policy.update(decision="non_identity", include=[{"service_token": {"token_id": service_id}}])
    elif role == "oauth":
        if not settings.oauth or not settings.emails:
            raise ValueError("OAuth protection requires an email policy")
        policy.update(decision="allow", include=[{"email": {"email": email}} for email in settings.emails])
        app["oauth_configuration"] = {"enabled": True, "dynamic_client_registration": {
            "enabled": True, "allow_any_on_localhost": settings.allow_localhost,
            "allow_any_on_loopback": settings.allow_loopback, "allowed_uris": list(settings.allowed_redirect_uris)},
            "grant": {"access_token_lifetime": "5m", "session_duration": "24h"}}
    else:
        raise ValueError("Unsupported Access application role")
    return app, policy


def table_from_settings(remote: dict | None) -> dict:
    if remote is None:
        return {"schema": 1, "hosts": {}}
    bindings = remote.get("bindings")
    if not isinstance(bindings, list):
        raise ValueError("Worker binding inventory is incomplete")
    values = {}
    for binding in bindings:
        if not isinstance(binding, dict) or not isinstance(binding.get("name"), str) or binding["name"] in values:
            raise ValueError("Worker binding inventory has duplicate or invalid names")
        values[binding["name"]] = binding.get("text") if binding.get("type") == "plain_text" else None
    raw = values.get("ROUTE_TABLE")
    if raw is None:
        count = values.get("ROUTE_TABLE_PARTS", "")
        if not isinstance(count, str) or not count.isdigit() or not 1 <= int(count) <= 60:
            raise ValueError("Worker route table is missing")
        parts = [values.get(f"ROUTE_TABLE_{index}") for index in range(int(count))]
        if any(not isinstance(part, str) for part in parts):
            raise ValueError("Worker route table is incomplete")
        raw = "".join(parts)
    if not isinstance(raw, str) or len(raw) > 240000:
        raise ValueError("Invalid Worker route table")
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid Worker route table JSON") from exc
    if not isinstance(result, dict) or result.get("schema") != 1 or not isinstance(result.get("hosts"), dict):
        raise ValueError("Invalid Worker route table schema")
    return result


def deployment(owner: str, table: dict, secret_values: dict, code: bytes, *, keep_secrets=False) -> tuple[dict, dict]:
    """Serialize within Free-plan limits; avoid a separate mutable route store."""
    raw = canonical(table)
    parts = [raw[index:index + 4000] for index in range(0, len(raw), 4000)]
    bindings = [{"name": "ROUTE_TABLE_PARTS", "type": "plain_text", "text": str(len(parts))}]
    bindings += [{"name": f"ROUTE_TABLE_{index}", "type": "plain_text", "text": value}
                 for index, value in enumerate(parts)]
    for name, value in secret_values.items():
        if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or not isinstance(value, str)
                or not value or len(value.encode()) > 5000):
            raise ValueError("Worker Secret is empty, invalid, or exceeds the 5 KB limit")
        bindings.append({"name": name, "type": "secret_text", "text": value})
    if len(bindings) > 63:
        raise ValueError("API configuration exceeds the Worker Free-plan binding limit")
    bindings.append({"name": "API_LIMIT", "type": "ratelimit", "namespace_id": str(int(owner[:12], 16) + 1),
                     "simple": {"limit": 120, "period": 60}})
    tags = [f"citadel-owner:{owner}", f"citadel-code:{hashlib.sha256(code).hexdigest()}",
            f"citadel-table:{hashlib.sha256(raw.encode()).hexdigest()}"]
    if not keep_secrets:
        key = secret_values.get("SESSION_KEY", "")
        if not re.fullmatch(r"[a-f0-9]{64}", key):
            raise ValueError("Worker session key is missing")
        # Hashing a low-entropy upstream API key publicly would enable guesses.
        digest = hmac.new(bytes.fromhex(key), canonical(secret_values).encode(), hashlib.sha256).hexdigest()
        tags.append(f"citadel-secrets:{digest}")
    metadata = {"main_module": "worker.mjs", "compatibility_date": "2025-06-18", "bindings": bindings,
                "tags": tags, "logpush": False, "tail_consumers": [], "observability": {"enabled": False}}
    if keep_secrets:
        metadata["keep_bindings"] = ["secret_text"]
    return metadata, {"worker.mjs": ("application/javascript+module", code)}


def append_table(previous: dict, desired: dict) -> tuple[dict, list[str]]:
    """Add preserves existing auth policies and endpoints; full scans remove."""
    result = deepcopy(previous)
    warnings = []
    if not result.get("issuer") and desired.get("issuer"):
        result["issuer"] = desired["issuer"]
    for hostname, host in previous["hosts"].items():
        if hostname not in desired["hosts"]:
            warnings.append(f"{hostname}: removal pending a full scan")
    for hostname, host in desired["hosts"].items():
        if hostname not in result["hosts"]:
            result["hosts"][hostname] = deepcopy(host)
            continue
        existing = result["hosts"][hostname]
        ids = {route["id"] for route in existing["routes"]}
        if {k: v for k, v in existing.items() if k != "routes"} != {k: v for k, v in host.items() if k != "routes"}:
            warnings.append(f"{hostname}: policy changes pending a full scan")
        existing["routes"] += [deepcopy(route) for route in host["routes"] if route["id"] not in ids]
        if any(route not in host["routes"] for route in existing["routes"] if route["id"] in ids):
            warnings.append(f"{hostname}: endpoint changes pending a full scan")
    return result, warnings
