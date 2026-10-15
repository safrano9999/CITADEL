"""Local declarations for HTTP APIs without machine-readable operation metadata."""
from __future__ import annotations

from pathlib import Path

from cloudflare_api_policy import endpoint_path, read_object, route_id

FILENAME = "CLOUDFLARE-API_discovery.json"
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def within(path: str, base: str) -> bool:
    return base == "/" or path == base or path.startswith(base.rstrip("/") + "/")


def load_rules(root: Path) -> tuple[dict, ...]:
    if not (root / FILENAME).exists() and not (root / FILENAME).is_symlink():
        return ()
    data = read_object(root / FILENAME, missing=False)
    if set(data) != {"routes"} or not isinstance(data["routes"], list) or len(data["routes"]) > 128:
        raise ValueError(f"{FILENAME} requires a routes list (maximum 128)")
    identities, counts = set(), {}
    for rule in data["routes"]:
        if not isinstance(rule, dict) or set(rule) != {"port", "title", "path", "probe", "operations"}:
            raise ValueError("Discovery rule requires port, title, path, probe and operations")
        identity = route_id(rule["port"], "rest", rule["path"])
        if identity in identities:
            raise ValueError("Duplicate local discovery route")
        identities.add(identity)
        counts[rule["port"]] = counts.get(rule["port"], 0) + 1
        if counts[rule["port"]] > 4:
            raise ValueError("At most four discovery rules per port")
        if not isinstance(rule["title"], str) or not rule["title"].strip() or len(rule["title"]) > 256:
            raise ValueError("Discovery rule needs an exact nonempty service title")
        probe = rule["probe"]
        if (not isinstance(probe, dict) or not {"path", "json_type"} <= set(probe)
                or set(probe) - {"path", "json_type", "json_keys"}
                or probe["json_type"] not in ("object", "array")):
            raise ValueError("Discovery probe requires a path and JSON object/array type")
        if not within(endpoint_path(probe["path"]), rule["path"]):
            raise ValueError("Discovery probe must stay inside its API base path")
        keys = probe.get("json_keys", [])
        if (not isinstance(keys, list) or len(keys) > 32
                or any(not isinstance(key, str) or not key or len(key) > 256 for key in keys)
                or (keys and probe["json_type"] != "object")):
            raise ValueError("Discovery json_keys must be object property names")
        operations = rule["operations"]
        if not isinstance(operations, list) or not 1 <= len(operations) <= 2000:
            raise ValueError("Discovery rule requires exact HTTP operations")
        seen = set()
        for operation in operations:
            if (not isinstance(operation, dict) or set(operation) != {"path", "method", "requires_auth"}
                    or not isinstance(operation["method"], str) or operation["method"] not in METHODS
                    or type(operation["requires_auth"]) is not bool):
                raise ValueError("Discovery operation requires path, method and boolean requires_auth")
            if not within(endpoint_path(operation["path"], template=True), rule["path"]):
                raise ValueError("Discovery operation escapes its API base path")
            key = (operation["method"], operation["path"])
            if key in seen:
                raise ValueError("Duplicate discovery operation")
            seen.add(key)
    return tuple(data["routes"])


def matches_service(rule: dict, service: dict) -> bool:
    return (rule["port"] == service.get("port")
            and rule["title"].strip().casefold() == str(service.get("title") or service.get("name") or "").strip().casefold())


def matches_json(probe: dict, data) -> bool:
    if probe["json_type"] == "array":
        return isinstance(data, list)
    return isinstance(data, dict) and all(key in data for key in probe.get("json_keys", []))
