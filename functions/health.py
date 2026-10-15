"""Read-only health view of the existing scan output. Never runs providers."""
from __future__ import annotations

import hashlib
import json
import re
from runtime_state import data_directory, provider_output
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def extensions_arg(value: str) -> list[str]:
    names = list(dict.fromkeys(v.strip() for v in value.split(",") if v.strip()))
    if any(not ID.fullmatch(name) for name in names):
        raise ValueError("Invalid extension name")
    return names


def read_object(path: Path) -> dict:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"Invalid object: {path.name}")
    return data


def public_url(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Missing route URL")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid route URL")
    # Health checks never transport embedded credentials or query tokens.
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def check_artifacts(base: Path, artifacts: object, *, caddy_export: bool = False) -> list[dict]:
    """Validate indexed files and hashes within the repository, without running them."""
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("Configured export has no indexed artifacts")
    root = base.resolve()
    results = []
    for artifact in artifacts:
        record = {"status": "FAIL", "detail": "Invalid artifact record"}
        results.append(record)
        if not isinstance(artifact, dict):
            continue
        path, digest = artifact.get("path"), artifact.get("sha256")
        record.update(path=path, sha256=digest)
        if (not isinstance(path, str) or not path or "\\" in path or "\x00" in path
                or Path(path).is_absolute() or ".." in Path(path).parts):
            record["detail"] = "Artifact path must be relative and inside the repository"
            continue
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            record["detail"] = "Invalid artifact SHA-256"
            continue
        try:
            target = (root / path).resolve()
            if not target.is_relative_to(root):
                record["detail"] = "Artifact path escapes the repository"
                continue
            if not target.is_file():
                record["detail"] = "Artifact file missing or not a regular file"
                continue
            checksum = hashlib.sha256()
            with target.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    checksum.update(chunk)
            record["actual_sha256"] = checksum.hexdigest()
            if checksum.hexdigest() != digest.lower():
                record["detail"] = "Artifact SHA-256 mismatch"
                continue
            record.update(status="PASS", detail="Indexed artifact exists and SHA-256 matches")
        except (OSError, ValueError, RuntimeError):
            record["detail"] = "Artifact file unavailable or invalid"
    return results


def snapshot(base: Path, selected: list[str] | None = None) -> dict:
    enabled = base / "extensions" / "enabled"
    names = selected if selected is not None else sorted(p.name for p in enabled.iterdir() if p.is_dir()) if enabled.is_dir() else []
    if any(not ID.fullmatch(name) for name in names):
        raise ValueError("Invalid extension name")
    result = {"schema_version": 1, "scope": "index", "status": "NOT_TESTED",
              "generated_at": datetime.now(timezone.utc).isoformat(), "last_index_at": None,
              "errors": [], "extensions": []}
    try:
        result["last_index_at"] = (data_directory(base) / "last_scan.txt").read_text().strip()
        if not result["last_index_at"]:
            raise ValueError("Missing index timestamp")
        services = read_object(data_directory(base) / "services.json")["http_services"]
        if not isinstance(services, list):
            raise ValueError("Invalid services list")
        indexed = {str(int(s["port"])): s for s in services}
        state = read_object(data_directory(base) / "providers_state.json")
    except (OSError, ValueError, KeyError, TypeError):
        result["errors"].append("Index data missing or invalid")
        indexed, state = {}, {}

    for name in dict.fromkeys(names):
        entry = {"id": name, "kind": "provider", "status": "SKIP", "detail": "Extension not enabled", "services": []}
        result["extensions"].append(entry)
        directory = enabled / name
        if not directory.is_dir():
            continue
        try:
            if not directory.resolve().is_relative_to(enabled.resolve()):
                raise ValueError("Extension directory escapes enabled directory")
            manifest = read_object(directory / "extension.json")
            kind = manifest.get("kind", "provider")
            entry["kind"] = kind
            if kind not in ("provider", "export"):
                raise ValueError("Unknown extension kind")
            if kind == "export":
                entry["artifacts"] = []
            if manifest.get("enabled") is False:
                continue
            if result["errors"]:
                entry.update(status="NOT_TESTED", detail="Index data unavailable")
                continue
            routes = read_object(provider_output(base, name, kind))
            provider = state.get("providers", {}).get(name, {})
            if provider.get("status") != "ok" or routes.get("errors"):
                raise ValueError("Provider failed in the index")
            if kind == "export":
                if (routes.get("kind") != "export" or routes.get("services") != {}
                        or not isinstance(routes.get("considered"), bool)
                        or not isinstance(routes.get("available"), bool)
                        or not isinstance(routes.get("artifacts"), list)):
                    raise ValueError("Invalid export status")
                if not routes["considered"] and (routes["available"] or routes["artifacts"]):
                    raise ValueError("Unconfigured export has output")
            if not routes.get("considered"):
                entry["detail"] = "Extension not configured in the index"
                continue
            if name == "CLOUDFLARE-API":
                for mode, view in (routes.get("views") or {}).items():
                    if mode not in {"api-bearer", "api-oauth"} or not isinstance(view, dict):
                        raise ValueError("Invalid API mode")
                    for port, route in (view.get("services") or {}).items():
                        for endpoint in route.get("endpoints", []):
                            service = {"port": int(port), "provider": mode, "url": public_url(endpoint.get("url")),
                                       "protocol": endpoint.get("protocol"), "status": "NOT_TESTED",
                                       "detail": "Public certificate or auth challenge pending; application calls not tested"}
                            if str(port) not in indexed:
                                service.update(status="FAIL", detail="API endpoint missing from service index")
                            elif endpoint.get("status") == "provisioned":
                                service.update(status="PASS", detail="TLS and anonymous machine-auth challenge verified; authenticated protocol check NOT_TESTED")
                            entry["services"].append(service)
                statuses = [service["status"] for service in entry["services"]]
                entry.update(status="FAIL" if "FAIL" in statuses else "PASS" if statuses and all(s == "PASS" for s in statuses) else "NOT_TESTED",
                             detail="API route state; browser OTP redirects are not MCP authentication")
                continue
            if not routes.get("available"):
                raise ValueError("Configured extension unavailable")
            if kind == "export":
                entry["artifacts"] = check_artifacts(
                    base, routes["artifacts"],
                    caddy_export=manifest.get("provider", name) == "caddy",
                )
                for key in ("generated_file", "mappings_count", "generated_at", "label"):
                    if key in routes:
                        entry[key] = routes[key]
                entry.update(
                    status="PASS" if all(a["status"] == "PASS" for a in entry["artifacts"]) else "FAIL",
                    detail="Index artifact validation (existence and SHA-256); running Caddy and live reachability NOT_TESTED",
                )
                continue
            for port, route in routes.get("services", {}).items():
                url = public_url(route.get("url"))
                service = {"port": int(port), "provider": name, "url": url, "status": "PASS", "detail": "Indexed route"}
                entry["services"].append(service)
                try:
                    if port not in indexed:
                        raise ValueError("Route missing from service index")
                    cache = read_object(base / "cache" / f"{int(port)}.json")
                    if cache.get("kind") not in ("html", "openai-v1", "http-service"):
                        raise ValueError("Unsupported or missing cache kind")
                    service.update(name=str(indexed[port].get("name") or f"Port {port}"), kind=cache["kind"])
                except (OSError, ValueError, TypeError):
                    service.update(status="FAIL", detail="Route has no valid indexed service/cache")
            # Detect lost routes for services that the last scan assigned to this provider.
            routed = {str(s["port"]) for s in entry["services"]}
            for port, svc in indexed.items():
                if name in (svc.get("urls") or {}) and port not in routed:
                    entry["services"].append({"port": int(port), "status": "FAIL", "detail": "Indexed provider URL has no route"})
            if not entry["services"]:
                raise ValueError("Configured extension has no indexed routes")
            entry.update(status="PASS" if all(s["status"] == "PASS" for s in entry["services"]) else "FAIL",
                         detail="Index state; live reachability checked by external CLI")
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError):
            detail = ("Export status or artifacts missing, invalid or unavailable" if entry["kind"] == "export"
                      else "Provider state or routes missing, invalid or unavailable")
            entry.update(status="FAIL", detail=detail)
    statuses = [e["status"] for e in result["extensions"]]
    result["status"] = ("FAIL" if result["errors"] or "FAIL" in statuses else
                        "PASS" if "PASS" in statuses else "NOT_TESTED")
    return result
