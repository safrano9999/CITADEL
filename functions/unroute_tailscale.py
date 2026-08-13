#!/usr/bin/env python3
"""Release selected, exactly owned CITADEL Tailscale Serve listeners."""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from providers.atomic_io import atomic_write_json


PUBLIC_SCHEMES = ("http", "https")
STATE_RELATIVE_PATHS = (
    Path("tailscale.json"),
    Path("extensions/enabled/tailscale/routes.json"),
)


class UnrouteError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class ListenerSelection:
    scheme: str
    logical_port: int
    public_port: int
    allocated: bool = False
    owned: bool = False
    variant: str = "legacy"


@dataclass(frozen=True)
class PortResolution:
    requested_port: int
    kind: str
    listeners: tuple[ListenerSelection, ...]


def read_configured_port(project_dir: Path) -> int:
    config_path = project_dir / "config.conf"
    if not config_path.is_file():
        raise UnrouteError(f"missing configuration file: {config_path}")

    raw_value: str | None = None
    try:
        for raw_line in config_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == "CITADEL_WEBUI_PORT":
                raw_value = value.split("#", 1)[0].strip().strip("\"'")
    except OSError as exc:
        raise UnrouteError(f"cannot read {config_path}: {exc}") from exc

    if raw_value is None:
        raise UnrouteError(f"CITADEL_WEBUI_PORT is missing in {config_path}")
    try:
        port = int(raw_value)
    except ValueError as exc:
        raise UnrouteError(
            f"CITADEL_WEBUI_PORT={raw_value!r} is not a valid port"
        ) from exc
    if not 1 <= port <= 65535:
        raise UnrouteError(
            f"CITADEL_WEBUI_PORT={port} is not a valid port (1-65535)"
        )
    return port


def command_succeeded(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode == 0:
        return True
    message = f"{result.stderr}\n{result.stdout}".lower()
    return "handler does not exist" in message


def release_serve_port(
    tailscale_bin: str,
    port: int,
    scheme: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Remove one exact Serve variant, never both schemes speculatively."""

    if scheme not in PUBLIC_SCHEMES:
        raise UnrouteError(f"unsupported Tailscale Serve scheme: {scheme!r}")
    command = [
        tailscale_bin,
        "serve",
        "--yes",
        f"--{scheme}={port}",
        "off",
    ]
    result = runner(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if command_succeeded(result):
        return
    detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
    raise UnrouteError(
        f"could not release Tailscale {scheme.upper()} Serve port {port}: {detail}"
    )


def read_json_object(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UnrouteError(f"cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise UnrouteError(f"expected a JSON object in {path}")
    return payload


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    try:
        atomic_write_json(path, payload)
    except OSError as exc:
        raise UnrouteError(f"cannot update {path}: {exc}") from exc


def _managed_routes(payload: dict[str, Any]) -> dict[str, str]:
    raw = payload.get("managed_routes")
    if not isinstance(raw, dict):
        return {}
    return {
        str(port): str(scheme).strip().lower()
        for port, scheme in raw.items()
        if str(port).isdigit() and str(scheme).strip().lower() in PUBLIC_SCHEMES
    }


def _port_assignments(
    payload: dict[str, Any],
) -> dict[str, dict[str, int]]:
    raw_assignments = payload.get("port_assignments")
    if raw_assignments is None:
        return {scheme: {} for scheme in PUBLIC_SCHEMES}
    if not isinstance(raw_assignments, dict):
        raise UnrouteError("persisted port_assignments must be a JSON object")

    assignments: dict[str, dict[str, int]] = {}
    seen_public: dict[int, tuple[str, str]] = {}
    for scheme in PUBLIC_SCHEMES:
        raw_scheme = raw_assignments.get(scheme, {})
        if not isinstance(raw_scheme, dict):
            raise UnrouteError(
                f"persisted {scheme.upper()} port_assignments must be a JSON object"
            )
        normalized: dict[str, int] = {}
        for raw_logical, raw_public in raw_scheme.items():
            logical = str(raw_logical)
            try:
                logical_port = int(logical)
                public_port = int(raw_public)
            except (TypeError, ValueError) as exc:
                raise UnrouteError(
                    f"invalid persisted {scheme.upper()} assignment "
                    f"{raw_logical!r}={raw_public!r}"
                ) from exc
            if not 1 <= logical_port <= 65535 or not 1 <= public_port <= 65535:
                raise UnrouteError(
                    f"invalid persisted {scheme.upper()} assignment "
                    f"{logical_port}={public_port}"
                )
            owner = seen_public.get(public_port)
            if owner is not None and owner != (scheme, logical):
                raise UnrouteError(
                    f"persisted public port {public_port} is assigned to both "
                    f"{owner[0].upper()} service {owner[1]} and "
                    f"{scheme.upper()} service {logical}"
                )
            seen_public[public_port] = (scheme, logical)
            normalized[str(logical_port)] = public_port
        assignments[scheme] = normalized
    return assignments


def _route_port_and_scheme(route: Any) -> tuple[int | None, str | None]:
    if not isinstance(route, dict):
        return None, None
    raw_public = route.get("public_port")
    raw_scheme = str(route.get("public_scheme") or "").strip().lower()
    if str(raw_public or "").isdigit() and raw_scheme in PUBLIC_SCHEMES:
        return int(raw_public), raw_scheme

    url = str(route.get("url") or "").strip()
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None, None
    scheme = parsed.scheme.lower()
    return (port, scheme) if port and scheme in PUBLIC_SCHEMES else (None, None)


def _route_logical_port(route: Any, fallback: int) -> int:
    if isinstance(route, dict):
        raw = route.get("logical_port")
        if str(raw or "").isdigit() and 1 <= int(raw) <= 65535:
            return int(raw)
    return fallback


def _all_recorded_routes(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    routes: list[tuple[str, dict[str, Any]]] = []
    for map_name in (
        "remembered_serve_routes",
        "serve_routes",
        "remembered_services",
        "services",
    ):
        route_map = payload.get(map_name)
        if not isinstance(route_map, dict):
            continue
        for key, route in route_map.items():
            if isinstance(route, dict):
                routes.append((str(key), route))
    for variants_name in ("remembered_variants", "variants"):
        variants = payload.get(variants_name)
        if not isinstance(variants, dict):
            continue
        for variant in variants.values():
            services = variant.get("services") if isinstance(variant, dict) else None
            if not isinstance(services, dict):
                continue
            for key, route in services.items():
                if isinstance(route, dict):
                    routes.append((str(key), route))
    return routes


def _legacy_owned_selection(
    payload: dict[str, Any],
    requested_port: int,
) -> ListenerSelection | None:
    managed = _managed_routes(payload)
    managed_scheme = managed.get(str(requested_port))
    candidates: set[ListenerSelection] = set()
    for key, route in _all_recorded_routes(payload):
        public_port, route_scheme = _route_port_and_scheme(route)
        if public_port != requested_port or route_scheme not in PUBLIC_SCHEMES:
            continue
        if managed_scheme and route_scheme != managed_scheme:
            continue
        owns_listener = bool(route.get("owns_listener", False))
        if not managed_scheme and not owns_listener:
            continue
        fallback = int(key) if key.isdigit() and 1 <= int(key) <= 65535 else requested_port
        candidates.add(
            ListenerSelection(
                route_scheme,
                _route_logical_port(route, fallback),
                requested_port,
                allocated=False,
                owned=bool(managed_scheme or owns_listener),
            )
        )

    if managed_scheme and not candidates:
        candidates.add(
            ListenerSelection(
                managed_scheme,
                requested_port,
                requested_port,
                allocated=False,
                owned=True,
            )
        )
    if len(candidates) > 1:
        rendered = ", ".join(
            f"{item.scheme}:{item.logical_port}->{item.public_port}"
            for item in sorted(candidates)
        )
        raise UnrouteError(
            f"port {requested_port} has ambiguous legacy CITADEL ownership: {rendered}"
        )
    return next(iter(candidates), None)


def _default_route(
    payload: dict[str, Any],
    logical_port: int,
) -> dict[str, Any] | None:
    logical_key = str(logical_port)
    for variants_name in ("variants", "remembered_variants"):
        variants = payload.get(variants_name)
        default_variant = variants.get("default") if isinstance(variants, dict) else None
        services = (
            default_variant.get("services")
            if isinstance(default_variant, dict)
            else None
        )
        candidate = services.get(logical_key) if isinstance(services, dict) else None
        if isinstance(candidate, dict):
            return candidate
    return None


def _default_selection(
    payload: dict[str, Any],
    logical_port: int,
) -> ListenerSelection | None:
    """Return the recorded Default route, including a non-actionable direct one.

    A directly reachable Default route deliberately has no CITADEL-owned
    listener. Keeping it in the resolution lets preflight reject a foreign
    Serve listener on the same port, while execution filters it out and never
    issues a speculative ``tailscale serve ... off`` call.
    """

    route = _default_route(payload, logical_port)
    if route is None:
        return None

    public_port, scheme = _route_port_and_scheme(route)
    if public_port != logical_port or scheme not in PUBLIC_SCHEMES:
        raise UnrouteError(
            f"persisted Default route for logical port {logical_port} is not 1:1; "
            "nothing was changed"
        )
    claims_listener = bool(route.get("owns_listener", False))
    owned = _managed_routes(payload).get(str(logical_port)) == scheme
    if claims_listener and not owned:
        raise UnrouteError(
            f"persisted Default route for port {logical_port} has inconsistent "
            "CITADEL ownership; nothing was changed"
        )
    return ListenerSelection(
        scheme,
        logical_port,
        logical_port,
        allocated=False,
        owned=owned and claims_listener,
        variant="default",
    )


def resolve_requested_port(
    payload: dict[str, Any],
    requested_port: int,
) -> PortResolution:
    """Resolve logical ports to Default plus allocations, or one public allocation."""

    assignments = _port_assignments(payload)
    managed = _managed_routes(payload)
    logical_matches: set[ListenerSelection] = set()
    public_matches: set[ListenerSelection] = set()
    for scheme in PUBLIC_SCHEMES:
        for logical, public in assignments[scheme].items():
            selection = ListenerSelection(
                scheme,
                int(logical),
                public,
                allocated=True,
                owned=managed.get(str(public)) == scheme,
                variant=scheme,
            )
            if int(logical) == requested_port:
                logical_matches.add(selection)
            if public == requested_port:
                public_matches.add(selection)

    default_route_present = _default_route(payload, requested_port) is not None
    default = _default_selection(payload, requested_port)
    if default is not None:
        logical_matches.add(default)

    if (
        (logical_matches or default_route_present)
        and public_matches
        and logical_matches != public_matches
    ):
        logical_text = ", ".join(
            f"{item.scheme}:{item.public_port}" for item in sorted(logical_matches)
        )
        public_text = ", ".join(
            f"{item.scheme}:{item.logical_port}" for item in sorted(public_matches)
        )
        raise UnrouteError(
            f"port {requested_port} is ambiguous: as a logical service it selects "
            f"[{logical_text}], but as a public port it belongs to [{public_text}]; "
            "nothing was changed"
        )

    if logical_matches:
        kind = "logical" if not public_matches else "logical-public-identical"
        return PortResolution(requested_port, kind, tuple(sorted(logical_matches)))
    if default_route_present:
        return PortResolution(requested_port, "logical", ())
    if public_matches:
        return PortResolution(requested_port, "public", tuple(sorted(public_matches)))

    legacy = _legacy_owned_selection(payload, requested_port)
    return PortResolution(
        requested_port,
        "legacy",
        (legacy,) if legacy is not None else (),
    )


def _normalize_authority(value: Any) -> str:
    authority = str(value or "").strip()
    host, separator, port = authority.rpartition(":")
    if separator and port.isdigit():
        return f"{host.rstrip('.')}:{int(port)}"
    return authority.rstrip(".")


def _authority_port(authority: Any) -> int | None:
    normalized = _normalize_authority(authority)
    _host, separator, raw_port = normalized.rpartition(":")
    if not separator or not raw_port.isdigit():
        return None
    port = int(raw_port)
    return port if 1 <= port <= 65535 else None


def _config_mentions_port(payload: Any, port: int) -> bool:
    if not isinstance(payload, dict):
        return False
    tcp = payload.get("TCP")
    if isinstance(tcp, dict) and str(port) in {str(key) for key in tcp}:
        return True
    web = payload.get("Web")
    if isinstance(web, dict) and any(_authority_port(key) == port for key in web):
        return True
    funnel = payload.get("AllowFunnel")
    if isinstance(funnel, dict) and any(
        allowed and _authority_port(key) == port for key, allowed in funnel.items()
    ):
        return True
    foreground = payload.get("Foreground")
    return isinstance(foreground, dict) and any(
        _config_mentions_port(value, port) for value in foreground.values()
    )


def live_listener_at(payload: dict[str, Any], port: int) -> dict[str, Any] | None:
    """Describe a live port conservatively; non-exact shapes remain foreign."""

    if not _config_mentions_port(payload, port):
        return None

    tcp = payload.get("TCP")
    if tcp is not None and not isinstance(tcp, dict):
        raise UnrouteError("unexpected TCP field in Tailscale Serve status")
    tcp_listener = None
    if isinstance(tcp, dict):
        tcp_listener = next(
            (value for key, value in tcp.items() if str(key) == str(port)),
            None,
        )
    public_scheme = None
    exact_tcp = False
    if isinstance(tcp_listener, dict):
        if tcp_listener.get("HTTPS") is True:
            public_scheme = "https"
            exact_tcp = set(tcp_listener) == {"HTTPS"}
        elif tcp_listener.get("HTTP") is True:
            public_scheme = "http"
            exact_tcp = set(tcp_listener) == {"HTTP"}

    web = payload.get("Web")
    if web is not None and not isinstance(web, dict):
        raise UnrouteError("unexpected Web field in Tailscale Serve status")
    web_matches = [
        (str(authority), value)
        for authority, value in (web.items() if isinstance(web, dict) else [])
        if _authority_port(authority) == port
    ]
    authority = None
    target = None
    exact_web = False
    if len(web_matches) == 1:
        raw_authority, web_config = web_matches[0]
        authority = _normalize_authority(raw_authority)
        if isinstance(web_config, dict):
            handlers = web_config.get("Handlers")
            root_handler = handlers.get("/") if isinstance(handlers, dict) else None
            if isinstance(root_handler, dict) and root_handler.get("Proxy"):
                target = str(root_handler["Proxy"])
                exact_web = (
                    set(web_config) == {"Handlers"}
                    and set(handlers) == {"/"}
                    and set(root_handler) == {"Proxy"}
                )

    funnel = payload.get("AllowFunnel")
    funnel_active = isinstance(funnel, dict) and any(
        allowed and _authority_port(key) == port for key, allowed in funnel.items()
    )
    foreground = payload.get("Foreground")
    foreground_active = isinstance(foreground, dict) and any(
        _config_mentions_port(value, port) for value in foreground.values()
    )
    return {
        "public_scheme": public_scheme,
        "target": target,
        "authority": authority,
        "exact_tcp": exact_tcp,
        "exact_web": exact_web,
        "foreground": foreground_active,
        "funnel": funnel_active,
    }


def load_live_serve_config(
    tailscale_bin: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    command = [tailscale_bin, "serve", "status", "--json"]
    result = runner(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise UnrouteError(f"cannot verify Tailscale Serve ownership: {detail}")
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise UnrouteError("cannot parse Tailscale Serve status JSON") from exc
    if not isinstance(payload, dict):
        raise UnrouteError("Tailscale Serve status must be a JSON object")
    return payload


def _recorded_route(
    payload: dict[str, Any],
    selection: ListenerSelection,
) -> dict[str, Any] | None:
    public_key = str(selection.public_port)
    logical_key = str(selection.logical_port)
    for map_name in ("remembered_serve_routes", "serve_routes"):
        route_map = payload.get(map_name)
        route = route_map.get(public_key) if isinstance(route_map, dict) else None
        if isinstance(route, dict):
            return route
    for variants_name in ("remembered_variants", "variants"):
        variants = payload.get(variants_name)
        variant = (
            variants.get(_selection_variant(selection))
            if isinstance(variants, dict)
            else None
        )
        services = variant.get("services") if isinstance(variant, dict) else None
        route = services.get(logical_key) if isinstance(services, dict) else None
        if isinstance(route, dict):
            return route
    for map_name in ("remembered_services", "services"):
        route_map = payload.get(map_name)
        if not isinstance(route_map, dict):
            continue
        for key in (logical_key, public_key):
            route = route_map.get(key)
            if not isinstance(route, dict):
                continue
            public_port, scheme = _route_port_and_scheme(route)
            if public_port == selection.public_port and scheme == selection.scheme:
                return route
    return None


def live_listener_matches_record(
    live: dict[str, Any],
    recorded: dict[str, Any],
    selection: ListenerSelection,
) -> bool:
    target = str(recorded.get("target") or "")
    url = str(recorded.get("url") or "")
    try:
        authority = _normalize_authority(urlsplit(url).netloc)
    except ValueError:
        return False
    return bool(target and authority) and (
        live.get("public_scheme") == selection.scheme
        and live.get("target") == target
        and live.get("authority") == authority
        and live.get("exact_tcp") is True
        and live.get("exact_web") is True
        and live.get("foreground") is False
        and live.get("funnel") is False
    )


def _route_matches_selection(route: Any, selection: ListenerSelection) -> bool:
    public_port, scheme = _route_port_and_scheme(route)
    return public_port == selection.public_port and scheme == selection.scheme


def _selection_variant(selection: ListenerSelection) -> str:
    return (
        selection.variant
        if selection.variant in {"default", "http", "https"}
        else selection.scheme
    )


def _prune_variant_service(
    payload: dict[str, Any],
    variants_name: str,
    selection: ListenerSelection,
) -> bool:
    variants = payload.get(variants_name)
    if not isinstance(variants, dict):
        return False
    variant = variants.get(_selection_variant(selection))
    if not isinstance(variant, dict):
        return False
    services = variant.get("services")
    if not isinstance(services, dict):
        return False
    logical_key = str(selection.logical_port)
    route = services.get(logical_key)
    if not _route_matches_selection(route, selection):
        return False
    services.pop(logical_key)
    variant["available"] = bool(services)
    return True


def _refresh_compatibility_route(
    payload: dict[str, Any],
    services_name: str,
    variants_name: str,
    logical_port: int,
) -> bool:
    services = payload.get(services_name)
    if not isinstance(services, dict):
        return False
    logical_key = str(logical_port)
    variants = payload.get(variants_name)
    replacement = None
    if isinstance(variants, dict):
        for variant_name in ("default", "https", "http"):
            variant = variants.get(variant_name)
            variant_services = (
                variant.get("services") if isinstance(variant, dict) else None
            )
            route = (
                variant_services.get(logical_key)
                if isinstance(variant_services, dict)
                else None
            )
            if isinstance(route, dict):
                replacement = route
                break
    previous = services.get(logical_key)
    if replacement is None:
        if logical_key in services:
            services.pop(logical_key)
            return True
        return False
    if previous != replacement:
        services[logical_key] = replacement
        return True
    return False


def prune_listener_state(
    payload: dict[str, Any],
    selection: ListenerSelection,
) -> bool:
    """Remove active route ownership but retain allocator reservations forever."""

    changed = False
    public_key = str(selection.public_port)
    logical_key = str(selection.logical_port)

    managed_routes = payload.get("managed_routes")
    if (
        isinstance(managed_routes, dict)
        and str(managed_routes.get(public_key) or "").lower() == selection.scheme
    ):
        managed_routes.pop(public_key)
        changed = True

    managed_ports = payload.get("managed_ports")
    if isinstance(managed_ports, list):
        retained = [value for value in managed_ports if str(value) != public_key]
        if retained != managed_ports:
            payload["managed_ports"] = retained
            changed = True

    for map_name in ("serve_routes", "remembered_serve_routes"):
        route_map = payload.get(map_name)
        route = route_map.get(public_key) if isinstance(route_map, dict) else None
        if isinstance(route_map, dict) and (
            _route_matches_selection(route, selection)
            or map_name == "remembered_serve_routes"
            and isinstance(route, dict)
            and str(route.get("public_scheme") or selection.scheme).lower()
            == selection.scheme
        ):
            route_map.pop(public_key)
            changed = True

    for variants_name in ("variants", "remembered_variants"):
        changed |= _prune_variant_service(payload, variants_name, selection)

    for map_name in ("services", "remembered_services"):
        route_map = payload.get(map_name)
        if not isinstance(route_map, dict):
            continue
        for key in dict.fromkeys((logical_key, public_key)):
            if _route_matches_selection(route_map.get(key), selection):
                route_map.pop(key)
                changed = True

    for map_name in ("service_signatures", "route_failures", "fallbacks"):
        values = payload.get(map_name)
        if not isinstance(values, dict):
            continue
        signature_key = f"{_selection_variant(selection)}:{logical_key}"
        for key in dict.fromkeys((signature_key, public_key if not selection.allocated else "")):
            if key and key in values:
                values.pop(key)
                changed = True

    changed |= _refresh_compatibility_route(
        payload, "services", "variants", selection.logical_port
    )
    changed |= _refresh_compatibility_route(
        payload,
        "remembered_services",
        "remembered_variants",
        selection.logical_port,
    )
    variants = payload.get("variants")
    if isinstance(variants, dict):
        payload["available"] = any(
            bool(variant.get("services"))
            for variant in variants.values()
            if isinstance(variant, dict)
        )
    # Deliberately do not touch port_assignments or allocation_policy. Entries
    # without an active route are allocator tombstones and remain reserved.
    return changed


def _service_logical_port(service: dict[str, Any]) -> int:
    try:
        if service.get("origin") == "host":
            return int(service.get("route_port") or 0)
        return int(service.get("port") or 0)
    except (TypeError, ValueError):
        return 0


def _remaining_variant_url(payload: dict[str, Any], logical_port: int) -> str:
    variants = payload.get("variants")
    if not isinstance(variants, dict):
        return ""
    logical_key = str(logical_port)
    for variant_name in ("default", "https", "http"):
        variant = variants.get(variant_name)
        services = variant.get("services") if isinstance(variant, dict) else None
        route = services.get(logical_key) if isinstance(services, dict) else None
        if isinstance(route, dict) and isinstance(route.get("url"), str):
            return route["url"]
    return ""


def _clear_url_metadata(
    payload: dict[str, Any],
    selection: ListenerSelection,
    remaining_url: str,
) -> tuple[bool, set[int]]:
    changed = False
    cache_ports: set[int] = set()
    for list_name in ("http_services", "host_http_services"):
        services = payload.get(list_name)
        if not isinstance(services, list):
            continue
        for service in services:
            if not isinstance(service, dict):
                continue
            if _service_logical_port(service) != selection.logical_port:
                continue
            raw_port = service.get("port")
            if str(raw_port or "").isdigit():
                cache_ports.add(int(raw_port))
            urls = service.get("urls")
            if not isinstance(urls, dict):
                continue
            variant_key = f"tailscale-{_selection_variant(selection)}"
            if variant_key in urls:
                urls.pop(variant_key)
                changed = True
            compatibility = str(urls.get("tailscale") or "")
            try:
                compatibility_port = urlsplit(compatibility).port
            except ValueError:
                compatibility_port = None
            if compatibility_port == selection.public_port:
                if remaining_url:
                    urls["tailscale"] = remaining_url
                else:
                    urls.pop("tailscale", None)
                changed = True
    return changed, cache_ports


def clear_discovery_route_metadata(
    project_dir: Path,
    selections: list[ListenerSelection],
    authoritative_state: dict[str, Any],
) -> None:
    """Clear only stale route URLs; never delete a service, cache, or icon."""

    cache_selections: dict[int, set[ListenerSelection]] = {}
    for relative in (Path("services.json"), Path("host_services.json")):
        path = project_dir / relative
        payload = read_json_object(path)
        if payload is None:
            continue
        changed = False
        for selection in selections:
            selection_changed, cache_ports = _clear_url_metadata(
                payload,
                selection,
                _remaining_variant_url(authoritative_state, selection.logical_port),
            )
            changed |= selection_changed
            for cache_port in cache_ports:
                cache_selections.setdefault(cache_port, set()).add(selection)
        if changed:
            write_json_atomic(path, payload)

    for cache_port, relevant_selections in cache_selections.items():
        cache_path = project_dir / "cache" / f"{cache_port}.json"
        cache_payload = read_json_object(cache_path)
        if cache_payload is None:
            continue
        changed = False
        for selection in relevant_selections:
            remaining_url = _remaining_variant_url(
                authoritative_state, selection.logical_port
            )
            key = f"tailscale_{_selection_variant(selection)}_url"
            removed_url = str(cache_payload.get(key) or "")
            if key in cache_payload:
                cache_payload.pop(key)
                changed = True
            compatibility = str(cache_payload.get("tailscale_url") or "")
            if compatibility and compatibility == removed_url:
                if remaining_url:
                    cache_payload["tailscale_url"] = remaining_url
                else:
                    cache_payload.pop("tailscale_url", None)
                    cache_payload.pop("tailscale_path", None)
                changed = True
        if changed:
            write_json_atomic(cache_path, cache_payload)


def _load_state_files(
    project_dir: Path,
) -> tuple[dict[Path, dict[str, Any]], Path | None]:
    states: dict[Path, dict[str, Any]] = {}
    for relative in STATE_RELATIVE_PATHS:
        path = project_dir / relative
        payload = read_json_object(path)
        if payload is not None:
            states[path] = payload
    authoritative = next(
        (project_dir / relative for relative in STATE_RELATIVE_PATHS if project_dir / relative in states),
        None,
    )
    return states, authoritative


def unroute(project_dir: Path, requested_ports: list[int] | None = None) -> int:
    project_dir = project_dir.resolve()
    ports = requested_ports or [read_configured_port(project_dir)]
    if any(port < 1 or port > 65535 for port in ports):
        raise UnrouteError("ports must be between 1 and 65535")
    ports = list(dict.fromkeys(ports))

    states, authoritative_path = _load_state_files(project_dir)
    authoritative = states.get(authoritative_path, {}) if authoritative_path else {}
    resolutions = [resolve_requested_port(authoritative, port) for port in ports]

    tailscale_bin = shutil.which("tailscale")
    if tailscale_bin is None:
        raise UnrouteError("tailscale CLI is unavailable")
    live_config = load_live_serve_config(tailscale_bin)

    selections = sorted(
        {selection for resolution in resolutions for selection in resolution.listeners}
    )
    actionable_selections = [
        selection
        for selection in selections
        if not (selection.variant == "default" and not selection.owned)
    ]
    selected_public_ports = {
        selection.public_port for selection in actionable_selections
    }

    preflight_errors: list[str] = []
    for resolution in resolutions:
        if resolution.listeners:
            continue
        live = live_listener_at(live_config, resolution.requested_port)
        if live is not None:
            preflight_errors.append(
                f"port {resolution.requested_port} has a foreign or unmanaged "
                "Tailscale listener; left untouched"
            )
    for selection in selections:
        live = live_listener_at(live_config, selection.public_port)
        if live is None:
            continue
        recorded = _recorded_route(authoritative, selection)
        if (
            not selection.owned
            or recorded is None
            or not live_listener_matches_record(live, recorded, selection)
        ):
            preflight_errors.append(
                f"port {selection.public_port} no longer exactly matches CITADEL's "
                f"recorded {selection.scheme.upper()} listener; left untouched"
            )
    if preflight_errors:
        raise UnrouteError("; ".join(preflight_errors))

    successful: list[ListenerSelection] = []
    failures: list[str] = []
    for selection in actionable_selections:
        live = live_listener_at(live_config, selection.public_port)
        if live is not None:
            try:
                release_serve_port(
                    tailscale_bin,
                    selection.public_port,
                    selection.scheme,
                )
            except UnrouteError as exc:
                failures.append(str(exc))
                continue
        successful.append(selection)

    updated_states: dict[Path, dict[str, Any]] = {}
    for path, original in states.items():
        updated = copy.deepcopy(original)
        changed = False
        for selection in successful:
            changed |= prune_listener_state(updated, selection)
        if changed:
            updated_states[path] = updated
    for path, payload in updated_states.items():
        write_json_atomic(path, payload)

    updated_authoritative = (
        updated_states.get(authoritative_path, authoritative)
        if authoritative_path is not None
        else authoritative
    )
    clear_discovery_route_metadata(
        project_dir,
        successful,
        updated_authoritative,
    )

    if requested_ports:
        print(f"[unroute] requested ports: {', '.join(map(str, ports))}")
    else:
        print(f"[unroute] configured CITADEL service port: {ports[0]}")
    for resolution in resolutions:
        resolved = [
            selection
            for selection in resolution.listeners
            if selection in successful
        ]
        if not resolved:
            print(
                f"[unroute] port {resolution.requested_port}: no active "
                "CITADEL-owned listener"
            )
            continue
        rendered = ", ".join(
            f"{selection.scheme.upper()} :{selection.public_port}"
            for selection in resolved
        )
        print(
            f"[unroute] {resolution.kind} :{resolution.requested_port} "
            f"released {rendered}"
        )
    if selected_public_ports:
        print("[unroute] stable port assignments remain reserved")
    print("[unroute] discovery services, cache files, and icons were preserved")

    if failures:
        raise UnrouteError("; ".join(failures))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("ports", nargs="*", type=int, metavar="PORT")
    args = parser.parse_args()
    try:
        return unroute(args.root, args.ports)
    except UnrouteError as exc:
        print(f"[unroute] failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
