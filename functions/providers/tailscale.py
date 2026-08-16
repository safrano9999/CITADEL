#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import importlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from common import (
    ROUTE_SCHEMA_VERSION,
    now_iso,
    parse_bool,
    read_json,
    routable_services,
    route_record,
    run,
    set_ini_value,
    write_json,
)
from tailscale_allocator import (
    PUBLIC_SCHEMES,
    AllocationResult,
    SchemeBlock,
    allocate_scheme_ports,
    build_scheme_blocks,
    parse_optional_start,
    parse_spacing,
)


VARIANT_LABELS = {
    "default": "Tailscale Default",
    "http": "Tailscale HTTP",
    "https": "Tailscale HTTPS",
}
VARIANT_KEYS = ("default", *PUBLIC_SCHEMES)


def clear_stale_tailscale(cache_dir: str, services_payload: dict[str, Any]) -> None:
    if os.path.isdir(cache_dir):
        for name in os.listdir(cache_dir):
            if not name.endswith(".json"):
                continue
            path = os.path.join(cache_dir, name)
            payload = read_json(path, {})
            if not isinstance(payload, dict):
                payload = {}
            for key in (
                "tailscale_url",
                "tailscale_path",
                "tailscale_default_url",
                "tailscale_http_url",
                "tailscale_https_url",
            ):
                payload.pop(key, None)
            write_json(path, payload)

    all_services = list(services_payload.get("http_services", []))
    all_services.extend(services_payload.get("host_http_services", []))
    for service in all_services:
        if not isinstance(service, dict):
            continue
        urls = service.get("urls")
        if not isinstance(urls, dict):
            urls = {}
            service["urls"] = urls
        for key in (
            "tailscale",
            "tailscale-default",
            "tailscale-http",
            "tailscale-https",
        ):
            urls.pop(key, None)


def build_tailscale_url(domain: str, port: int, scheme: str) -> str:
    return f"{scheme}://{domain}:{port}"


def serve_target(
    port: int,
    scheme: str,
    origin_host: str = "127.0.0.1",
    origin_port: int | None = None,
) -> str:
    protocol = "https+insecure" if scheme == "https" else "http"
    return f"{protocol}://{origin_host}:{origin_port or port}"


def remove_serve_route(port: str | int, public_scheme: str = "https") -> str | None:
    if public_scheme not in set(PUBLIC_SCHEMES):
        return f"unsupported Tailscale Serve scheme '{public_scheme}'"
    removed = run(["tailscale", "serve", "--yes", f"--{public_scheme}={port}", "off"])
    message = f"{removed.stderr}\n{removed.stdout}".strip()
    if removed.returncode == 0 or "handler does not exist" in message.lower():
        return None
    return message or "tailscale serve removal failed"


def apply_serve_route(port: int, target: str, public_scheme: str):
    return run(
        [
            "tailscale",
            "serve",
            "--bg",
            "--yes",
            f"--{public_scheme}={port}",
            target,
        ]
    )


def serve_apply_collision(result: Any) -> bool:
    message = f"{getattr(result, 'stderr', '')}\n{getattr(result, 'stdout', '')}".lower()
    return any(
        marker in message
        for marker in (
            "address already in use",
            "port already in use",
            "port is already in use",
            "listener already exists",
            "handler already exists",
            "already has a handler",
        )
    )


def service_scheme(service: dict[str, Any]) -> str:
    scheme = str(service.get("scheme") or "http").strip().lower()
    return scheme if scheme in set(PUBLIC_SCHEMES) else "http"


def _listener_is_loopback(listener: dict[str, Any]) -> bool:
    address = str(listener.get("address") or "").strip("[]").casefold()
    return address in {"127.0.0.1", "::1", "localhost"}


def service_is_directly_reachable(
    service: dict[str, Any],
    tailscale_ips: set[str],
    live_serve_route: dict[str, Any] | None = None,
) -> bool:
    """Return whether the local app already owns its Tailnet address/port."""

    if service.get("origin") == "host":
        return False

    # Prefer per-listener data when available. The scanner's aggregate addr/addrs
    # can include tailscaled's listener on the same port and can even inherit the
    # app process name because process discovery is port-wide.
    detailed_listeners = [
        listener
        for listener in service.get("listeners") or []
        if isinstance(listener, dict) and listener.get("addr") is not None
    ]
    if detailed_listeners:
        addresses = {
            str(listener["addr"]).strip("[]").casefold()
            for listener in detailed_listeners
            if str(listener.get("process") or "").strip().casefold() != "tailscaled"
        }
    else:
        addresses = {
            str(value).strip("[]").casefold()
            for value in (service.get("addr"), *(service.get("addrs") or []))
            if value is not None
        }

    # A live Serve handler explains the Tailnet-IP socket on this exact port.
    # Wildcard app bindings remain directly reachable, but a Tailnet-IP entry
    # must not turn a loopback app into a Direct route while Serve owns the port.
    if live_serve_route is not None:
        addresses.difference_update(tailscale_ips)
    return bool(addresses & {"0.0.0.0", "*", "::", *tailscale_ips})


def normalize_authority(value: Any) -> str:
    authority = str(value or "").strip().lower()
    host, separator, port = authority.rpartition(":")
    if separator and port.isdigit():
        return f"{host.rstrip('.')}:{int(port)}"
    return authority.rstrip(".")


def _empty_live_route() -> dict[str, Any]:
    return {
        "public_scheme": None,
        "target": None,
        "authority": None,
        "listener_type": None,
        "tcp_target": None,
        "exact_tcp_handler": False,
        "exclusive_root_proxy": False,
        "foreground": False,
        "funnel": False,
    }


def parse_live_serve_routes(payload: Any) -> dict[str, dict[str, Any]]:
    """Parse every occupied Tailscale TCP key, including raw forwards."""

    if not isinstance(payload, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}

    tcp = payload.get("TCP")
    if tcp is not None and not isinstance(tcp, dict):
        raise ValueError("unexpected TCP ServeConfig")
    if isinstance(tcp, dict):
        for raw_port, listener in tcp.items():
            port_key = str(raw_port)
            if not port_key.isdigit() or not isinstance(listener, dict):
                raise ValueError("unexpected TCP listener")
            entry = _empty_live_route()
            if listener.get("HTTPS") is True:
                entry["public_scheme"] = "https"
                entry["listener_type"] = "HTTPS"
                entry["exact_tcp_handler"] = set(listener) == {"HTTPS"}
            elif listener.get("HTTP") is True:
                entry["public_scheme"] = "http"
                entry["listener_type"] = "HTTP"
                entry["exact_tcp_handler"] = set(listener) == {"HTTP"}
            elif "TCPForward" in listener:
                entry["listener_type"] = "TCPForward"
                entry["tcp_target"] = str(listener.get("TCPForward") or "") or None
            else:
                entry["listener_type"] = "+".join(sorted(str(key) for key in listener)) or "TCP"
                entry["tcp_target"] = json.dumps(listener, sort_keys=True)
            result[port_key] = entry

    web = payload.get("Web")
    if web is not None and not isinstance(web, dict):
        raise ValueError("unexpected Web ServeConfig")
    if isinstance(web, dict):
        seen_web_ports: set[str] = set()
        for authority, web_config in web.items():
            if not isinstance(web_config, dict):
                raise ValueError("unexpected web listener")
            authority_text = normalize_authority(authority)
            if ":" not in authority_text:
                raise ValueError("unexpected web listener authority")
            port_key = authority_text.rsplit(":", 1)[-1]
            if not port_key.isdigit():
                raise ValueError("unexpected web listener port")
            entry = result.setdefault(port_key, _empty_live_route())
            if port_key in seen_web_ports:
                entry["target"] = None
                entry["authority"] = None
                entry["exclusive_root_proxy"] = False
                continue
            seen_web_ports.add(port_key)
            entry["authority"] = authority_text
            handlers = web_config.get("Handlers")
            if not isinstance(handlers, dict):
                continue
            root_handler = handlers.get("/")
            target = root_handler.get("Proxy") if isinstance(root_handler, dict) else None
            entry["target"] = str(target) if target else None
            entry["exclusive_root_proxy"] = (
                bool(target)
                and set(web_config) == {"Handlers"}
                and set(handlers) == {"/"}
                and isinstance(root_handler, dict)
                and set(root_handler) == {"Proxy"}
            )

    allow_funnel = payload.get("AllowFunnel")
    if allow_funnel is not None and not isinstance(allow_funnel, dict):
        raise ValueError("unexpected AllowFunnel payload")
    if isinstance(allow_funnel, dict):
        for authority, allowed in allow_funnel.items():
            if not allowed:
                continue
            port_key = normalize_authority(authority).rsplit(":", 1)[-1]
            if port_key.isdigit():
                entry = result.setdefault(port_key, _empty_live_route())
                entry["funnel"] = True
                entry["exclusive_root_proxy"] = False

    foreground = payload.get("Foreground")
    if foreground is not None and not isinstance(foreground, dict):
        raise ValueError("unexpected Foreground payload")
    if isinstance(foreground, dict):
        for foreground_config in foreground.values():
            if not isinstance(foreground_config, dict):
                raise ValueError("unexpected foreground ServeConfig")
            for port_key, foreground_route in parse_live_serve_routes(foreground_config).items():
                entry = result.setdefault(port_key, _empty_live_route())
                if entry["public_scheme"] is None:
                    entry["public_scheme"] = foreground_route.get("public_scheme")
                entry["listener_type"] = foreground_route.get("listener_type")
                entry["target"] = None
                entry["authority"] = None
                entry["exact_tcp_handler"] = False
                entry["exclusive_root_proxy"] = False
                entry["foreground"] = True
    return result


def live_route_matches(
    live_route: dict[str, Any] | None,
    *,
    public_scheme: str,
    target: str,
    authority: str,
) -> bool:
    if not isinstance(live_route, dict):
        return False
    return (
        live_route.get("public_scheme") == public_scheme
        and live_route.get("target") == target
        and live_route.get("authority") == normalize_authority(authority)
        and live_route.get("exact_tcp_handler") is True
        and live_route.get("exclusive_root_proxy") is True
        and live_route.get("foreground") is False
        and live_route.get("funnel") is False
    )


def parse_local_listeners(output: str) -> dict[int, list[dict[str, Any]]]:
    listeners: dict[int, list[dict[str, Any]]] = {}
    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split()
        if fields and fields[0].upper() == "LISTEN":
            fields = fields[1:]
        if len(fields) < 3:
            continue
        local = fields[2]
        match = re.search(r":(\d+)$", local)
        if match is None:
            continue
        port = int(match.group(1))
        address = local[: match.start()].strip("[]") or "*"
        process_matches = re.findall(r'"([^"]+)",pid=(\d+)', line)
        if process_matches:
            rows = [
                {"address": address, "process": process, "pid": int(pid)}
                for process, pid in process_matches
            ]
        else:
            rows = [{"address": address, "process": None, "pid": None}]
        bucket = listeners.setdefault(port, [])
        for row in rows:
            if row not in bucket:
                bucket.append(row)
    return listeners


def local_listener_description(port: int, listener: dict[str, Any]) -> str:
    process = str(listener.get("process") or "unknown")
    pid = listener.get("pid")
    pid_text = str(pid) if pid is not None else "unknown"
    return (
        f"lokaler Listener {listener.get('address') or '*'}:{port} "
        f"process={process} pid={pid_text}"
    )


def live_listener_description(port: int, route: dict[str, Any]) -> str:
    listener_type = str(route.get("listener_type") or "TCP")
    details = [f"Tailscale {listener_type} :{port}"]
    if route.get("tcp_target"):
        details.append(f"target={route['tcp_target']}")
    elif route.get("target"):
        details.append(f"target={route['target']}")
    if route.get("authority"):
        details.append(f"authority={route['authority']}")
    if route.get("foreground"):
        details.append("foreground=true")
    if route.get("funnel"):
        details.append("funnel=true")
    return " ".join(details)


def _persisted_port(value: Any, context: str) -> str:
    port = str(value)
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f"{context} has invalid port {value!r}")
    return str(int(port))


def previous_managed_routes(previous_payload: dict[str, Any]) -> dict[str, str]:
    if "managed_routes" not in previous_payload:
        return {}
    configured = previous_payload.get("managed_routes")
    if not isinstance(configured, dict):
        raise ValueError("persisted managed_routes must be a JSON object")
    result: dict[str, str] = {}
    for raw_port, raw_scheme in configured.items():
        port = _persisted_port(raw_port, "persisted managed_routes")
        scheme = str(raw_scheme).strip().lower()
        if scheme not in set(PUBLIC_SCHEMES):
            raise ValueError(
                f"persisted managed_routes port {port} has invalid scheme {raw_scheme!r}"
            )
        result[port] = scheme
    return result


def previous_serve_routes(previous_payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if "remembered_serve_routes" in previous_payload:
        field = "remembered_serve_routes"
    elif "serve_routes" in previous_payload:
        field = "serve_routes"
    else:
        return {}
    raw = previous_payload.get(field)
    if not isinstance(raw, dict):
        raise ValueError(f"persisted {field} must be a JSON object")
    result: dict[str, dict[str, Any]] = {}
    for raw_port, route in raw.items():
        port = _persisted_port(raw_port, f"persisted {field}")
        if not isinstance(route, dict):
            raise ValueError(f"persisted {field} port {port} must contain a route object")
        target = route.get("target")
        url = route.get("url")
        if not isinstance(target, str) or not target.strip():
            raise ValueError(f"persisted {field} port {port} has no valid target")
        if not isinstance(url, str) or not url.strip():
            raise ValueError(f"persisted {field} port {port} has no valid url")
        parsed = urlparse(url)
        if parsed.scheme not in set(PUBLIC_SCHEMES) or not parsed.netloc:
            raise ValueError(f"persisted {field} port {port} has invalid url {url!r}")
        try:
            url_port = parsed.port
        except ValueError as exc:
            raise ValueError(
                f"persisted {field} port {port} has invalid url {url!r}"
            ) from exc
        if url_port != int(port):
            raise ValueError(
                f"persisted {field} port {port} url points at public port {url_port!r}"
            )
        route_scheme = route.get("public_scheme")
        if route_scheme is not None and str(route_scheme).lower() not in set(PUBLIC_SCHEMES):
            raise ValueError(
                f"persisted {field} port {port} has invalid public_scheme {route_scheme!r}"
            )
        result[port] = route
    return result


def previous_variants(previous_payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = previous_payload.get("remembered_variants")
    if not isinstance(raw, dict):
        raw = previous_payload.get("variants")
    return raw if isinstance(raw, dict) else {}


def load_existing_json(path: str) -> tuple[dict[str, Any], str | None]:
    """Load mutable state without turning corrupt JSON into an empty migration."""

    if not os.path.exists(path):
        return {}, None
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        return {}, f"cannot read existing Tailscale state {path}: {exc}"
    if not isinstance(payload, dict):
        return {}, f"existing Tailscale state {path} must contain a JSON object"
    return payload, None


def previous_allocation_policy(previous_payload: dict[str, Any]) -> dict[str, Any]:
    policy = previous_payload.get("allocation_policy")
    if policy is not None:
        if not isinstance(policy, dict):
            raise ValueError("persisted allocation_policy must be a JSON object")
        starts = policy.get("last_nonblank", policy.get("starts", {}))
        if not isinstance(starts, dict):
            raise ValueError(
                "persisted allocation_policy last_nonblank/starts must be a JSON object"
            )
        normalized_starts: dict[str, int] = {}
        for scheme, raw_start in starts.items():
            if scheme not in set(PUBLIC_SCHEMES):
                raise ValueError(
                    f"persisted allocation_policy has unknown scheme {scheme!r}"
                )
            normalized_starts[scheme] = int(
                _persisted_port(raw_start, "persisted allocation_policy")
            )
        raw_range = policy.get("range", 10)
        if not str(raw_range).isdigit() or int(raw_range) <= 0:
            raise ValueError("persisted allocation_policy range must be a positive integer")
        return {
            **policy,
            "starts": normalized_starts,
            "range": int(raw_range),
            "range_recorded": "range" in policy,
        }
    starts: dict[str, int] = {}
    for scheme in PUBLIC_SCHEMES:
        value = previous_payload.get(f"{scheme}_start")
        if str(value or "").isdigit() and int(value) > 0:
            starts[scheme] = int(value)
    spacing = previous_payload.get("range")
    return {
        "starts": starts,
        "range": int(spacing) if str(spacing or "").isdigit() else 10,
        "range_recorded": False,
    }


def recorded_live_match(
    port: str,
    public_scheme: str,
    live_route: dict[str, Any] | None,
    previous_routes: dict[str, dict[str, Any]],
) -> bool:
    recorded = previous_routes.get(port)
    if not isinstance(recorded, dict):
        return False
    target = str(recorded.get("target") or "")
    url = str(recorded.get("url") or "")
    authority = normalize_authority(url.split("://", 1)[-1])
    return bool(target and authority) and live_route_matches(
        live_route,
        public_scheme=public_scheme,
        target=target,
        authority=authority,
    )


def citadel_value(provider_dir: str, key: str, default: str = "") -> str:
    root = Path(provider_dir).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    header = importlib.import_module("python_header")
    return str(header.get(key, default)).strip()


def citadel_bool(provider_dir: str, key: str, default: str = "false") -> bool:
    return parse_bool(citadel_value(provider_dir, key, default))


def _service_logical_port(service: dict[str, Any]) -> int:
    is_host = service.get("origin") == "host"
    try:
        return int(service.get("route_port") or (0 if is_host else service.get("port", 0)))
    except (TypeError, ValueError):
        return 0


def _service_target(service: dict[str, Any], logical_port: int) -> str:
    origin_scheme = service_scheme(service)
    if service.get("origin") == "host":
        origin_host = str(service.get("origin_host") or "host.containers.internal")
        origin_port = int(service.get("origin_port") or service.get("port") or logical_port)
    else:
        origin_host = "127.0.0.1"
        origin_port = int(service.get("port") or logical_port)
    return serve_target(logical_port, origin_scheme, origin_host, origin_port)


def _route(
    domain: str,
    logical_port: int,
    public_port: int,
    public_scheme: str,
    target: str,
) -> dict[str, Any]:
    return {
        **route_record(
            "proxy",
            build_tailscale_url(domain, public_port, public_scheme),
            target=target,
            owns_listener=True,
        ),
        "logical_port": logical_port,
        "public_port": public_port,
        "public_scheme": public_scheme,
    }


def _direct_route(
    domain: str,
    logical_port: int,
    public_scheme: str,
) -> dict[str, Any]:
    return {
        **route_record(
            "direct",
            build_tailscale_url(domain, logical_port, public_scheme),
            owns_listener=False,
        ),
        "logical_port": logical_port,
        "public_port": logical_port,
        "public_scheme": public_scheme,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-dir", required=True)
    parser.add_argument("--services-file", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--config-ini", required=True)
    parser.add_argument("--routes-out", required=True)
    parser.add_argument("--tailscale-file", required=True)
    args = parser.parse_args()

    ext_cfg = read_json(f"{args.provider_dir}/extension.json", {})
    ini_cfg_path = os.path.join(args.provider_dir, "config.ini")
    ini_parser = configparser.ConfigParser()
    if os.path.exists(ini_cfg_path):
        try:
            ini_parser.read(ini_cfg_path, encoding="utf-8")
        except Exception:
            ini_parser = configparser.ConfigParser()

    def get_cfg(key: str, default: str) -> str:
        if ini_parser.has_section("provider") and ini_parser.has_option("provider", key):
            return ini_parser.get("provider", key).strip()
        return default

    services_payload = read_json(args.services_file, {})
    if not isinstance(services_payload, dict):
        services_payload = {}
    previous_payload, state_load_error = load_existing_json(args.tailscale_file)

    label = get_cfg("label", str(ext_cfg.get("label") or "Tailscale"))
    fetch_enabled = parse_bool(get_cfg("fetch", "true"))
    enabled = citadel_bool(args.provider_dir, "CITADEL_TAILSCALE")
    default_enabled = citadel_bool(
        args.provider_dir, "CITADEL_TAILSCALE_DEFAULT", "true"
    )
    if state_load_error is not None:
        print(state_load_error, file=sys.stderr)
        return 1

    validation_errors: list[str] = []
    assignment_warnings: list[str] = []
    running = False
    domain: str | None = None
    reconciliation_completed = False

    try:
        starts = {
            "http": parse_optional_start(
                citadel_value(args.provider_dir, "CITADEL_TAILSCALE_HTTP_START"),
                "CITADEL_TAILSCALE_HTTP_START",
            ),
            "https": parse_optional_start(
                citadel_value(
                    args.provider_dir, "CITADEL_TAILSCALE_HTTPS_START", "35000"
                ),
                "CITADEL_TAILSCALE_HTTPS_START",
            ),
        }
        spacing = parse_spacing(
            citadel_value(args.provider_dir, "CITADEL_TAILSCALE_RANGE", "10")
        )
    except ValueError as exc:
        starts = {"http": None, "https": None}
        spacing = 10
        validation_errors.append(str(exc))

    try:
        previous_policy = previous_allocation_policy(previous_payload)
    except ValueError as exc:
        previous_policy = {"starts": {}, "range": spacing}
        validation_errors.append(str(exc))
    previous_policy_starts = previous_policy.get("starts")
    if not isinstance(previous_policy_starts, dict):
        previous_policy_starts = {}
    historical_starts = {
        scheme: int(value)
        for scheme, value in previous_policy_starts.items()
        if scheme in set(PUBLIC_SCHEMES) and str(value).isdigit() and int(value) > 0
    }
    historical_range = previous_policy.get("range")
    historical_range = (
        int(historical_range)
        if str(historical_range or "").isdigit() and int(historical_range) > 0
        else spacing
    )

    try:
        previous_managed = previous_managed_routes(previous_payload)
    except ValueError as exc:
        previous_managed = {}
        validation_errors.append(str(exc))
    try:
        previous_serve = previous_serve_routes(previous_payload)
    except ValueError as exc:
        previous_serve = {}
        validation_errors.append(str(exc))
    for port, scheme in previous_managed.items():
        recorded = previous_serve.get(port)
        if recorded is None:
            validation_errors.append(
                f"persisted managed_routes port {port} has no matching remembered Serve route"
            )
            continue
        url_scheme = urlparse(str(recorded.get("url") or "")).scheme.lower()
        recorded_scheme = str(recorded.get("public_scheme") or url_scheme).lower()
        if recorded_scheme != scheme or url_scheme != scheme:
            validation_errors.append(
                f"persisted ownership for port {port} disagrees on public scheme "
                f"({scheme!r} vs {recorded_scheme!r})"
            )

    previous_variant_state = previous_variants(previous_payload)
    raw_previous_assignments = previous_payload.get("port_assignments")
    if not isinstance(raw_previous_assignments, dict):
        if raw_previous_assignments is not None:
            validation_errors.append("persisted port_assignments must be a JSON object")
        raw_previous_assignments = {}
    for raw_scheme in raw_previous_assignments:
        if raw_scheme not in set(PUBLIC_SCHEMES):
            validation_errors.append(
                f"persisted port_assignments has unknown scheme {raw_scheme!r}"
            )

    assignments: dict[str, dict[str, int]] = {}
    for scheme in PUBLIC_SCHEMES:
        raw = raw_previous_assignments.get(scheme)
        if isinstance(raw, dict):
            normalized: dict[str, int] = {}
            seen_ports: dict[int, str] = {}
            historical_start = historical_starts.get(scheme)
            if historical_start is None and raw:
                validation_errors.append(
                    f"{scheme.upper()}: persisted assignments have no allocation policy"
                )
            for key, value in raw.items():
                key_text = str(key)
                if not key_text.isdigit() or int(key_text) <= 0:
                    validation_errors.append(
                        f"{scheme.upper()}: invalid persisted service key {key_text!r}"
                    )
                    continue
                if not str(value).isdigit() or not 1 <= int(value) <= 65535:
                    validation_errors.append(
                        f"{scheme.upper()}: invalid persisted port {value!r} for service {key_text}"
                    )
                    continue
                port = int(value)
                other = seen_ports.get(port)
                if other is not None:
                    validation_errors.append(
                        f"{scheme.upper()}: persisted port {port} is shared by services {other} and {key_text}"
                    )
                    continue
                normalized[key_text] = port
                seen_ports[port] = key_text
            ordered = sorted(normalized, key=int)
            if any(
                normalized[left] >= normalized[right]
                for left, right in zip(ordered, ordered[1:])
            ):
                validation_errors.append(
                    f"{scheme.upper()}: persisted assignments are not ordered by logical service port"
                )
            assignments[scheme] = normalized
        else:
            if raw is not None:
                validation_errors.append(
                    f"{scheme.upper()}: persisted assignments must be a JSON object"
                )
            assignments[scheme] = {}

    if any(assignments[scheme] for scheme in PUBLIC_SCHEMES):
        if spacing != historical_range:
            validation_errors.append(
                "CITADEL_TAILSCALE_RANGE cannot change while persisted Tailscale assignments exist"
            )
        for scheme in PUBLIC_SCHEMES:
            desired_start = starts.get(scheme)
            historical_start = historical_starts.get(scheme)
            if (
                desired_start is not None
                and assignments[scheme]
                and historical_start is not None
                and desired_start != historical_start
            ):
                validation_errors.append(
                    f"CITADEL_TAILSCALE_{scheme.upper()}_START cannot change from "
                    f"{historical_start} to {desired_start} while persisted assignments exist"
                )

    effective_starts: dict[str, int | None] = {}
    for scheme in PUBLIC_SCHEMES:
        if assignments[scheme]:
            effective_starts[scheme] = historical_starts.get(scheme)
        else:
            effective_starts[scheme] = starts.get(scheme)
    effective_spacing = historical_range if any(assignments.values()) else spacing
    try:
        effective_blocks = build_scheme_blocks(effective_starts, effective_spacing)
    except (TypeError, ValueError) as exc:
        effective_blocks = {}
        validation_errors.append(str(exc))

    globally_assigned: dict[int, tuple[str, str]] = {}
    for scheme in PUBLIC_SCHEMES:
        block = effective_blocks.get(scheme)
        for logical_key, public_port in assignments[scheme].items():
            if block is None or not block.start <= public_port <= block.end:
                description = (
                    f"configured block {block.start}-{block.end}"
                    if block is not None
                    else "a configured allocation block"
                )
                validation_errors.append(
                    f"{scheme.upper()}: persisted port {public_port} for service "
                    f"{logical_key} is outside {description}"
                )
            previous_owner = globally_assigned.get(public_port)
            if previous_owner is not None:
                validation_errors.append(
                    f"persisted public port {public_port} is assigned across schemes to "
                    f"{previous_owner[0].upper()} service {previous_owner[1]} and "
                    f"{scheme.upper()} service {logical_key}"
                )
            else:
                globally_assigned[public_port] = (scheme, logical_key)

    blocks = {
        scheme: effective_blocks[scheme]
        for scheme in PUBLIC_SCHEMES
        if starts.get(scheme) is not None and scheme in effective_blocks
    }

    allocation_policy = {
        "starts": {
            scheme: starts[scheme]
            for scheme in PUBLIC_SCHEMES
            if starts.get(scheme) is not None
        },
        "last_nonblank": {
            **historical_starts,
            **{
                scheme: starts[scheme]
                for scheme in PUBLIC_SCHEMES
                if starts.get(scheme) is not None
            },
        },
        "range": spacing if not any(assignments.values()) else historical_range,
    }

    all_services = [
        service
        for service in (
            routable_services(services_payload)
            + routable_services(services_payload, "host_http_services")
        )
        if service_scheme(service) in set(PUBLIC_SCHEMES)
    ]
    services_by_key: dict[str, dict[str, Any]] = {}
    for service in all_services:
        logical_port = _service_logical_port(service)
        if logical_port <= 0:
            continue
        logical_key = str(logical_port)
        if logical_key in services_by_key:
            first = services_by_key[logical_key]
            validation_errors.append(
                f"duplicate logical service port {logical_port}: "
                f"origin={first.get('origin', 'local')} port={first.get('port')} and "
                f"origin={service.get('origin', 'local')} port={service.get('port')}"
            )
            continue
        services_by_key[logical_key] = service

    if validation_errors:
        for error in validation_errors:
            print(error, file=sys.stderr)
        return 1

    errors: list[str] = []
    previous_assignments = {
        scheme: dict(assignments[scheme]) for scheme in PUBLIC_SCHEMES
    }

    variant_routes: dict[str, dict[str, dict[str, Any]]] = {
        "default": {},
        "http": {},
        "https": {},
    }
    serve_routes: dict[str, dict[str, Any]] = {}
    managed_routes: dict[str, str] = dict(previous_managed)
    route_failures: dict[str, str] = {}
    service_signatures: dict[str, dict[str, Any]] = {}
    retained_serve: dict[str, dict[str, Any]] = {}

    live_routes: dict[str, dict[str, Any]] = {}
    local_listeners: dict[int, list[dict[str, Any]]] = {}
    tailscale_ips: set[str] = set()

    if enabled and fetch_enabled and shutil.which("tailscale"):
        status_result = run(["tailscale", "status", "--json"])
        if status_result.returncode == 0:
            try:
                status_payload = json.loads(status_result.stdout)
            except Exception:
                status_payload = {}
            running = status_payload.get("BackendState") == "Running"
            domains = status_payload.get("CertDomains") or []
            domain = (domains[0] if domains else None) or (
                status_payload.get("Self", {}).get("DNSName", "").rstrip(".") or None
            )
            tailscale_ips = {
                str(value).strip("[]").casefold()
                for value in status_payload.get("Self", {}).get("TailscaleIPs", [])
                if value
            }

        if running and domain and not errors:
            live_result = run(["tailscale", "serve", "status", "--json"])
            if live_result.returncode != 0:
                errors.append(
                    live_result.stderr.strip()
                    or live_result.stdout.strip()
                    or "tailscale serve status failed"
                )
            else:
                try:
                    live_routes = parse_live_serve_routes(json.loads(live_result.stdout))
                except Exception:
                    errors.append("could not parse tailscale serve status")

            ss_result = run(["ss", "-H", "-ltnp"])
            if ss_result.returncode != 0:
                errors.append(
                    ss_result.stderr.strip()
                    or ss_result.stdout.strip()
                    or "could not inspect local TCP listeners with ss"
                )
            else:
                local_listeners = parse_local_listeners(ss_result.stdout)

            if not errors:
                reconciliation_completed = True

    elif not enabled and previous_managed and shutil.which("tailscale"):
        status_result = run(["tailscale", "serve", "status", "--json"])
        if status_result.returncode == 0:
            try:
                live_routes = parse_live_serve_routes(json.loads(status_result.stdout))
                reconciliation_completed = True
            except Exception:
                errors.append("could not parse tailscale serve status")
        else:
            errors.append(
                status_result.stderr.strip()
                or status_result.stdout.strip()
                or "tailscale serve status failed"
            )
    elif not enabled and not previous_managed:
        reconciliation_completed = True

    desired_specs: dict[str, dict[str, Any]] = {}
    allocation_results: dict[str, AllocationResult] = {}

    if enabled and reconciliation_completed and domain and not errors:
        if default_enabled:
            for logical_key, service in sorted(
                services_by_key.items(), key=lambda item: int(item[0])
            ):
                logical_port = int(logical_key)
                public_scheme = service_scheme(service)
                target = _service_target(service, logical_port)
                live = live_routes.get(logical_key)
                if service_is_directly_reachable(
                    service, tailscale_ips, live
                ):
                    old_scheme = previous_managed.get(logical_key)
                    old_owned = bool(
                        old_scheme in set(PUBLIC_SCHEMES)
                        and recorded_live_match(
                            logical_key,
                            str(old_scheme),
                            live,
                            previous_serve,
                        )
                    )
                    if live is not None and not old_owned:
                        errors.append(
                            f"DEFAULT service {logical_key}: "
                            f"{live_listener_description(logical_port, live)} belegt "
                            "den 1:1-Port; direkte Kachel bleibt pending"
                        )
                        continue
                    variant_routes["default"][logical_key] = _direct_route(
                        domain, logical_port, public_scheme
                    )
                    globally_assigned.setdefault(
                        logical_port, ("default", logical_key)
                    )
                    continue

                existing = desired_specs.get(logical_key)
                if existing is not None:
                    errors.append(
                        f"DEFAULT service {logical_key}: public port {logical_port} "
                        "is already selected by another CITADEL route"
                    )
                    continue
                desired_specs[logical_key] = {
                    "variant": "default",
                    "logical_key": logical_key,
                    "logical_port": logical_port,
                    "public_port": logical_port,
                    "public_scheme": public_scheme,
                    "target": target,
                    "service": service,
                    "new_assignment": False,
                }
                globally_assigned.setdefault(
                    logical_port, ("default", logical_key)
                )

        for public_scheme, block in blocks.items():
            eligible_keys = [
                key
                for key, service in services_by_key.items()
                if not (public_scheme == "http" and service_scheme(service) == "https")
            ]

            def collision_lookup(
                scheme: str,
                service_key: str,
                candidate: int,
            ) -> list[str]:
                details: list[str] = []
                assigned_owner = globally_assigned.get(candidate)
                if assigned_owner is not None:
                    details.append(
                        f"stabile CITADEL-Zuordnung {assigned_owner[0].upper()} "
                        f"Dienst {assigned_owner[1]}"
                    )
                if str(candidate) in previous_managed:
                    recorded = previous_serve.get(str(candidate), {})
                    details.append(
                        f"bestehende CITADEL-Serve-Route "
                        f"{previous_managed[str(candidate)].upper()} "
                        f"target={recorded.get('target') or 'unknown'}"
                    )
                for listener in local_listeners.get(candidate, []):
                    details.append(local_listener_description(candidate, listener))
                live = live_routes.get(str(candidate))
                if live is not None:
                    details.append(live_listener_description(candidate, live))
                return details

            allocation = allocate_scheme_ports(
                eligible_keys,
                block,
                assignments.get(public_scheme, {}),
                collision_lookup,
            )
            allocation_results[public_scheme] = allocation
            assignments[public_scheme] = allocation.assignments
            assignment_warnings.extend(allocation.warnings)
            errors.extend(allocation.errors)
            for assigned_key, assigned_port in allocation.assignments.items():
                globally_assigned.setdefault(
                    assigned_port, (public_scheme, assigned_key)
                )

            for logical_key in eligible_keys:
                public_port = allocation.assignments.get(logical_key)
                if public_port is None:
                    continue
                service = services_by_key[logical_key]
                public_key = str(public_port)
                if public_key in desired_specs:
                    errors.append(
                        f"{public_scheme.upper()} service {logical_key}: public port "
                        f"{public_port} is already selected by the Default route"
                    )
                    continue
                desired_specs[public_key] = {
                    "variant": public_scheme,
                    "logical_key": logical_key,
                    "logical_port": int(logical_key),
                    "public_port": public_port,
                    "public_scheme": public_scheme,
                    "target": _service_target(service, int(logical_key)),
                    "service": service,
                    "new_assignment": logical_key in allocation.new_assignments,
                }

    allocation_failed = any(result.errors for result in allocation_results.values())
    if allocation_failed:
        assignments = {
            scheme: dict(previous_assignments[scheme]) for scheme in PUBLIC_SCHEMES
        }
        desired_specs = {}
    mutation_blocked = bool(errors) or allocation_failed

    stale_owned: list[tuple[str, str]] = []
    if reconciliation_completed and not mutation_blocked:
        for port, previous_scheme in sorted(previous_managed.items(), key=lambda item: int(item[0])):
            desired = desired_specs.get(port)
            # A desired route on the same public port may intentionally change
            # scheme (legacy HTTPS-everywhere -> detected HTTP/HTTPS Default).
            # The replacement path below owns that migration and rollback.
            if desired is not None:
                continue
            if allocation_failed and enabled:
                managed_routes[port] = previous_scheme
                if port in previous_serve:
                    retained_serve[port] = previous_serve[port]
                errors.append(
                    f"port {port}: stale-listener cleanup deferred because a new assignment interval is exhausted"
                )
                continue
            live = live_routes.get(port)
            if live is None:
                managed_routes.pop(port, None)
                continue
            if not recorded_live_match(port, previous_scheme, live, previous_serve):
                managed_routes.pop(port, None)
                errors.append(
                    f"port {port}: live listener no longer matches CITADEL state; "
                    "left untouched and released from CITADEL management"
                )
                continue
            stale_owned.append((port, previous_scheme))

    if enabled and reconciliation_completed and domain and not mutation_blocked:
        for public_port_key, spec in sorted(
            desired_specs.items(), key=lambda item: int(item[0])
        ):
            logical_key = str(spec["logical_key"])
            public_port = int(spec["public_port"])
            public_scheme = str(spec["public_scheme"])
            variant = str(spec["variant"])
            target = str(spec["target"])
            race_failure_message: str | None = None
            signature_key = f"{variant}:{logical_key}"
            service_signatures[signature_key] = {
                "variant": variant,
                "logical_port": int(logical_key),
                "origin_scheme": service_scheme(spec["service"]),
                "public_scheme": public_scheme,
                "public_port": public_port,
                "target": target,
            }

            live = live_routes.get(public_port_key)
            previous_scheme = previous_managed.get(public_port_key)
            previous_exact_owned = bool(
                previous_scheme in set(PUBLIC_SCHEMES)
                and recorded_live_match(
                    public_port_key,
                    str(previous_scheme),
                    live,
                    previous_serve,
                )
            )
            owned_live_match = (
                previous_scheme == public_scheme
                and recorded_live_match(
                    public_port_key,
                    public_scheme,
                    live,
                    previous_serve,
                )
            )
            blocking_local = [
                listener
                for listener in local_listeners.get(public_port, [])
                if (
                    not (variant == "default" and _listener_is_loopback(listener))
                    and not previous_exact_owned
                )
            ]
            if blocking_local:
                message = (
                    f"persistierter Port {public_port} ist belegt durch "
                    + "; ".join(
                        local_listener_description(public_port, listener)
                        for listener in blocking_local
                    )
                    + "; Zuordnung bleibt fest und pending"
                )
                route_failures[signature_key] = message
                errors.append(f"{public_scheme.upper()} service {logical_key}: {message}")
                if public_port_key in previous_managed:
                    managed_routes[public_port_key] = previous_managed[public_port_key]
                    if public_port_key in previous_serve:
                        retained_serve[public_port_key] = previous_serve[public_port_key]
                continue

            authority = f"{domain}:{public_port}"
            if live_route_matches(
                live,
                public_scheme=public_scheme,
                target=target,
                authority=authority,
            ):
                if not owned_live_match:
                    message = (
                        f"persistierter Port {public_port} ist belegt durch "
                        f"{live_listener_description(public_port, live)}; "
                        "Zuordnung bleibt fest und pending"
                    )
                    route_failures[signature_key] = message
                    errors.append(f"{public_scheme.upper()} service {logical_key}: {message}")
                    managed_routes.pop(public_port_key, None)
                    continue
                route = _route(domain, int(logical_key), public_port, public_scheme, target)
            elif live is not None:
                if previous_exact_owned:
                    previous_route = previous_serve.get(public_port_key, {})
                    previous_target = str(previous_route.get("target") or "")
                    previous_public_scheme = str(previous_scheme)
                    removal_error = remove_serve_route(
                        public_port, previous_public_scheme
                    )
                    if removal_error is not None:
                        message = f"could not replace existing route: {removal_error}"
                        route_failures[signature_key] = message
                        errors.append(f"{public_scheme.upper()} service {logical_key}: {message}")
                        managed_routes[public_port_key] = previous_public_scheme
                        if public_port_key in previous_serve:
                            retained_serve[public_port_key] = previous_serve[public_port_key]
                        continue
                    live_routes.pop(public_port_key, None)
                else:
                    message = (
                        f"persistierter Port {public_port} ist belegt durch "
                        f"{live_listener_description(public_port, live)}; "
                        "Zuordnung bleibt fest und pending"
                    )
                    route_failures[signature_key] = message
                    errors.append(f"{public_scheme.upper()} service {logical_key}: {message}")
                    managed_routes.pop(public_port_key, None)
                    continue

                applied = apply_serve_route(public_port, target, public_scheme)
                if applied.returncode != 0:
                    apply_message = (
                        applied.stderr.strip()
                        or applied.stdout.strip()
                        or f"Tailscale {public_scheme.upper()} Serve failed"
                    )
                    rollback = (
                        apply_serve_route(
                            public_port,
                            previous_target,
                            previous_public_scheme,
                        )
                        if previous_target
                        else None
                    )
                    if rollback is not None and rollback.returncode == 0:
                        managed_routes[public_port_key] = previous_public_scheme
                        retained_serve[public_port_key] = previous_route
                        message = (
                            f"{apply_message}; vorherige Route wurde wiederhergestellt"
                        )
                    else:
                        managed_routes.pop(public_port_key, None)
                        rollback_message = "previous route metadata is incomplete"
                        if rollback is not None:
                            rollback_message = (
                                rollback.stderr.strip()
                                or rollback.stdout.strip()
                                or "Tailscale rollback failed"
                            )
                        message = (
                            f"{apply_message}; Wiederherstellung der vorherigen Route "
                            f"fehlgeschlagen: {rollback_message}"
                        )
                    route_failures[signature_key] = message
                    errors.append(f"{public_scheme.upper()} service {logical_key}: {message}")
                    continue
                route = _route(
                    domain,
                    int(logical_key),
                    public_port,
                    public_scheme,
                    target,
                )
            else:
                applied = apply_serve_route(public_port, target, public_scheme)
                if applied.returncode != 0 and spec["new_assignment"] and serve_apply_collision(applied):
                    original_public_port = public_port
                    block = blocks[public_scheme]
                    ordered_keys = sorted(assignments[public_scheme], key=int)
                    following = [
                        key for key in ordered_keys if int(key) > int(logical_key)
                    ]
                    if following:
                        interval_end = assignments[public_scheme][following[0]] - 1
                    else:
                        grid = (public_port - block.start) // block.spacing
                        interval_end = min(
                            block.start + (grid + 1) * block.spacing - 1,
                            block.end,
                        )
                    collision_message = (
                        applied.stderr.strip()
                        or applied.stdout.strip()
                        or "Tailscale listener collision"
                    )
                    for candidate in range(public_port + 1, interval_end + 1):
                        assignment_warnings.append(
                            f"{public_scheme.upper()}: Kandidat {public_port} fuer "
                            f"Dienst {logical_key} kollidierte beim Apply "
                            f"({collision_message}); pruefe {candidate}"
                        )
                        occupied: list[str] = []
                        owner = globally_assigned.get(candidate)
                        if owner is not None:
                            occupied.append(
                                f"stabile CITADEL-Zuordnung {owner[0].upper()} "
                                f"Dienst {owner[1]}"
                            )
                        occupied.extend(
                            local_listener_description(candidate, listener)
                            for listener in local_listeners.get(candidate, [])
                        )
                        if str(candidate) in live_routes:
                            occupied.append(
                                live_listener_description(
                                    candidate, live_routes[str(candidate)]
                                )
                            )
                        if occupied:
                            public_port = candidate
                            collision_message = "; ".join(occupied)
                            continue
                        retry = apply_serve_route(candidate, target, public_scheme)
                        if retry.returncode == 0:
                            globally_assigned.pop(original_public_port, None)
                            globally_assigned[candidate] = (
                                public_scheme,
                                logical_key,
                            )
                            assignments[public_scheme][logical_key] = candidate
                            public_port = candidate
                            public_port_key = str(candidate)
                            spec["public_port"] = candidate
                            service_signatures[signature_key]["public_port"] = candidate
                            applied = retry
                            break
                        if not serve_apply_collision(retry):
                            applied = retry
                            break
                        public_port = candidate
                        collision_message = (
                            retry.stderr.strip()
                            or retry.stdout.strip()
                            or "Tailscale listener collision"
                        )
                    if applied.returncode != 0 and serve_apply_collision(applied):
                        race_failure_message = (
                            f"keine freie Portzuordnung fuer neuen Dienst {logical_key} "
                            f"nach Apply-Kollision im Intervall "
                            f"{original_public_port}-{interval_end}; letzter Kandidat "
                            f"{public_port} belegt ({collision_message})"
                        )
                if applied.returncode != 0:
                    message = (
                        race_failure_message
                        or applied.stderr.strip()
                        or applied.stdout.strip()
                        or f"Tailscale {public_scheme.upper()} Serve failed"
                    )
                    route_failures[signature_key] = message
                    errors.append(f"{public_scheme.upper()} service {logical_key}: {message}")
                    continue
                route = _route(
                    domain,
                    int(logical_key),
                    public_port,
                    public_scheme,
                    target,
                )

            variant_routes[variant][logical_key] = route
            managed_routes[public_port_key] = public_scheme
            serve_routes[public_port_key] = {
                "url": route["url"],
                "target": target,
                "logical_port": int(logical_key),
                "public_scheme": public_scheme,
                "variant": variant,
                "active": True,
            }
            urls = spec["service"].setdefault("urls", {})
            urls[f"tailscale-{variant}"] = route["url"]

    apply_failed = bool(route_failures)
    if stale_owned and not apply_failed and not mutation_blocked:
        for port, previous_scheme in stale_owned:
            removal_error = remove_serve_route(port, previous_scheme)
            if removal_error is None:
                managed_routes.pop(port, None)
                live_routes.pop(port, None)
            else:
                managed_routes[port] = previous_scheme
                if port in previous_serve:
                    retained_serve[port] = previous_serve[port]
                errors.append(f"port {port}: {removal_error}")
    elif stale_owned:
        for port, previous_scheme in stale_owned:
            managed_routes[port] = previous_scheme
            if port in previous_serve:
                retained_serve[port] = previous_serve[port]
            errors.append(
                f"port {port}: stale exact-owned listener retained because new routes are not all active"
            )

    for retained_port in retained_serve:
        for variant in VARIANT_KEYS:
            previous_variant = previous_variant_state.get(variant)
            previous_services = (
                previous_variant.get("services")
                if isinstance(previous_variant, dict)
                else None
            )
            if not isinstance(previous_services, dict):
                continue
            for logical_key, previous_route in previous_services.items():
                if not isinstance(previous_route, dict):
                    continue
                route_port = previous_route.get("public_port")
                if str(route_port or "") == retained_port:
                    variant_routes[variant].setdefault(
                        str(logical_key), previous_route
                    )

    if not reconciliation_completed or allocation_failed:
        managed_routes = dict(previous_managed)
        remembered_serve_routes = previous_serve
        remembered_variants = previous_variant_state
        for variant in VARIANT_KEYS:
            remembered_variant = previous_variant_state.get(variant)
            if isinstance(remembered_variant, dict):
                remembered_services = remembered_variant.get("services")
                if isinstance(remembered_services, dict):
                    variant_routes[variant] = {
                        str(key): route
                        for key, route in remembered_services.items()
                        if isinstance(route, dict)
                    }
        previous_failures = previous_payload.get("route_failures")
        if isinstance(previous_failures, dict):
            route_failures = {
                str(key): str(value) for key, value in previous_failures.items() if value
            }
        previous_signatures = previous_payload.get("service_signatures")
        if isinstance(previous_signatures, dict):
            service_signatures = previous_signatures
    else:
        remembered_serve_routes = {**retained_serve, **serve_routes}
        remembered_variants = {
            variant: {
                "label": VARIANT_LABELS[variant],
                "considered": (
                    default_enabled if variant == "default" else variant in blocks
                ),
                "available": bool(variant_routes[variant]),
                "services": variant_routes[variant],
            }
            for variant in VARIANT_KEYS
        }

    clear_stale_tailscale(args.cache_dir, services_payload)

    compatibility_services: dict[str, dict[str, Any]] = {}
    for logical_key in sorted(services_by_key, key=int):
        route = (
            variant_routes["default"].get(logical_key)
            or variant_routes["https"].get(logical_key)
            or variant_routes["http"].get(logical_key)
        )
        if route is not None:
            compatibility_services[logical_key] = route
            service = services_by_key[logical_key]
            urls = service.setdefault("urls", {})
            urls["tailscale"] = route["url"]
            cache_file = os.path.join(args.cache_dir, f"{service.get('port', logical_key)}.json")
            cache_payload = read_json(cache_file, {})
            if not isinstance(cache_payload, dict):
                cache_payload = {}
            for variant_name in VARIANT_KEYS:
                variant_route = variant_routes[variant_name].get(logical_key)
                if variant_route is not None:
                    urls[f"tailscale-{variant_name}"] = variant_route["url"]
                    cache_payload[f"tailscale_{variant_name}_url"] = variant_route["url"]
            cache_payload["tailscale_url"] = route["url"]
            cache_payload["tailscale_path"] = None
            write_json(cache_file, cache_payload)

    variants = {
        variant: {
            "label": VARIANT_LABELS[variant],
            "considered": bool(
                enabled
                and (
                    default_enabled
                    if variant == "default"
                    else variant in blocks
                )
            ),
            "available": bool(variant_routes[variant]),
            "services": variant_routes[variant],
        }
        for variant in VARIANT_KEYS
    }

    set_ini_value(args.config_ini, "tailscale", "true" if running else "false")
    write_json(args.services_file, services_payload)

    payload = {
        "provider_id": "tailscale",
        "label": label,
        "considered": any(variant["considered"] for variant in variants.values()),
        "available": any(variant["available"] for variant in variants.values()),
        "generated_at": now_iso(),
        "default_candidate": True,
        "enabled": enabled,
        "running": running,
        "fetch_enabled": fetch_enabled,
        "default_enabled": default_enabled,
        "route_mode": "proxy",
        "route_schema": ROUTE_SCHEMA_VERSION,
        "config_file": ini_cfg_path if os.path.exists(ini_cfg_path) else None,
        "domain": domain,
        "http_start": starts.get("http"),
        "https_start": starts.get("https"),
        "range": spacing,
        "port_blocks": {
            scheme: {"start": block.start, "end": block.end}
            for scheme, block in blocks.items()
        },
        "port_assignments": {
            scheme: dict(
                sorted(assignments.get(scheme, {}).items(), key=lambda item: int(item[0]))
            )
            for scheme in PUBLIC_SCHEMES
        },
        "allocation_policy": allocation_policy,
        "variants": variants,
        "services": compatibility_services,
        "serve_routes": serve_routes,
        "remembered_services": (
            previous_payload.get("remembered_services", previous_payload.get("services", {}))
            if not reconciliation_completed
            else compatibility_services
        ),
        "remembered_variants": remembered_variants,
        "remembered_serve_routes": remembered_serve_routes,
        "managed_ports": sorted(managed_routes, key=int),
        "managed_routes": dict(
            sorted(managed_routes.items(), key=lambda item: int(item[0]))
        ),
        "service_signatures": service_signatures,
        "route_failures": route_failures,
        "fallbacks": {},
        "assignment_warnings": assignment_warnings,
        "warnings": assignment_warnings,
        "errors": errors,
    }
    write_json(args.routes_out, payload)
    write_json(args.tailscale_file, payload)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
