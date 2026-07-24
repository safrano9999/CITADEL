#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import importlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from common import (
    ROUTE_SCHEMA_VERSION,
    WILDCARD_ADDRESSES,
    now_iso,
    normalize_address,
    parse_bool,
    read_json,
    route_record,
    run,
    service_addresses,
    set_ini_value,
    write_json,
)


def clear_stale_tailscale(cache_dir: str, services_payload: dict) -> None:
    if os.path.isdir(cache_dir):
        for name in os.listdir(cache_dir):
            if not name.endswith(".json"):
                continue
            path = os.path.join(cache_dir, name)
            payload = read_json(path, {})
            if not isinstance(payload, dict):
                payload = {}
            payload.pop("tailscale_url", None)
            payload.pop("tailscale_path", None)
            write_json(path, payload)

    for svc in services_payload.get("http_services", []):
        urls = svc.get("urls")
        if not isinstance(urls, dict):
            urls = {}
            svc["urls"] = urls
        urls.pop("tailscale", None)


def build_tailscale_url(domain: str, port: int, scheme: str) -> str:
    return f"{scheme}://{domain}:{port}"


def serve_target(port: int, scheme: str) -> str:
    protocol = "https+insecure" if scheme == "https" else "http"
    return f"{protocol}://127.0.0.1:{port}"


def remove_serve_route(port: str | int, public_scheme: str = "https") -> str | None:
    if public_scheme not in {"http", "https"}:
        return f"unsupported Tailscale Serve scheme '{public_scheme}'"
    removed = run(["tailscale", "serve", "--yes", f"--{public_scheme}={port}", "off"])
    message = f"{removed.stderr}\n{removed.stdout}".strip()
    if removed.returncode == 0 or "handler does not exist" in message.lower():
        return None
    return message or "tailscale serve removal failed"


def apply_serve_route(
    port: int,
    target: str,
    public_scheme: str,
):
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


def resolve_route_mode(
    configured_mode: str,
    service: dict[str, Any],
    tailscale_ips: set[str],
) -> str:
    if configured_mode in {"direct", "proxy"}:
        return configured_mode
    if configured_mode != "auto":
        raise ValueError(f"unsupported route_mode '{configured_mode}'")

    addresses = service_addresses(service)
    if any(address in WILDCARD_ADDRESSES for address in addresses):
        return "direct"
    if any(normalize_address(address) in tailscale_ips for address in addresses):
        return "direct"
    return "proxy"


def service_scheme(service: dict[str, Any]) -> str:
    scheme = str(service.get("scheme") or "http").strip().lower()
    return scheme if scheme in {"http", "https"} else "http"


def route_public_scheme(route: dict[str, Any]) -> str | None:
    url = str(route.get("url") or "").strip()
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https"}:
        return parsed.scheme
    return None


def parse_live_serve_routes(payload: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        return {}

    result: dict[str, dict[str, Any]] = {}
    tcp = payload.get("TCP")
    if isinstance(tcp, dict):
        for port, listener in tcp.items():
            port_key = str(port)
            if not port_key.isdigit() or not isinstance(listener, dict):
                continue
            if listener.get("HTTPS") is True:
                public_scheme = "https"
            elif listener.get("HTTP") is True or listener.get("HTTPS") is False:
                public_scheme = "http"
            else:
                public_scheme = None
            result[port_key] = {
                "public_scheme": public_scheme,
                "target": None,
                "exclusive_root_proxy": False,
            }

    web = payload.get("Web")
    if not isinstance(web, dict):
        return result

    for authority, web_config in web.items():
        if not isinstance(web_config, dict):
            continue
        authority_text = str(authority)
        if ":" not in authority_text:
            continue
        port_key = authority_text.rsplit(":", 1)[-1]
        if not port_key.isdigit():
            continue
        handlers = web_config.get("Handlers")
        if not isinstance(handlers, dict):
            continue
        root_handler = handlers.get("/")
        target = root_handler.get("Proxy") if isinstance(root_handler, dict) else None
        entry = result.setdefault(
            port_key,
            {
                "public_scheme": None,
                "target": None,
                "exclusive_root_proxy": False,
            },
        )
        entry["target"] = str(target) if target else None
        entry["exclusive_root_proxy"] = bool(target) and set(handlers) == {"/"}
    return result


def live_route_matches(
    live_route: dict[str, Any] | None,
    *,
    public_scheme: str,
    target: str,
) -> bool:
    if not isinstance(live_route, dict):
        return False
    return (
        live_route.get("public_scheme") == public_scheme
        and live_route.get("target") == target
        and live_route.get("exclusive_root_proxy") is True
    )


def service_signature(
    service: dict[str, Any],
    configured_mode: str,
    tailscale_ips: set[str],
) -> dict[str, Any]:
    if configured_mode not in {"auto", "direct", "proxy"}:
        raise ValueError(f"unsupported route_mode '{configured_mode}'")
    return {
        "origin_scheme": service_scheme(service),
        "direct_capable": resolve_route_mode("auto", service, tailscale_ips) == "direct",
        "route_mode": configured_mode,
    }


def previous_managed_routes(previous_payload: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    configured = previous_payload.get("managed_routes")
    if isinstance(configured, dict):
        for port, scheme in configured.items():
            port_key = str(port)
            public_scheme = str(scheme).strip().lower()
            if port_key.isdigit() and public_scheme in {"http", "https"}:
                result[port_key] = public_scheme

    previous_services = previous_payload.get("remembered_services")
    if not isinstance(previous_services, dict):
        previous_services = previous_payload.get("services")
    if not isinstance(previous_services, dict):
        previous_services = {}
    previous_serve_routes = previous_payload.get("remembered_serve_routes")
    if not isinstance(previous_serve_routes, dict):
        previous_serve_routes = previous_payload.get("serve_routes")
    if not isinstance(previous_serve_routes, dict):
        previous_serve_routes = {}

    for port in previous_payload.get("managed_ports", []):
        port_key = str(port)
        if not port_key.isdigit() or port_key in result:
            continue
        route = previous_services.get(port_key)
        if isinstance(route, dict):
            result[port_key] = route_public_scheme(route) or "https"
            continue
        serve_route = previous_serve_routes.get(port_key)
        if isinstance(serve_route, dict):
            url = str(serve_route.get("url") or "")
            parsed_scheme = urlparse(url).scheme
            result[port_key] = (
                parsed_scheme if parsed_scheme in {"http", "https"} else "https"
            )
            continue
        result[port_key] = "https"
    return result


def normalize_previous_route(
    value: Any,
    port_key: str,
    previous_serve_routes: dict[str, Any],
    managed_routes: dict[str, str],
) -> dict[str, Any] | None:
    if isinstance(value, dict):
        mode = str(value.get("mode") or "").strip().lower()
        url = str(value.get("url") or "").strip()
        target = value.get("target")
        owns_listener = bool(value.get("owns_listener", False))
        if mode not in {"direct", "proxy"} or route_public_scheme({"url": url}) is None:
            return None
        if owns_listener and port_key not in managed_routes:
            return None
        if owns_listener:
            serve_route = previous_serve_routes.get(port_key)
            if isinstance(serve_route, dict):
                if serve_route.get("active") is False:
                    return None
                serve_url = str(serve_route.get("url") or "")
                serve_target_value = serve_route.get("target")
                if (
                    route_public_scheme({"url": serve_url})
                    != route_public_scheme({"url": url})
                    or (
                        serve_target_value is not None
                        and str(serve_target_value) != str(target)
                    )
                ):
                    return None
        return route_record(
            mode,
            url,
            target=str(target) if target is not None else None,
            owns_listener=owns_listener,
        )

    if not isinstance(value, str) or route_public_scheme({"url": value}) is None:
        return None

    serve_route = previous_serve_routes.get(port_key)
    target = serve_route.get("target") if isinstance(serve_route, dict) else None
    owns_listener = port_key in managed_routes
    return route_record(
        "proxy" if owns_listener else "direct",
        value,
        target=str(target) if target is not None else None,
        owns_listener=owns_listener,
    )


def reusable_route(
    route: dict[str, Any],
    *,
    port: int,
    domain: str,
    signature: dict[str, Any],
    managed_routes: dict[str, str],
) -> dict[str, Any] | None:
    public_scheme = route_public_scheme(route)
    if public_scheme is None:
        return None

    port_key = str(port)
    mode = str(route.get("mode") or "")
    owns_listener = bool(route.get("owns_listener", False))
    origin_scheme = str(signature.get("origin_scheme") or "http")
    direct_capable = bool(signature.get("direct_capable", False))

    if owns_listener:
        if mode != "proxy" or port_key not in managed_routes:
            return None
        if managed_routes.get(port_key) != public_scheme:
            return None
        if str(route.get("target") or "") != serve_target(port, origin_scheme):
            return None
    elif mode != "direct" or not direct_capable or public_scheme != origin_scheme:
        return None

    return route_record(
        mode,
        build_tailscale_url(domain, port, public_scheme),
        target=str(route.get("target")) if route.get("target") is not None else None,
        owns_listener=owns_listener,
    )


def citadel_bool(provider_dir: str, key: str, default: str = "false") -> bool:
    root = Path(provider_dir).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    header = importlib.import_module("python_header")
    return header.get_bool(key, parse_bool(default))


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
    previous_payload = read_json(args.tailscale_file, {})
    if not isinstance(previous_payload, dict):
        previous_payload = {}

    label = get_cfg("label", str(ext_cfg.get("label") or "Tailscale"))
    fetch_enabled = parse_bool(get_cfg("fetch", "true"))
    route_mode = get_cfg("route_mode", "auto").lower()
    errors: list[str] = []
    enabled = citadel_bool(args.provider_dir, "CITADEL_TAILSCALE")

    running = False

    clear_stale_tailscale(args.cache_dir, services_payload)

    routes: dict[str, dict[str, Any]] = {}
    serve_routes: dict[str, dict[str, object]] = {}
    previous_services = previous_payload.get("remembered_services")
    if not isinstance(previous_services, dict):
        previous_services = previous_payload.get("services")
    if not isinstance(previous_services, dict):
        previous_services = {}
    previous_serve_routes = previous_payload.get("remembered_serve_routes")
    if not isinstance(previous_serve_routes, dict):
        previous_serve_routes = previous_payload.get("serve_routes")
    if not isinstance(previous_serve_routes, dict):
        previous_serve_routes = {}
    previous_signatures = previous_payload.get("service_signatures")
    if not isinstance(previous_signatures, dict):
        previous_signatures = {}
    previous_failures = previous_payload.get("route_failures")
    if not isinstance(previous_failures, dict):
        previous_failures = {}
    previous_fallbacks = previous_payload.get("fallbacks")
    if not isinstance(previous_fallbacks, dict):
        previous_fallbacks = {}

    managed_routes = previous_managed_routes(previous_payload)
    previous_managed_routes_state = dict(managed_routes)
    desired_managed_ports: set[str] = set()
    service_signatures: dict[str, dict[str, Any]] = {}
    route_failures: dict[str, str] = {}
    fallbacks: dict[str, dict[str, str]] = {}
    retained_services: dict[str, Any] = {}
    retained_serve_routes: dict[str, Any] = {}
    reconciliation_completed = False
    live_routes_loaded = False
    live_routes: dict[str, dict[str, Any]] = {}
    live_routes_error: str | None = None
    domain = None

    def store_route(
        service: dict[str, Any],
        port: int,
        route: dict[str, Any],
        signature: dict[str, Any],
    ) -> None:
        port_key = str(port)
        route_url = str(route["url"])
        routes[port_key] = route
        service_signatures[port_key] = signature

        if bool(route.get("owns_listener", False)):
            public_scheme = route_public_scheme(route)
            if public_scheme is not None:
                desired_managed_ports.add(port_key)
                managed_routes[port_key] = public_scheme
                serve_routes[port_key] = {
                    "url": route_url,
                    "target": route.get("target"),
                    "active": True,
                }

        urls = service.get("urls")
        if not isinstance(urls, dict):
            urls = {}
            service["urls"] = urls
        urls["tailscale"] = route_url

        cache_file = os.path.join(args.cache_dir, f"{port}.json")
        cache_payload = read_json(cache_file, {})
        if not isinstance(cache_payload, dict):
            cache_payload = {}
        cache_payload["tailscale_url"] = route_url
        cache_payload["tailscale_path"] = None
        write_json(cache_file, cache_payload)

    def get_live_routes() -> tuple[dict[str, dict[str, Any]], str | None]:
        nonlocal live_routes_loaded, live_routes, live_routes_error
        if live_routes_loaded:
            return live_routes, live_routes_error

        live_routes_loaded = True
        result = run(["tailscale", "serve", "status", "--json"])
        if result.returncode != 0:
            live_routes_error = (
                result.stderr.strip()
                or result.stdout.strip()
                or "tailscale serve status failed"
            )
            return live_routes, live_routes_error
        try:
            live_routes = parse_live_serve_routes(json.loads(result.stdout))
        except Exception:
            live_routes_error = "could not parse tailscale serve status"
        return live_routes, live_routes_error

    def recorded_target(port_key: str) -> str | None:
        serve_route = previous_serve_routes.get(port_key)
        if isinstance(serve_route, dict) and serve_route.get("target") is not None:
            return str(serve_route["target"])
        previous_route = normalize_previous_route(
            previous_services.get(port_key),
            port_key,
            previous_serve_routes,
            previous_managed_routes_state,
        )
        if previous_route is not None and previous_route.get("target") is not None:
            return str(previous_route["target"])
        return None

    def retain_previous_route_state(port_key: str) -> None:
        if port_key in previous_services:
            retained_services[port_key] = previous_services[port_key]
        if port_key in previous_serve_routes:
            retained_serve_routes[port_key] = previous_serve_routes[port_key]
        previous_signature = previous_signatures.get(port_key)
        if isinstance(previous_signature, dict):
            service_signatures.setdefault(port_key, previous_signature)
        previous_failure = previous_failures.get(port_key)
        if previous_failure:
            route_failures.setdefault(port_key, str(previous_failure))
        previous_fallback = previous_fallbacks.get(port_key)
        if isinstance(previous_fallback, dict):
            fallbacks.setdefault(
                port_key,
                {
                    str(key): str(value)
                    for key, value in previous_fallback.items()
                },
            )
        previous_public_scheme = previous_managed_routes_state.get(port_key)
        if previous_public_scheme is not None:
            managed_routes[port_key] = previous_public_scheme
            desired_managed_ports.add(port_key)

    def mark_pending(
        port: str | int,
        signature: dict[str, Any],
        message: str,
        *,
        retain_previous: bool = False,
    ) -> None:
        port_key = str(port)
        service_signatures[port_key] = {
            **signature,
            "pending_reconciliation": True,
        }
        route_failures[port_key] = message
        if retain_previous:
            retain_previous_route_state(port_key)
        errors.append(f"port {port_key}: {message}")

    if not enabled:
        if managed_routes and not shutil.which("tailscale"):
            for port in sorted(managed_routes, key=int):
                retain_previous_route_state(port)
                errors.append(
                    f"port {port}: cannot remove managed listener: "
                    "tailscale CLI is unavailable"
                )
        elif managed_routes:
            sorted_routes = sorted(
                managed_routes.items(),
                key=lambda item: int(item[0]),
            )
            current_live_routes, status_error = get_live_routes()
            for port, public_scheme in sorted_routes:
                if status_error is not None:
                    retain_previous_route_state(port)
                    errors.append(
                        f"port {port}: cannot verify managed listener: {status_error}"
                    )
                    continue

                live_route = current_live_routes.get(port)
                target = recorded_target(port)
                if live_route is None:
                    managed_routes.pop(port, None)
                    continue
                if target is None or not live_route_matches(
                    live_route,
                    public_scheme=public_scheme,
                    target=target,
                ):
                    managed_routes.pop(port, None)
                    errors.append(
                        f"port {port}: live listener no longer matches CITADEL state; "
                        "left untouched and released from CITADEL management"
                    )
                    continue

                removal_error = remove_serve_route(port, public_scheme)
                if removal_error is None:
                    managed_routes.pop(port, None)
                    current_live_routes.pop(port, None)
                    continue

                retain_previous_route_state(port)
                errors.append(f"port {port}: {removal_error}")
        write_json(args.services_file, services_payload)
        reconciliation_completed = True
    elif fetch_enabled and shutil.which("tailscale"):
        status_json = run(["tailscale", "status", "--json"])
        running = status_json.returncode == 0
        if running:
            status_payload: dict[str, Any] = {}
            try:
                status_payload = json.loads(status_json.stdout)
            except Exception:
                status_payload = {}

            running = status_payload.get("BackendState") == "Running"
            tailscale_ips = {
                normalize_address(value)
                for value in status_payload.get("Self", {}).get("TailscaleIPs", [])
                if normalize_address(value)
            }
            domains = status_payload.get("CertDomains") or []
            domain = (domains[0] if domains else None) or (
                status_payload.get("Self", {}).get("DNSName", "").rstrip(".") or None
            )
            valid_route_mode = route_mode in {"auto", "direct", "proxy"}
            if not valid_route_mode:
                errors.append(f"unsupported route_mode '{route_mode}'")
            if running and domain and valid_route_mode:
                reconciliation_completed = True
                for svc in services_payload.get("http_services", []):
                    port = int(svc.get("port", 0))
                    if port <= 0:
                        continue
                    port_key = str(port)

                    try:
                        signature = service_signature(svc, route_mode, tailscale_ips)
                    except ValueError as exc:
                        errors.append(str(exc))
                        continue
                    origin_scheme = str(signature["origin_scheme"])
                    direct_capable = bool(signature["direct_capable"])

                    previous_route = normalize_previous_route(
                        previous_services.get(port_key),
                        port_key,
                        previous_serve_routes,
                        previous_managed_routes_state,
                    )
                    previous_signature = previous_signatures.get(port_key)
                    signature_matches = (
                        isinstance(previous_signature, dict)
                        and previous_signature == signature
                    )
                    legacy_route = (
                        route_mode == "auto"
                        and previous_signature is None
                        and previous_route is not None
                    )

                    if signature_matches or legacy_route:
                        if previous_route is not None:
                            reused = reusable_route(
                                previous_route,
                                port=port,
                                domain=domain,
                                signature=signature,
                                managed_routes=previous_managed_routes_state,
                            )
                            if reused is not None:
                                store_route(svc, port, reused, signature)
                                previous_fallback = previous_fallbacks.get(port_key)
                                if isinstance(previous_fallback, dict):
                                    fallbacks[port_key] = {
                                        str(key): str(value)
                                        for key, value in previous_fallback.items()
                                    }
                                    reason = str(previous_fallback.get("reason") or "")
                                    if reason:
                                        errors.append(f"port {port}: {reason}")
                                continue

                        previous_failure = previous_failures.get(port_key)
                        if signature_matches and previous_failure:
                            message = str(previous_failure)
                            service_signatures[port_key] = signature
                            route_failures[port_key] = message
                            errors.append(f"port {port}: {message}")
                            continue

                    previous_public_scheme = previous_managed_routes_state.get(port_key)
                    if (
                        route_mode == "direct"
                        and not direct_capable
                        and previous_public_scheme is None
                    ):
                        message = "direct route requested, but the service is loopback-only"
                        service_signatures[port_key] = signature
                        route_failures[port_key] = message
                        errors.append(f"port {port}: {message}")
                        continue

                    current_live_routes, status_error = get_live_routes()
                    if status_error is not None:
                        mark_pending(
                            port,
                            signature,
                            f"cannot verify Tailscale listeners: {status_error}",
                            retain_previous=previous_public_scheme is not None,
                        )
                        continue

                    live_route = current_live_routes.get(port_key)
                    if previous_public_scheme is not None:
                        previous_target = recorded_target(port_key)
                        if live_route is None:
                            managed_routes.pop(port_key, None)
                        elif previous_target is None or not live_route_matches(
                            live_route,
                            public_scheme=previous_public_scheme,
                            target=previous_target,
                        ):
                            managed_routes.pop(port_key, None)
                            mark_pending(
                                port,
                                signature,
                                "live listener no longer matches CITADEL state; "
                                "left untouched and released from CITADEL management",
                            )
                            continue
                        else:
                            removal_error = remove_serve_route(
                                port,
                                previous_public_scheme,
                            )
                            if removal_error is not None:
                                mark_pending(
                                    port,
                                    signature,
                                    "could not replace existing route: "
                                    f"{removal_error}",
                                    retain_previous=True,
                                )
                                continue
                            managed_routes.pop(port_key, None)
                            current_live_routes.pop(port_key, None)
                    elif live_route is not None:
                        mark_pending(
                            port,
                            signature,
                            "port already has a Tailscale Serve listener not managed "
                            "by CITADEL; left untouched",
                        )
                        continue

                    if route_mode == "direct":
                        if not direct_capable:
                            message = "direct route requested, but the service is loopback-only"
                            service_signatures[port_key] = signature
                            route_failures[port_key] = message
                            errors.append(f"port {port}: {message}")
                            continue
                        store_route(
                            svc,
                            port,
                            route_record(
                                "direct",
                                build_tailscale_url(domain, port, origin_scheme),
                                target=None,
                                owns_listener=False,
                            ),
                            signature,
                        )
                        continue

                    target = serve_target(port, origin_scheme)
                    https_result = apply_serve_route(port, target, "https")
                    if https_result.returncode == 0:
                        store_route(
                            svc,
                            port,
                            route_record(
                                "proxy",
                                build_tailscale_url(domain, port, "https"),
                                target=target,
                                owns_listener=True,
                            ),
                            signature,
                        )
                        continue

                    https_error = (
                        https_result.stderr.strip()
                        or https_result.stdout.strip()
                        or "Tailscale HTTPS Serve failed"
                    )
                    http_result = apply_serve_route(port, target, "http")
                    if http_result.returncode == 0:
                        reason = f"HTTPS unavailable; using HTTP ({https_error})"
                        fallbacks[port_key] = {
                            "from": "https",
                            "to": "http",
                            "reason": reason,
                        }
                        errors.append(f"port {port}: {reason}")
                        store_route(
                            svc,
                            port,
                            route_record(
                                "proxy",
                                build_tailscale_url(domain, port, "http"),
                                target=target,
                                owns_listener=True,
                            ),
                            signature,
                        )
                        continue

                    http_error = (
                        http_result.stderr.strip()
                        or http_result.stdout.strip()
                        or "Tailscale HTTP Serve failed"
                    )
                    if route_mode == "auto" and direct_capable:
                        reason = (
                            "Tailscale Serve unavailable; using direct "
                            f"{origin_scheme.upper()} "
                            f"(HTTPS: {https_error}; HTTP: {http_error})"
                        )
                        fallbacks[port_key] = {
                            "from": "serve",
                            "to": f"direct-{origin_scheme}",
                            "reason": reason,
                        }
                        errors.append(f"port {port}: {reason}")
                        store_route(
                            svc,
                            port,
                            route_record(
                                "direct",
                                build_tailscale_url(domain, port, origin_scheme),
                                target=None,
                                owns_listener=False,
                            ),
                            signature,
                        )
                        continue

                    message = (
                        "could not create a Tailscale route "
                        f"(HTTPS: {https_error}; HTTP: {http_error})"
                    )
                    service_signatures[port_key] = signature
                    route_failures[port_key] = message
                    errors.append(f"port {port}: {message}")

                stale_ports = set(managed_routes) - desired_managed_ports
                for stale_port in sorted(stale_ports, key=int):
                    public_scheme = managed_routes[stale_port]
                    current_live_routes, status_error = get_live_routes()
                    if status_error is not None:
                        retain_previous_route_state(stale_port)
                        errors.append(
                            f"port {stale_port}: cannot verify stale listener: "
                            f"{status_error}"
                        )
                        continue

                    live_route = current_live_routes.get(stale_port)
                    previous_target = recorded_target(stale_port)
                    if live_route is None:
                        managed_routes.pop(stale_port, None)
                        continue
                    if previous_target is None or not live_route_matches(
                        live_route,
                        public_scheme=public_scheme,
                        target=previous_target,
                    ):
                        managed_routes.pop(stale_port, None)
                        errors.append(
                            f"port {stale_port}: stale live listener no longer "
                            "matches CITADEL state; left untouched and released "
                            "from CITADEL management"
                        )
                        continue

                    removal_error = remove_serve_route(stale_port, public_scheme)
                    if removal_error is None:
                        managed_routes.pop(stale_port, None)
                        current_live_routes.pop(stale_port, None)
                        continue

                    retain_previous_route_state(stale_port)
                    errors.append(f"port {stale_port}: {removal_error}")

    if enabled and not reconciliation_completed:
        service_signatures = {
            str(port): value
            for port, value in previous_signatures.items()
            if isinstance(value, dict)
        }
        route_failures = {
            str(port): str(value)
            for port, value in previous_failures.items()
            if value
        }
        fallbacks = {
            str(port): {
                str(key): str(value)
                for key, value in fallback.items()
            }
            for port, fallback in previous_fallbacks.items()
            if isinstance(fallback, dict)
        }
        remembered_services = previous_services
        remembered_serve_routes = previous_serve_routes
    else:
        remembered_services = {**retained_services, **routes}
        remembered_serve_routes = {**retained_serve_routes, **serve_routes}

    set_ini_value(args.config_ini, "tailscale", "true" if running else "false")
    write_json(args.services_file, services_payload)

    payload = {
        "provider_id": "tailscale",
        "label": label,
        "considered": bool(routes),
        "available": bool(routes),
        "generated_at": now_iso(),
        "default_candidate": True,
        "enabled": enabled,
        "running": running,
        "fetch_enabled": fetch_enabled,
        "route_mode": route_mode,
        "route_schema": ROUTE_SCHEMA_VERSION,
        "config_file": ini_cfg_path if os.path.exists(ini_cfg_path) else None,
        "domain": domain,
        "services": routes,
        "serve_routes": serve_routes,
        "remembered_services": remembered_services,
        "remembered_serve_routes": remembered_serve_routes,
        "managed_ports": sorted(managed_routes, key=int),
        "managed_routes": dict(sorted(managed_routes.items(), key=lambda item: int(item[0]))),
        "service_signatures": service_signatures,
        "route_failures": route_failures,
        "fallbacks": fallbacks,
        "errors": errors,
    }

    write_json(args.routes_out, payload)
    write_json(args.tailscale_file, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
