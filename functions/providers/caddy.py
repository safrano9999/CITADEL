#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from urllib.parse import urlparse

from common import ensure_provider_ini, ini_get, now_iso, parse_bool, read_json, write_json


def normalize_scheme(value: str) -> str:
    scheme = (value or "").strip().lower()
    return scheme if scheme in {"http", "https"} else "http"


def repo_root(provider_dir: str) -> str:
    return os.path.abspath(os.path.join(provider_dir, "..", "..", ".."))


def resolve_output_path(provider_dir: str, provider_id: str) -> str:
    return os.path.join(repo_root(provider_dir), "CADDYFILES", f"{provider_id}.caddy")


def build_entry_root(base_url: str) -> tuple[str, int, str]:
    parsed = urlparse(base_url)
    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    if scheme not in {"http", "https"}:
        scheme = "https"
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port if parsed.port else (443 if scheme == "https" else 80)

    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    authority = host if default_port else f"{host}:{port}"
    return f"{scheme}://{authority}", port, host


def normalize_prefix(value: str) -> str:
    prefix = (value or "").strip().strip("/")
    return prefix or "p"


def humanize_provider_id(provider_id: str) -> str:
    return provider_id.replace("-", " ").replace("_", " ").strip().title() or provider_id


def parse_port(value: str, fallback: int) -> int:
    try:
        port = int((value or "").strip())
        if port > 0:
            return port
    except Exception:
        pass
    return fallback


def make_path(template: str, port: int) -> str:
    path = template.replace("{port}", str(port)).strip()
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def caddy_block_for_route(
    path: str,
    port: int,
    backend_host: str,
    header_host: str,
    backend_scheme: str,
    tls_insecure_skip_verify: bool,
) -> list[str]:
    upstream = f"{backend_scheme}://{backend_host}:{port}"

    lines: list[str] = []
    lines.append(f"handle_path {path}* {{")
    lines.append(f"    reverse_proxy {upstream} {{")
    if backend_scheme == "https" and tls_insecure_skip_verify:
        lines.append("        transport http {")
        lines.append("            tls_insecure_skip_verify")
        lines.append("        }")
    lines.append(f"        header_up Host {header_host}:{port}")
    lines.append("        header_up X-Forwarded-Proto {scheme}")
    lines.append("        header_up X-Forwarded-Host {host}")
    lines.append("        header_up X-Forwarded-For {remote_host}")
    lines.append("        header_up X-Real-IP {remote_host}")
    lines.append("        header_up Connection {>Connection}")
    lines.append("        header_up Upgrade {>Upgrade}")
    lines.append("    }")
    lines.append("}")
    return lines


def write_text_file(path: str, content: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-dir", required=True)
    parser.add_argument("--routes-out", required=True)
    parser.add_argument("--services-file", required=True)
    parser.add_argument("--cache-dir")
    parser.add_argument("--config-ini")
    parser.add_argument("--tailscale-file")
    args = parser.parse_args()

    ext_cfg = read_json(f"{args.provider_dir}/extension.json", {})
    provider_instance_id = os.path.basename(os.path.abspath(args.provider_dir))
    services_payload = read_json(args.services_file, {})

    parser_ini, ini_path, created_ini = ensure_provider_ini(
        args.provider_dir,
        {
            "citadel_host": "127.0.0.1",
        },
    )

    label = ini_get(parser_ini, "label", "") or humanize_provider_id(provider_instance_id)
    citadel_scheme = normalize_scheme(ini_get(parser_ini, "citadel_scheme", "https"))
    citadel_host = ini_get(parser_ini, "citadel_host", "127.0.0.1") or "127.0.0.1"
    citadel_port = parse_port(ini_get(parser_ini, "citadel_port", "446"), 446)
    path_prefix = normalize_prefix(ini_get(parser_ini, "path_prefix", "p"))
    path_template_override = ini_get(parser_ini, "path_template", "")
    path_template = f"/{path_prefix}/{{port}}"
    if path_template_override and "{port}" in path_template_override:
        path_template = path_template_override

    base_url = f"{citadel_scheme}://{citadel_host}:{citadel_port}"
    backend_host = ini_get(parser_ini, "backend_host", "") or "host.containers.internal"
    header_host = citadel_host
    write_generated_file = parse_bool(ini_get(parser_ini, "write_generated_file", "true"))
    tls_insecure_skip_verify = parse_bool(ini_get(parser_ini, "tls_insecure_skip_verify", "true"))
    output_file = resolve_output_path(args.provider_dir, provider_instance_id)

    routes: dict[str, str] = {}
    errors: list[str] = []
    caddy_lines: list[str] = []

    payload = {
        "provider_id": provider_instance_id,
        "provider_instance_id": provider_instance_id,
        "label": label,
        "considered": True,
        "available": False,
        "generated_at": now_iso(),
        "default_candidate": False,
        "base_url": base_url,
        "citadel_scheme": citadel_scheme,
        "citadel_host": citadel_host,
        "citadel_port": citadel_port,
        "path_prefix": path_prefix,
        "path_template": path_template,
        "config_file": ini_path,
        "generated_file": output_file if write_generated_file else None,
        "services": routes,
        "errors": errors,
    }

    if created_ini:
        errors.append(f"created {ini_path}; review config.ini")

    if "{port}" not in path_template:
        errors.append("path_template must contain '{port}'")
        write_json(args.routes_out, payload)
        return 0

    entry_root, entry_port, _entry_host = build_entry_root(base_url)
    http_services = services_payload.get("http_services", []) if isinstance(services_payload, dict) else []

    caddy_lines.append("# Auto-generated by CITADEL caddy provider. Do not edit manually.")
    caddy_lines.append(f"# generated_at={now_iso()}")
    caddy_lines.append(f"# entry_base={entry_root}")
    caddy_lines.append(f"# provider={provider_instance_id}")
    caddy_lines.append("")

    for svc in http_services:
        port = int(svc.get("port", 0))
        if port <= 0:
            continue
        if port == entry_port:
            errors.append(f"skip port {port}: would loop into caddy entrypoint")
            continue

        backend_scheme = normalize_scheme(str(svc.get("scheme") or "http"))
        path = make_path(path_template, port)
        route_url = f"{entry_root}{path}"

        routes[str(port)] = route_url
        urls = svc.get("urls")
        if not isinstance(urls, dict):
            urls = {}
            svc["urls"] = urls
        urls["caddy"] = route_url

        caddy_lines.extend(
            caddy_block_for_route(
                path=path,
                port=port,
                backend_host=backend_host,
                header_host=header_host,
                backend_scheme=backend_scheme,
                tls_insecure_skip_verify=tls_insecure_skip_verify,
            )
        )
        caddy_lines.append("")

    write_json(args.services_file, services_payload)

    if not routes:
        caddy_lines.append("# No caddy routes generated from current services.json.")

    if write_generated_file:
        try:
            write_text_file(output_file, "\n".join(caddy_lines).rstrip() + "\n")
        except Exception as exc:
            errors.append(f"failed writing generated file: {exc}")

    payload["available"] = bool(routes)
    write_json(args.routes_out, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
