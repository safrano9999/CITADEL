from __future__ import annotations

import ipaddress
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


TCP_LISTEN = "0A"


def _decode_address(raw: str, ipv6: bool) -> str:
    try:
        packed = bytes.fromhex(raw)
        if ipv6:
            # /proc/net/tcp6 stores each 32-bit word in host byte order.
            packed = b"".join(
                packed[index : index + 4][::-1]
                for index in range(0, len(packed), 4)
            )
        else:
            packed = packed[::-1]
        return str(ipaddress.ip_address(packed))
    except (ValueError, IndexError):
        return ""


def parse_proc_listeners(path: Path, *, ipv6: bool = False) -> list[dict[str, Any]]:
    listeners: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return listeners

    for line in lines:
        fields = line.split()
        if len(fields) < 4 or fields[3] != TCP_LISTEN:
            continue
        try:
            raw_address, raw_port = fields[1].rsplit(":", 1)
            port = int(raw_port, 16)
        except (ValueError, IndexError):
            continue
        if not (1 <= port <= 65535):
            continue
        address = _decode_address(raw_address, ipv6)
        row = {"port": port, "addr": address or "*", "process": None}
        if row not in listeners:
            listeners.append(row)
    return listeners


def discover_host_listeners(proc_root: Path) -> list[dict[str, Any]]:
    by_port: dict[int, dict[str, Any]] = {}
    for path, ipv6 in (
        (proc_root / "1" / "net" / "tcp", False),
        (proc_root / "1" / "net" / "tcp6", True),
    ):
        for listener in parse_proc_listeners(path, ipv6=ipv6):
            port = int(listener["port"])
            entry = by_port.setdefault(
                port,
                {
                    "port": port,
                    "addr": "host.containers.internal",
                    "addrs": [],
                    "listeners": [],
                    "process": None,
                    "service": None,
                    "origin": "host",
                    "origin_host": "host.containers.internal",
                    "origin_port": port,
                },
            )
            address = str(listener["addr"])
            if address not in entry["addrs"]:
                entry["addrs"].append(address)
            entry["listeners"].append(listener)
            try:
                entry["service"] = socket.getservbyport(port, "tcp")
            except OSError:
                pass
    return [by_port[port] for port in sorted(by_port)]


def parse_nmap_listeners(path: Path, host: str) -> list[dict[str, Any]]:
    try:
        document = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return []

    listeners: list[dict[str, Any]] = []
    for port_node in document.findall(".//port"):
        state_node = port_node.find("state")
        if state_node is None or state_node.get("state") != "open":
            continue
        try:
            port = int(port_node.get("portid") or 0)
        except ValueError:
            continue
        if not (1 <= port <= 65535):
            continue
        service_node = port_node.find("service")
        service = (
            str(service_node.get("name") or "").strip()
            if service_node is not None
            else ""
        )
        if not service or service == "unknown":
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = None
        listeners.append({
            "port": port,
            "addr": host,
            "addrs": [host],
            "listeners": [{"addr": host, "process": None}],
            "process": None,
            "service": service,
            "origin": "host",
            "origin_host": host,
            "origin_port": port,
        })
    return sorted(listeners, key=lambda item: item["port"])


def assign_host_route_ports(
    local_services: list[dict[str, Any]],
    host_services: list[dict[str, Any]],
    dedupe_start: int | None,
    previous: dict[str, int] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int], list[str]]:
    previous = previous if isinstance(previous, dict) else {}
    local_ports = {
        int(service.get("port", 0))
        for service in local_services
        if int(service.get("port", 0)) > 0
    }
    assignments: dict[str, int] = {}
    errors: list[str] = []
    next_port = dedupe_start or 0
    reserved_ports: set[int] = set()
    if dedupe_start is not None:
        for value in previous.values():
            try:
                reserved = int(value)
            except (TypeError, ValueError):
                continue
            if dedupe_start <= reserved <= 65535:
                reserved_ports.add(reserved)

    for service in sorted(host_services, key=lambda item: int(item.get("port", 0))):
        origin_port = int(service.get("origin_port") or service.get("port") or 0)
        service["origin"] = "host"
        service["origin_host"] = "host.containers.internal"
        service["origin_port"] = origin_port
        service["route_port"] = None
        if dedupe_start is None:
            continue

        key = f"host.containers.internal:{origin_port}"
        if origin_port not in local_ports:
            route_port = origin_port
        elif key in previous and str(previous[key]).isdigit() and dedupe_start <= int(previous[key]) <= 65535:
            route_port = int(previous[key])
        else:
            while next_port in reserved_ports or next_port in assignments.values():
                next_port += 1
            if next_port > 65535:
                errors.append(f"No Dedupe-Port mehr frei fuer {key}; Maximum ist 65535.")
                continue
            route_port = next_port
            next_port += 1
        service["route_port"] = route_port
        if origin_port in local_ports:
            assignments[key] = route_port

    return host_services, assignments, errors
