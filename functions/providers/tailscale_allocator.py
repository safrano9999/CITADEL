from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any


PUBLIC_SCHEMES = ("http", "https")
MAX_PORT = 65535


@dataclass(frozen=True)
class SchemeBlock:
    scheme: str
    start: int
    end: int
    spacing: int


@dataclass
class AllocationResult:
    assignments: dict[str, int]
    new_assignments: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


CollisionLookup = Callable[[str, str, int], Iterable[str]]


def parse_optional_start(value: Any, name: str) -> int | None:
    raw = str(value or "").strip()
    if not raw or raw.casefold() == "blank" or raw == "0":
        return None
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be blank, 0, or a port between 1 and 65535") from exc
    if not 1 <= port <= MAX_PORT:
        raise ValueError(f"{name} must be blank, 0, or a port between 1 and 65535")
    return port


def parse_spacing(value: Any, name: str = "CITADEL_TAILSCALE_RANGE") -> int:
    raw = str(value or "").strip()
    if not raw or raw.casefold() == "blank":
        return 10
    try:
        spacing = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if spacing <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return spacing


def build_scheme_blocks(
    starts: Mapping[str, int | None],
    spacing: int,
) -> dict[str, SchemeBlock]:
    enabled: list[tuple[int, str]] = []
    for scheme in PUBLIC_SCHEMES:
        start = starts.get(scheme)
        if start is not None:
            enabled.append((int(start), scheme))
    enabled.sort()

    if len({start for start, _scheme in enabled}) != len(enabled):
        raise ValueError("enabled Tailscale HTTP and HTTPS port blocks must have different starts")

    blocks: dict[str, SchemeBlock] = {}
    for index, (start, scheme) in enumerate(enabled):
        end = enabled[index + 1][0] - 1 if index + 1 < len(enabled) else MAX_PORT
        if start + spacing - 1 > end:
            raise ValueError(
                f"Tailscale {scheme.upper()} block {start}-{end} is smaller than "
                f"CITADEL_TAILSCALE_RANGE={spacing}"
            )
        blocks[scheme] = SchemeBlock(scheme, start, end, spacing)
    return blocks


def normalize_previous_assignments(
    value: Any,
    block: SchemeBlock,
) -> tuple[dict[str, int], list[str]]:
    if not isinstance(value, dict):
        return {}, []

    assignments: dict[str, int] = {}
    errors: list[str] = []
    assigned_ports: dict[int, str] = {}
    for raw_key, raw_port in sorted(
        value.items(),
        key=lambda item: int(str(item[0])) if str(item[0]).isdigit() else MAX_PORT + 1,
    ):
        key = str(raw_key)
        if not key.isdigit() or int(key) <= 0:
            errors.append(
                f"{block.scheme.upper()}: invalid persisted service key {key!r}; assignment retained only in source state"
            )
            continue
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            errors.append(
                f"{block.scheme.upper()}: invalid persisted assignment for service {key}: {raw_port!r}"
            )
            continue
        if not block.start <= port <= block.end:
            errors.append(
                f"{block.scheme.upper()}: persisted assignment {port} for service {key} "
                f"is outside configured block {block.start}-{block.end}"
            )
            continue
        other = assigned_ports.get(port)
        if other is not None:
            errors.append(
                f"{block.scheme.upper()}: persisted assignment {port} is shared by services {other} and {key}"
            )
            continue
        assignments[key] = port
        assigned_ports[port] = key

    ordered = sorted(assignments, key=int)
    for left, right in zip(ordered, ordered[1:]):
        if assignments[left] >= assignments[right]:
            errors.append(
                f"{block.scheme.upper()}: persisted assignments are not ordered: "
                f"service {left} uses {assignments[left]}, service {right} uses {assignments[right]}"
            )
    return assignments, errors


def _collision_warning(
    scheme: str,
    service_key: str,
    candidate: int,
    details: list[str],
    next_port: int,
) -> str:
    return (
        f"{scheme.upper()}: Kandidat {candidate} fuer Dienst {service_key} ist belegt "
        f"durch {'; '.join(details)}; pruefe {next_port}"
    )


def _exhaustion_error(
    scheme: str,
    service_key: str,
    start: int,
    end: int,
    reason: str = "",
) -> str:
    suffix = f" ({reason})" if reason else ""
    return (
        f"{scheme.upper()}: keine freie Portzuordnung fuer Dienst {service_key} "
        f"im Intervall {start}-{end}{suffix}; bestehende Zuordnungen bleiben unveraendert"
    )


def allocate_scheme_ports(
    service_keys: Iterable[str | int],
    block: SchemeBlock,
    previous: Any,
    collisions: CollisionLookup,
) -> AllocationResult:
    """Allocate stable public Serve ports for one public scheme.

    Persisted assignments are immutable. New keys are inserted into the numeric
    gap between their nearest persisted/just-assigned neighbours. With no
    history, sorted services get grid slots START, START+spacing, ... . A
    collision advances only the new assignment, and only inside its interval.
    """

    assignments, errors = normalize_previous_assignments(previous, block)
    result = AllocationResult(assignments=dict(assignments), errors=list(errors))
    requested = sorted(
        {
            str(key)
            for key in service_keys
            if str(key).isdigit() and int(str(key)) > 0
        },
        key=int,
    )
    reserved = set(result.assignments.values())

    for service_key in requested:
        if service_key in result.assignments:
            continue

        ordered = sorted(result.assignments, key=int)
        lower_keys = [key for key in ordered if int(key) < int(service_key)]
        upper_keys = [key for key in ordered if int(key) > int(service_key)]
        lower = lower_keys[-1] if lower_keys else None
        upper = upper_keys[0] if upper_keys else None

        if not ordered:
            interval_start = block.start
            interval_end = min(block.start + block.spacing - 1, block.end)
        elif lower is None:
            interval_start = block.start
            interval_end = result.assignments[upper] - 1
        elif upper is None:
            previous_port = result.assignments[lower]
            grid_index = ((previous_port - block.start) // block.spacing) + 1
            interval_start = block.start + grid_index * block.spacing
            interval_end = min(interval_start + block.spacing - 1, block.end)
        else:
            interval_start = result.assignments[lower] + 1
            interval_end = result.assignments[upper] - 1

        if interval_start > interval_end or interval_start > block.end:
            position = "vor der ersten stabilen Zuordnung" if lower is None else "zwischen stabilen Zuordnungen"
            result.errors.append(
                _exhaustion_error(
                    block.scheme,
                    service_key,
                    max(block.start, min(interval_start, block.end)),
                    max(block.start, min(interval_end, block.end)),
                    position,
                )
            )
            continue

        interval_end = min(interval_end, block.end)
        assigned = None
        final_collision: list[str] = []
        for candidate in range(interval_start, interval_end + 1):
            if candidate in reserved:
                details = ["stabile CITADEL-Zuordnung"]
            else:
                details = [str(detail) for detail in collisions(block.scheme, service_key, candidate) if detail]
            if not details:
                assigned = candidate
                break
            final_collision = details
            if candidate < interval_end:
                result.warnings.append(
                    _collision_warning(
                        block.scheme,
                        service_key,
                        candidate,
                        details,
                        candidate + 1,
                    )
                )

        if assigned is None:
            collision_reason = (
                f"letzter Kandidat {interval_end} belegt durch {'; '.join(final_collision)}"
                if final_collision
                else ""
            )
            result.errors.append(
                _exhaustion_error(
                    block.scheme,
                    service_key,
                    interval_start,
                    interval_end,
                    collision_reason,
                )
            )
            continue

        result.assignments[service_key] = assigned
        result.new_assignments.add(service_key)
        reserved.add(assigned)

    result.assignments = dict(
        sorted(result.assignments.items(), key=lambda item: int(item[0]))
    )
    return result
