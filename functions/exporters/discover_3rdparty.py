"""Export whitelist matches from scanned service titles and display names."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "providers"))
from atomic_io import atomic_write_json
from common import now_iso


def load_rules(directory, root):
    rules = []
    for entry in json.loads((directory / "whitelist.json").read_text(encoding="utf-8")):
        pattern = re.compile(entry["match"], re.IGNORECASE)
        fields = {}
        if title := entry.get("title"):
            fields["name"] = title
        if icon := entry.get("icon"):
            if Path(icon).name != icon or not (root / "assets/3rd-party" / icon).is_file():
                raise ValueError(f"Invalid third-party icon: {icon!r}")
            fields["icon"] = f"assets/3rd-party/{icon}"
        if not fields:
            raise ValueError(f"Missing tile metadata for {pattern.pattern!r}")
        rules.append((pattern, entry.get("process"), fields))
    return rules


def match_tiles(services, rules):
    matches = {}
    for service in services:
        for value in (service.get("name"), service.get("title")):
            if not isinstance(value, str) or not value.strip():
                continue
            for pattern, _, fields in rules:
                if pattern.fullmatch(value.strip()):
                    matches[value] = fields
                    break
        process = service.get("process")
        if process:
            for _, expected_process, fields in rules:
                if process == expected_process:
                    matches[f"process:{process}"] = fields
                    break
    return matches


def main():
    parser = argparse.ArgumentParser()
    for name in ("provider-dir", "services-file", "routes-out"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("cache-dir", "config-ini", "tailscale-file"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    root = args.provider_dir.resolve().parents[2]
    status = {"kind": "export", "provider_id": "discover-3rdparty", "label": "Third-party tile metadata",
              "services": {}, "considered": True, "available": False, "artifacts": [],
              "errors": [], "generated_at": now_iso()}
    try:
        rules = load_rules(args.provider_dir, root)
        services = json.loads(args.services_file.read_text(encoding="utf-8"))["http_services"]
        matches = match_tiles(services, rules)
        artifact = args.routes_out.with_name("discover-3rdparty-tiles.json")
        atomic_write_json(artifact, matches)
        status["artifacts"] = [{"path": str(artifact.relative_to(root)),
                                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}]
        status["available"] = True
    except (KeyError, OSError, TypeError, ValueError, re.error) as error:
        status["errors"].append(str(error))
    atomic_write_json(args.routes_out, status)
    return int(bool(status["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
