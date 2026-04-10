#!/usr/bin/env python3
"""Interactive modular container generator for CITADEL."""

from __future__ import annotations

import json
import random
import shlex
import subprocess
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class ModuleEntry:
    list_file: str
    name: str
    kind: str
    source: str
    target_dir: str
    env_ref: str
    description: str
    default_selected: bool


BASE_DIR = Path(__file__).resolve().parent
CITADEL_DIR = BASE_DIR.parent
WORKSPACE_DIR = CITADEL_DIR.parent
REPO_LIST_DIR = BASE_DIR / "REPOS"
ENV_DIR = BASE_DIR / "ENV"
GENERATED_DIR = BASE_DIR / "generated"
DEFAULT_DNF_PACKAGES = ["python3", "python3-pip", "git"]
ADJECTIVES = [
    "brisk",
    "calm",
    "clever",
    "fuzzy",
    "lively",
    "nimble",
    "quiet",
    "rapid",
    "steady",
    "witty",
]
ANIMALS = [
    "otter",
    "lynx",
    "falcon",
    "badger",
    "fox",
    "wolf",
    "panda",
    "raven",
    "stoat",
    "tiger",
]


def ask_text(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{prompt}{suffix}: ").strip()
    return raw or default


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    default_hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt} [{default_hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes", "j", "ja"}:
            return True
        if raw in {"n", "no", "nein"}:
            return False
        print("Bitte y oder n eingeben.")


def suggest_codename() -> str:
    return f"{random.choice(ADJECTIVES)}-{random.choice(ANIMALS)}"


def normalize_container_name(value: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    if not cleaned:
        cleaned = suggest_codename()
    if not cleaned.startswith("citadel-"):
        cleaned = f"citadel-{cleaned}"
    return cleaned


def normalize_hostname(value: str, fallback: str) -> str:
    cleaned = value.strip().lower().replace(" ", "-")
    return cleaned or fallback


def run(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    print("+", " ".join(shlex.quote(part) for part in cmd))
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=check)


def parse_list_file(path: Path) -> list[ModuleEntry]:
    entries: list[ModuleEntry] = []
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 7:
            raise ValueError(
                f"{path.name}:{lineno} expected 7 columns but got {len(parts)}: {line}"
            )
        name, kind, source, target_dir, env_ref, description, default = parts
        if kind not in {"repo", "directive"}:
            raise ValueError(f"{path.name}:{lineno} invalid kind '{kind}'")
        entries.append(
            ModuleEntry(
                list_file=path.name,
                name=name,
                kind=kind,
                source=source,
                target_dir=target_dir,
                env_ref=env_ref,
                description=description,
                default_selected=default.lower() in {"y", "yes", "1", "true"},
            )
        )
    return entries


def load_entries() -> list[ModuleEntry]:
    order = ["public.list", "private.list", "3rdparty.list"]
    files = []
    for known in order:
        candidate = REPO_LIST_DIR / known
        if candidate.exists():
            files.append(candidate)
    for path in sorted(REPO_LIST_DIR.glob("*.list")):
        if path not in files:
            files.append(path)

    entries: list[ModuleEntry] = []
    for path in files:
        entries.extend(parse_list_file(path))
    return entries


def env_ref_to_path(env_ref: str) -> Path | None:
    if not env_ref or env_ref == "-":
        return None
    candidate = Path(env_ref)
    if candidate.is_absolute():
        return candidate
    return CITADEL_DIR / candidate


def source_ref_to_path(source_ref: str) -> Path | None:
    if not source_ref or source_ref == "-":
        return None
    candidate = Path(source_ref)
    if candidate.is_absolute():
        return candidate
    return BASE_DIR / candidate


def parse_env_template(path: Path) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body, _, comment = line.partition("#")
        body = body.strip()
        if "=" not in body:
            continue
        key, value = body.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        out.append((key, value, comment.strip()))
    return out


def select_modules(entries: Iterable[ModuleEntry]) -> list[ModuleEntry]:
    selected: list[ModuleEntry] = []
    current_group = None
    for entry in entries:
        if entry.list_file != current_group:
            current_group = entry.list_file
            print(f"\n=== {current_group} ===")
        question = f"{entry.name} ({entry.kind}) -> {entry.description}"
        if ask_yes_no(question, default=entry.default_selected):
            selected.append(entry)
    return selected


def validate_directives(selected: Iterable[ModuleEntry]) -> None:
    for entry in selected:
        if entry.kind != "directive":
            continue
        source_path = source_ref_to_path(entry.source)
        if not source_path or not source_path.exists():
            raise FileNotFoundError(
                f"Directive source missing for {entry.name}: {entry.source}"
            )


def sync_repo(entry: ModuleEntry) -> None:
    target = WORKSPACE_DIR / entry.target_dir
    if target.exists():
        git_dir = target / ".git"
        if git_dir.exists() and ask_yes_no(f"{entry.target_dir} existiert. git pull ausfuehren?", default=False):
            run(["git", "-C", str(target), "pull", "--ff-only"], check=False)
        else:
            print(f"- skip clone/update for {entry.target_dir}")
        return

    run(["git", "clone", "--depth", "1", entry.source, str(target)], check=False)


def collect_env(selected: list[ModuleEntry]) -> OrderedDict[str, str]:
    env_values: OrderedDict[str, str] = OrderedDict()

    common_env = ENV_DIR / "common.env"
    if common_env.exists():
        for key, default, hint in parse_env_template(common_env):
            if key in env_values:
                continue
            value = ask_text(f"{key} ({hint})", default)
            env_values[key] = value

    for entry in selected:
        env_path = env_ref_to_path(entry.env_ref)
        if not env_path or not env_path.exists():
            continue
        print(f"\nEnv fuer {entry.name}: {env_path}")
        for key, default, hint in parse_env_template(env_path):
            if key in env_values:
                continue
            value = ask_text(f"{key} ({hint})", default)
            env_values[key] = value

    return env_values


def generate_dockerfile(profile: str, selected: list[ModuleEntry]) -> Path:
    out = GENERATED_DIR / f"{profile}.Dockerfile"
    repos = [entry for entry in selected if entry.kind == "repo"]
    directives = [entry for entry in selected if entry.kind == "directive"]

    lines = [
        "FROM quay.io/fedora/fedora:latest",
        "",
        "# Generated by CITADEL/CONTAINER/build.py",
        "RUN dnf install -y python3 python3-pip git && dnf clean all",
        "",
        "COPY CITADEL /opt/citadel",
    ]
    for repo in repos:
        lines.append(f"COPY {repo.target_dir} /opt/modules/{repo.target_dir}")

    if directives:
        lines.extend([
            "",
            "# Third-party directive repository",
            "COPY 3RDPARTY /opt/thirdparty",
        ])

    lines.extend([
        "",
        "WORKDIR /opt/citadel",
        "CMD [\"/bin/bash\"]",
    ])

    out.write_text("\n".join(lines) + "\n")
    return out


def generate_env_file(profile: str, env_values: OrderedDict[str, str]) -> Path:
    out = GENERATED_DIR / f"{profile}.env"
    lines = [f"{key}={value}" for key, value in env_values.items()]
    out.write_text("\n".join(lines) + "\n")
    return out


def generate_container_file(
    profile: str,
    image_name: str,
    container_name: str,
    hostname: str,
    network_mode: str,
    publish_ports: list[str],
    env_values: OrderedDict[str, str],
    selected: list[ModuleEntry],
) -> Path:
    out = GENERATED_DIR / f"{profile}.container"
    lines = [
        "[Unit]",
        f"Description=CITADEL modular profile {profile}",
        "",
        "[Container]",
        f"ContainerName={container_name}",
        f"HostName={hostname}",
        f"Image={image_name}",
        f"Network={network_mode}",
    ]
    if network_mode != "host":
        for port in publish_ports:
            lines.append(f"PublishPort={port}")
    else:
        lines.append("# PublishPort lines are ignored in host mode")
        for port in publish_ports:
            lines.append(f"# PublishPort={port}")

    for key, value in env_values.items():
        lines.append(f"Environment={key}={value}")

    lines.extend([
        "",
        "[Service]",
        "Restart=always",
        "RestartSec=5",
        "",
        "[Install]",
        "WantedBy=default.target",
    ])
    lines.extend(["", "# Built packages (comment-only manifest)"])
    for pkg in DEFAULT_DNF_PACKAGES:
        lines.append(f"# dnf-package: {pkg}")
    lines.append("# base-repo: CITADEL")
    for entry in selected:
        if entry.kind == "repo":
            lines.append(f"# repo-package: {entry.target_dir} ({entry.source})")
        elif entry.kind == "directive":
            lines.append(f"# directive-package: {entry.name} ({entry.source})")
    out.write_text("\n".join(lines) + "\n")
    return out


def generate_run_script(
    profile: str,
    image_name: str,
    container_name: str,
    hostname: str,
    network_mode: str,
    publish_ports: list[str],
) -> Path:
    out = GENERATED_DIR / f"{profile}.run.sh"
    dockerfile_name = f"{profile}.Dockerfile"
    env_file_name = f"{profile}.env"
    publish_args = "".join([f" -p {port}" for port in publish_ports]) if network_mode != "host" else ""

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"",
        f"IMAGE_NAME=\"{image_name}\"",
        f"CONTAINER_NAME=\"{container_name}\"",
        f"HOST_NAME=\"{hostname}\"",
        "",
        "podman build -f \"${SCRIPT_DIR}/" + dockerfile_name + "\" -t \"${IMAGE_NAME}\" \"/home/openclaw/safrano9999\"",
        "podman rm -f \"${CONTAINER_NAME}\" >/dev/null 2>&1 || true",
        "podman run -d --name \"${CONTAINER_NAME}\" --hostname \"${HOST_NAME}\" --network " + network_mode + publish_args + " --env-file \"${SCRIPT_DIR}/" + env_file_name + "\" \"${IMAGE_NAME}\"",
    ]
    out.write_text("\n".join(lines) + "\n")
    out.chmod(0o755)
    return out


def generate_docker_run_script(
    profile: str,
    image_name: str,
    container_name: str,
    hostname: str,
    network_mode: str,
    publish_ports: list[str],
) -> Path:
    out = GENERATED_DIR / f"{profile}.docker.sh"
    dockerfile_name = f"{profile}.Dockerfile"
    env_file_name = f"{profile}.env"
    publish_args = "".join([f" -p {port}" for port in publish_ports]) if network_mode != "host" else ""

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"",
        f"IMAGE_NAME=\"{image_name}\"",
        f"CONTAINER_NAME=\"{container_name}\"",
        f"HOST_NAME=\"{hostname}\"",
        "",
        "docker build -f \"${SCRIPT_DIR}/" + dockerfile_name + "\" -t \"${IMAGE_NAME}\" \"/home/openclaw/safrano9999\"",
        "docker rm -f \"${CONTAINER_NAME}\" >/dev/null 2>&1 || true",
        "docker run -d --name \"${CONTAINER_NAME}\" --hostname \"${HOST_NAME}\" --network " + network_mode + publish_args + " --env-file \"${SCRIPT_DIR}/" + env_file_name + "\" \"${IMAGE_NAME}\"",
    ]
    out.write_text("\n".join(lines) + "\n")
    out.chmod(0o755)
    return out


def generate_metadata(
    profile: str,
    container_name: str,
    hostname: str,
    image_name: str,
    selected: list[ModuleEntry],
    env_values: OrderedDict[str, str],
) -> Path:
    out = GENERATED_DIR / f"{profile}.json"
    payload = {
        "profile": profile,
        "workspace": str(WORKSPACE_DIR),
        "container_name": container_name,
        "hostname": hostname,
        "image_name": image_name,
        "selected": [
            {
                "list": entry.list_file,
                "name": entry.name,
                "kind": entry.kind,
                "source": entry.source,
                "target_dir": entry.target_dir,
                "env_ref": entry.env_ref,
            }
            for entry in selected
        ],
        "env": env_values,
    }
    out.write_text(json.dumps(payload, indent=2) + "\n")
    return out


def main() -> int:
    print("CITADEL Modular Container Builder")
    print(f"Workspace: {WORKSPACE_DIR}")

    profile = ask_text("Profile name", "modular")
    generated_codename = suggest_codename()
    codename = ask_text("Container codename (without citadel-)", generated_codename)
    container_name = normalize_container_name(codename)
    hostname = normalize_hostname(ask_text("Container hostname", container_name), container_name)
    image_name = ask_text("Image tag", f"localhost/{container_name}:latest")
    network_mode = ask_text("Network mode (host/bridge)", "host").lower()
    ports_csv = ask_text("Publish ports (comma, e.g. 9443:9443,8080:8080)", "9443:9443,8080:8080,820:820,840:840,7700:7700")
    publish_ports = [p.strip() for p in ports_csv.split(",") if p.strip()]

    entries = load_entries()
    if not entries:
        print("No entries found in REPOS/*.list")
        return 1

    selected = select_modules(entries)
    if not selected:
        print("Nichts ausgewaehlt. Abbruch.")
        return 1

    validate_directives(selected)

    print("\nSynchronisiere Repo-Module ...")
    for entry in selected:
        if entry.kind == "repo":
            sync_repo(entry)

    print("\nErfasse Env-Variablen ...")
    env_values = collect_env(selected)

    GENERATED_DIR.mkdir(parents=True, exist_ok=True)

    env_file = generate_env_file(profile, env_values)
    dockerfile = generate_dockerfile(profile, selected)
    container_file = generate_container_file(
        profile=profile,
        image_name=image_name,
        container_name=container_name,
        hostname=hostname,
        network_mode=network_mode,
        publish_ports=publish_ports,
        env_values=env_values,
        selected=selected,
    )
    run_script = generate_run_script(
        profile=profile,
        image_name=image_name,
        container_name=container_name,
        hostname=hostname,
        network_mode=network_mode,
        publish_ports=publish_ports,
    )
    docker_script = generate_docker_run_script(
        profile=profile,
        image_name=image_name,
        container_name=container_name,
        hostname=hostname,
        network_mode=network_mode,
        publish_ports=publish_ports,
    )
    meta_file = generate_metadata(
        profile=profile,
        container_name=container_name,
        hostname=hostname,
        image_name=image_name,
        selected=selected,
        env_values=env_values,
    )

    print("\nGeneriert:")
    print(f"- {env_file}")
    print(f"- {dockerfile}")
    print(f"- {container_file}")
    print(f"- {run_script}")
    print(f"- {docker_script}")
    print(f"- {meta_file}")

    print("\nNaechster Schritt:")
    print(f"  {run_script}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        raise SystemExit(130)
