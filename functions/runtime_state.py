"""Direct runtime paths, identical on the host and in either image."""
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def data_directory(root: Path = ROOT) -> Path:
    return root / "CITADEL_DATA"


def provider_output(root: Path, provider: str, kind: str = "provider") -> Path:
    directory = root / "cache" if provider in {"cloudflare", "CLOUDFLARE-API"} else data_directory(root)
    filename = "status.json" if kind == "export" else "routes.json"
    return directory / f"{provider}-{filename}"


def prepare_state(root: Path = ROOT) -> None:
    for directory in (data_directory(root) / "icons", data_directory(root) / "CADDY", root / "cache"):
        directory.mkdir(parents=True, exist_ok=True)


def prepare_image(root: Path = ROOT) -> None:
    prepare_state(root)
    (root / "CITADEL_TAILSCALE").mkdir(mode=0o700, exist_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", action="store_true")
    (prepare_image if parser.parse_args().image else prepare_state)()
