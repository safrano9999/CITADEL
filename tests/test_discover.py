from __future__ import annotations

import importlib.util
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "skills" / "citadel-cloudflare" / "scripts" / "discover.py"
SPEC = importlib.util.spec_from_file_location("citadel_cloudflare_discover", SOURCE)
discover = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(discover)


class DiscoverFileTests(unittest.TestCase):
    def test_updates_existing_values_and_preserves_other_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.conf"
            path.write_text(
                "# existing comment\n"
                "CITADEL_CLOUDFLARE_DOMAIN=\n"
                "UNRELATED=value\n",
                encoding="utf-8",
            )
            discover.update_key_values(
                path,
                {
                    "CITADEL_CLOUDFLARE_DOMAIN": "services.example.net",
                    "CITADEL_CLOUDFLARE_ZONE_ID": "zone-id",
                },
            )
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "# existing comment\n"
                "CITADEL_CLOUDFLARE_DOMAIN=services.example.net\n"
                "UNRELATED=value\n"
                "\n"
                "CITADEL_CLOUDFLARE_ZONE_ID=zone-id\n",
            )

    def test_secret_file_is_mode_0600_and_token_is_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env"
            path.write_text(
                "CLOUDFLARE_API_TOKEN='api-token'\nTUNNEL_TOKEN=\n",
                encoding="utf-8",
            )
            path.chmod(0o644)
            discover.update_key_values(
                path,
                {"TUNNEL_TOKEN": "connector-token"},
                secret=True,
            )
            values = discover.read_key_values(path)
            self.assertEqual(values["CLOUDFLARE_API_TOKEN"], "api-token")
            self.assertEqual(values["TUNNEL_TOKEN"], "connector-token")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
