import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))
from cloudflare_api_state import deployment, table_from_settings


class DeploymentTests(unittest.TestCase):
    def test_large_route_table_round_trips_under_binding_limits(self):
        table = {"schema": 1, "hosts": {}, "fixture": "x" * 14000}
        metadata, _ = deployment("a" * 24, table, {"SESSION_KEY": "b" * 64}, b"worker")
        self.assertEqual(table_from_settings(metadata), table)
        self.assertTrue(all(len(binding.get("text", "")) <= 5000 for binding in metadata["bindings"]))
        broken = {**metadata, "bindings": [b for b in metadata["bindings"] if b["name"] != "ROUTE_TABLE_1"]}
        with self.assertRaises(ValueError):
            table_from_settings(broken)

    def test_limits_fail_before_upload_and_secret_tags_do_not_allow_plain_hash_guesses(self):
        for table, secrets in (
            ({"schema": 1, "hosts": {}, "fixture": "x" * 240001}, {}),
            ({"schema": 1, "hosts": {}}, {"SESSION_KEY": "b" * 64, "BACKEND": "x" * 5001}),
            ({"schema": 1, "hosts": {}}, {"SESSION_KEY": "b" * 64, **{f"KEY_{i}": "s" for i in range(62)}}),
        ):
            with self.assertRaises(ValueError):
                deployment("a" * 24, table, secrets, b"worker")
        tags = []
        for key in ("b" * 64, "c" * 64):
            metadata, _ = deployment("a" * 24, {"schema": 1, "hosts": {}}, {"SESSION_KEY": key, "BACKEND": "guessable"}, b"worker")
            tags.append(next(tag for tag in metadata["tags"] if tag.startswith("citadel-secrets:")))
        self.assertNotEqual(*tags)
