from pathlib import Path
import unittest

from functions.exporters.discover_3rdparty import load_rules, match_tiles


class ThirdPartyMetadataTests(unittest.TestCase):
    def test_match_identity_independently_of_port_and_preserve_native_icons(self):
        root = Path(__file__).resolve().parents[1]
        rules = load_rules(root / "extensions/enabled/discover-3rdparty", root)
        services = [
            {"port": 42, "name": "Gotenberg", "title": "HTTP Service"},
            {"port": 2016, "title": "HTTP Service"},
            {"title": "Welcome to the Apache Tika 10.2 Server"},
            {"title": "Paperless-ngx sign in", "icon": "icons/native.ico"},
            {"title": "Other DataForSEO MCP Client"},
        ]
        result = match_tiles(services, rules)
        self.assertEqual(set(result), {"Gotenberg", "Welcome to the Apache Tika 10.2 Server", "Paperless-ngx sign in"})
        self.assertEqual(result["Welcome to the Apache Tika 10.2 Server"]["name"], "Tika")
        self.assertEqual(result["Paperless-ngx sign in"], {"name": "Paperless-ngx"})
        self.assertTrue((root / result["Gotenberg"]["icon"]).is_file())
