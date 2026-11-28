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

    def test_importer_and_third_party_mcp_names(self):
        root = Path(__file__).resolve().parents[1]
        rules = load_rules(root / "extensions/enabled/discover-3rdparty", root)
        names = ["Mailfathom MCP", "Mailfathom MCP 0.6.0", "Mailfathom 0.8.0 MCP",
                 "Nextcloud MCP", "Firefly III Data Importer // Index"]
        matches = match_tiles([{"title": name} for name in names], rules)
        self.assertEqual(set(matches), set(names))
        self.assertEqual(matches[names[1]], matches[names[2]])
        self.assertEqual(matches[names[-1]]["name"], "Firefly III Data Importer")


    def test_protected_opencode_is_identified_by_its_listener(self):
        root = Path(__file__).resolve().parents[1]
        rules = load_rules(root / "extensions/enabled/discover-3rdparty", root)
        result = match_tiles([{"title": "HTTP Service", "process": "opencode"},
                              {"title": "HTTP Service", "process": "caddy"}], rules)
        self.assertEqual(result, {"process:opencode": {"name": "OpenCode",
                                                      "icon": "assets/3rd-party/opencode.svg"}})
