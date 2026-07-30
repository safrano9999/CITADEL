import sys
import unittest
from pathlib import Path


FUNCTIONS_DIR = Path(__file__).resolve().parents[1] / "functions"
sys.path.insert(0, str(FUNCTIONS_DIR))

import core


class TailscaleDiscoveryTests(unittest.TestCase):
    def test_discovery_urls_allow_expected_protocols_only(self):
        self.assertEqual(
            core._safe_discovery_url("https://node.example.ts.net:8443/"),
            "https://node.example.ts.net:8443/",
        )
        self.assertEqual(
            core._safe_discovery_url("postgresql://100.64.0.2:5432"),
            "postgresql://100.64.0.2:5432",
        )
        self.assertEqual(core._safe_discovery_url("javascript:alert(1)"), "")

    def test_host_payload_filters_invalid_ports_and_sorts_services(self):
        hosts = core._ts_discovery_hosts({
            "hosts": [{
                "name": "node",
                "services": [
                    {"port": 443, "url": "https://node:443"},
                    {"port": 22, "url": "ssh://node:22"},
                    {"port": 70000, "url": "tcp://node:70000"},
                ],
            }]
        })
        self.assertEqual(
            [service["port"] for service in hosts[0]["services"]],
            [22, 443],
        )

    def test_normal_scan_never_calls_tailscale_discovery_script(self):
        scan_script = FUNCTIONS_DIR.parent / "scan.sh"
        contents = scan_script.read_text(encoding="utf-8")
        self.assertNotIn("Scan_TS.sh", contents)


if __name__ == "__main__":
    unittest.main()
