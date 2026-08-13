from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROVIDERS_DIR = ROOT / "functions" / "providers"
sys.path.insert(0, str(PROVIDERS_DIR))

from common import route_record  # noqa: E402


def load_tailscale_provider():
    spec = importlib.util.spec_from_file_location(
        "citadel_tailscale_route_helpers",
        PROVIDERS_DIR / "tailscale.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tailscale = load_tailscale_provider()


def exact_route_payload(
    port: int,
    public_scheme: str,
    target: str,
    *,
    authority: str = "node.example.ts.net",
) -> dict:
    listener = {"HTTPS": True} if public_scheme == "https" else {"HTTP": True}
    return {
        "TCP": {str(port): listener},
        "Web": {
            f"{authority}:{port}": {
                "Handlers": {"/": {"Proxy": target}},
            },
        },
    }


class RouteHelperTests(unittest.TestCase):
    def test_serve_target_uses_origin_port_with_public_port_fallback(self) -> None:
        self.assertEqual(
            tailscale.serve_target(8443, "https"),
            "https+insecure://127.0.0.1:8443",
        )
        self.assertEqual(
            tailscale.serve_target(
                25000,
                "http",
                "host.containers.internal",
                8080,
            ),
            "http://host.containers.internal:8080",
        )

    def test_common_route_record_has_shared_proxy_schema(self) -> None:
        self.assertEqual(
            route_record(
                "proxy",
                "https://node.example.ts.net:25000",
                target="http://127.0.0.1:8080",
                owns_listener=True,
            ),
            {
                "mode": "proxy",
                "url": "https://node.example.ts.net:25000",
                "target": "http://127.0.0.1:8080",
                "owns_listener": True,
            },
        )

    def test_parse_live_routes_recognizes_exact_https_and_http_proxies(self) -> None:
        parsed = tailscale.parse_live_serve_routes({
            "TCP": {
                "25000": {"HTTPS": True},
                "15000": {"HTTP": True},
            },
            "Web": {
                "Node.Example.TS.NET.:25000": {
                    "Handlers": {
                        "/": {"Proxy": "https+insecure://127.0.0.1:9443"},
                    },
                },
                "node.example.ts.net:15000": {
                    "Handlers": {
                        "/": {"Proxy": "http://127.0.0.1:8080"},
                    },
                },
            },
        })

        self.assertEqual(
            parsed["25000"],
            {
                "public_scheme": "https",
                "target": "https+insecure://127.0.0.1:9443",
                "authority": "node.example.ts.net:25000",
                "listener_type": "HTTPS",
                "tcp_target": None,
                "exact_tcp_handler": True,
                "exclusive_root_proxy": True,
                "foreground": False,
                "funnel": False,
            },
        )
        self.assertEqual(
            parsed["15000"],
            {
                "public_scheme": "http",
                "target": "http://127.0.0.1:8080",
                "authority": "node.example.ts.net:15000",
                "listener_type": "HTTP",
                "tcp_target": None,
                "exact_tcp_handler": True,
                "exclusive_root_proxy": True,
                "foreground": False,
                "funnel": False,
            },
        )

    def test_parse_live_routes_preserves_raw_tcp_forward_metadata(self) -> None:
        parsed = tailscale.parse_live_serve_routes({
            "TCP": {"5432": {"TCPForward": "127.0.0.1:15432"}},
        })

        self.assertEqual(
            parsed["5432"],
            {
                "public_scheme": None,
                "target": None,
                "authority": None,
                "listener_type": "TCPForward",
                "tcp_target": "127.0.0.1:15432",
                "exact_tcp_handler": False,
                "exclusive_root_proxy": False,
                "foreground": False,
                "funnel": False,
            },
        )

    def test_multiple_web_authorities_on_one_port_are_not_exact(self) -> None:
        parsed = tailscale.parse_live_serve_routes({
            "TCP": {"443": {"HTTPS": True}},
            "Web": {
                "node.example.ts.net:443": {
                    "Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}},
                },
                "other.example.ts.net:443": {
                    "Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}},
                },
            },
        })

        route = parsed["443"]
        self.assertTrue(route["exact_tcp_handler"])
        self.assertIsNone(route["target"])
        self.assertIsNone(route["authority"])
        self.assertFalse(route["exclusive_root_proxy"])

    def test_foreground_and_funnel_routes_are_marked_nonexclusive(self) -> None:
        foreground = tailscale.parse_live_serve_routes({
            "Foreground": {
                "session-1": exact_route_payload(
                    25000,
                    "https",
                    "http://127.0.0.1:8080",
                ),
            },
        })["25000"]
        self.assertEqual(foreground["public_scheme"], "https")
        self.assertEqual(foreground["listener_type"], "HTTPS")
        self.assertIsNone(foreground["target"])
        self.assertFalse(foreground["exact_tcp_handler"])
        self.assertFalse(foreground["exclusive_root_proxy"])
        self.assertTrue(foreground["foreground"])

        funnel_payload = exact_route_payload(
            15000,
            "http",
            "http://127.0.0.1:8080",
        )
        funnel_payload["AllowFunnel"] = {"node.example.ts.net:15000": True}
        funnel = tailscale.parse_live_serve_routes(funnel_payload)["15000"]
        self.assertTrue(funnel["funnel"])
        self.assertFalse(funnel["exclusive_root_proxy"])

    def test_live_route_matches_requires_exact_background_ownership(self) -> None:
        route = tailscale.parse_live_serve_routes(
            exact_route_payload(
                25000,
                "https",
                "https+insecure://127.0.0.1:9443",
            )
        )["25000"]
        expected = {
            "public_scheme": "https",
            "target": "https+insecure://127.0.0.1:9443",
            "authority": "NODE.EXAMPLE.TS.NET.:25000",
        }

        self.assertTrue(tailscale.live_route_matches(route, **expected))
        for field in (
            "exact_tcp_handler",
            "exclusive_root_proxy",
            "foreground",
            "funnel",
        ):
            with self.subTest(field=field):
                changed = dict(route)
                changed[field] = not route[field]
                self.assertFalse(tailscale.live_route_matches(changed, **expected))

        mismatches = (
            {**expected, "public_scheme": "http"},
            {**expected, "target": "http://127.0.0.1:9443"},
            {**expected, "authority": "other.example.ts.net:25000"},
        )
        for arguments in mismatches:
            with self.subTest(arguments=arguments):
                self.assertFalse(tailscale.live_route_matches(route, **arguments))
        self.assertFalse(tailscale.live_route_matches(None, **expected))

    def test_parse_local_listeners_extracts_ipv4_ipv6_processes_and_pids(self) -> None:
        output = "\n".join((
            'LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("python3",pid=123,fd=7))',
            'LISTEN 0 4096 [::1]:8080 [::]:* users:(("node",pid=456,fd=20))',
            'LISTEN 0 511 [::]:9090 [::]:* users:(("nginx",pid=22,fd=5),("nginx",pid=21,fd=5))',
            "LISTEN 0 128 0.0.0.0:10000 0.0.0.0:*",
            "malformed line",
        ))

        self.assertEqual(
            tailscale.parse_local_listeners(output),
            {
                8080: [
                    {"address": "127.0.0.1", "process": "python3", "pid": 123},
                    {"address": "::1", "process": "node", "pid": 456},
                ],
                9090: [
                    {"address": "::", "process": "nginx", "pid": 22},
                    {"address": "::", "process": "nginx", "pid": 21},
                ],
                10000: [
                    {"address": "0.0.0.0", "process": None, "pid": None},
                ],
            },
        )


if __name__ == "__main__":
    unittest.main()
