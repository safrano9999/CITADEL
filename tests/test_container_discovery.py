import sys
import tempfile
import unittest
from pathlib import Path


FUNCTIONS_DIR = Path(__file__).resolve().parents[1] / "functions"
sys.path.insert(0, str(FUNCTIONS_DIR))

from container_discovery import (
    assign_host_route_ports,
    discover_host_listeners,
    parse_nmap_listeners,
    parse_proc_listeners,
)


class HostListenerDiscoveryTests(unittest.TestCase):
    def test_parses_only_open_nmap_ports(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nmap.xml"
            path.write_text(
                """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql"/></port>
<port protocol="tcp" portid="8080"><state state="closed"/></port>
</ports></host></nmaprun>
""",
                encoding="utf-8",
            )
            rows = parse_nmap_listeners(path, "host.containers.internal")
            self.assertEqual([row["port"] for row in rows], [22, 5432])
            self.assertEqual(rows[1]["service"], "postgresql")
            self.assertEqual(rows[1]["addr"], "host.containers.internal")

    def test_reads_only_listening_tcp_ports(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tcp"
            path.write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
                "   0: 0100007F:1538 00000000:0000 0A 0:0 0:0 0 0 0 1\n"
                "   1: 0100007F:1F90 00000000:0000 01 0:0 0:0 0 0 0 2\n",
                encoding="ascii",
            )
            self.assertEqual(
                parse_proc_listeners(path),
                [{"port": 5432, "addr": "127.0.0.1", "process": None}],
            )

    def test_combines_host_listener_addresses_by_port(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            net = root / "1" / "net"
            net.mkdir(parents=True)
            header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
            (net / "tcp").write_text(
                header + "0: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 1\n",
                encoding="ascii",
            )
            (net / "tcp6").write_text(header, encoding="ascii")

            rows = discover_host_listeners(root)

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["port"], 22)
            self.assertEqual(rows[0]["origin_host"], "host.containers.internal")
            self.assertEqual(rows[0]["addrs"], ["0.0.0.0"])


class DedupeAssignmentTests(unittest.TestCase):
    def setUp(self):
        self.local = [{"port": 8080}, {"port": 11000}]

    def test_missing_dedupe_port_keeps_host_services_unrouted(self):
        host = [{"port": 8080}, {"port": 9090}]
        services, assignments, errors = assign_host_route_ports(self.local, host, None)
        self.assertEqual([item["route_port"] for item in services], [None, None])
        self.assertEqual(assignments, {})
        self.assertEqual(errors, [])

    def test_only_duplicate_uses_high_port(self):
        host = [{"port": 8080}, {"port": 9090}]
        services, assignments, errors = assign_host_route_ports(self.local, host, 65100)
        self.assertEqual([item["route_port"] for item in services], [65100, 9090])
        self.assertEqual(assignments, {"host.containers.internal:8080": 65100})
        self.assertEqual(errors, [])

    def test_persisted_assignment_is_reused_and_reserved(self):
        host = [{"port": 8080}, {"port": 11000}]
        previous = {"host.containers.internal:11000": 65100}
        services, assignments, _ = assign_host_route_ports(
            self.local,
            host,
            65100,
            previous,
        )
        self.assertEqual([item["route_port"] for item in services], [65101, 65100])
        self.assertEqual(assignments["host.containers.internal:11000"], 65100)

    def test_reports_range_exhaustion(self):
        host = [{"port": 8080}, {"port": 11000}]
        services, _, errors = assign_host_route_ports(self.local, host, 65535)
        self.assertEqual(services[0]["route_port"], 65535)
        self.assertIsNone(services[1]["route_port"])
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
