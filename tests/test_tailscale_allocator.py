from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROVIDERS_DIR = Path(__file__).resolve().parents[1] / "functions" / "providers"
sys.path.insert(0, str(PROVIDERS_DIR))

from tailscale_allocator import (  # noqa: E402
    SchemeBlock,
    allocate_scheme_ports,
    build_scheme_blocks,
    parse_optional_start,
    parse_spacing,
)


class TailscaleAllocatorTests(unittest.TestCase):
    def no_collisions(self, _scheme: str, _key: str, _port: int) -> list[str]:
        return []

    def test_optional_start_disables_blank_and_zero(self) -> None:
        for value in ("", "blank", " BLANK ", "0", 0, None):
            with self.subTest(value=value):
                self.assertIsNone(parse_optional_start(value, "START"))

    def test_start_and_spacing_validation(self) -> None:
        for value in ("abc", "-1", "65536"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_optional_start(value, "START")
        for value in ("0", "-1", "abc"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_spacing(value)

    def test_scheme_blocks_are_disjoint_and_large_enough(self) -> None:
        blocks = build_scheme_blocks({"http": 25000, "https": 35000}, 100)
        self.assertEqual((blocks["http"].start, blocks["http"].end), (25000, 34999))
        self.assertEqual((blocks["https"].start, blocks["https"].end), (35000, 65535))

        with self.assertRaises(ValueError):
            build_scheme_blocks({"http": 25000, "https": 25000}, 100)
        with self.assertRaises(ValueError):
            build_scheme_blocks({"http": 25000, "https": 25050}, 100)
        with self.assertRaises(ValueError):
            build_scheme_blocks({"https": 65500}, 100)

    def test_initial_sorted_assignment_starts_exactly_at_start(self) -> None:
        result = allocate_scheme_ports(
            [11000, 4000, 8080],
            SchemeBlock("https", 25000, 65535, 100),
            {},
            self.no_collisions,
        )
        self.assertEqual(
            result.assignments,
            {"4000": 25000, "8080": 25100, "11000": 25200},
        )
        self.assertEqual(result.errors, [])

    def test_new_service_fills_gap_without_moving_existing_ports(self) -> None:
        previous = {"4000": 25000, "11000": 25100}
        result = allocate_scheme_ports(
            [4000, 8080, 11000],
            SchemeBlock("https", 25000, 65535, 100),
            previous,
            self.no_collisions,
        )
        self.assertEqual(
            result.assignments,
            {"4000": 25000, "8080": 25001, "11000": 25100},
        )
        self.assertEqual(result.new_assignments, {"8080"})

    def test_new_collision_advances_only_inside_gap_with_detail(self) -> None:
        def collisions(_scheme: str, _key: str, port: int) -> list[str]:
            if port == 25001:
                return ["lokaler Listener 0.0.0.0:25001 process=uvicorn pid=42"]
            if port == 25002:
                return [
                    "Tailscale TCPForward target=127.0.0.1:5432 authority=node.example:25002"
                ]
            return []

        result = allocate_scheme_ports(
            [4000, 8080, 11000],
            SchemeBlock("https", 25000, 65535, 100),
            {"4000": 25000, "11000": 25100},
            collisions,
        )
        self.assertEqual(result.assignments["8080"], 25003)
        self.assertEqual(len(result.warnings), 2)
        self.assertIn("HTTPS: Kandidat 25001", result.warnings[0])
        self.assertIn("0.0.0.0:25001", result.warnings[0])
        self.assertIn("pruefe 25002", result.warnings[0])
        self.assertIn("TCPForward", result.warnings[1])

    def test_persisted_collision_never_moves_assignment(self) -> None:
        calls: list[int] = []

        def collisions(_scheme: str, _key: str, port: int) -> list[str]:
            calls.append(port)
            return ["foreign listener"]

        result = allocate_scheme_ports(
            [4000],
            SchemeBlock("https", 25000, 65535, 100),
            {"4000": 25000},
            collisions,
        )
        self.assertEqual(result.assignments, {"4000": 25000})
        self.assertEqual(calls, [])

    def test_head_and_gap_exhaustion_are_explicit(self) -> None:
        head = allocate_scheme_ports(
            [1000, 4000],
            SchemeBlock("http", 25000, 65535, 100),
            {"4000": 25000},
            self.no_collisions,
        )
        self.assertNotIn("1000", head.assignments)
        self.assertIn("vor der ersten stabilen Zuordnung", head.errors[0])

        gap = allocate_scheme_ports(
            [4000, 5000, 6000],
            SchemeBlock("http", 25000, 65535, 100),
            {"4000": 25000, "6000": 25001},
            self.no_collisions,
        )
        self.assertNotIn("5000", gap.assignments)
        self.assertIn("zwischen stabilen Zuordnungen", gap.errors[0])

    def test_exhausted_collision_range_does_not_change_existing(self) -> None:
        result = allocate_scheme_ports(
            [4000, 5000],
            SchemeBlock("http", 65534, 65535, 2),
            {"4000": 65534},
            lambda _scheme, _key, _port: ["local listener"],
        )
        self.assertEqual(result.assignments, {"4000": 65534})
        self.assertIn("Intervall 65535-65535", result.errors[0])


if __name__ == "__main__":
    unittest.main()
