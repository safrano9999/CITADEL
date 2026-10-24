import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("image_version", Path(__file__).resolve().parents[1] / ".github/scripts/resolve-image-tag.py")
version = importlib.util.module_from_spec(spec)
spec.loader.exec_module(version)


class ImageVersionTests(unittest.TestCase):
    def test_automatic_version_advances_past_published_images(self):
        now = datetime(2026, 10, 24, tzinfo=timezone.utc)
        self.assertEqual(version.select_version(
            ["2026.10.5", "2026.10.12", "latest"], now=now), "2026.10.13")

    def test_automatic_version_starts_a_new_month(self):
        now = datetime(2026, 11, 1, tzinfo=timezone.utc)
        self.assertEqual(version.select_version(
            ["2026.10.99", "latest"], now=now), "2026.11.1")

    def test_version_replacement_requires_explicit_authorization(self):
        with self.assertRaises(ValueError):
            version.select_version(["2026.10.1", "latest"], "2026.10.1")
        self.assertEqual(version.select_version(["2026.10.1", "latest"], "2026.10.1",
                                               replace_existing=True), "2026.10.1")

    def test_month_is_canonical(self):
        self.assertEqual(version.canonical("2026.9.1"), "2026.09.1")
