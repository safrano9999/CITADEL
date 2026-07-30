import sys
import unittest
from pathlib import Path


FUNCTIONS_DIR = Path(__file__).resolve().parents[1] / "functions"
sys.path.insert(0, str(FUNCTIONS_DIR))

from favicon_policy import icon_extension, safe_icon_urls


class FaviconPolicyTests(unittest.TestCase):
    def test_accepts_relative_and_same_endpoint_urls(self):
        urls = safe_icon_urls(
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080/app/",
            ["/favicon.ico", "icon.png", "https://127.0.0.1:8080/secure.webp"],
        )
        self.assertEqual(
            urls,
            [
                "http://127.0.0.1:8080/favicon.ico",
                "http://127.0.0.1:8080/app/icon.png",
                "https://127.0.0.1:8080/secure.webp",
            ],
        )

    def test_rejects_foreign_link_local_and_other_ports(self):
        urls = safe_icon_urls(
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080/",
            [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:9090/favicon.ico",
                "https://example.net/favicon.ico",
                "file:///etc/passwd",
            ],
        )
        self.assertEqual(urls, [])

    def test_foreign_redirect_base_is_ignored(self):
        urls = safe_icon_urls(
            "http://127.0.0.1:8080",
            "http://example.net/redirected/",
            ["relative.png"],
        )
        self.assertEqual(urls, ["http://127.0.0.1:8080/relative.png"])

    def test_only_passive_supported_image_types_are_accepted(self):
        self.assertEqual(icon_extension("image/png; charset=binary"), ".png")
        self.assertEqual(icon_extension("image/x-icon"), ".ico")
        self.assertEqual(icon_extension("image/svg+xml"), ".svg")
        self.assertEqual(icon_extension("text/html"), "")


if __name__ == "__main__":
    unittest.main()
