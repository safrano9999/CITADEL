import unittest
from pathlib import Path

import webui


class WebUiScanBoundaryTests(unittest.TestCase):
    def test_scan_endpoint_is_not_exposed(self):
        paths = {route.path for route in webui.app.routes}
        self.assertNotIn("/api/scan", paths)

    def test_template_contains_no_scan_request(self):
        template = Path(webui.__file__).resolve().parent / "templates" / "index.html"
        contents = template.read_text(encoding="utf-8")
        self.assertNotIn("/api/scan", contents)
        self.assertNotIn("SAVE &amp; SCAN", contents)


if __name__ == "__main__":
    unittest.main()
