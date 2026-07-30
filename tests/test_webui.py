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

    def test_hidden_controls_cannot_be_overridden_by_component_display(self):
        stylesheet = Path(webui.__file__).resolve().parent / "assets" / "style.css"
        contents = stylesheet.read_text(encoding="utf-8")
        self.assertIn("[hidden]", contents)
        self.assertIn("display: none !important", contents)

    def test_html_templates_autoescape_dynamic_values(self):
        rendered = webui._jinja.from_string("{{ value }}").render(
            value='<script>alert("xss")</script>',
        )
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)


class EditTokenGuardTests(unittest.TestCase):
    def setUp(self):
        self.guard = webui.EditTokenGuard(
            max_failures=3,
            failure_window=10,
            lock_seconds=30,
        )

    def test_blank_configuration_disables_token_check(self):
        self.assertEqual(
            self.guard.authenticate("client", "", "", now=0),
            (True, 0),
        )

    def test_correct_token_is_accepted(self):
        self.assertEqual(
            self.guard.authenticate("client", "correct", "correct", now=0),
            (True, 0),
        )

    def test_repeated_failures_lock_client(self):
        self.assertEqual(
            self.guard.authenticate("client", "wrong", "correct", now=0),
            (False, 0),
        )
        self.assertEqual(
            self.guard.authenticate("client", "wrong", "correct", now=1),
            (False, 0),
        )
        self.assertEqual(
            self.guard.authenticate("client", "wrong", "correct", now=2),
            (False, 30),
        )
        self.assertEqual(
            self.guard.authenticate("client", "correct", "correct", now=3),
            (False, 29),
        )
        self.assertEqual(
            self.guard.authenticate("client", "correct", "correct", now=32),
            (True, 0),
        )

    def test_failures_outside_window_do_not_accumulate(self):
        self.guard.authenticate("client", "wrong", "correct", now=0)
        self.guard.authenticate("client", "wrong", "correct", now=11)
        self.assertEqual(
            self.guard.authenticate("client", "wrong", "correct", now=12),
            (False, 0),
        )


if __name__ == "__main__":
    unittest.main()
