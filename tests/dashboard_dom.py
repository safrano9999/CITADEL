"""Run the actual inline dashboard JavaScript with DOM mode-switch assertions."""
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess


def simulate_dashboard(page):
    class Page(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tiles, self.modes, self.script = [], [], []
            self.default_mode, self.in_script, self.in_modes = "localhost", False, False

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "body":
                self.default_mode = attrs.get("data-default-mode", "localhost")
            if tag == "article" and "tile" in attrs.get("class", "").split():
                self.tiles.append(attrs)
            if tag == "script" and not attrs.get("src"):
                self.in_script = True
            if tag == "select":
                self.in_modes = attrs.get("id") == "route-mode-sel"
            if tag == "option" and self.in_modes:
                self.modes.append(attrs["value"])

        def handle_endtag(self, tag):
            if tag == "script":
                self.in_script = False
            if tag == "select":
                self.in_modes = False

        def handle_data(self, data):
            if self.in_script:
                self.script.append(data)

    parsed = Page()
    parsed.feed(page)
    result = subprocess.run(["node", str(Path(__file__).with_suffix(".mjs"))],
                            input=json.dumps({"tiles": parsed.tiles, "modes": parsed.modes,
                                "defaultMode": parsed.default_mode, "script": "".join(parsed.script)}),
                            text=True, capture_output=True, check=True, timeout=10)
    return json.loads(result.stdout)
