import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROVIDERS_DIR = Path(__file__).resolve().parents[1] / "functions" / "providers"
sys.path.insert(0, str(PROVIDERS_DIR))

import atomic_io


class AtomicJsonTests(unittest.TestCase):
    def test_replaces_complete_json_and_preserves_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            path.write_text('{"old": true}\n', encoding="utf-8")
            path.chmod(0o640)

            atomic_io.atomic_write_json(path, {"new": [1, 2, 3]})

            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"new": [1, 2, 3]})
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_failed_replace_leaves_original_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            original = '{"stable": true}\n'
            path.write_text(original, encoding="utf-8")

            with mock.patch.object(atomic_io.os, "replace", side_effect=OSError("failed")):
                with self.assertRaises(OSError):
                    atomic_io.atomic_write_json(path, {"partial": True})

            self.assertEqual(path.read_text(encoding="utf-8"), original)
            self.assertEqual(list(path.parent.glob(".state.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
