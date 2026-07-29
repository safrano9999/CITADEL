from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESCAN = ROOT / "tailscale-rescan.sh"


class TailscaleRescanTests(unittest.TestCase):
    def fixture(self, base: Path) -> dict[str, str]:
        binary_dir = base / "bin"
        binary_dir.mkdir()
        listeners = base / "listeners"
        listeners.write_text(
            "LISTEN 0 4096 0.0.0.0:11000 0.0.0.0:*\n",
            encoding="utf-8",
        )
        calls = base / "calls"
        tailscale_state = base / "tailscale.json"

        scripts = {
            "ss": '#!/usr/bin/env bash\ncat "$FAKE_LISTENERS"\n',
            "tailscale": (
                "#!/usr/bin/env bash\n"
                '[[ "$*" == "serve status --json" ]] || exit 2\n'
                "printf '%s\\n' '{\"TCP\":{}}'\n"
            ),
            "scan": (
                "#!/usr/bin/env bash\n"
                'printf "%s\\n" "$*" >> "$FAKE_SCAN_CALLS"\n'
                "printf '{\"enabled\":true,\"running\":%s,"
                "\"route_failures\":{}}\\n' "
                '"${FAKE_TAILSCALE_RUNNING:-true}" '
                '> "$FAKE_TAILSCALE_STATE"\n'
            ),
        }
        for name, source in scripts.items():
            path = binary_dir / name
            path.write_text(source, encoding="utf-8")
            path.chmod(0o755)

        return {
            **os.environ,
            "PATH": f"{binary_dir}:/usr/bin:/bin",
            "FAKE_LISTENERS": str(listeners),
            "FAKE_SCAN_CALLS": str(calls),
            "FAKE_TAILSCALE_STATE": str(tailscale_state),
            "CITADEL_SCAN_SCRIPT": str(binary_dir / "scan"),
            "CITADEL_TAILSCALE_STATE_FILE": str(tailscale_state),
            "CITADEL_TAILSCALE_RESCAN_STATE": str(base / "rescan.state"),
            "CITADEL_TAILSCALE_RESCAN_MAX_AGE": "300",
        }

    def run_rescan(
        self,
        environ: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(RESCAN)],
            env=environ,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_skips_unchanged_state_and_runs_after_listener_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            environ = self.fixture(base)

            first = self.run_rescan(environ)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(
                (base / "calls").read_text(encoding="utf-8").splitlines(),
                ["--provider tailscale"],
            )

            second = self.run_rescan(environ)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("listeners unchanged", second.stdout)
            self.assertEqual(
                (base / "calls").read_text(encoding="utf-8").splitlines(),
                ["--provider tailscale"],
            )

            (base / "listeners").write_text(
                "LISTEN 0 4096 0.0.0.0:11000 0.0.0.0:*\n"
                "LISTEN 0 4096 127.0.0.1:11040 0.0.0.0:*\n",
                encoding="utf-8",
            )
            third = self.run_rescan(environ)
            self.assertEqual(third.returncode, 0, third.stderr)
            self.assertEqual(
                (base / "calls").read_text(encoding="utf-8").splitlines(),
                ["--provider tailscale", "--provider tailscale"],
            )

    def test_pending_tailscale_state_is_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            environ = self.fixture(base)
            environ["FAKE_TAILSCALE_RUNNING"] = "false"

            first = self.run_rescan(environ)
            second = self.run_rescan(environ)
            self.assertNotEqual(first.returncode, 0)
            self.assertNotEqual(second.returncode, 0)
            self.assertFalse((base / "rescan.state").exists())
            self.assertEqual(
                (base / "calls").read_text(encoding="utf-8").splitlines(),
                ["--provider tailscale", "--provider tailscale"],
            )
            payload = json.loads(
                (base / "tailscale.json").read_text(encoding="utf-8")
            )
            self.assertFalse(payload["running"])

    def test_injected_disabled_value_never_runs_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            environ = self.fixture(base)
            environ["CITADEL_TAILSCALE"] = "false"

            result = self.run_rescan(environ)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("reconciliation is disabled", result.stdout)
            self.assertFalse((base / "calls").exists())
            self.assertFalse((base / "rescan.state").exists())

    def test_injected_zero_max_age_forces_unchanged_rescan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            environ = self.fixture(base)

            first = self.run_rescan(environ)
            self.assertEqual(first.returncode, 0, first.stderr)
            environ["CITADEL_TAILSCALE_RESCAN_MAX_AGE"] = "0"
            second = self.run_rescan(environ)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("reached max age", second.stdout)
            self.assertEqual(
                (base / "calls").read_text(encoding="utf-8").splitlines(),
                ["--provider tailscale", "--provider tailscale"],
            )


if __name__ == "__main__":
    unittest.main()
