"""Offline contract tests; the real Tailscale CLI is never called."""
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parent / "image/runtime"
SCRIPT = (RUNTIME / "usr/local/bin/tailscale-serve-reset.sh"
          if RUNTIME.is_dir() else HERE / "tailscale-serve-reset.sh")
DROPIN = (RUNTIME / "etc/systemd/system/tailscale-up.service.d/tailscale-serve-reset.conf"
          if RUNTIME.is_dir() else HERE / "tailscale-serve-reset.conf")


class TailscaleServeResetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.log = self.directory / "calls"
        self.cli = self.directory / "tailscale"
        self.cli.write_text(
            '#!/bin/sh\nif [ "$1" = status ]; then printf \'{"BackendState":"Running"}\\n\'; exit 0; fi\n'
            'printf "%s\\n" "$@" >> "$RESET_TEST_LOG"\n'
            'exit "${RESET_TEST_EXIT:-0}"\n'
        )
        self.cli.chmod(0o755)
        for name in ("date", "sleep", "timeout", "jq"):
            (self.directory / name).symlink_to(shutil.which(name))
        # An isolated PATH prevents accidental access to host Tailscale.
        self.env = {"PATH": str(self.directory), "RESET_TEST_LOG": str(self.log)}

    def run_reset(self, value=None, **environment):
        env = self.env | environment
        if value is not None:
            env["TAILSCALE_SERVE_RESET"] = value
        return subprocess.run(["/bin/sh", str(SCRIPT)], env=env,
                              capture_output=True, text=True, timeout=3)

    def test_unset_is_a_noop(self):
        self.assertEqual(self.run_reset().returncode, 0)
        self.assertFalse(self.log.exists())

    def test_every_value_except_literal_one_is_a_noop(self):
        for value in ("", "0", "blank", "false", "true", "yes", "01", " 1 ", "2"):
            with self.subTest(value=value):
                self.assertEqual(self.run_reset(value).returncode, 0)
                self.assertFalse(self.log.exists())

    def test_one_only_resets_serve_and_does_not_touch_ssh_or_login(self):
        self.assertEqual(self.run_reset("1").returncode, 0)
        self.assertEqual(self.log.read_text(), "serve\nreset\n")

    def test_independent_of_citadel_scan_setting(self):
        self.assertEqual(self.run_reset("1", CITADEL_TAILSCALE_SERVE="off").returncode, 0)
        self.assertEqual(self.log.read_text(), "serve\nreset\n")
        self.log.unlink()
        self.assertEqual(self.run_reset("0", CITADEL_TAILSCALE_SERVE="full").returncode, 0)
        self.assertFalse(self.log.exists())

    def test_disabled_does_not_need_a_tailscale_installation(self):
        self.cli.unlink()
        self.assertEqual(self.run_reset("0").returncode, 0)
        self.assertEqual(self.run_reset().returncode, 0)
        self.assertNotEqual(self.run_reset("1").returncode, 0)

    def test_reset_failure_is_not_ignored_or_retried(self):
        self.assertEqual(self.run_reset("1", RESET_TEST_EXIT="23").returncode, 23)
        self.assertEqual(self.log.read_text(), "serve\nreset\n")

    def test_service_passes_the_flag_to_the_post_up_helper(self):
        self.assertEqual(DROPIN.read_text().splitlines(), [
            "[Service]", "PassEnvironment=TAILSCALE_SERVE_RESET",
            "ExecStartPost=/usr/local/bin/tailscale-serve-reset.sh",
        ])
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
