from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DaemonInstallerTests(unittest.TestCase):
    def render(self, transport: str | None) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "set_daemon.sh"
            script.write_text((ROOT / "set_daemon.sh").read_text())
            if transport is not None:
                (root / "config.conf").write_text(
                    f"CITADEL_WEBUI_TRANSPORT={transport}\n"
                    "CITADEL_WEBUI_SOCKET=%t/citadel/citadel.sock\n"
                )
            environment = dict(os.environ)
            environment.pop("PYTHON_BIN", None)
            # A project Python on PATH must not become the service interpreter.
            bin_dir = root / "bin"
            bin_dir.mkdir()
            python = bin_dir / "python3"
            python.write_text("#!/bin/sh\nexit 99\n")
            python.chmod(0o755)
            for command in ("systemctl", "loginctl"):
                stub = bin_dir / command
                stub.write_text('#!/bin/sh\ntouch "$CALL_LOG"\nexit 99\n')
                stub.chmod(0o755)
            environment["CALL_LOG"] = str(root / "service-calls")
            environment["XDG_CONFIG_HOME"] = str(root / "config")
            environment["XDG_RUNTIME_DIR"] = str(root / "runtime")
            environment["PATH"] = f"{bin_dir}:{environment['PATH']}"
            subprocess.run(
                ["bash", str(script), "--render-only"], env=environment,
                check=True, capture_output=True, text=True, timeout=10,
            )
            self.assertFalse((root / "service-calls").exists())
            self.assertFalse((root / "config").exists())
            self.assertFalse((root / "runtime").exists())
            self.assertFalse((root / ".systemd").exists())
            self.assertIn(f"WorkingDirectory={root}\n", (root / "citadel.service").read_text())
            return (root / "citadel.service").read_text()

    def test_unix_service_uses_shared_python_entrypoint(self) -> None:
        unit = self.render("unix")
        self.assertIn("ExecStart=/usr/bin/python3 -E ", unit)
        self.assertIn("/webui.py\n", unit)
        self.assertNotIn("RuntimeDirectory", unit)
        self.assertNotIn("--uds", unit)
        self.assertNotIn(".venv", unit)

    def test_tcp_service_uses_system_python_without_ambient_python_environment(self) -> None:
        for transport in (None, "", "tcp"):
            with self.subTest(transport=transport):
                unit = self.render(transport)
                self.assertIn("ExecStart=/usr/bin/python3 -E ", unit)
                self.assertIn("/webui.py\n", unit)
                self.assertNotIn("RuntimeDirectory=", unit)

    def test_render_defers_transport_validation_to_runtime(self) -> None:
        self.assertIn("/webui.py\n", self.render("invalid"))

    def test_dependency_check_precedes_writes_and_restarts_existing_service(self) -> None:
        script = (ROOT / "set_daemon.sh").read_text()
        self.assertLess(script.index("import dotenv, fastapi, jinja2, uvicorn"), script.index('mkdir -p "$LOCAL_UNIT_DIR"'))
        self.assertIn('systemctl --user restart "$UNIT_NAME"', script)


if __name__ == "__main__":
    unittest.main()
