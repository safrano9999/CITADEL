from __future__ import annotations

from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import webui
from webui_transport import bind_unix_socket, unix_socket_path, listener_ready, probe_target


ROOT = Path(__file__).resolve().parents[1]


class TransportSelectionTests(unittest.TestCase):
    def test_tcp_unset_blank_and_explicit_preserve_default_bind(self):
        for value in (None, "", "  ", "tcp"):
            environment = {} if value is None else {"CITADEL_WEBUI_TRANSPORT": value}
            with self.subTest(value=value), patch.dict(os.environ, environment, clear=True):
                with patch.object(webui.uvicorn, "run") as run:
                    self.assertEqual(webui.main([]), 0)
                run.assert_called_once_with(webui.app, host="127.0.0.1", port=11000)

    def test_tcp_preserves_configured_bind_and_ignores_unused_socket(self):
        environment = {"FASTAPI_HOST": "192.0.2.10", "CITADEL_WEBUI_PORT": "12000",
                       "CITADEL_WEBUI_SOCKET": "relative", "XDG_RUNTIME_DIR": "relative"}
        with patch.dict(os.environ, environment, clear=True), patch.object(webui.uvicorn, "run") as run:
            webui.main([])
        run.assert_called_once_with(webui.app, host="192.0.2.10", port=12000)

    def test_unix_defaults_and_runtime_expansion(self):
        for runtime, expected in ((None, "/run"), ("", "/run"), ("/run/user/123", "/run/user/123")):
            for value in (None, "", "%t/citadel/citadel.sock"):
                environment = {"CITADEL_WEBUI_TRANSPORT": "unix"}
                if runtime is not None:
                    environment["XDG_RUNTIME_DIR"] = runtime
                if value is not None:
                    environment["CITADEL_WEBUI_SOCKET"] = value
                with self.subTest(runtime=runtime, value=value):
                    target = Path(expected) / "citadel/citadel.sock" if value else ROOT / "CITADEL_DATA/CADDY/citadel.sock"
                    self.assertEqual(unix_socket_path(environment), target)

    def test_explicit_unix_does_not_depend_on_runtime_or_container(self):
        self.assertEqual(unix_socket_path({
            "CITADEL_WEBUI_TRANSPORT": "unix", "CITADEL_WEBUI_SOCKET": "/tmp/custom.sock",
            "XDG_RUNTIME_DIR": "unused-relative", "container": "podman",
        }), Path("/tmp/custom.sock"))

    def test_invalid_transports_and_paths_are_rejected(self):
        for value in ("udp", "auto", "socket", "UNIX", "default"):
            with self.subTest(transport=value), self.assertRaisesRegex(ValueError, "CITADEL_WEBUI_TRANSPORT"):
                unix_socket_path({"CITADEL_WEBUI_TRANSPORT": value})
        for value in ("relative.sock", "~/citadel.sock", "%x/citadel.sock", "/", "/tmp/", "/tmp/.", "/tmp/../x.sock", "/tmp/\0sock"):
            with self.subTest(path=value), self.assertRaisesRegex(ValueError, "CITADEL_WEBUI_SOCKET"):
                unix_socket_path({"CITADEL_WEBUI_TRANSPORT": "unix", "CITADEL_WEBUI_SOCKET": value})
        with self.assertRaisesRegex(ValueError, "XDG_RUNTIME_DIR"):
            unix_socket_path({"CITADEL_WEBUI_TRANSPORT": "unix", "CITADEL_WEBUI_SOCKET": "%t/citadel.sock", "XDG_RUNTIME_DIR": "relative"})

    def test_readiness_and_start_share_defaults(self):
        with patch.dict(os.environ, {"CITADEL_WEBUI_TRANSPORT": "unix"}, clear=True):
            self.assertEqual(probe_target(), ["unix", str(ROOT / "CITADEL_DATA/CADDY/citadel.sock")])
        with patch.dict(os.environ, {"FASTAPI_HOST": "::", "CITADEL_WEBUI_PORT": "12000"}, clear=True):
            with patch("webui_transport.socket.create_connection") as connect:
                self.assertTrue(listener_ready())
                connect.assert_called_once_with(("::1", 12000), timeout=0.5)

    def test_invalid_configuration_exits_before_starting_uvicorn(self):
        with patch.dict(os.environ, {"CITADEL_WEBUI_TRANSPORT": "invalid"}, clear=True):
            with patch.object(webui.uvicorn, "run") as run, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    webui.main([])
        self.assertEqual(error.exception.code, 2)
        run.assert_not_called()

    def test_readiness_uses_selected_transport_without_creating_socket(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing" / "citadel.sock"
            cases = [
                ({}, ["tcp", "127.0.0.1", "11000"]),
                ({"FASTAPI_HOST": "0.0.0.0", "CITADEL_WEBUI_PORT": "12000"}, ["tcp", "127.0.0.1", "12000"]),
                ({"FASTAPI_HOST": "::"}, ["tcp", "::1", "11000"]),
                ({"CITADEL_WEBUI_TRANSPORT": "unix", "CITADEL_WEBUI_SOCKET": str(path),
                  "CITADEL_WEBUI_PORT": "unused-invalid"}, ["unix", str(path)]),
            ]
            for environment, target in cases:
                with self.subTest(target=target), patch.dict(os.environ, environment, clear=True):
                    with patch.object(webui.subprocess, "run") as run, patch.object(webui.uvicorn, "run") as server:
                        run.return_value.returncode = 7
                        self.assertEqual(webui.main(["--wait-ready", "/test/wait-ready"]), 7)
                        run.assert_called_once_with(["/test/wait-ready", "--timeout", "60", *target], check=False)
                        server.assert_not_called()
            self.assertFalse(path.parent.exists())


class UnixSocketOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "citadel.sock"

    def test_creates_only_socket_directory_and_cleans_owned_socket(self):
        self.root.chmod(0o750)
        path = self.root / "citadel" / "citadel.sock"
        with bind_unix_socket(path) as listener:
            self.assertTrue(path.is_socket())
            self.assertEqual(listener.getsockname(), str(path))
        self.assertFalse(path.exists())
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o750)
        self.assertEqual(list(self.root.iterdir()), [path.parent])

    def test_preserves_existing_parent_permissions(self):
        self.root.chmod(0o711)
        with bind_unix_socket(self.path):
            self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o711)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o711)

    def test_does_not_create_missing_ancestors(self):
        with self.assertRaises(FileNotFoundError):
            with bind_unix_socket(self.root / "missing" / "parent" / "citadel.sock"):
                self.fail("unexpected bind")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_refuses_regular_file_directory_and_symlink(self):
        target = self.root / "target"
        target.write_text("preserve")
        for kind in ("file", "directory", "symlink", "broken-symlink"):
            path = self.root / kind
            if kind == "file":
                path.write_text("preserve")
            elif kind == "directory":
                path.mkdir()
            else:
                path.symlink_to(target if kind == "symlink" else self.root / "missing")
            before = path.lstat()
            with self.subTest(kind=kind), self.assertRaises(OSError):
                with bind_unix_socket(path):
                    self.fail("unexpected bind")
            self.assertEqual(path.lstat().st_ino, before.st_ino)
        self.assertEqual(target.read_text(), "preserve")

    def test_replaces_live_and_stale_sockets(self):
        for live in (True, False):
            with self.subTest(live=live), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as existing:
                existing.bind(str(self.path))
                if live:
                    existing.listen(1)
                else:
                    existing.close()
                with bind_unix_socket(self.path) as listener:
                    listener.listen(1)
                    listener.settimeout(1)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.connect(str(self.path))
                        client.sendall(b"new listener")
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(1)
                            self.assertEqual(connection.recv(32), b"new listener")
                self.assertFalse(self.path.exists())

    def test_cleanup_preserves_replacement_file_and_live_socket(self):
        with bind_unix_socket(self.path):
            self.path.unlink()
            self.path.write_text("replacement")
        self.assertEqual(self.path.read_text(), "replacement")
        self.path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
            with bind_unix_socket(self.path):
                self.path.unlink()
                replacement.bind(str(self.path))
                replacement.listen(1)
                inode = self.path.stat().st_ino
            self.assertEqual(self.path.stat().st_ino, inode)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(self.path))

    def test_startup_error_cleans_socket_and_restores_signal_handler(self):
        environment = {"CITADEL_WEBUI_TRANSPORT": "unix", "CITADEL_WEBUI_SOCKET": str(self.path),
                       "CITADEL_WEBUI_PORT": "unused-invalid"}
        previous = signal.getsignal(signal.SIGTERM)
        with patch.dict(os.environ, environment, clear=True), patch.object(webui.uvicorn, "run", side_effect=RuntimeError("startup")):
            with self.assertRaisesRegex(RuntimeError, "startup"):
                webui.main([])
        self.assertFalse(self.path.exists())
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)


class LiveUnixTransportTests(unittest.TestCase):
    def test_python_entrypoint_serves_unix_and_cleans_up_on_sigterm(self):
        # Copy only code into a temporary project: no host config or services.
        with tempfile.TemporaryDirectory(prefix="citadel-uds-") as temporary:
            root = Path(temporary)
            for name in ("webui.py", "python_header.py"):
                shutil.copy2(ROOT / name, root / name)
            shutil.copytree(ROOT / "functions", root / "functions", ignore=shutil.ignore_patterns("__pycache__"))
            (root / "assets").mkdir()
            instance_ids = []
            for source in ("config", "environment"):
                with self.subTest(source=source):
                    runtime = root / source
                    runtime.mkdir()
                    path = runtime / "citadel" / "citadel.sock"
                    environment = {"PATH": os.defpath, "XDG_RUNTIME_DIR": str(runtime), "PYTHONUNBUFFERED": "1"}
                    config = "CITADEL_WEBUI_TRANSPORT=unix\nCITADEL_WEBUI_SOCKET=%t/citadel/citadel.sock\n"
                    if source == "environment":
                        config = "CITADEL_WEBUI_TRANSPORT=invalid\nCITADEL_WEBUI_SOCKET=relative\n"
                        environment.update(CITADEL_WEBUI_TRANSPORT="unix", CITADEL_WEBUI_SOCKET=str(path), container="podman")
                    (root / "config.conf").write_text(config + "CITADEL_WEBUI_PORT=unused-invalid\n")
                    process = subprocess.Popen([sys.executable, "-s", str(root / "webui.py")], cwd=root,
                                               env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    output = ""
                    try:
                        deadline = time.monotonic() + 15
                        while True:
                            if process.poll() is not None:
                                self.fail(f"WebUI exited early: {process.communicate()[0]}")
                            try:
                                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                                    client.settimeout(1)
                                    client.connect(str(path))
                                    client.sendall(b"GET /openapi.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                                    response = b""
                                    while chunk := client.recv(65536):
                                        response += chunk
                                break
                            except OSError:
                                if time.monotonic() >= deadline:
                                    self.fail("Unix HTTP listener did not become ready")
                                time.sleep(0.05)
                        self.assertIn(b"HTTP/1.1 200 OK", response)
                        self.assertIn(b'"openapi"', response)
                        self.assertTrue(path.is_socket())
                        header = next(line for line in response.split(b"\r\n") if line.lower().startswith(b"x-citadel-instance:"))
                        instance_id = header.split(b":", 1)[1].strip().decode("ascii")
                        self.assertRegex(instance_id, r"^[0-9a-f]{32}$")
                        instance_ids.append(instance_id)
                        # Both handled errors and an absent fixture's unhandled
                        # FileResponse error identify the same backend.
                        for request_path, status in (("/missing", 404), ("/citadel.svg", 500)):
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                                client.settimeout(2)
                                client.connect(str(path))
                                client.sendall(f"GET {request_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
                                response = b""
                                while chunk := client.recv(65536):
                                    response += chunk
                            self.assertIn(f"HTTP/1.1 {status} ".encode(), response)
                            self.assertIn(header, response)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                        try:
                            output = process.communicate(timeout=10)[0]
                        except subprocess.TimeoutExpired:
                            process.kill()
                            output = process.communicate(timeout=5)[0]
                            self.fail(f"WebUI did not stop gracefully: {output}")
                    self.assertEqual(process.returncode, 0, output)
                    self.assertFalse(path.exists(), output)
            self.assertEqual(len(set(instance_ids)), 2)


if __name__ == "__main__":
    unittest.main()
