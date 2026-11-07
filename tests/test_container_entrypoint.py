import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, mock_open, patch

from container.entrypoint import configure_optional_clients, enabled, start_cloudflare, start_tailscale


class OptionalClientTests(unittest.TestCase):
    def setUp(self):
        # Tests must not inherit the developer host's authenticated Tailscale socket.
        exists = Path.exists
        self.enterContext(patch("container.entrypoint.Path.exists", autospec=True,
                               side_effect=lambda path: str(path) != "/var/run/tailscale/tailscaled.sock"
                               and exists(path)))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "extensions/disabled").mkdir(parents=True)
        for provider in ("tailscale", "cloudflare"):
            directory = self.root / "extensions/enabled" / provider
            directory.mkdir(parents=True)
            (directory / "extension.json").write_text(json.dumps({"enabled": True}))

    def test_missing_credentials_disable_clients_on_overlay_filesystems(self):
        with patch.dict(os.environ, {}, clear=True), patch(
            "shutil.os.rename", side_effect=OSError(errno.EXDEV, "cross-device rename")
        ):
            configure_optional_clients(self.root)
            configure_optional_clients(self.root)
        for provider in ("tailscale", "cloudflare"):
            self.assertFalse(enabled(self.root, provider))
            self.assertTrue((self.root / "extensions/disabled" / provider / "extension.json").is_file())

    def test_existing_cloudflare_credentials_do_not_require_a_tailscale_key(self):
        for key in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_TUNNEL_TOKEN"):
            with self.subTest(key=key), patch.dict(os.environ, {key: "test-only"}, clear=True):
                configure_optional_clients(self.root)
                self.assertTrue(enabled(self.root, "cloudflare"))
                self.assertFalse(enabled(self.root, "tailscale"))

    def test_present_credentials_leave_both_extensions_enabled(self):
        with patch.dict(os.environ, {"TS_AUTHKEY": "test-only", "CLOUDFLARE_API_TOKEN": "test-only"}, clear=True):
            configure_optional_clients(self.root)
            self.assertTrue(enabled(self.root, "tailscale"))

    def test_tailscaled_gets_certificate_storage_as_well_as_identity_state(self):
        runtime = Mock()
        with patch.dict(os.environ, {"TS_AUTHKEY": "test-only"}, clear=True), \
                patch("container.entrypoint.Path.exists", return_value=False), \
                patch("container.entrypoint.tailscale_state", return_value="Running"), \
                patch("container.entrypoint.subprocess.run", return_value=Mock(returncode=0)):
            start_tailscale(runtime, self.root)
        runtime.start.assert_called_once_with(
            "tailscaled", f"--statedir={self.root / 'CITADEL_TAILSCALE'}")
        self.assertTrue(enabled(self.root, "cloudflare"))

    def test_cloudflare_uses_http2_by_default_and_respects_explicit_transport(self):
        for configured, expected in ((None, "http2"), ("", "http2"), ("  ", "http2"),
                                     ("http2", "http2"), ("auto", "auto"), ("quic", "quic")):
            with self.subTest(protocol=configured):
                runtime = Mock()
                env = {"CLOUDFLARE_TUNNEL_TOKEN": "test-only-token"}
                if configured is not None:
                    env["TUNNEL_TRANSPORT_PROTOCOL"] = configured
                token_file = mock_open()
                with patch.dict(os.environ, env, clear=True), patch("builtins.open", token_file):
                    start_cloudflare(runtime, self.root)
                runtime.start.assert_called_once_with(
                    "cloudflared", "tunnel", "--no-autoupdate", "--protocol", expected,
                    "run", "--token-file", "/run/citadel/cloudflared.token")
                token_file().write.assert_called_once_with("test-only-token")
                self.assertNotIn("test-only-token", runtime.start.call_args.args)

    def test_invalid_cloudflare_transport_fails_before_start_or_token_write(self):
        runtime = Mock()
        env = {"CLOUDFLARE_TUNNEL_TOKEN": "test-only-token", "TUNNEL_TRANSPORT_PROTOCOL": "http3"}
        with patch.dict(os.environ, env, clear=True), patch("builtins.open") as token_file:
            with self.assertRaisesRegex(ValueError, "TUNNEL_TRANSPORT_PROTOCOL must be"):
                start_cloudflare(runtime, self.root)
        runtime.start.assert_not_called()
        token_file.assert_not_called()

    def test_cloudflare_without_credentials_does_not_start_a_connector(self):
        runtime = Mock()
        with patch.dict(os.environ, {}, clear=True), patch("builtins.open") as token_file:
            start_cloudflare(runtime, self.root)
        runtime.start.assert_not_called()
        token_file.assert_not_called()

    def test_disabled_cloudflare_does_not_start_a_connector(self):
        (self.root / "extensions/enabled/cloudflare/extension.json").write_text('{"enabled": false}')
        runtime = Mock()
        with patch.dict(os.environ, {"CLOUDFLARE_TUNNEL_TOKEN": "test-only-token"}, clear=True), \
                patch("builtins.open") as token_file:
            start_cloudflare(runtime, self.root)
        runtime.start.assert_not_called()
        token_file.assert_not_called()


if __name__ == "__main__":
    unittest.main()
