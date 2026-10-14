from __future__ import annotations

import argparse
from contextlib import redirect_stderr
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("citadel_refresh", ROOT / "image/init/citadel-refresh.py")
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class LiveRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.old = self.root / "CITADEL"
        self.old.mkdir()
        (self.old / "webui.py").write_text("# old WebUI\n")
        (self.old / "scan.sh").write_text("# old scan\n")
        self.seed = self.root / "seed"
        self.seed.mkdir()
        for relative in ("webui.py", "python_header.py", "scan.sh", "functions/webui_transport.py",
                         "image/runtime/etc/systemd/system/citadel.service",
                         "image/runtime/etc/systemd/system/citadel-scan.service",
                         "extensions/enabled/caddy/config.json", "extensions/enabled/tailscale/extension.json"):
            path = self.seed / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n")
        self.export = self.root / "exports"
        self.export.mkdir()
        (self.export / "ports.json").write_text('{"preserve": 4000}')
        self.args = argparse.Namespace(source=self.old, export_dir=self.export, repository="local-fixture",
                                       branch="main", backend="container-backend", host=["node.example"],
                                       unit_dir=self.root / "units", instance_dir=self.root / "instance", live=False)
        self.calls = []

    def fake_run(self, command, **kwargs):
        self.calls.append(command)
        if command[:2] == ["git", "clone"]:
            self.assertEqual(kwargs["timeout"], 90)
            self.assertIn("--depth", command)
            shutil.copytree(self.seed, Path(command[-1]))
        if command[0] == "/usr/bin/mv":
            # The only real subprocess here moves our isolated fixture trees.
            for value in command[-2:]:
                self.assertTrue(Path(value).is_relative_to(self.root))
            return subprocess.run(command, check=True, capture_output=True, timeout=10)
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    def execute(self, state="inactive"):
        with patch.dict(os.environ, {"CITADEL_SCAN_LOCK_FILE": str(self.root / "scan.lock")}):
            with patch.object(refresh, "run", side_effect=self.fake_run), patch.object(refresh, "revision", return_value=b"commit"):
                with patch.object(refresh, "active_state", side_effect=lambda name: state if name == "citadel.service" else "inactive"):
                    refresh.refresh(self.args)

    def test_preserves_data_links_and_known_disabled_selection(self):
        (self.old / ".env").write_text("CUSTOM=value\n")
        (self.old / "config.conf").write_text("CUSTOM=keep\nCITADEL_TAILSCALE_SERVE=full\n")
        (self.old / "config.ini").write_text("ca_cert=/custom/cert\n")
        (self.old / "icons").mkdir()
        (self.old / "icons/custom.svg").write_text("custom")
        volume = self.root / "policy.json"
        volume.write_text("policy")
        (self.old / "ports.filter.json").symlink_to(volume)
        cf = self.old / "extensions/enabled/cloudflare"
        cf.mkdir(parents=True)
        (cf / "routes.json").symlink_to(volume)
        (self.seed / "extensions/enabled/cloudflare").mkdir()
        (self.old / "extensions/disabled/tailscale").mkdir(parents=True)
        (self.old / "legacy.py").write_text("old code")
        self.execute()
        self.assertEqual((self.old / ".env").read_text(), "CUSTOM=value\n")
        self.assertIn("CUSTOM=keep", (self.old / "config.conf").read_text())
        self.assertIn("CITADEL_TAILSCALE_SERVE=full", (self.old / "config.conf").read_text())
        self.assertEqual((self.old / "icons/custom.svg").read_text(), "custom")
        self.assertTrue((self.old / "ports.filter.json").is_symlink())
        self.assertTrue((self.old / "extensions/enabled/cloudflare/routes.json").is_symlink())
        self.assertTrue((self.old / "extensions/disabled/tailscale/extension.json").exists())
        self.assertFalse((self.old / "legacy.py").exists())
        self.assertEqual(len(list(self.root.glob(".CITADEL-backup-*"))), 1)
        self.assertEqual((self.export / "ports.json").read_text(), '{"preserve": 4000}')
        self.assertEqual(os.readlink(self.old / "CADDY"), str(self.export))
        self.assertFalse(any(command[1:2] in (["start"], ["stop"], ["restart"]) for command in self.calls))
        for unit in refresh.UNITS:
            self.assertIn("Environment=CITADEL_TAILSCALE_SERVE=full", (self.args.unit_dir / f"{unit}.d/95-citadel-instance.conf").read_text())
            self.assertIn("UnsetEnvironment=CITADEL_PERSISTENT CITADEL_WEBUI_HTTPS_PORT", (self.args.unit_dir / f"{unit}.d/95-citadel-instance.conf").read_text())

    def test_same_commit_still_reconciles_units_without_extra_backup(self):
        self.execute()
        self.execute()
        self.assertEqual(len(list(self.root.glob(".CITADEL-backup-*"))), 1)
        self.assertTrue((self.args.unit_dir / "citadel-scan.service").exists())

    def test_preserves_api_extension_selection_and_whole_port_ignore_file(self):
        enabled = self.old / "extensions/enabled/CLOUDFLARE-API"
        enabled.mkdir(parents=True)
        (enabled / "extension.json").write_text('{"version":"old"}')
        disabled = self.seed / "extensions/disabled/CLOUDFLARE-API"
        disabled.mkdir(parents=True)
        (disabled / "extension.json").write_text('{"version":"new"}')
        (self.old / "CLOUDFLARE-API_ignore.json").write_text('{"ports":[3070]}')
        (self.old / "CLOUDFLARE-API_discovery.json").write_text('{"routes":[]}')
        (self.seed / "CLOUDFLARE-API_ignore.json").write_text('{"ports":[]}')
        self.execute()
        self.assertEqual(json.loads((enabled / "extension.json").read_text()), {"version": "new"})
        self.assertFalse((self.old / "extensions/disabled/CLOUDFLARE-API").exists())
        self.assertEqual(json.loads((self.old / "CLOUDFLARE-API_ignore.json").read_text()), {"ports": [3070]})
        self.assertEqual(json.loads((self.old / "CLOUDFLARE-API_discovery.json").read_text()), {"routes": []})

    def test_shared_instance_files_are_authoritative_and_unchanged(self):
        directory = self.args.instance_dir
        directory.mkdir()
        contents = {
            "instance.conf": "CADDYFILE_START=4500\nCITADEL_TAILSCALE_SERVE=full\nCITADEL_WEBUI_TRANSPORT=tcp\nFASTAPI_HOST=0.0.0.0\nCITADEL_WEBUI_PORT=11000\nPRIVATE_TOKEN=not-copied\n",
            "export-config.json": '{"backend":"shared-backend","hosts":["node.example","localhost","127.0.0.1"]}\n',
            "service.conf": f"[Unit]\nAfter=fedora45-ai-init-hooks.service\n[Service]\nEnvironmentFile={directory}/instance.conf\n",
        }
        for name, content in contents.items():
            (directory / name).write_text(content)
        self.args.backend = None
        self.args.host = None
        self.execute()
        for name, content in contents.items():
            self.assertEqual((directory / name).read_text(), content)
        self.assertEqual((self.old / "extensions/enabled/caddy/config.json").read_text(), contents["export-config.json"])
        config = (self.old / "config.conf").read_text()
        self.assertIn("CADDYFILE_START=4500", config)
        self.assertIn("FASTAPI_HOST=0.0.0.0", config)
        self.assertNotIn("PRIVATE_TOKEN", config)
        for unit in refresh.UNITS:
            dropin = (self.args.unit_dir / f"{unit}.d/95-citadel-instance.conf").read_text()
            self.assertTrue(dropin.startswith(contents["service.conf"]))
            self.assertNotIn("CADDYFILE_START=4000", dropin)

    def test_partial_shared_instance_fails_before_clone(self):
        self.args.instance_dir.mkdir()
        (self.args.instance_dir / "instance.conf").write_text("CADDYFILE_START=4000\n")
        with self.assertRaisesRegex(RuntimeError, "Shared instance requires"):
            self.execute()
        self.assertEqual(self.calls, [])

    def test_live_stops_only_after_clone_and_restarts_only_webui(self):
        self.args.live = True
        self.execute("active")
        stop = ["systemctl", "stop", "citadel.service"]
        self.assertLess(next(i for i, c in enumerate(self.calls) if c[:2] == ["git", "clone"]), self.calls.index(stop))
        self.assertIn(["systemctl", "restart", "citadel.service"], self.calls)
        self.assertFalse(any("citadel-scan.service" in c for c in self.calls))

    def test_boot_refuses_running_webui(self):
        with self.assertRaisesRegex(RuntimeError, "running WebUI"):
            self.execute("active")
        self.assertFalse(any(c[1:2] == ["stop"] for c in self.calls))

    def test_scan_lock_contention_does_not_stop_anything(self):
        with refresh.exclusive_lock(self.root / "scan.lock"):
            with self.assertRaisesRegex(RuntimeError, "scan is running"):
                self.execute()
        self.assertFalse(any(c[1:2] == ["stop"] for c in self.calls))

    def test_install_move_failure_restores_original(self):
        (self.old / "original").write_text("keep")
        move = refresh.move_tree
        def fail_checkout(path, target):
            if path.name == "checkout":
                raise OSError("injected move failure")
            return move(path, target)
        with patch.object(refresh, "move_tree", fail_checkout), self.assertRaises(OSError):
            self.execute()
        self.assertEqual((self.old / "original").read_text(), "keep")

    def reveal_lowerdir_after_backup(self, move):
        def simulated_move(source, target):
            move(source, target)
            if source == self.old and target.parent.name.startswith(".CITADEL-backup-"):
                # fuse-overlayfs can expose image contents after moving an
                # upper-only tree away from the same pathname.
                self.old.mkdir()
                (self.old / "image-original").write_text("preserve lowerdir")
        return simulated_move

    def test_reappearing_lowerdir_is_archived_before_install(self):
        self.args.live = True
        move = self.reveal_lowerdir_after_backup(refresh.move_tree)
        with patch.object(refresh, "move_tree", side_effect=move):
            # No Path.rename fallback may reintroduce EXDEV for source swaps.
            with patch.object(Path, "rename", side_effect=OSError(errno.EXDEV, "overlay rename")):
                self.execute("active")
        self.assertEqual((self.old / "webui.py").read_text(), "{}\n")
        backup = next(self.root.glob(".CITADEL-backup-*/tree"))
        lower = next(self.root.glob(".CITADEL-image-fallback-*/tree"))
        self.assertEqual((backup / "webui.py").read_text(), "# old WebUI\n")
        self.assertEqual((lower / "image-original").read_text(), "preserve lowerdir")
        self.assertIn(["systemctl", "restart", "citadel.service"], self.calls)

    def test_lowerdir_and_failed_install_are_preserved_during_rollback(self):
        self.args.live = True
        move = self.reveal_lowerdir_after_backup(refresh.move_tree)
        def fail_install(source, target):
            if source.name == "checkout":
                target.mkdir()
                (target / "partial-install").write_text("preserve partial tree")
                raise OSError(errno.ENOTEMPTY, "injected incomplete install")
            return move(source, target)
        with patch.object(refresh, "move_tree", side_effect=fail_install), self.assertRaises(OSError):
            self.execute("active")
        self.assertEqual((self.old / "webui.py").read_text(), "# old WebUI\n")
        lower = next(self.root.glob(".CITADEL-image-fallback-*/tree"))
        failed = next(self.root.glob(".CITADEL-failed-*/tree"))
        self.assertTrue((lower / "image-original").exists())
        self.assertTrue((failed / "partial-install").exists())
        self.assertIn(["systemctl", "start", "citadel.service"], self.calls)

    def test_failed_backup_move_does_not_replace_original_with_partial_backup(self):
        self.args.live = True
        def fail_backup(source, target):
            target.mkdir()
            (target / "partial-backup").write_text("retained")
            raise OSError(errno.EXDEV, "injected backup failure")
        with patch.object(refresh, "move_tree", side_effect=fail_backup), self.assertRaises(OSError):
            self.execute("active")
        self.assertEqual((self.old / "webui.py").read_text(), "# old WebUI\n")
        self.assertEqual(len(list(self.root.glob(".CITADEL-backup-*/tree/partial-backup"))), 1)
        self.assertIn(["systemctl", "start", "citadel.service"], self.calls)

    def test_move_refuses_occupied_destination_without_merging(self):
        target = self.root / "occupied"
        target.mkdir()
        (target / "user-file").write_text("keep")
        with self.assertRaisesRegex(RuntimeError, "occupied destination"):
            refresh.move_tree(self.old, target)
        self.assertEqual((target / "user-file").read_text(), "keep")
        self.assertTrue((self.old / "webui.py").exists())

    def test_aligned_config_keeps_unrelated_values_and_is_idempotent(self):
        text = "# comment\nCUSTOM=quoted value\nexport CITADEL_TAILSCALE_SERVE=full\nCITADEL_TAILSCALE_SERVE=full\n"
        result = refresh.aligned_config(text)
        self.assertEqual(result.count("CITADEL_TAILSCALE_SERVE="), 1)
        self.assertIn("CUSTOM=quoted value", result)
        self.assertEqual(refresh.aligned_config(result), result)

    def test_alignment_removes_retired_keys_without_aliasing_them(self):
        text = "# custom settings\nCUSTOM=keep\n" + "".join(
            f"export {key}=old-value\n" for key in refresh.RETIRED
        )
        result = refresh.aligned_config(text, {"CITADEL_TAILSCALE_SERVE": "full"})
        self.assertEqual(result, "# custom settings\nCUSTOM=keep\nCITADEL_TAILSCALE_SERVE=full\n")
        self.assertNotIn("CADDYFILE_START", result)

    def test_failed_live_restart_restores_old_code_and_unit(self):
        self.args.live = True
        self.args.unit_dir.mkdir()
        unit = self.args.unit_dir / "citadel.service"
        unit.write_text("old unit\n")
        original_run = self.fake_run
        def fail_restart(command, **kwargs):
            if command == ["systemctl", "restart", "citadel.service"]:
                raise subprocess.CalledProcessError(1, command)
            return original_run(command, **kwargs)
        with patch.dict(os.environ, {"CITADEL_SCAN_LOCK_FILE": str(self.root / "scan.lock")}):
            with patch.object(refresh, "run", side_effect=fail_restart), patch.object(refresh, "revision", return_value=b"commit"):
                with patch.object(refresh, "active_state", side_effect=lambda name: "active" if name == "citadel.service" else "inactive"):
                    with self.assertRaises(subprocess.CalledProcessError):
                        refresh.refresh(self.args)
        self.assertEqual((self.old / "webui.py").read_text(), "# old WebUI\n")
        self.assertEqual(unit.read_text(), "old unit\n")
        self.assertIn(["systemctl", "start", "citadel.service"], self.calls)
        self.assertEqual(len(list(self.root.glob(".CITADEL-failed-*"))), 1)

    def test_active_scan_refused_without_stopping_webui(self):
        with patch.dict(os.environ, {"CITADEL_SCAN_LOCK_FILE": str(self.root / "scan.lock")}):
            with patch.object(refresh, "run", side_effect=self.fake_run), patch.object(refresh, "active_state", return_value="active"):
                with self.assertRaisesRegex(RuntimeError, "scan is active"):
                    refresh.refresh(self.args)
        self.assertFalse(any(c[1:2] == ["stop"] for c in self.calls))


if __name__ == "__main__":
    unittest.main()
