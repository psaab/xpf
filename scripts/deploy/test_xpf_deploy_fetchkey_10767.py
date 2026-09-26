"""#10767 F5/F6: preserve a prior Incus alias on staging failure and verify
rotation sidecars pinned only by the incoming key, including latest.json.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parents[1]
sys.path.insert(0, str(_ROOT / "scripts" / "dist"))
import sign  # noqa: E402

_SPEC = importlib.util.spec_from_file_location("xpf_deploy_10767", _HERE / "xpf-deploy.py")
deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(deploy)


@unittest.skipUnless(shutil.which("minisign") and shutil.which("curl"),
                     "minisign and curl are required")
class FetchKeyRotation10767(unittest.TestCase):
    VER = "1.2.3-4-gbbbbbbb"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-10767-fetchkey."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.old_pub, self.old_sec = self._keypair("old")
        self.new_pub, self.new_sec = self._keypair("new")
        self.host = self.tmp / "host"
        self.host.mkdir()
        self.out = self.tmp / "out"
        self.names = {
            "qcow2": f"xpf-{self.VER}.qcow2",
            "metadata": f"xpf-{self.VER}.incus-metadata.tar.gz",
            "manifest": f"xpf-{self.VER}.SHA256SUMS",
            "sig": f"xpf-{self.VER}.SHA256SUMS.minisig",
        }
        (self.host / self.names["qcow2"]).write_bytes(b"signed qcow2 image\n" * 32)
        (self.host / self.names["metadata"]).write_bytes(b"signed metadata\n" * 4)
        self.manifest = self.host / self.names["manifest"]
        sign.write_manifest(str(self.manifest), [
            str(self.host / self.names["qcow2"]),
            str(self.host / self.names["metadata"]),
        ])
        sign.sign_manifest(str(self.manifest), [str(self.old_sec), str(self.new_sec)])

        self.saved_env = {name: os.environ.get(name) for name in (
            "XPF_IMAGE_PUBKEY", "XPF_IMAGE_PUBKEYS", "XDG_STATE_HOME")}
        os.environ.pop("XPF_IMAGE_PUBKEY", None)
        os.environ.pop("XPF_IMAGE_PUBKEYS", None)
        os.environ["XDG_STATE_HOME"] = str(self.tmp / "state")
        self.addCleanup(self._restore_env)

        self.real_run = subprocess.run
        self.real_copyfile = shutil.copyfile
        self.incu_calls = []
        self.staged_names = []
        self.aliases = {"xpf-appliance": "old-fingerprint"}
        self.alias_present = True
        self.fail_switch = False

    def _keypair(self, name):
        pub, sec = self.tmp / f"{name}.pub", self.tmp / f"{name}.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(pub), "-s", str(sec)],
                       check=True, capture_output=True)
        return pub, sec

    def _restore_env(self):
        for name, value in self.saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def _args(self, pubkey=None):
        self.out.mkdir(exist_ok=True)
        return argparse.Namespace(
            version=self.VER, image_url=self.host.as_uri(), out=str(self.out),
            alias="xpf-appliance", channel="stable", allow_rollback=False,
            allow_unvalidated=False, qcow2_only=False, install_libvirt=False,
            no_import=False, dry_run=False,
            pubkey=pubkey or [str(self.new_pub)])

    def _run(self, argv, *args, **kwargs):
        if argv and argv[0] == "incus":
            self.incu_calls.append(list(argv))
            if argv[1] == "image" and argv[2] == "import":
                self.assertCountEqual(self.staged_names,
                                      [self.names["metadata"], self.names["qcow2"]],
                                      "Incus import ran before both private copies staged")
                self.assertIn("xpf-appliance", self.aliases,
                              "the old alias must remain during image import")
                if self.fail_import:
                    return subprocess.CompletedProcess(argv, 1, "", "import failed")
                imported = argv[argv.index("--alias") + 1]
                self.aliases[imported] = "new-fingerprint"
            elif argv[1] == "image" and argv[2] == "alias" and argv[3] == "rename":
                source, destination = argv[4], argv[5]
                if (source not in self.aliases or destination in self.aliases
                        or (self.fail_switch and source.startswith("xpf-fetch-"))):
                    return subprocess.CompletedProcess(argv, 1, "", "alias rename failed")
                self.aliases[destination] = self.aliases.pop(source)
                self.alias_present = "xpf-appliance" in self.aliases
            elif argv[1] == "image" and argv[2] == "alias" and argv[3] == "delete":
                self.aliases.pop(argv[4], None)
                self.alias_present = "xpf-appliance" in self.aliases
            return subprocess.CompletedProcess(argv, 0, "", "")
        return self.real_run(argv, *args, **kwargs)

    def _copyfile(self, src, dst, *args, **kwargs):
        src_name = Path(src).name
        stage = Path(dst).parent.name.startswith("xpf-verify-")
        if stage and src_name in (self.names["metadata"], self.names["qcow2"]):
            self.staged_names.append(src_name)
            if src_name == self.names["qcow2"] and self.fail_qcow_stage:
                raise OSError(errno.ENOSPC, "No space left on device", str(dst))
        return self.real_copyfile(src, dst, *args, **kwargs)

    def _fetch(self, fail_qcow_stage=False, no_import=False, fail_import=False,
               fail_switch=False, pubkey=None):
        self.fail_qcow_stage = fail_qcow_stage
        self.fail_import = fail_import
        self.fail_switch = fail_switch
        args = self._args(pubkey)
        args.no_import = no_import
        buf = io.StringIO()
        with mock.patch.object(subprocess, "run", side_effect=self._run), \
                mock.patch.object(shutil, "copyfile", side_effect=self._copyfile), \
                contextlib.redirect_stdout(buf):
            rc = deploy.cmd_fetch(args)
        return rc, buf.getvalue()

    def test_staging_enospc_keeps_the_previous_alias(self):
        with self.assertRaises(OSError) as caught:
            self._fetch(fail_qcow_stage=True)
        self.assertEqual(caught.exception.errno, errno.ENOSPC)
        self.assertTrue(self.alias_present)
        self.assertFalse(self.incu_calls,
                         "Incus must not replace the alias before staging succeeds")
        self.assertEqual(self.staged_names, [self.names["metadata"], self.names["qcow2"]])

    def test_successful_import_switches_alias_after_staging(self):
        rc, _ = self._fetch()
        self.assertEqual(rc, 0)
        self.assertEqual([(call[2] if call[2] == "import" else call[3])
                         for call in self.incu_calls],
                         ["import", "rename", "rename", "delete"])
        self.assertEqual(self.aliases, {"xpf-appliance": "new-fingerprint"})
        self.assertTrue(self.alias_present)

    def test_import_failure_keeps_the_previous_alias(self):
        with self.assertRaises(SystemExit):
            self._fetch(fail_import=True)
        self.assertEqual([call[2] if call[2] == "import" else call[3]
                         for call in self.incu_calls], ["import"])
        self.assertEqual(self.aliases, {"xpf-appliance": "old-fingerprint"})
        self.assertTrue(self.alias_present)

    def test_alias_switch_failure_restores_the_previous_alias(self):
        with self.assertRaises(SystemExit):
            self._fetch(fail_switch=True)
        self.assertEqual(self.aliases, {"xpf-appliance": "old-fingerprint"})
        self.assertTrue(self.alias_present)

    def test_fetch_accepts_manifest_signed_by_new_key_only(self):
        rc, _ = self._fetch(no_import=True)
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / self.names["qcow2"]).is_file())
        self.assertFalse(self.incu_calls)

    def test_legacy_fetch_accepts_old_key_from_canonical_signature(self):
        rc, _ = self._fetch(no_import=True, pubkey=[str(self.old_pub)])
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / self.names["qcow2"]).is_file())

    def test_latest_pointer_is_downloaded_with_the_key_addressed_signature(self):
        channel = self.host / "stable"
        channel.mkdir()
        latest = channel / "latest.json"
        latest.write_text(json.dumps({"channel": "stable", "version": self.VER}) + "\n")
        sign.sign_manifest(str(latest), [str(self.old_sec), str(self.new_sec)])
        resolved = deploy._resolve_channel_version(
            self.host.as_uri(), "stable", sign, pubkey_path=[str(self.new_pub)])
        self.assertEqual(resolved, self.VER)
        legacy_resolved = deploy._resolve_channel_version(
            self.host.as_uri(), "stable", sign, pubkey_path=[str(self.old_pub)])
        self.assertEqual(legacy_resolved, self.VER,
                         "old-key-only checkout must verify canonical latest signature")


if __name__ == "__main__":
    unittest.main()
