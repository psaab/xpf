"""#10767 F6: dual-sign image manifests, latest pointers and direct files."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parents[1]
sys.path.insert(0, str(_HERE))
import sign  # noqa: E402

_SPEC = importlib.util.spec_from_file_location("xpf_publish_10767", _HERE / "publish.py")
publish = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(publish)


@unittest.skipUnless(shutil.which("minisign"), "minisign is required")
class MultiKeyRotation10767(unittest.TestCase):
    VER = "1.2.3-4-gbbbbbbb"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-10767-distkey."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.old_pub, self.old_sec = self._keypair("old")
        self.new_pub, self.new_sec = self._keypair("new")
        self.saved_env = {name: os.environ.get(name) for name in (
            "XPF_IMAGE_PUBKEY", "XPF_IMAGE_PUBKEYS",
            "XPF_SIGN_SECKEY", "XPF_SIGN_SECKEYS")}
        os.environ.pop("XPF_IMAGE_PUBKEY", None)
        os.environ["XPF_IMAGE_PUBKEYS"] = os.pathsep.join(
            (str(self.old_pub), str(self.new_pub)))
        os.environ["XPF_SIGN_SECKEY"] = str(self.old_sec)
        os.environ["XPF_SIGN_SECKEYS"] = str(self.new_sec)
        self.addCleanup(self._restore_env)
        self.dist = self.tmp / "dist"
        self.dist.mkdir()
        self.manifest = self._write_signed_bake_set()

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

    def _write_signed_bake_set(self):
        paths = []
        for name in sign.bake_set_basenames(self.VER):
            path = self.dist / name
            if name.endswith(".manifest"):
                path.write_text("validated: true\nbase_image_pinned: true\nguest_kernel: 6.8.0\n")
            elif name.endswith(".pkgs"):
                path.write_text("# signed package inventory\n")
            else:
                path.write_bytes((name + "\n").encode() * 8)
            paths.append(str(path))
        manifest = self.dist / f"xpf-{self.VER}.SHA256SUMS"
        sign.write_and_sign_manifest(str(manifest), paths,
                                     [str(self.old_sec), str(self.new_sec)])
        return manifest

    def test_image_and_latest_gates_accept_key_addressed_overlap_signatures(self):
        publish.make_latest(str(self.dist), "stable", self.VER)
        latest = self.dist / "stable" / "latest.json"
        newest_signature = Path(sign.signature_paths(
            str(latest), [str(self.new_pub)])[-1])
        self.assertTrue(newest_signature.is_file(), "latest.json lacks the new-key signature")

        versions, pubkeys = publish.gate_images(str(self.dist), require_installer=False)
        self.assertEqual(set(versions), {self.VER})
        self.assertEqual(len(pubkeys), 2)
        self.assertEqual(sign.verify_manifest_map(
            str(self.manifest), str(self.manifest) + ".minisig",
            [str(self.new_pub)]).keys(), set(sign.bake_set_basenames(self.VER)))
        publish.gate_latest(str(self.dist), "stable", versions, pubkeys)

    def test_direct_file_cli_signs_and_verifies_with_new_key_only(self):
        target = self.tmp / "install.sh"
        target.write_text("#!/bin/sh\necho verified\n")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sign._main([
                "sign-file", "--seckey", str(self.old_sec),
                "--seckey", str(self.new_sec), str(target)])
        self.assertEqual(rc, 0)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sign._main([
                "verify-file", "--pubkey", str(self.new_pub),
                "--sig", str(target) + ".minisig", str(target)])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
