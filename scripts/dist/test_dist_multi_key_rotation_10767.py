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

    def test_legacy_singular_public_key_stays_first_in_overlap(self):
        os.environ["XPF_IMAGE_PUBKEY"] = str(self.old_pub)
        os.environ["XPF_IMAGE_PUBKEYS"] = str(self.new_pub)
        self.assertEqual(sign.resolve_image_pubkeys(),
                         [str(self.old_pub), str(self.new_pub)])
        versions, pubkeys = publish.gate_images(
            str(self.dist), require_installer=False)
        self.assertIn(self.VER, versions)
        self.assertEqual(pubkeys[0], str(self.old_pub))

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

    def test_direct_file_cli_preserves_legacy_and_new_key_verification(self):
        target = self.tmp / "install.sh"
        target.write_text("#!/bin/sh\necho verified\n")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sign._main([
                "sign-file", "--seckey", str(self.old_sec),
                "--seckey", str(self.new_sec), str(target)])
        self.assertEqual(rc, 0)
        canonical = str(target) + ".minisig"
        self.assertEqual(sign.minisign_key_id(canonical),
                         sign.minisign_key_id(str(self.old_pub)))
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sign._main([
                "verify-file", "--pubkey", str(self.old_pub),
                "--sig", canonical, str(target)])
        self.assertEqual(rc, 0, "old-key-only checkout must verify canonical signature")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sign._main([
                "verify-file", "--pubkey", str(self.new_pub),
                "--sig", canonical, str(target)])
        self.assertEqual(rc, 0, "new-key-only checkout must discover key-addressed sidecar")

    def _write_installer(self):
        path = self.dist / "install.sh"
        path.write_text(
            "XPF_APT_BASE_URL_BAKED='https://apt.example.invalid'\n"
            "XPF_CHANNEL_BAKED='stable'\n"
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "fake real archive key for gate fixture\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n")
        sign.sign_manifest(str(path), [str(self.old_sec), str(self.new_sec)])
        return path

    def test_publish_manifest_gate_requires_each_configured_key(self):
        sidecar = Path(sign.signature_paths(
            str(self.manifest), [str(self.new_pub)])[-1])
        sidecar.unlink()
        with self.assertRaises(SystemExit) as caught:
            publish.gate_images(str(self.dist), require_installer=False)
        self.assertIn("new.pub", str(caught.exception))

    def test_publish_installer_gate_requires_each_configured_key(self):
        installer = self._write_installer()
        sidecar = Path(sign.signature_paths(
            str(installer), [str(self.new_pub)])[-1])
        sidecar.unlink()
        with self.assertRaises(SystemExit) as caught:
            publish.gate_images(str(self.dist))
        self.assertIn("new.pub", str(caught.exception))

    def test_latest_gate_requires_each_configured_key(self):
        publish.make_latest(str(self.dist), "stable", self.VER)
        latest = self.dist / "stable" / "latest.json"
        sidecar = Path(sign.signature_paths(
            str(latest), [str(self.new_pub)])[-1])
        sidecar.unlink()
        with self.assertRaises(SystemExit) as caught:
            publish.gate_latest(str(self.dist), "stable", {self.VER: self.manifest},
                                [str(self.old_pub), str(self.new_pub)])
        self.assertIn("new.pub", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
