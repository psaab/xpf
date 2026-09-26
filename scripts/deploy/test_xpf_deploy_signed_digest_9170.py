#!/usr/bin/env python3
"""No-import fetch preserves the signed digest and privately stages installs
(#9170, #10757).

The printed command runs later, after `--out` is again writable by local
processes. It copies the public qcow2 into a fresh private directory, checks
that staged copy against the signed digest, and installs the checked copy. A
writer swapping `--out` after the checksum cannot change the staged bytes.

These tests drive `cmd_fetch`, execute the actual printed command under a fake
`sudo`, and race a writer against the checksum/install boundary. The digest
comes from `sign.verify_image_artifact`, never from a re-hash of the public
path. Hermetic: throwaway minisign keys, `file://`, private `XDG_STATE_HOME`,
and no real incus or root access.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
sys.path.insert(0, str(_ROOT / "scripts" / "dist"))

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy_9170", _HERE / "xpf-deploy.py")
deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(deploy)

import sign  # noqa: E402

VER = "1.2.3-4-gaaaaaaa"

# The bytes a local dir-writer swaps in AFTER the signature check has passed.
EVIL = b"MALICIOUS-UNAUTHENTICATED-QCOW2-BYTES" * 16

_PRINTED = re.compile(
    r"printf '%s  %s\\n' '([0-9a-f]{64})' \"\$stage/image\" \| sha256sum -c -")


@unittest.skipUnless(shutil.which("minisign") and shutil.which("curl"),
                     "minisign and curl are required")
class NoImportDigestIsTheSignedOne9170(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-9170."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.pub = self.tmp / "img.pub"
        self.sec = self.tmp / "img.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub),
                        "-s", str(self.sec)], check=True, capture_output=True)

        self.host = self.tmp / "host"
        self.host.mkdir()
        self.base = self.host.as_uri()
        self.out = self.tmp / "out"
        self.state = self.tmp / "state"
        self.golden_dir = self.tmp / "golden"
        self._libvirt_images = deploy.LIBVIRT_IMAGES
        deploy.LIBVIRT_IMAGES = str(self.golden_dir)
        self.addCleanup(setattr, deploy, "LIBVIRT_IMAGES", self._libvirt_images)

        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.sudo = self.bin / "sudo"
        self.sudo.write_text("#!/bin/sh\nexec \"$@\"\n")
        self.sudo.chmod(0o755)
        self.real_sha256sum = shutil.which("sha256sum")

        self._env = {}
        for k, v in (("XPF_IMAGE_PUBKEY", str(self.pub)),
                     ("XDG_STATE_HOME", str(self.state))):
            self._env[k] = os.environ.get(k)
            os.environ[k] = v
        self.addCleanup(self._restore_env)

        self.names = {
            "qcow2": f"xpf-{VER}.qcow2",
            "metadata": f"xpf-{VER}.incus-metadata.tar.gz",
        }
        self.authentic = {n: n.encode() * 64 for n in self.names.values()}
        for n, b in self.authentic.items():
            (self.host / n).write_bytes(b)
        man = self.host / f"xpf-{VER}.SHA256SUMS"
        man.write_text("".join(
            f"{sign.sha256_file(str(self.host / n))}  {n}\n"
            for n in self.names.values()))
        sign.sign_manifest(str(man), str(self.sec), comment="9170 test")

        self.signed_qcow2_sha = hashlib.sha256(
            self.authentic[self.names["qcow2"]]).hexdigest()

        self.incus_calls = []
        self._real_run = deploy.subprocess.run
        deploy.subprocess.run = self._fake_run
        self.addCleanup(self._restore_run)

    # ── harness ──

    def _restore_env(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _restore_run(self):
        deploy.subprocess.run = self._real_run

    def _fake_run(self, cmd, *a, **kw):
        """Let curl through (it is the file:// transport); stub incus."""
        if cmd and cmd[0] == "incus":
            self.incus_calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return self._real_run(cmd, *a, **kw)

    def _args(self, **over):
        ns = argparse.Namespace(
            version=VER, image_url=self.base, out=str(self.out),
            alias=None, channel="stable", allow_rollback=False,
            qcow2_only=False, install_libvirt=False, no_import=False,
            dry_run=False)
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def _pub_qcow2(self):
        return self.out / self.names["qcow2"]

    def _swap_public_qcow2_after_its_verify(self):
        """Model the local dir-writer: overwrite the PUBLIC qcow2 the instant
        its signature check returns. Returns the `fired` list so a cell can
        prove the window was actually entered (an unfired hook makes the cell
        vacuous, not passing)."""
        real = sign.verify_image_artifact
        fired = []

        def hooked(path, *a, **kw):
            out = real(path, *a, **kw)
            if os.path.basename(path) == self.names["qcow2"] and not fired:
                fired.append(True)
                self._pub_qcow2().write_bytes(EVIL)
            return out

        sign.verify_image_artifact = hooked
        self.addCleanup(setattr, sign, "verify_image_artifact", real)
        return fired

    def _run_fetch(self, **over):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = deploy.cmd_fetch(self._args(**over))
        return rc, buf.getvalue()

    def _printed(self, text):
        m = _PRINTED.search(text)
        self.assertIsNotNone(
            m, "the --no-import hint no longer verifies the staged image "
               "against its signed digest; re-derive this cell from its output:\n"
               f"{text}")
        return m.group(1)

    def _installer_command(self, text):
        """Extract and run the command exactly as printed for the operator."""
        lines = text.splitlines()
        start = next((i for i, line in enumerate(lines)
                      if line.startswith("      ")), None)
        self.assertIsNotNone(start, f"no install command printed:\n{text}")
        command = []
        line = lines[start]
        while True:
            self.assertTrue(line.startswith("      "),
                            f"unexpected command continuation: {line!r}")
            command.append(line[6:])
            if not line.rstrip().endswith("\\"):
                break
            start += 1
            line = lines[start]
        return "\n".join(command)

    def _run_installer(self, text, extra_env=None):
        env = os.environ.copy()
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        if extra_env:
            env.update(extra_env)
        return subprocess.run(["/bin/sh", "-c", self._installer_command(text)],
                              env=env, text=True, capture_output=True)

    # ── the defect ──

    def test_a_post_verify_swap_does_not_change_the_printed_digest(self):
        """The no-import command uses the signed digest even if --out changes
        immediately after the signature check."""
        fired = self._swap_public_qcow2_after_its_verify()
        rc, text = self._run_fetch(no_import=True)
        self.assertEqual(rc, 0)

        self.assertTrue(fired, "the post-verify swap never fired — this cell "
                               "would be vacuous, not passing")
        self.assertEqual(self._pub_qcow2().read_bytes(), EVIL,
                         "the swap did not land on the public path")
        self.assertEqual(self._printed(text), self.signed_qcow2_sha)

    def test_the_swapped_file_fails_the_printed_install(self):
        """A pre-install swap to unauthenticated bytes must not be installed."""
        self._swap_public_qcow2_after_its_verify()
        _, text = self._run_fetch(no_import=True)
        result = self._run_installer(text)
        self.assertNotEqual(result.returncode, 0,
                            "the install command accepted unauthenticated bytes")
        self.assertFalse((self.golden_dir / "xpf-appliance.qcow2").exists(),
                         "a rejected image was left at the golden path")

    def test_an_untampered_fetch_installs_the_verified_image(self):
        """The printed command must still install authentic bytes."""
        rc, text = self._run_fetch(no_import=True)
        self.assertEqual(rc, 0)
        self.assertEqual(self._printed(text), self.signed_qcow2_sha)

        result = self._run_installer(text)
        self.assertEqual(result.returncode, 0,
                         f"the authentic command failed: {result.stdout}{result.stderr}")
        self.assertEqual((self.golden_dir / "xpf-appliance.qcow2").read_bytes(),
                         self.authentic[self.names["qcow2"]])

    def test_public_swap_after_stage_check_does_not_change_installed_bytes(self):
        """A writer that swaps --out after the install-time checksum must not
        affect the private staged file subsequently installed."""
        rc, text = self._run_fetch(no_import=True)
        self.assertEqual(rc, 0)

        fired = self.tmp / "checksum-swap-fired"
        shim = self.bin / "sha256sum"
        shim.write_text(
            "#!/bin/sh\n"
            f"{self.real_sha256sum} \"$@\"\n"
            "status=$?\n"
            "if [ \"$1\" = \"-c\" ] && [ \"$2\" = \"-\" ]; then\n"
            "  printf '%s' \"$XPF_EVIL_BYTES\" > \"$XPF_PUBLIC_QCOW2\"\n"
            "  : > \"$XPF_SWAP_FIRED\"\n"
            "fi\n"
            "exit \"$status\"\n")
        shim.chmod(0o755)

        result = self._run_installer(text, {
            "XPF_PUBLIC_QCOW2": str(self._pub_qcow2()),
            "XPF_SWAP_FIRED": str(fired),
            "XPF_EVIL_BYTES": EVIL.decode(),
        })
        self.assertEqual(result.returncode, 0,
                         f"the private staged image failed: {result.stdout}{result.stderr}")
        self.assertTrue(fired.exists(), "the checksum-to-install swap did not fire")
        self.assertEqual(self._pub_qcow2().read_bytes(), EVIL,
                         "the race cell did not replace the public image")
        self.assertEqual((self.golden_dir / "xpf-appliance.qcow2").read_bytes(),
                         self.authentic[self.names["qcow2"]],
                         "the install reopened --out after its digest check")

    def test_qcow2_only_takes_the_same_path(self):
        """--qcow2-only shares the branch with --no-import, so it must get the
        same digest. It fetches ONLY the qcow2, so it also proves the digest
        does not depend on the metadata artifact being present."""
        rc, text = self._run_fetch(qcow2_only=True)
        self.assertEqual(rc, 0)
        sha = self._printed(text)
        self.assertEqual(sha, self.signed_qcow2_sha)

    def test_the_incus_import_path_is_unaffected(self):
        """POSITIVE CONTROL, sibling path 1. The importing path must still
        import."""
        rc, _ = self._run_fetch()
        self.assertEqual(rc, 0)
        imports = [c for c in self.incus_calls if c[1:3] == ["image", "import"]]
        self.assertEqual(len(imports), 1,
                         "the incus import path stopped publishing")

    def test_the_install_libvirt_path_still_stages_privately(self):
        """POSITIVE CONTROL, sibling path 2. `--install-libvirt` must still
        hand `_install_libvirt_golden` a PRIVATE staged copy (#5817) carrying
        the authentic bytes — not the public path, and not a broken one."""
        seen = []
        real = deploy._install_libvirt_golden
        deploy._install_libvirt_golden = lambda src, name: seen.append(
            (src, Path(src).read_bytes()))
        self.addCleanup(setattr, deploy, "_install_libvirt_golden", real)

        rc, _ = self._run_fetch(install_libvirt=True)
        self.assertEqual(rc, 0)
        self.assertEqual(len(seen), 1, "the libvirt golden install never ran")
        src, data = seen[0]
        self.assertEqual(data, self.authentic[self.names["qcow2"]])
        self.assertNotEqual(
            os.path.dirname(os.path.realpath(src)),
            os.path.realpath(self.out),
            "#5817: the golden must be installed from the private staging "
            "copy, not from the re-openable public --out path")

    # ── the digest is the manifest's, not any file's ──

    def test_the_digest_survives_deleting_the_public_file(self):
        """The sharpest form of the property: with the public qcow2 REMOVED
        after verification there is no file left to hash, so a re-hash cannot
        produce a digest at all. The printed value must still be the signed
        one, because it came from the manifest."""
        real = sign.verify_image_artifact
        fired = []

        def hooked(path, *a, **kw):
            out = real(path, *a, **kw)
            if os.path.basename(path) == self.names["qcow2"] and not fired:
                fired.append(True)
                os.unlink(self._pub_qcow2())
            return out

        sign.verify_image_artifact = hooked
        self.addCleanup(setattr, sign, "verify_image_artifact", real)

        rc, text = self._run_fetch(no_import=True)
        self.assertTrue(fired, "the unlink hook never fired")
        self.assertEqual(rc, 0,
                         "#9170: the digest is re-derived from the public path, "
                         "so removing that path aborts a fetch whose signature "
                         "check had already succeeded")
        sha = self._printed(text)
        self.assertEqual(sha, self.signed_qcow2_sha)


class VerifyImageArtifactReturnsTheSignedDigest9170(unittest.TestCase):
    """The wiring the fix depends on, pinned at its own layer.

    `verify_image_artifact` returned a bare `True`, discarding the signed
    digest it had just established inside the very call the deploy path makes.
    Returning it is what lets the caller print a value it did not have to
    re-read a file to get."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-9170-sign."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pub = self.tmp / "k.pub"
        self.sec = self.tmp / "k.sec"
        if not shutil.which("minisign"):
            self.skipTest("minisign is required")
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub),
                        "-s", str(self.sec)], check=True, capture_output=True)
        self.art = self.tmp / "artifact.bin"
        self.art.write_bytes(b"authentic-bytes" * 32)
        self.man = self.tmp / "SHA256SUMS"
        self.man.write_text(
            f"{sign.sha256_file(str(self.art))}  artifact.bin\n")
        sign.sign_manifest(str(self.man), str(self.sec), comment="9170")
        self.sig = str(self.man) + ".minisig"

    def test_it_returns_the_signed_digest(self):
        got = sign.verify_image_artifact(
            str(self.art), str(self.man), self.sig, str(self.pub))
        self.assertEqual(
            got, hashlib.sha256(self.art.read_bytes()).hexdigest(),
            "#9170: verify_image_artifact must hand back the digest that "
            "authorised the artifact, so callers never re-hash to learn it")

    def test_a_mismatch_still_raises(self):
        """The refusal must survive the return-value change: a function that
        returns a digest unconditionally would satisfy the cell above."""
        self.art.write_bytes(b"tampered")
        with self.assertRaises(sign.SignError):
            sign.verify_image_artifact(
                str(self.art), str(self.man), self.sig, str(self.pub))


if __name__ == "__main__":
    unittest.main(verbosity=2)
