#!/usr/bin/env python3
"""Consumer-level fail-closed regressions for issue #12208.

The signed controls use throwaway minisign keys. Negative verifier cases drive
both CLI consumers (`verify-file` and `verify`), not only publish's own
pre-check; the installer case calls its non-dry `main` through the existing
source-only seam with host commands and write paths redirected into a temp
fixture. No live apt, keyring, or source-list mutation is possible.
"""

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

_DIST = Path(__file__).resolve().parent
sys.path.insert(0, str(_DIST))
import sign  # noqa: E402

_PUBLISH_SPEC = importlib.util.spec_from_file_location(
    "publish_12208", _DIST / "publish.py")
publish = importlib.util.module_from_spec(_PUBLISH_SPEC)
assert _PUBLISH_SPEC.loader is not None
_PUBLISH_SPEC.loader.exec_module(publish)

_HAVE_MINISIGN = shutil.which("minisign") is not None
_INSTALL_SH = _DIST / "install.sh"
_FAKE_ARCHIVE_KEY = """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZmFakeArchiveKeyFor12208TestNotARealKeyAAAAAAAAAAAAAAA
=AbC1
-----END PGP PUBLIC KEY BLOCK-----
"""


def _run_sign(*argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = sign._main(list(argv))
    return rc, stdout.getvalue() + stderr.getvalue()


@unittest.skipUnless(_HAVE_MINISIGN, "minisign not installed")
class VerifyFileNegativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-12208-file-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pub, self.sec = self.tmp / "image.pub", self.tmp / "image.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub),
                        "-s", str(self.sec)], check=True, capture_output=True)
        self.file = self.tmp / "install.sh"
        self.file.write_text("#!/bin/sh\necho signed positive control\n")
        sign.sign_manifest(str(self.file), [str(self.sec)])

    def _verify(self):
        return _run_sign("verify-file", "--pubkey", str(self.pub), str(self.file))

    def test_signed_positive_control_verifies(self):
        rc, output = self._verify()
        self.assertEqual(rc, 0, output)

    def test_missing_signature_is_refused(self):
        Path(str(self.file) + ".minisig").unlink()
        rc, output = self._verify()
        self.assertNotEqual(rc, 0, "verify-file accepted a file with no signature")
        self.assertIn("no minisign signature found", output)

    def test_empty_signature_is_refused(self):
        Path(str(self.file) + ".minisig").write_bytes(b"")
        rc, output = self._verify()
        self.assertNotEqual(rc, 0, "verify-file accepted an empty signature")
        self.assertIn("minisign signature verification FAILED", output)


@unittest.skipUnless(_HAVE_MINISIGN, "minisign not installed")
class VerifyArtifactNegativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-12208-manifest-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pub, self.sec = self.tmp / "image.pub", self.tmp / "image.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub),
                        "-s", str(self.sec)], check=True, capture_output=True)
        self.listed = self.tmp / "listed.bin"
        self.listed.write_bytes(b"signed listed artifact\n")
        self.manifest = self.tmp / "SHA256SUMS"
        sign.write_manifest(str(self.manifest), [str(self.listed)])
        sign.sign_manifest(str(self.manifest), [str(self.sec)])

    def _verify(self, artifact):
        return _run_sign("verify", "--manifest", str(self.manifest),
                         "--pubkey", str(self.pub), str(artifact))

    def test_signed_listed_artifact_positive_control_verifies(self):
        rc, output = self._verify(self.listed)
        self.assertEqual(rc, 0, output)

    def test_missing_manifest_signature_is_refused(self):
        Path(str(self.manifest) + ".minisig").unlink()
        rc, output = self._verify(self.listed)
        self.assertNotEqual(rc, 0, "verify accepted an unsigned manifest")
        self.assertIn("no minisign signature found", output)

    def test_empty_manifest_signature_is_refused(self):
        Path(str(self.manifest) + ".minisig").write_bytes(b"")
        rc, output = self._verify(self.listed)
        self.assertNotEqual(rc, 0, "verify accepted an empty manifest signature")
        self.assertIn("minisign signature verification FAILED", output)

    def test_unlisted_artifact_is_refused(self):
        unlisted = self.tmp / "unlisted.bin"
        unlisted.write_bytes(b"not covered by the signed manifest\n")
        rc, output = self._verify(unlisted)
        self.assertNotEqual(rc, 0, "verify accepted an unlisted artifact")
        self.assertIn("is not listed in the signed manifest", output)


class InstallerPlaceholderNegativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-12208-install-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fakebin = self.tmp / "bin"
        self.fakebin.mkdir()
        # `validate` requires root for a non-dry run. This stub only satisfies
        # that check; install.sh's write paths and install command are sandboxed.
        self._stub("id", "#!/bin/sh\necho 0\n")
        # install_keyring uses `install -d`; keep even that command inert.
        self._stub("install", "#!/bin/sh\nexit 0\n")
        self.sources = self.tmp / "sources"
        self.sources.mkdir()

    def _stub(self, name, body):
        path = self.fakebin / name
        path.write_text(body)
        path.chmod(0o755)

    def _run_main(self, installer):
        env = dict(os.environ)
        env.update({
            "XPF_INSTALL_SOURCE_ONLY": "1",
            "XPF_APT_BASE_URL": "https://apt.example.invalid/apt",
            "XPF_CHANNEL": "stable",
            "XPF_DRY_RUN": "0",
            "PATH": str(self.fakebin) + os.pathsep + env.get("PATH", ""),
        })
        shell = (
            '. "$1"; '
            'KEYRING="$2/keyring"; '
            'SRC="$2/sources/xpf.sources"; '
            'preflight() { echo PREFLIGHT_RAN; }; '
            'do_install() { :; }; '
            'main'
        )
        result = subprocess.run(
            ["sh", "-c", shell, "sh", str(installer), str(self.tmp)],
            capture_output=True, text=True, env=env, timeout=30)
        writes = (self.tmp / "keyring").exists(), (self.sources / "xpf.sources").exists()
        return result.returncode, result.stdout + result.stderr, writes

    def test_non_dry_placeholder_key_is_refused_before_writes(self):
        rc, output, writes = self._run_main(_INSTALL_SH)
        self.assertNotEqual(rc, 0, "non-dry installer accepted its placeholder key")
        self.assertIn("PLACEHOLDER", output)
        self.assertEqual(writes, (False, False),
                         "installer wrote the keyring or apt source before refusal")

    def test_non_placeholder_key_positive_control_reaches_sandboxed_writes(self):
        archive_key = self.tmp / "archive.asc"
        archive_key.write_text(_FAKE_ARCHIVE_KEY)
        stamped = self.tmp / "install-stamped.sh"
        publish.stamp_installer(
            str(stamped), archive_key=str(archive_key),
            apt_url="https://apt.example.invalid/apt", channel="stable")
        rc, output, writes = self._run_main(stamped)
        self.assertEqual(rc, 0, output)
        self.assertIn("PREFLIGHT_RAN", output)
        self.assertEqual(writes, (True, True),
                         "non-placeholder control did not reach sandboxed writes")


if __name__ == "__main__":
    unittest.main()
