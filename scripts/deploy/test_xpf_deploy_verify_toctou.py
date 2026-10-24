#!/usr/bin/env python3
"""Fail-on-revert tests for the fetch verify/use TOCTOU close (#5817).

`xpf-deploy.py fetch` authenticated each downloaded artifact by PATHNAME, then
handed that SAME public pathname to a DIFFERENT consumer — libvirt copy-to-golden
(`_install_libvirt_golden`) or `incus image import`. The verified inode was not
retained, so a process able to write the `--out` directory could RENAME/REPLACE
the file with unauthenticated content AFTER the checksum check and BEFORE the
consumer's open: the consumer then received bytes that were never authenticated
(verify-by-name / use-by-name race). Secondarily, downloads landed in a
predictable shared `<dst>.tmp` with no exclusive create, so a concurrent fetch to
the same `--out` (or a pre-planted temp) could collide with / clobber the
in-flight download and widen the race.

The fix:
  - `_verified_private_artifacts` copies each to-be-consumed artifact into a
    private 0700 mkdtemp OUTSIDE `--out`, verifies the COPY there, and hands the
    consumer THAT path — nothing that can write `--out` can reach the staging
    dir, so the consumed bytes are exactly the verified bytes.
  - `_download_to` downloads via an EXCLUSIVE, unpredictable `mkstemp` temp and
    publishes atomically, so concurrent fetches / a pre-planted predictable temp
    cannot collide or clobber.

RED on revert:
  - `_verified_private_artifacts` -> hand back the public path: the staged path
    is inside `--out` AND a post-verify swap of the public bytes changes what the
    consumer reads -> the swap-doesn't-reach-consumer asserts flip.
  - `_download_to` -> `dst + ".tmp"`: a pre-planted predictable temp is clobbered
    -> the untouched-temp asserts flip.

These vectors exercise the CHECKSUM binding (pure Python) with the minisign
signature step neutralized, mirroring test_xpf_deploy_gate's signed-manifest
tests; the full minisign chain is covered there. pytest is not installed — run
with `python3 -m unittest`.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

xpf_deploy = load_subject("xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))


class VerifyUseTOCTOUTests(unittest.TestCase):
    """The staging seam: the consumer must receive the VERIFIED inode, not a
    re-openable public pathname whose bytes can be swapped after the check."""

    def setUp(self):
        here = Path(__file__).resolve().parent
        sys.path.insert(0, str(here.parent / "dist"))
        import sign
        self.sign = sign
        self.tmp = tempfile.mkdtemp(prefix="xpf-5817-")
        self.out = os.path.join(self.tmp, "out")
        os.makedirs(self.out)
        # A real (non-placeholder) pubkey so _resolve_pubkey(None) accepts it —
        # production supplies the real key the same way (XPF_IMAGE_PUBKEY). The
        # checksum binding, not the signature, is what these vectors exercise, so
        # neutralize the minisign check and drive the pure-Python hash compare.
        self.pub = os.path.join(self.tmp, "test.pub")
        with open(self.pub, "w") as f:
            f.write("untrusted-test-key\n")
        self._orig_env = os.environ.get("XPF_IMAGE_PUBKEY")
        os.environ["XPF_IMAGE_PUBKEY"] = self.pub
        self._orig_verify_sig = sign.verify_signature
        sign.verify_signature = lambda m, s, p: None

        self.names = {
            "qcow2": "xpf-1.2.3.qcow2",
            "metadata": "xpf-1.2.3.incus-metadata.tar.gz",
            "manifest": "xpf-1.2.3.SHA256SUMS",
            "sig": "xpf-1.2.3.SHA256SUMS.minisig",
        }
        self.qcow2_bytes = b"AUTHENTIC-QCOW2-BYTES"
        self.meta_bytes = b"AUTHENTIC-METADATA-BYTES"
        self._write(self.names["qcow2"], self.qcow2_bytes)
        self._write(self.names["metadata"], self.meta_bytes)
        self.manifest = os.path.join(self.out, self.names["manifest"])
        sign.write_manifest(self.manifest, [
            os.path.join(self.out, self.names["qcow2"]),
            os.path.join(self.out, self.names["metadata"]),
        ])
        self.sig = os.path.join(self.out, self.names["sig"])
        with open(self.sig, "w") as f:
            f.write("stub-signature (verify_signature patched)\n")

    def tearDown(self):
        self.sign.verify_signature = self._orig_verify_sig
        if self._orig_env is None:
            os.environ.pop("XPF_IMAGE_PUBKEY", None)
        else:
            os.environ["XPF_IMAGE_PUBKEY"] = self._orig_env
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        with open(os.path.join(self.out, name), "wb") as f:
            f.write(data)

    def _under_out(self, path):
        return os.path.abspath(path).startswith(os.path.abspath(self.out) + os.sep)

    def test_staged_path_private_and_swap_does_not_reach_consumer(self):
        """The verify/use TOCTOU close: the consumer path is OUTSIDE --out, and a
        post-verify swap of the public bytes does NOT change what it reads."""
        with xpf_deploy._verified_private_artifacts(
                self.sign, self.out, self.names, ["qcow2", "metadata"],
                self.manifest, self.sig) as staged:
            qpath, mpath = staged["qcow2"], staged["metadata"]
            # (1) the consumer receives a path that is NOT the re-openable public
            #     one — a --out writer cannot reach a private 0700 mkdtemp.
            self.assertFalse(self._under_out(qpath),
                             f"staged qcow2 {qpath} is inside public --out")
            self.assertFalse(self._under_out(mpath),
                             f"staged metadata {mpath} is inside public --out")
            # (2) attacker swaps the PUBLIC files' bytes AFTER verification.
            self._write(self.names["qcow2"], b"MALICIOUS-UNAUTHENTICATED-BYTES")
            self._write(self.names["metadata"], b"MALICIOUS-METADATA")
            # (3) the consumer still reads the VERIFIED bytes (swap didn't land).
            with open(qpath, "rb") as f:
                self.assertEqual(f.read(), self.qcow2_bytes)
            with open(mpath, "rb") as f:
                self.assertEqual(f.read(), self.meta_bytes)
            # (4) the staged copy still verifies clean against the signed manifest.
            self.assertTrue(
                self.sign.verify_image_artifact(qpath, self.manifest, self.sig))

    def test_authentic_artifacts_stage_and_verify(self):
        """Regression: an untampered fetch stages + verifies both artifacts
        end-to-end, hands back readable verified copies, and cleans up on exit."""
        with xpf_deploy._verified_private_artifacts(
                self.sign, self.out, self.names, ["metadata", "qcow2"],
                self.manifest, self.sig) as staged:
            with open(staged["qcow2"], "rb") as f:
                self.assertEqual(f.read(), self.qcow2_bytes)
            with open(staged["metadata"], "rb") as f:
                self.assertEqual(f.read(), self.meta_bytes)
            qpath = staged["qcow2"]
            self.assertTrue(os.path.exists(qpath))
        # staging dir is rmtree'd once the consumer returns.
        self.assertFalse(os.path.exists(qpath))

    def test_tampered_public_artifact_fails_closed(self):
        """An artifact tampered BEFORE staging (copied bytes mismatch the signed
        manifest) fails closed — staging does not weaken the checksum verify."""
        self._write(self.names["qcow2"], b"TAMPERED-BEFORE-STAGE")
        with self.assertRaises(SystemExit):
            with xpf_deploy._verified_private_artifacts(
                    self.sign, self.out, self.names, ["qcow2"],
                    self.manifest, self.sig):
                self.fail("must not yield a staged path for a tampered artifact")


class DownloadExclusiveTempTests(unittest.TestCase):
    """The secondary race: downloads must use an exclusive, unpredictable temp,
    never a predictable shared `<dst>.tmp` a concurrent fetch could clobber."""

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="xpf-5817-dl-")
        self.dst = os.path.join(self.workdir, "xpf-1.2.3.qcow2")
        self._orig_run = xpf_deploy.subprocess.run

    def tearDown(self):
        xpf_deploy.subprocess.run = self._orig_run
        shutil.rmtree(self.workdir, ignore_errors=True)

    @staticmethod
    def _fake_curl_ok(argv, *a, **k):
        # Emulate `curl -fsSL -o <tmp> <url>`: write known bytes to the -o target.
        target = argv[argv.index("-o") + 1]
        with open(target, "wb") as f:
            f.write(b"DOWNLOADED-BYTES")

        class _R:
            returncode = 0
        return _R()

    @staticmethod
    def _fake_curl_fail(argv, *a, **k):
        class _R:
            returncode = 22
        return _R()

    def test_exclusive_temp_does_not_clobber_predictable_name(self):
        """A pre-planted predictable `<dst>.tmp` (a concurrent fetch's temp) is
        left untouched; the download still succeeds via its own unpredictable
        mkstemp temp and publishes atomically to dst."""
        predictable = self.dst + ".tmp"
        with open(predictable, "wb") as f:
            f.write(b"PRE-EXISTING-JUNK")
        xpf_deploy.subprocess.run = self._fake_curl_ok
        xpf_deploy._download_to("http://x/xpf-1.2.3.qcow2", self.dst, self.workdir)
        # download landed at dst via the unpredictable temp
        with open(self.dst, "rb") as f:
            self.assertEqual(f.read(), b"DOWNLOADED-BYTES")
        # the predictable shared temp is UNTOUCHED (revert to `dst + ".tmp"`
        # would overwrite+consume it -> these asserts flip RED)
        self.assertTrue(os.path.exists(predictable),
                        "predictable temp was consumed — download reused it")
        with open(predictable, "rb") as f:
            self.assertEqual(f.read(), b"PRE-EXISTING-JUNK")
        # only the pre-existing predictable temp remains; the mkstemp temp was
        # consumed by the atomic rename.
        remaining = sorted(n for n in os.listdir(self.workdir)
                           if n.endswith(".tmp"))
        self.assertEqual(remaining, ["xpf-1.2.3.qcow2.tmp"])

    def test_failed_download_cleans_temp_and_dies(self):
        """A failed download fails closed and leaves no stray temp behind."""
        xpf_deploy.subprocess.run = self._fake_curl_fail
        with self.assertRaises(SystemExit):
            xpf_deploy._download_to("http://x/xpf-1.2.3.qcow2", self.dst,
                                    self.workdir)
        self.assertFalse(os.path.exists(self.dst))
        self.assertEqual(sorted(os.listdir(self.workdir)), [])


if __name__ == "__main__":
    unittest.main()
