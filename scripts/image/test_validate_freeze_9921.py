#!/usr/bin/env python3
"""Unit tests for psaab/xpf#9921 F-068 (validate.py half) — verify-then-freeze.

On base, Harness hashed the LIVE qcow2/metadata in verify_signatures while
import_image and scenario_qemu re-opened those same re-openable paths minutes
later, so a concurrent host writer during the gate window could make
`validated: true` attest to never-validated bytes.

The fix freezes both artifacts into private 0700 staging (freeze_artifacts,
called first by main() and defensively by assert_image_sealed() and
verify_signatures()) and runs every consumer against the staged copies, with
signed manifests still looked up next to the LIVE files.

RED on revert: no freeze_artifacts (AttributeError), import/verify consume
live paths, main's ordering spy observes _frozen False.
"""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("validate", _HERE / "validate.py")
validate = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(validate)


def _live_pair(tmpdir, qbytes=b"ORIGINAL-QCOW-BYTES", mbytes=b"ORIGINAL-META-BYTES"):
    q = os.path.join(tmpdir, "x-test.qcow2")
    m = os.path.join(tmpdir, "x-test.incus-metadata.tar.gz")
    Path(q).write_bytes(qbytes)
    Path(m).write_bytes(mbytes)
    return q, m


class FreezeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-freeze9921-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)
        for h in getattr(self, "_harnesses", []):
            import shutil as _sh
            _sh.rmtree(h.work, ignore_errors=True)

    def _harness(self, q, m, **kw):
        kw.setdefault("verify_sig", False)
        h = validate.Harness(q, m, "xpf-image-net", False, kw["verify_sig"])
        self.__dict__.setdefault("_harnesses", []).append(h)
        return h

    def test_freeze_copies_and_repoints_private(self):
        q, m = _live_pair(self.dir)
        h = self._harness(q, m)
        h.freeze_artifacts()
        self.assertTrue(h._frozen)
        self.assertEqual(h.qcow2_src, q)
        self.assertEqual(h.metadata_src, m)
        self.assertNotEqual(h.qcow2, q)
        self.assertNotEqual(h.metadata, m)
        self.assertTrue(h.qcow2.startswith(h.work + os.sep))
        self.assertEqual(os.path.basename(h.qcow2), os.path.basename(q))
        self.assertEqual(os.path.basename(h.metadata), os.path.basename(m))
        self.assertEqual(Path(h.qcow2).read_bytes(), b"ORIGINAL-QCOW-BYTES")
        self.assertEqual(Path(h.metadata).read_bytes(), b"ORIGINAL-META-BYTES")
        self.assertEqual(stat.S_IMODE(os.stat(h.work).st_mode), 0o700)

    def test_freeze_is_flag_guarded_not_recopied(self):
        q, m = _live_pair(self.dir)
        h = self._harness(q, m)
        with mock.patch.object(validate.shutil, "copyfile",
                               wraps=validate.shutil.copyfile) as spy:
            h.freeze_artifacts()
            first_q, first_m = h.qcow2, h.metadata
            h.freeze_artifacts()
            self.assertEqual((h.qcow2, h.metadata), (first_q, first_m))
            self.assertEqual(spy.call_count, 2,
                             "second freeze must not re-copy")

    def test_live_swap_after_freeze_invisible_to_consumers(self):
        q, m = _live_pair(self.dir)
        h = self._harness(q, m)
        h.freeze_artifacts()
        Path(q).write_bytes(b"SWAPPED-QCOW-BYTES")
        Path(m).write_bytes(b"SWAPPED-META-BYTES")
        self.assertEqual(Path(h.qcow2).read_bytes(), b"ORIGINAL-QCOW-BYTES")
        self.assertEqual(Path(h.metadata).read_bytes(), b"ORIGINAL-META-BYTES")

    def test_nonregular_live_refused(self):
        q, m = _live_pair(self.dir)
        os.remove(q)
        os.mkfifo(q)
        h = self._harness(q, m)
        with self.assertRaises(SystemExit):
            h.freeze_artifacts()

    def test_missing_live_refused(self):
        q, m = _live_pair(self.dir)
        h = self._harness(q + "-absent", m)
        with self.assertRaises(SystemExit):
            h.freeze_artifacts()

    def test_verify_freezes_before_no_verify_return(self):
        # verify_sig=False returns early — but the freeze must already have
        # happened, because import/scenarios consume the paths in every mode.
        q, m = _live_pair(self.dir)
        h = self._harness(q, m, verify_sig=False)
        h.verify_signatures()  # no manifests next to live: would skip
        self.assertTrue(h._frozen, "freeze must precede the early return")
        self.assertNotEqual(h.qcow2, q)

    def test_verify_uses_frozen_paths_against_live_manifest(self):
        q, m = _live_pair(self.dir)
        sums = os.path.join(self.dir, "x.SHA256SUMS")
        Path(sums).write_text("00  x\n")
        Path(sums + ".minisig").write_text("sig\n")
        seen = []

        def fake_verify(path, manifest, sig, pubkey_path=None):
            seen.append((path, manifest, sig))
            return "0" * 64

        h = self._harness(q, m, verify_sig=True)
        with mock.patch.object(validate.sign, "verify_image_artifact",
                               side_effect=fake_verify):
            h.verify_signatures()
        # Manifests found next-to-LIVE (staging holds none), frozen bytes
        # verified against them.
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0][1], sums)
        self.assertTrue(seen[0][0].startswith(h.work + os.sep), seen)
        self.assertTrue(seen[1][0].startswith(h.work + os.sep), seen)
        self.assertEqual(os.path.basename(seen[0][0]), os.path.basename(q))
        self.assertEqual(os.path.basename(seen[1][0]), os.path.basename(m))

    def test_import_uses_frozen_without_prefreeze(self):
        q, m = _live_pair(self.dir)
        h = self._harness(q, m, verify_sig=False)
        calls = []

        def fake_incus(*a, **k):
            calls.append(tuple(a))
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(validate, "incus", side_effect=fake_incus):
            h.import_image()
        imports = [c for c in calls if c[:2] == ("image", "import")]
        self.assertEqual(len(imports), 1)
        _img, _imp, got_m, got_q = imports[0][:4]
        self.assertTrue(got_q.startswith(h.work + os.sep), got_q)
        self.assertTrue(got_m.startswith(h.work + os.sep), got_m)

    def test_seal_freezes_before_first_read(self):
        q, m = _live_pair(self.dir)
        h = self._harness(q, m, verify_sig=False)
        argv_seen = []

        def fake_run(argv, **kw):
            argv_seen.append(list(argv))
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(validate.shutil, "which", return_value="/usr/bin/x"), \
                mock.patch.object(validate.subprocess, "run", side_effect=fake_run):
            h.assert_image_sealed()
        self.assertTrue(h._frozen)
        qcow_refs = [a for call in argv_seen for a in call
                     if a == q or a == h.qcow2]
        self.assertTrue(qcow_refs, "seal never referenced the artifact?")
        self.assertNotIn(q, qcow_refs,
                         "seal read the LIVE path after freezing")
        self.assertIn(h.qcow2, qcow_refs)


class MainOrderingTests(unittest.TestCase):
    def test_main_freezes_before_seal(self):
        d = tempfile.mkdtemp(prefix="xpf-freeze9921main-")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        q, m = _live_pair(d)
        observed = {}
        RealHarness = validate.Harness

        class SpyHarness(RealHarness):
            # NOTE: overriding (not wrapping) seal is what makes this pin
            # main()'s call specifically: the defensive freeze lives in the
            # real method body, so only main()'s explicit call can have run.
            def assert_image_sealed(self):
                observed["seal_frozen"] = self._frozen
                observed["seal_qcow2"] = self.qcow2

            def ensure_network(self):
                observed["net"] = True

            def import_image(self):
                observed["import_frozen"] = self._frozen

            def scenario_a(self):
                observed["a"] = self.qcow2

            def cleanup(self):
                observed["cleanup"] = True
                import shutil as _sh
                _sh.rmtree(self.work, ignore_errors=True)

        with mock.patch.object(validate, "Harness", SpyHarness), \
                mock.patch.object(validate, "maybe_reexec_incus_admin",
                                  lambda: None), \
                mock.patch.object(sys, "argv",
                                  ["validate.py", "--qcow2", q,
                                   "--metadata", m, "a"]):
            rc = validate.main()
        self.assertEqual(rc, 0)
        self.assertTrue(observed.get("seal_frozen"),
                        "seal ran before main() froze — ordering missing")
        self.assertNotEqual(observed.get("seal_qcow2"), q)
        self.assertTrue(observed.get("import_frozen"))
        self.assertEqual(observed.get("a"), observed.get("seal_qcow2"))


if __name__ == "__main__":
    unittest.main()
