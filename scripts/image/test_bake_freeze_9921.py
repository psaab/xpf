#!/usr/bin/env python3
"""Unit tests for psaab/xpf#9921 F-068 (bake.py half) — freeze gate inputs,
hash the staged bytes, re-assert live-vs-snapshot before signing.

bake.py hashes its checksum manifest pre-gate and signs it post-gate while
the gate boots the live files for minutes. The fix stages the gate-consumed
artifacts (stage_artifacts_for_gate), snapshots {basename: digest} IN MEMORY
at hash time (snapshot_manifest_inputs), and re-asserts inside sign_step
(assert_live_matches_manifest): a rewritten live sums file OR a swapped live
artifact both die before the signature.

The joint-tamper cell is the key: rewriting the live sums to match swapped
live artifacts must STILL die, because the snapshot (not the live sums) is
ground truth. A live-vs-live comparison would pass it — exactly the F-068
impact.

RED on revert: no helpers (AttributeError).
"""

from __future__ import annotations

import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name, directory):
    spec = importlib.util.spec_from_file_location(
        name, Path(directory) / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


bake = _load("bake", _HERE)
sign = _load("sign", _HERE.parent / "dist")


class StageTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-bake9921-")
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.dir, ignore_errors=True))
        self.work = os.path.join(self.dir, "work")
        os.makedirs(self.work)
        self.out = os.path.join(self.dir, "out")
        os.makedirs(self.out)
        self.qcow = os.path.join(self.out, "xpf-9.qcow2")
        self.meta = os.path.join(self.out, "xpf-9.incus-metadata.tar.gz")
        Path(self.qcow).write_bytes(b"Q" * 1000)
        Path(self.meta).write_bytes(b"M" * 100)
        self.manifest = os.path.join(self.out, "xpf-9.manifest")
        self.pkgs = os.path.join(self.out, "xpf-9.pkgs")
        Path(self.manifest).write_text("validated: true\n")
        Path(self.pkgs).write_text("pkg-a\n")

    def _hash_and_snapshot(self):
        staged = bake.stage_artifacts_for_gate(self.work, self.qcow, self.meta)
        live_inputs = [self.qcow, self.meta, self.manifest, self.pkgs]
        hashing = [staged.get(p, p) for p in live_inputs]
        snap = bake.snapshot_manifest_inputs(hashing)
        sums = os.path.join(self.out, "xpf-9.SHA256SUMS")
        sign.write_manifest(sums, hashing)
        return staged, live_inputs, snap, sums

    def test_stage_copies_bytes_private(self):
        staged = bake.stage_artifacts_for_gate(self.work, self.qcow, self.meta)
        self.assertEqual(set(staged), {self.qcow, self.meta})
        for live, frozen in staged.items():
            self.assertTrue(frozen.startswith(self.work + os.sep))
            self.assertEqual(os.path.basename(frozen), os.path.basename(live))
            self.assertEqual(Path(frozen).read_bytes(), Path(live).read_bytes())
        stage_dir = os.path.dirname(staged[self.qcow])
        self.assertEqual(stat.S_IMODE(os.stat(stage_dir).st_mode), 0o700)

    def test_stage_collision_dies(self):
        other = os.path.join(self.dir, "other")
        os.makedirs(other)
        twin = os.path.join(other, os.path.basename(self.qcow))
        Path(twin).write_bytes(b"twin")
        with self.assertRaises(SystemExit):
            bake.stage_artifacts_for_gate(self.work, self.qcow, twin)

    def test_snapshot_duplicate_basename_dies(self):
        with self.assertRaises(SystemExit):
            bake.snapshot_manifest_inputs([self.qcow, self.qcow])

    def test_assert_passes_when_live_undrifted(self):
        _staged, live_inputs, snap, sums = self._hash_and_snapshot()
        bake.assert_live_matches_manifest(live_inputs, sums, snap)  # no raise

    def test_assert_dies_on_artifact_drift(self):
        _staged, live_inputs, snap, sums = self._hash_and_snapshot()
        Path(self.qcow).write_bytes(b"EVIL-QCOW")
        with self.assertRaises(SystemExit) as ctx:
            bake.assert_live_matches_manifest(live_inputs, sums, snap)
        self.assertIn("drifted", str(ctx.exception))

    def test_assert_dies_on_sidecar_drift(self):
        _staged, live_inputs, snap, sums = self._hash_and_snapshot()
        Path(self.manifest).write_text("validated: false\n")
        with self.assertRaises(SystemExit) as ctx:
            bake.assert_live_matches_manifest(live_inputs, sums, snap)
        self.assertIn("drifted", str(ctx.exception))

    def test_assert_dies_on_joint_sums_plus_artifact_tamper(self):
        # The F-068 forgery: live artifacts swapped AND the live sums file
        # rewritten to match them. A live-vs-live comparison would pass;
        # the in-memory snapshot must still die.
        _staged, live_inputs, snap, sums = self._hash_and_snapshot()
        Path(self.qcow).write_bytes(b"EVIL-QCOW")
        Path(self.meta).write_bytes(b"EVIL-META")
        sign.write_manifest(sums, live_inputs)  # attacker covers their swap
        with self.assertRaises(SystemExit) as ctx:
            bake.assert_live_matches_manifest(live_inputs, sums, snap)
        self.assertIn("drifted", str(ctx.exception))

    def test_assert_dies_on_unparseable_live_sums(self):
        _staged, live_inputs, snap, sums = self._hash_and_snapshot()
        Path(sums).write_text("garbage not a manifest\n")
        with self.assertRaises(SystemExit):
            bake.assert_live_matches_manifest(live_inputs, sums, snap)


if __name__ == "__main__":
    unittest.main()
