#!/usr/bin/env python3
"""Unit tests for psaab/xpf#9921 F-068 (bake.py half) — freeze gate inputs,
hash the staged bytes, re-assert live-vs-snapshot, sign from memory.

bake.py hashes its checksum manifest pre-gate and signs it post-gate while
the gate boots the live files for minutes. The fix stages the gate-consumed
artifacts (stage_artifacts_for_gate), snapshots {basename: digest} IN MEMORY
at hash time (snapshot_manifest_inputs), re-asserts inside sign_step
(assert_live_matches_manifest, fail-fast), and signs bytes rendered from
that snapshot via a private manifest (sign_manifest_step_from_snapshot) that
is installed over the live pair — the live manifest is never reopened for
signing.

The joint-tamper cell is the key for the assert: rewriting the live sums to
match swapped live artifacts must STILL die, because the snapshot (not the
live sums) is ground truth. The post-parse-swap cell is the key for the
signer: a live-sums replacement landing AFTER the assert's parse (during
the multi-GB rehash) must be refused by the strict bake-set gate before any
signature is created.

RED on revert: no helpers (AttributeError); signing the live pathname fails
the swap cells.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

_HAVE_MINISIGN = shutil.which("minisign") is not None


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


class SignFromSnapshotTests(unittest.TestCase):
    """sign_manifest_step_from_snapshot signs memory, never the live file."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-bakesign9921-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
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
        Path(self.manifest).write_text(
            "validated: true\nbase_image_pinned: true\nguest_kernel: 6.18.0\n")
        Path(self.pkgs).write_text("pkg-a\n")

    def _hash_and_snapshot(self):
        staged = bake.stage_artifacts_for_gate(self.work, self.qcow, self.meta)
        live_inputs = [self.qcow, self.meta, self.manifest, self.pkgs]
        hashing = [staged.get(p, p) for p in live_inputs]
        snap = bake.snapshot_manifest_inputs(hashing)
        sums = os.path.join(self.out, "xpf-9.SHA256SUMS")
        sign.write_manifest(sums, hashing)
        return live_inputs, snap, sums

    def _evil_sums_text(self, expected):
        # Attacker manifest: valid format, same basenames, wrong qcow digest.
        # Constructed by replacing the qcow line of the good rendering so the
        # other three lines (and the exact format) stay identical.
        evil_digest = hashlib.sha256(b"EVIL-QCOW-POST-PARSE").hexdigest()
        lines = []
        for line in expected.splitlines():
            digest, base = line.split()
            if base == os.path.basename(self.qcow):
                digest = evil_digest
            lines.append(f"{digest}  {base}\n")
        return "".join(lines)

    def _capture_signer(self, captured):
        def fake_sign_manifest(manifest_path, seckey_path, comment=None,
                               sig_path=None):
            captured["bytes"] = Path(manifest_path).read_bytes()
            captured["path"] = manifest_path
            captured["seckey"] = seckey_path
            sig = sig_path or manifest_path + ".minisig"
            Path(sig).write_bytes(b"DUMMY-SIG")
            return sig
        return fake_sign_manifest

    def _run_sign_step(self, sums, snap, captured):
        with mock.patch.object(bake.sign, "require_minisign",
                               return_value="/usr/bin/minisign"), \
                mock.patch.object(bake.sign, "sign_manifest",
                                  side_effect=self._capture_signer(captured)), \
                mock.patch.dict(os.environ, {"XPF_SIGN_SECKEY": "dummy.sec"}):
            bake.sign_manifest_step_from_snapshot(
                self.out, sums, "9", snap, self.work)

    def test_render_matches_write_manifest_bytes(self):
        _live, snap, sums = self._hash_and_snapshot()
        self.assertEqual(bake.render_snapshot_manifest(snap),
                         Path(sums).read_text())

    def test_sign_refuses_attacker_live_sums(self):
        # Live sums already replaced with attacker bytes BEFORE the sign step;
        # the bake-set gate must refuse instead of signing a stale or altered
        # record.
        _live, snap, sums = self._hash_and_snapshot()
        expected = Path(sums).read_bytes()
        evil = self._evil_sums_text(expected.decode())
        Path(sums).write_text(evil)
        captured = {}
        with self.assertRaises(SystemExit) as ctx:
            self._run_sign_step(sums, snap, captured)
        self.assertIn("bytes differ from recorded hash", str(ctx.exception))
        self.assertEqual(captured, {}, "attacker bytes reached the signer")
        self.assertEqual(Path(sums).read_text(), evil)
        self.assertFalse(os.path.exists(sums + ".minisig"))

    def test_post_parse_live_swap_cannot_reach_signature(self):
        # The parent-review interleaving: the assert parses good live bytes,
        # then a writer swaps the sums file DURING the rehash (multi-GB work
        # takes seconds). The following strict bake-set gate must reject it
        # before the signer sees any bytes.
        live_inputs, snap, sums = self._hash_and_snapshot()
        expected = Path(sums).read_bytes()
        evil = self._evil_sums_text(expected.decode())
        swapped = []
        real_sha = bake.sign.sha256_file

        def swapping_sha(path):
            if path in live_inputs and not swapped:
                # Inside the assert's rehash loop: parse already consumed the
                # good live bytes. Land the replacement now.
                Path(sums).write_text(evil)
                swapped.append(True)
            return real_sha(path)

        with mock.patch.object(bake.sign, "sha256_file",
                               side_effect=swapping_sha):
            bake.assert_live_matches_manifest(live_inputs, sums, snap)
        self.assertTrue(swapped, "swap never fired — test is vacuous")
        self.assertEqual(Path(sums).read_text(), evil,
                         "race setup failed: live sums not replaced")
        captured = {}
        with self.assertRaises(SystemExit) as ctx:
            self._run_sign_step(sums, snap, captured)
        self.assertIn("bytes differ from recorded hash", str(ctx.exception))
        self.assertEqual(captured, {}, "replacement bytes reached the signer")
        self.assertEqual(Path(sums).read_text(), evil)
        self.assertFalse(os.path.exists(sums + ".minisig"))


    def test_sign_without_seckey_warns_and_leaves_live_untouched(self):
        _live, snap, sums = self._hash_and_snapshot()
        expected = Path(sums).read_bytes()
        env = dict(os.environ)
        env.pop("XPF_SIGN_SECKEY", None)
        with mock.patch.dict(os.environ, env, clear=True):
            bake.sign_manifest_step_from_snapshot(
                self.out, sums, "9", snap, self.work)
        self.assertEqual(Path(sums).read_bytes(), expected)
        self.assertFalse(os.path.exists(sums + ".minisig"))
    @unittest.skipUnless(_HAVE_MINISIGN, "minisign not installed")
    def test_sign_e2e_installed_pair_verifies_snapshot_bytes(self):
        # Real minisign end-to-end: the installed signature verifies the
        # snapshot rendered into the private manifest.
        _live, snap, sums = self._hash_and_snapshot()
        expected = Path(sums).read_bytes()
        pub = os.path.join(self.dir, "t.pub")
        sec = os.path.join(self.dir, "t.sec")
        subprocess.run(["minisign", "-G", "-W", "-p", pub, "-s", sec],
                       check=True, capture_output=True, timeout=60)
        with mock.patch.dict(os.environ, {"XPF_SIGN_SECKEY": sec}):
            bake.sign_manifest_step_from_snapshot(
                self.out, sums, "9", snap, self.work)
        self.assertEqual(Path(sums).read_bytes(), expected)
        r = subprocess.run(["minisign", "-V", "-p", pub, "-m", sums,
                            "-x", sums + ".minisig"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])


if __name__ == "__main__":
    unittest.main()
