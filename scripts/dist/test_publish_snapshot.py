#!/usr/bin/env python3
"""Unit tests for #4904 C — publish snapshots the tree before gating so the
bytes gated are the exact bytes uploaded (TOCTOU).

publish.py's gate_images hashed artifacts + verified install.sh against the
LIVE dist tree, kept no snapshot, then handed the SAME mutable path to the
backend, which reopened the files. A concurrent writer replacing an
artifact/sidecar/install.sh after the gate but before the backend read it made
a gate-pass log accompany DIFFERENT uploaded bytes (incl. an unsigned
installer). The fix copies the tree into a private immutable staging dir and
dispatches ONLY that snapshot.

These tests are hermetic (no minisign/gpg needed): the snapshot primitive is
tested directly, and main()'s dispatch wiring is tested with the gate functions
patched out and a concurrent-writer race injected. On revert (dispatch the
mutable tree) the race test uploads the REPLACED bytes and goes RED.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_DIST = Path(__file__).resolve().parent
publish = load_subject("publish", _DIST / "publish.py")


class SnapshotIsolationTests(unittest.TestCase):
    def test_snapshot_survives_original_mutation(self):
        src = tempfile.mkdtemp(prefix="xpf-snap-src-")
        self.addCleanup(shutil.rmtree, src, ignore_errors=True)
        Path(src, "a.txt").write_text("ORIG")
        os.makedirs(os.path.join(src, "sub"))
        Path(src, "sub", "b.txt").write_text("ORIG-B")

        staging, snap = publish._snapshot_dist(src)
        self.addCleanup(shutil.rmtree, staging, ignore_errors=True)

        # A concurrent writer replaces the original files AFTER the snapshot.
        Path(src, "a.txt").write_text("EVIL")
        Path(src, "sub", "b.txt").write_text("EVIL-B")

        # The snapshot still holds the gated bytes.
        self.assertEqual(Path(snap, "a.txt").read_text(), "ORIG")
        self.assertEqual(Path(snap, "sub", "b.txt").read_text(), "ORIG-B")

    def test_snapshot_is_private_0700(self):
        src = tempfile.mkdtemp(prefix="xpf-snap-src-")
        self.addCleanup(shutil.rmtree, src, ignore_errors=True)
        Path(src, "a.txt").write_text("x")
        staging, snap = publish._snapshot_dist(src)
        self.addCleanup(shutil.rmtree, staging, ignore_errors=True)
        self.assertEqual(stat.S_IMODE(os.stat(staging).st_mode), 0o700)

    def test_symlinks_copied_as_symlinks(self):
        # copytree(symlinks=True) preserves links so the gate's symlink refusal
        # still fires — a link must NOT be dereferenced into a real file.
        src = tempfile.mkdtemp(prefix="xpf-snap-src-")
        self.addCleanup(shutil.rmtree, src, ignore_errors=True)
        Path(src, "real.txt").write_text("real")
        os.symlink("real.txt", os.path.join(src, "link.txt"))
        staging, snap = publish._snapshot_dist(src)
        self.addCleanup(shutil.rmtree, staging, ignore_errors=True)
        self.assertTrue(os.path.islink(os.path.join(snap, "link.txt")))


class DispatchUsesSnapshotTests(unittest.TestCase):
    """main() must dispatch the immutable snapshot, not the mutable tree, even
    when a writer replaces a file between the snapshot and the upload."""

    def setUp(self):
        self.dist = tempfile.mkdtemp(prefix="xpf-snap-dist-")
        self.addCleanup(shutil.rmtree, self.dist, ignore_errors=True)
        self.record = os.path.join(self.dist + ".record")
        self.addCleanup(lambda: os.path.exists(self.record)
                        and os.remove(self.record))
        Path(self.dist, "marker.txt").write_text("ORIG")

        # A recorder backend: writes the marker bytes it actually sees.
        self.cmd = os.path.join(self.dist + ".cmd")
        self.addCleanup(lambda: os.path.exists(self.cmd)
                        and os.remove(self.cmd))
        Path(self.cmd).write_text(
            "#!/bin/sh\ncat \"$1/marker.txt\" > \"%s\"\n" % self.record)
        os.chmod(self.cmd, 0o755)

        # Patch the gates out; gate_images injects the concurrent-writer race
        # (replace the ORIGINAL marker AFTER the snapshot was taken).
        self._saved = {}
        dist = self.dist

        def fake_gate_images(gate_dir, require_installer=True):
            # The snapshot already happened; a racing writer clobbers the
            # ORIGINAL tree now. gate_dir is the snapshot, not `dist`.
            Path(dist, "marker.txt").write_text("EVIL")
            return ({}, "pub")

        for name, fn in (("gate_images", fake_gate_images),
                         ("gate_provenance", lambda *a, **k: None),
                         ("gate_latest", lambda *a, **k: None)):
            self._saved[name] = getattr(publish, name)
            setattr(publish, name, fn)

        self._env = {}
        for k, v in (("XPF_PUBLISH_CMD", self.cmd),
                     ("XPF_IMAGE_BASE_URL", "https://images.invalid")):
            self._env[k] = os.environ.get(k)
            os.environ[k] = v

    def tearDown(self):
        for name, fn in self._saved.items():
            setattr(publish, name, fn)
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_uploaded_bytes_are_the_gated_snapshot(self):
        rc = publish.main(["--dist", self.dist, "--channel", "stable",
                           "--no-apt", "--no-installer"])
        self.assertEqual(rc, 0)
        uploaded = Path(self.record).read_text()
        # The original was clobbered to EVIL after the snapshot; the upload must
        # carry the gated ORIG bytes. RED on revert (dispatch mutable tree).
        self.assertEqual(uploaded, "ORIG",
                         "publish uploaded the post-gate REPLACED bytes — the "
                         "TOCTOU snapshot is not in effect (#4904 C).")


if __name__ == "__main__":
    unittest.main()
