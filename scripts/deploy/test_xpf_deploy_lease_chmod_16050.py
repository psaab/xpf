#!/usr/bin/env python3
"""Regression tests for the #16050 chmod fail-closed guard in the
kernel-roll lease scripts (`_acquire_lease` / `_renew_lease` /
`_clear_lease` in xpf-deploy.py).

The on-node scripts chmod /var/lib/xpf to 0750 and a pre-existing
kernel-roll.lock to 0600 before flocking, because a readable lock file
lets any local user flock it on an O_RDONLY fd and block the roll.
These tests EXECUTE the real generated scripts (only the
/var/lib/xpf prefix is redirected to a temp root and `flock` is
resolved through a PATH shim) with `chmod` replaced by a command that
fails, and assert the script refuses BEFORE flock: no ACQUIRED /
RENEWED output, no lock taken, no lease written or deleted.

RED-on-revert: changing the `&&` chain back to `;` (proceed to flock
despite a failed chmod) makes every chmod-failure cell below take the
lock / mutate the lease and fail.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))
xpf_deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xpf_deploy)

R = xpf_deploy.NodeExecResult
HOLDER = "orchA:pid1234"


class _LocalRunner:
    """Feeds the generated scripts to a local `sh -c`, with the node
    prefix redirected into a temp root and a shim dir at the front of
    PATH (for the failing `chmod` / marker `flock` shims)."""

    def __init__(self, root: Path, shim: Path):
        self.root = root
        self.shim = shim

    def rewrite(self, argv):
        script = argv[-1].replace("/var/lib/xpf", str(self.root / "var/lib/xpf"))
        return script


def _run_script(script: str, shim: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PATH"] = f"{shim}:{env['PATH']}"
    return subprocess.run(["sh", "-c", script], capture_output=True,
                          text=True, env=env, timeout=30)


class LeaseChmodFailClosed16050Tests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.shim = self.root / "shim"
        self.shim.mkdir()
        self.state = self.root / "var/lib/xpf"
        self.state.mkdir(parents=True)

    # ── shim / capture helpers ──────────────────────────────────────

    def _failing_chmod(self):
        (self.shim / "chmod").write_text("#!/bin/sh\nexit 1\n")
        (self.shim / "chmod").chmod(0o755)

    def _marker_flock(self):
        # A flock shim that records it was REACHED and otherwise
        # delegates to the real flock, so "proceeded to flock" is
        # observable even if the critical section then runs.
        marker = self.root / "flock-reached"
        real = subprocess.run(["command", "-v", "flock"], shell=True,
                              capture_output=True, text=True).stdout.strip()
        (self.shim / "flock").write_text(
            f"#!/bin/sh\ntouch {marker}\nexec {real} \"$@\"\n")
        (self.shim / "flock").chmod(0o755)
        return marker

    def _capture(self, fn, *args):
        """Run fn with _node_exec/_node_exec_result captured; return the
        script strings actually emitted."""
        scripts = []

        def fake_exec(runner, backend, node, argv, check=True):
            scripts.append(argv[-1].replace(
                "/var/lib/xpf", str(self.root / "var/lib/xpf")))
            return ""

        def fake_result(runner, backend, node, argv):
            scripts.append(argv[-1].replace(
                "/var/lib/xpf", str(self.root / "var/lib/xpf")))
            return R(0, "", "", True)

        runner = xpf_deploy.Runner(False)
        with mock.patch.object(xpf_deploy, "_node_exec", fake_exec), \
                mock.patch.object(xpf_deploy, "_node_exec_result", fake_result):
            fn(runner, *args)
        return scripts

    # ── chmod-failure cells: refuse before flock ────────────────────

    def test_acquire_chmod_failure_never_flocks_or_writes(self):
        self._failing_chmod()
        marker = self._marker_flock()
        scripts = self._capture(
            lambda r: xpf_deploy._acquire_lease(r, "ssh", "fw0", 0, HOLDER, 300))
        self.assertEqual(len(scripts), 1)
        res = _run_script(scripts[0], self.shim)
        self.assertNotIn("ACQUIRED", res.stdout)
        self.assertFalse(marker.exists(),
                         "acquire reached flock despite a failed chmod")
        self.assertFalse((self.state / "kernel-roll.lease").exists(),
                         "acquire wrote a lease despite a failed chmod")

    def test_renew_chmod_failure_never_flocks_or_rewrites(self):
        lease = self.state / "kernel-roll.lease"
        lease.write_text(
            '{"node_id": 0, "holder": "%s", "expires_at": "2999-01-01T00:00:00Z"}'
            % HOLDER)
        before = lease.read_bytes()
        self._failing_chmod()
        marker = self._marker_flock()
        scripts = self._capture(
            lambda r: xpf_deploy._renew_lease(r, "ssh", "fw0", 0, HOLDER, 300))
        self.assertEqual(len(scripts), 1)
        res = _run_script(scripts[0], self.shim)
        self.assertNotIn("RENEWED", res.stdout)
        self.assertFalse(marker.exists(),
                         "renew reached flock despite a failed chmod")
        self.assertEqual(lease.read_bytes(), before,
                         "renew rewrote the lease despite a failed chmod")

    def test_clear_chmod_failure_never_flocks_or_deletes(self):
        lease = self.state / "kernel-roll.lease"
        lease.write_text('{"node_id": 0, "holder": "%s"}' % HOLDER)
        self._failing_chmod()
        marker = self._marker_flock()
        scripts = self._capture(
            lambda r: xpf_deploy._clear_lease(r, "ssh", "fw0", HOLDER))
        self.assertEqual(len(scripts), 1)
        _run_script(scripts[0], self.shim)
        self.assertFalse(marker.exists(),
                         "clear reached flock despite a failed chmod")
        self.assertTrue(lease.exists(),
                        "clear deleted the lease despite a failed chmod")

    # ── control: working chmod still acquires ───────────────────────

    def test_acquire_with_working_chmod_still_acquires(self):
        scripts = self._capture(
            lambda r: xpf_deploy._acquire_lease(r, "ssh", "fw0", 0, HOLDER, 300))
        res = _run_script(scripts[0], self.shim)
        self.assertIn("ACQUIRED", res.stdout)
        self.assertEqual((self.state.stat().st_mode & 0o777), 0o750)
        self.assertEqual(
            ((self.state / "kernel-roll.lock").stat().st_mode & 0o777), 0o600)
        self.assertEqual(
            ((self.state / "kernel-roll.lease").stat().st_mode & 0o777), 0o600)


if __name__ == "__main__":
    unittest.main()
