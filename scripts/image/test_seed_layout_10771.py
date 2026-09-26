#!/usr/bin/env python3
"""Behavioral fixture tests for the #10771 seeded runtime layout gate."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "seed_layout_10771", _HERE / "seed_layout_10771.py")
seed_layout = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(seed_layout)

BINS = ("xpfd", "cli", "xpf-userspace-dp", "xpf-day0-config")


class SeededRuntimeLayoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.versions = self.root / "var/lib/xpf/versions"
        self.sbin = self.root / "usr/local/sbin"
        self.version_dir = self.versions / "1.0.0"
        self.version_dir.mkdir(parents=True)
        self.sbin.mkdir(parents=True)
        for name in BINS:
            path = self.version_dir / name
            path.write_text(f"runtime-{name}\n")
            path.chmod(0o755)
        (self.versions / "current").symlink_to("1.0.0")
        for name in BINS:
            (self.sbin / name).symlink_to(self.versions / "current" / name)
        self.snippet = seed_layout.seeded_runtime_layout_snippet(test_root=True)

    def run_gate(self):
        env = dict(os.environ)
        env["XPF_SEED_LAYOUT_ROOT"] = str(self.root)
        return subprocess.run(
            ["sh", "-c", self.snippet], capture_output=True, text=True, env=env)

    def test_complete_versioned_layout_passes(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("seeded runtime layout OK", result.stdout)

    def test_direct_staged_link_fails(self):
        (self.sbin / "xpfd").unlink()
        (self.sbin / "xpfd").symlink_to(self.root / "usr/local/share/xpf/staged/xpfd")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sbin/xpfd points", result.stderr)

    def test_missing_managed_link_fails(self):
        (self.sbin / "xpf-day0-config").unlink()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sbin/xpf-day0-config is not a symlink", result.stderr)

    def test_current_outside_versions_fails(self):
        external = self.root / "foreign-runtime"
        external.mkdir()
        for name in BINS:
            path = external / name
            path.write_text("foreign\n")
            path.chmod(0o755)
        (self.versions / "current").unlink()
        (self.versions / "current").symlink_to(external)
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("current resolves outside versions/", result.stderr)


if __name__ == "__main__":
    unittest.main()
