#!/usr/bin/env python3
"""Unit tests for #10909's per-release shim verdict retention gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("retain_shim_verdict", _DIST / "retain_shim_verdict.py")
retain_shim_verdict = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(retain_shim_verdict)


class RetainShimVerdictTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.object_path = self.root / retain_shim_verdict._OBJECT
        self.verdict_path = self.root / retain_shim_verdict._VERDICT
        self.object_path.parent.mkdir(parents=True)
        self.verdict_path.parent.mkdir(parents=True, exist_ok=True)
        self.object_path.write_bytes(b"release shim object")

    def tearDown(self):
        self.temp.cleanup()

    def verdict(self, *, measured=True, override=False):
        if not measured:
            processed, limit, headroom, slack = 0, 0, 0.0, 0
        elif override:
            processed, limit, headroom, slack = 990796, 1000000, 0.92, -140796
        else:
            processed, limit, headroom, slack = 800000, 1000000, 20.0, 50000
        return {
            "schema_version": 1,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "object_sha256": hashlib.sha256(self.object_path.read_bytes()).hexdigest(),
            "verdict": "OVERRIDDEN" if override else "PASS",
            "override_consumed": override,
            "reason": "headroom was explicitly overridden" if override else "measured headroom meets the floor",
            "stats": {
                "measured": measured,
                "processed_insns": processed,
                "insn_limit": limit,
                "headroom_pct": headroom,
                "floor_pct": 15.0,
                "slack_to_floor_insns": slack,
            },
        }

    def write_verdict(self, verdict):
        self.verdict_path.write_text(json.dumps(verdict), encoding="utf-8")

    def test_checked_in_verdict_matches_tracked_shim_object(self):
        repo_root = _DIST.parents[1]
        expected = repo_root / retain_shim_verdict._VERDICT
        self.assertEqual(retain_shim_verdict.validate_verdict(repo_root), expected)

    def test_valid_pass_is_uploaded_as_release_asset(self):
        self.write_verdict(self.verdict())
        calls = []

        def run(argv, *, check):
            calls.append((argv, check))

        retain_shim_verdict.upload_verdict(self.root, "v1.2.3", run=run)
        self.assertEqual(
            calls,
            [(["gh", "release", "upload", "v1.2.3", str(self.verdict_path), "--clobber"], True)],
        )

    def test_explicit_unmeasured_override_is_retained(self):
        self.write_verdict(self.verdict(measured=False, override=True))
        self.assertEqual(retain_shim_verdict.validate_verdict(self.root), self.verdict_path)

    def test_mismatched_object_hash_fails_before_upload(self):
        verdict = self.verdict()
        verdict["object_sha256"] = "0" * 64
        self.write_verdict(verdict)
        calls = []
        with self.assertRaisesRegex(ValueError, "does not match"):
            retain_shim_verdict.upload_verdict(self.root, "v1.2.3", run=lambda *a, **kw: calls.append(a))
        self.assertEqual(calls, [])

    def test_unmeasured_verdict_without_override_is_rejected(self):
        self.write_verdict(self.verdict(measured=False, override=False))
        with self.assertRaisesRegex(ValueError, "not explicitly overridden"):
            retain_shim_verdict.validate_verdict(self.root)


if __name__ == "__main__":
    unittest.main()
