#!/usr/bin/env python3
"""Per-sink cross-language version fixture (#16190).

Unifies the three Python validate_version copies into sign.py (bake/deploy
keep only die()-adapters) and pins the Go<->Python divergence in
version_fixture_16190.json. The fixture encodes expected outcomes PER SINK:
the Python filename sink requires an initial alphanumeric and drops the
Debian epoch ':', while Go ValidateVersionSegment (systemd ExecStart sink)
allows ':' and leading '-+_~:'. Neither policy is changed.

RED on revert: restore a divergent bake/deploy copy (e.g. widen its charset
to allow ':') and the bake/deploy legs disagree with the fixture's python
column; collapse the fixture to one universal column and the divergent rows
('1:2.0', '-x', ...) cannot be expressed. The Go leg is
TestVersionFixture16190 in pkg/upgrade.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
sys.path.insert(0, str(_HERE))
import sign  # noqa: E402

_FIXTURE = json.loads((_HERE / "version_fixture_16190.json").read_text())
CASES = _FIXTURE["cases"]



bake = load_subject("xpf_bake_16190", _ROOT / "scripts" / "image" / "bake.py")
deploy = load_subject("xpf_deploy_16190", _ROOT / "scripts" / "deploy" / "xpf-deploy.py")


def _sign_ok(v):
    try:
        sign.validate_version(v, "--version")
        return True
    except sign.SignError:
        return False


def _die_ok(fn, v):
    try:
        fn(v, "--version")
        return True
    except SystemExit:
        return False


class VersionFixture16190Tests(unittest.TestCase):
    def test_python_column_holds_for_sign_bake_and_deploy(self):
        for case in CASES:
            want = case["python"] == "accept"
            v = case["input"]
            with self.subTest(v=v):
                self.assertEqual(_sign_ok(v), want, f"sign {v!r}")
                self.assertEqual(_die_ok(bake.validate_version, v), want,
                                 f"bake {v!r}")
                self.assertEqual(_die_ok(deploy.validate_version, v), want,
                                 f"deploy {v!r}")

    def test_fixture_encodes_per_sink_divergence(self):
        # The fixture must NOT be a universal table: the epoch and every
        # leading-punctuation class diverge between the two sinks.
        by_input = {c["input"]: c for c in CASES}
        for v in ("1:2.0", "a:b", "-x", "+x", "_x", "~x", ":x",
                  "-", "+", "_", "~", ":"):
            self.assertIn(v, by_input)
            self.assertEqual(by_input[v]["python"], "reject", v)
            self.assertEqual(by_input[v]["go"], "accept", v)
        for v in ("1.2.3", "1.0.0+build", "1.0.0~rc1", "1.2.3-5-gabcdef"):
            self.assertEqual(by_input[v], {"input": v, "python": "accept",
                                           "go": "accept"}, v)
        for v in (".x", ".", "..", "/x", "a/b", "a\\b", "%x", " ", "", "é"):
            self.assertEqual(by_input[v]["python"], "reject", v)
            self.assertEqual(by_input[v]["go"], "reject", v)

    def test_bake_and_deploy_are_sign_adapters(self):
        # The deleted copies must not leave a second regex/policy behind.
        for mod in (bake, deploy):
            self.assertFalse(hasattr(mod, "_SAFE_VERSION"),
                             f"{mod.__name__} still carries _SAFE_VERSION")


if __name__ == "__main__":
    unittest.main()
