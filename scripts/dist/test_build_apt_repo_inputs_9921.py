#!/usr/bin/env python3
"""Unit tests for psaab/xpf#9921 F-066 — build-apt-repo.sh must allowlist
COMPONENT/ARCH/ORIGIN before any write and pin the Release Valid-Until.

On base, only SUITE was allowlisted: publisher-env COMPONENT/ARCH with `/..`
wrote repo files outside --out (via POOL/DISTDIR), and a newline-bearing
ORIGIN injected Release fields — including duplicate `Valid-Until:` lines
ahead of the genuine one — past a presence-only grep, then GPG-signed into
the published repo.

Refusal cells need no external tools (the gate dies before any use of the
values); the positive build needs apt-ftparchive + dpkg-deb and is skipped
without them.

RED on revert: drop the gates and traversal escapes --out / the Release
carries three Valid-Until lines.
"""

from __future__ import annotations

import email.utils
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_BUILDER = _DIST / "build-apt-repo.sh"

_FAKE_DEB_NAME = "xpf-appliance_0.0.0-9921_amd64.deb"

_HAS_BUILD_TOOLS = bool(shutil.which("apt-ftparchive")
                        and shutil.which("dpkg-deb"))


def _build(outdir, debs, extra_env):
    """Run the builder; return (rc, combined_output)."""
    env = dict(os.environ)
    for var in ("XPF_APT_COMPONENT", "XPF_APT_ARCH", "XPF_APT_ORIGIN",
                "XPF_APT_SUITE", "XPF_APT_TOOL", "XPF_GPG_KEY",
                "XPF_APT_VALID_DAYS"):
        env.pop(var, None)
    env.update(extra_env)
    p = subprocess.run(
        ["sh", str(_BUILDER), "--out", outdir, "--suite", "stable",
         "--debs", debs],
        capture_output=True, text=True, env=env, timeout=120)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _make_deb(path):
    """Build a minimal VALID .deb (selftest.sh pattern) for positive legs."""
    pkgdir = os.path.join(os.path.dirname(path), "pkg")
    debdir = os.path.join(pkgdir, "DEBIAN")
    os.makedirs(debdir, exist_ok=True)
    Path(os.path.join(debdir, "control")).write_text(
        "Package: xpf-appliance\nVersion: 0.0.0-9921\nArchitecture: amd64\n"
        "Maintainer: t <t@x.invalid>\nDescription: 9921 fixture\n")
    subprocess.run(["dpkg-deb", "--build", pkgdir, path], check=True,
                   capture_output=True, timeout=60)


class RefusalTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-repo9921-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _refused(self, needle, extra_env):
        outdir = os.path.join(self.dir, "out")
        os.makedirs(outdir, exist_ok=True)
        rc, out = _build(outdir, os.path.join(self.dir, "fake.deb"), extra_env)
        self.assertNotEqual(rc, 0, f"malicious input accepted: {out[-500:]}")
        self.assertIn(needle, out.lower(),
                      f"refusal names no input (wrong reason?): {out[-500:]}")
        # The gate precedes the first mkdir: NOTHING may be written, inside
        # --out or out of it.
        self.assertFalse(os.path.exists(os.path.join(outdir, "apt")),
                         "repo tree written despite refused input")
        leftovers = [p for p in Path(self.dir).iterdir()
                     if p.name not in ("out",)]
        self.assertEqual(leftovers, [],
                         f"writes escaped --out: {leftovers}")
        return out

    def test_component_traversal_rejected_pre_write(self):
        for comp in ("../../../../escape9921-COMP", "a/b", "a b", "a\nb",
                     "..", ".", "-lead"):
            with self.subTest(component=comp):
                self._refused("component", {"XPF_APT_COMPONENT": comp})

    def test_component_valid_shapes_accept_gate(self):
        # Valid shapes sail past the gate and die later on the missing --debs
        # file (or proceed to build). Either way the error must NOT name the
        # component gate — proving the gate (not a later stage) is what the
        # refusal cells exercise.
        for comp in ("main", "a", "main-debug", "UPPER_ok-1.2+v3",
                     "trail-", "a" * 64):
            with self.subTest(component=comp):
                outdir = os.path.join(self.dir, "out")
                os.makedirs(outdir, exist_ok=True)
                rc, out = _build(outdir, os.path.join(self.dir, "fake.deb"),
                                 {"XPF_APT_COMPONENT": comp})
                self.assertNotIn("component must match", out.lower(),
                                 f"valid COMPONENT rejected: {out[-300:]}")

    def test_arch_traversal_rejected_pre_write(self):
        for arch in ("x/../../../../../../escape9921-ARCH", "a/b", "a b",
                     "a\nb"):
            with self.subTest(arch=arch):
                self._refused("arch", {"XPF_APT_ARCH": arch})

    def test_origin_newline_rejected_pre_write(self):
        for origin in ("xpf\nValid-Until: Sat, 01 Jan 2099 00:00:00 UTC",
                       "xpf\r\nLabel: evil",
                       "xpf\x07bell",
                       "xpf\x7fdel"):
            with self.subTest(origin=repr(origin)):
                self._refused("origin", {"XPF_APT_ORIGIN": origin})


@unittest.skipUnless(_HAS_BUILD_TOOLS,
                     "needs apt-ftparchive + dpkg-deb for a real build")
class PositiveBuildTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-repo9921pos-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.deb = os.path.join(self.dir, _FAKE_DEB_NAME)
        _make_deb(self.deb)

    def _release(self, outdir):
        rel = Path(outdir) / "apt" / "dists" / "stable" / "Release"
        self.assertTrue(rel.is_file(), "no Release written")
        return rel.read_text()

    def test_valid_inputs_build_with_singleton_exact_valid_until(self):
        outdir = os.path.join(self.dir, "out")
        rc, out = _build(outdir, self.deb, {
            "XPF_APT_COMPONENT": "main-debug",
            "XPF_APT_ORIGIN": "xpf 'test'; inc: ok",
            "XPF_APT_VALID_DAYS": "7",
        })
        self.assertEqual(rc, 0, out[-800:])
        text = self._release(outdir)
        lines = [ln for ln in text.splitlines() if ln.startswith("Valid-Until:")]
        self.assertEqual(len(lines), 1,
                         f"want exactly one Valid-Until, got {lines}")
        # Exact derivation from the Release's own Date (no wall-clock skew):
        # Valid-Until == Date + VALID_DAYS, to the second.
        date_line = next(ln for ln in text.splitlines()
                         if ln.startswith("Date:"))
        vu_epoch = email.utils.parsedate_to_datetime(lines[0][len("Valid-Until:"):].strip()).timestamp()
        date_epoch = email.utils.parsedate_to_datetime(date_line[len("Date:"):].strip()).timestamp()
        self.assertEqual(vu_epoch, date_epoch + 7 * 86400)
        # Single-line metacharacters pass through as literal field data.
        self.assertIn("Origin: xpf 'test'; inc: ok", text)
        self.assertIn("Label: xpf 'test'; inc: ok", text)
        self.assertIn("Components: main-debug", text)

    def test_default_inputs_build(self):
        outdir = os.path.join(self.dir, "out")
        rc, out = _build(outdir, self.deb, {})
        self.assertEqual(rc, 0, out[-800:])
        text = self._release(outdir)
        self.assertEqual(sum(1 for ln in text.splitlines()
                             if ln.startswith("Valid-Until:")), 1)


if __name__ == "__main__":
    unittest.main()
