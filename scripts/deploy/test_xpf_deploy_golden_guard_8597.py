#!/usr/bin/env python3
"""#8597 (muse-004 K07/K08) — two fail-open shapes in the libvirt golden path.

K07: `_dependent_overlays` swallowed an OSError from `os.listdir` and returned
two EMPTY lists, which the caller reads as "nothing backs onto the golden". The
guard passed and `_atomic_install_golden` overwrote the golden under live
overlays — #5043's HA-pair disk corruption, reached through the guard written
to prevent it.

The state is not hypothetical: the non-root `fetch --install-libvirt` flow is a
supported path where this process cannot read the images directory and the
`sudo install` fallback can still write the golden. The guard's inputs and the
write's privileges are different, so "I could not look" must not mean "there is
nothing there".

Two things in the same file already said so. The function's own docstring:
"`unknown` exists because an unprobeable file is not evidence of safety." And
its sibling `_golden_lock`, which prints its analogous OSError LOUDLY rather
than proceeding silently.

K08: the `--no-import` / `--qcow2-only` path printed `sudo install ... <public
path> <golden>` for the operator to run later. The two importing paths stage
into a private dir and re-verify (#5817) precisely so "a post-verify swap in
--out cannot poison the golden"; this one handed over a public path with an
unbounded gap between the verify and the install.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dist"))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "xpf_deploy_8597",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "xpf-deploy.py"))
xpf_deploy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(xpf_deploy)


class DependentOverlaysFailsClosed8597(unittest.TestCase):
    def setUp(self):
        self.imgdir = tempfile.mkdtemp(prefix="xpf-8597-img-")
        self.golden = os.path.join(self.imgdir, "xpf-appliance.qcow2")
        with open(self.golden, "wb") as f:
            f.write(b"GOLDEN-V1")

    def tearDown(self):
        os.chmod(self.imgdir, 0o755)
        shutil.rmtree(self.imgdir, ignore_errors=True)

    def test_unlistable_images_dir_reports_unknown(self):
        """RED ON REVERT. Restoring `except OSError: return deps, unknown`
        makes both lists empty and this fails."""
        orig = os.listdir

        def boom(path):
            if os.path.realpath(path) == os.path.realpath(self.imgdir):
                raise PermissionError(13, "Permission denied", path)
            return orig(path)

        os.listdir = boom
        try:
            deps, unknown = xpf_deploy._dependent_overlays(self.golden)
        finally:
            os.listdir = orig

        self.assertEqual(deps, [],
                         "an unlistable directory yields no KNOWN dependants")
        self.assertTrue(
            unknown,
            "an unlistable images directory must be reported as UNKNOWN: the "
            "caller reads two empty lists as 'nothing backs onto the golden' "
            "and overwrites it under live overlays (#8597/K07)")
        paths = [p for p, _ in unknown]
        self.assertIn(os.path.realpath(self.imgdir),
                      [os.path.realpath(p) for p in paths],
                      "the unknown entry must name the directory that could "
                      "not be listed, so the operator knows what to fix")

    def test_listable_dir_is_unaffected(self):
        """OVER-BROAD CONTROL. A readable directory with nothing backing onto
        the golden must still report clean, or the guard refuses every
        legitimate re-fetch."""
        with open(os.path.join(self.imgdir, "unrelated.qcow2"), "wb") as f:
            f.write(b"x")
        orig_probe = xpf_deploy._qcow2_backing_file
        xpf_deploy._qcow2_backing_file = lambda path: None
        try:
            deps, unknown = xpf_deploy._dependent_overlays(self.golden)
        finally:
            xpf_deploy._qcow2_backing_file = orig_probe
        self.assertEqual(deps, [])
        self.assertEqual(unknown, [],
                         "a readable directory with no backers must report "
                         "clean; refusing here would block every re-fetch")

    def test_probe_failure_is_still_reported_as_unknown(self):
        """The #6760 channel this fix reuses must keep working: a file that
        cannot be probed is still UNKNOWN, not absent."""
        overlay = os.path.join(self.imgdir, "ha-fw0.qcow2")
        with open(overlay, "wb") as f:
            f.write(b"ovl")

        def boom_probe(path):
            raise xpf_deploy._ProbeIndeterminate("cannot probe")

        orig_probe = xpf_deploy._qcow2_backing_file
        xpf_deploy._qcow2_backing_file = boom_probe
        try:
            deps, unknown = xpf_deploy._dependent_overlays(self.golden)
        finally:
            xpf_deploy._qcow2_backing_file = orig_probe
        self.assertEqual(deps, [])
        self.assertTrue(unknown, "an unprobeable overlay stays UNKNOWN (#6760)")




if __name__ == "__main__":
    unittest.main(verbosity=1)
