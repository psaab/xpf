#!/usr/bin/env python3
"""Regressions for #10767 F2: apt must not install a different signed suite."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_INSTALLSH = _DIST / "install.sh"
_SOURCE_ENTRY = "/etc/apt/sources.list.d/xpf.sources:1"


def _target(source, suite, codename):
    return (f"MetaKey: main/binary-amd64/Packages\n"
            f"Sourcesentry: {source}\nSuite: {suite}\nCodename: {codename}\n")


class AptChannelBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xpf-apt-channel-10767-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        bindir = self.root / "bin"
        bindir.mkdir()
        self.targets = self.root / "targets"
        self.calls = self.root / "calls"
        self.installed = self.root / "installed"
        apt_get = bindir / "apt-get"
        apt_get.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  update) echo update >> \"$XPF_TEST_CALLS\" ;;\n"
            "  indextargets) cat \"$XPF_TEST_TARGETS\" ;;\n"
            "  install) echo install >> \"$XPF_TEST_CALLS\"; "
            "touch \"$XPF_TEST_INSTALLED\" ;;\n"
            "  *) exit 99 ;;\n"
            "esac\n")
        apt_get.chmod(0o755)
        self.bindir = bindir

    def _run(self, targets, channel="stable"):
        self.targets.write_text(targets)
        env = dict(os.environ)
        env.update({
            "XPF_INSTALL_SOURCE_ONLY": "1",
            "XPF_DRY_RUN": "0",
            "XPF_TEST_TARGETS": str(self.targets),
            "XPF_TEST_CALLS": str(self.calls),
            "XPF_TEST_INSTALLED": str(self.installed),
            "PATH": str(self.bindir) + os.pathsep + env.get("PATH", ""),
        })
        p = subprocess.run(
            ["sh", "-c", '. "$1"; CHANNEL="$2"; DRY=0; do_install',
             "sh", str(_INSTALLSH), channel],
            capture_output=True, text=True, env=env, timeout=30)
        return p.returncode, (p.stdout or "") + (p.stderr or "")

    def test_signed_edge_release_at_stable_path_is_rejected_before_install(self):
        rc, output = self._run(_target(_SOURCE_ENTRY, "edge", "edge"))
        self.assertNotEqual(rc, 0, output)
        self.assertIn("does not match selected channel", output)
        self.assertTrue(self.calls.read_text().splitlines() == ["update"])
        self.assertFalse(self.installed.exists(), "apt install ran for edge Release")

    def test_release_codename_must_also_match(self):
        rc, output = self._run(_target(_SOURCE_ENTRY, "stable", "edge"))
        self.assertNotEqual(rc, 0, output)
        self.assertIn("does not match selected channel", output)
        self.assertEqual(self.calls.read_text().splitlines(), ["update"])
        self.assertFalse(self.installed.exists())

    def test_selected_suite_is_accepted_not_confused_by_other_sources(self):
        targets = (_target("/etc/apt/sources.list.d/other.sources:1", "edge", "edge")
                   + "\n" + _target(_SOURCE_ENTRY, "stable", "stable"))
        rc, output = self._run(targets)
        self.assertEqual(rc, 0, output)
        self.assertIn("match selected channel 'stable'", output)
        self.assertEqual(self.calls.read_text().splitlines(), ["update", "install"])
        self.assertTrue(self.installed.exists())

    def test_missing_xpf_index_target_fails_closed(self):
        rc, output = self._run(_target("/etc/apt/sources.list.d/other.sources:1",
                                      "stable", "stable"))
        self.assertNotEqual(rc, 0, output)
        self.assertIn("no index targets for the xpf source", output)
        self.assertEqual(self.calls.read_text().splitlines(), ["update"])
        self.assertFalse(self.installed.exists())


if __name__ == "__main__":
    unittest.main()
