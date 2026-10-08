#!/usr/bin/env python3
"""Behavioral checks for the #12153 networkd install prerequisite."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

_INSTALLSH = Path(__file__).resolve().with_name("install.sh")


def _preflight(networkd_active: bool) -> tuple[int, str]:
    env = dict(os.environ)
    env["XPF_INSTALL_SOURCE_ONLY"] = "1"
    env["XPF_DRY_RUN"] = "1"
    env["XPF_TEST_NETWORKD_ACTIVE"] = "1" if networkd_active else "0"
    script = r'''
uname() {
    case "$1" in
        -m) printf '%s\n' x86_64 ;;
        -r) printf '%s\n' 6.18.0-test ;;
        *) return 1 ;;
    esac
}
systemctl() {
    [ "$1" = is-active ] && [ "$2" = --quiet ] &&
        [ "$3" = systemd-networkd.service ] || return 2
    [ "$XPF_TEST_NETWORKD_ACTIVE" = 1 ]
}
. "$1"
preflight
'''
    proc = subprocess.run(
        ["sh", "-c", script, "sh", str(_INSTALLSH)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


class NetworkdPreflightTests(unittest.TestCase):
    def test_requires_active_networkd_before_install(self):
        rc, output = _preflight(networkd_active=False)
        self.assertNotEqual(rc, 0, output)
        self.assertIn("must be installed and active", output)
        self.assertIn("does not install or enable it", output)

    def test_accepts_active_networkd(self):
        rc, output = _preflight(networkd_active=True)
        self.assertEqual(rc, 0, output)
        self.assertIn("preflight OK", output)


if __name__ == "__main__":
    unittest.main()
