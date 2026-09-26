#!/usr/bin/env python3
"""Unit test for the standalone day-0 ISO file mode (#4905-C).

make_config_drive.build_config_drive() writes a day-0 config ISO whose sole
payload is xpf.conf — the most secret-bearing artifact on the box: the
root-authentication hash, the security IKE pre-shared-key, the SNMP community,
and the DDNS tsig/api-token/password. xorriso/genisoimage/mkisofs create that
ISO under the process umask (a typical ~0022 yields a world-readable 0644
file) and it lingers in CWD until an explicit destroy. Any co-located UID
could then `isoinfo -R -x /xpf.conf` the secrets straight out of it.

The deploy implementation (xpf-deploy.py:build_config_drive) already chmods the
finished ISO 0o600; make_config_drive.py did not (#4905-C). The fix chmods the
finished ISO 0o600 immediately after the build and stages xpf.conf 0o600 too.
These tests assert both:

  - after build_config_drive() the ISO has no group/other permission bits
    (mode & 0o077 == 0), regardless of the umask the ISO tool ran under;
  - the staged xpf.conf handed to the ISO builder is likewise owner-only.

RED on revert: restore the 0o644 staging chmod and drop the os.chmod(out,
0o600), and both assertions flip — the ISO comes back 0644 world-readable and
the staged copy 0644.
"""

from __future__ import annotations

import importlib.util
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "make_config_drive", Path(__file__).with_name("make_config_drive.py"))
mcd = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(mcd)


class MakeConfigDriveModeTests(unittest.TestCase):
    def _build(self, staged_mode_holder):
        """Drive build_config_drive() with the ISO builder mocked out.

        The fake subprocess.run emulates xorriso: it materialises the target
        ISO world-readable (0o644) under a lax umask — exactly the defect the
        fix must correct. It also records the mode of the staged xpf.conf about
        to be packed (the stage dir is rmtree'd right after build returns)."""

        def fake_run(argv, check=False):
            out = argv[argv.index("-o") + 1]
            stage = argv[-1]  # final positional arg = staging dir
            staged = os.path.join(stage, "xpf.conf")
            if os.path.isfile(staged):
                staged_mode_holder.append(os.stat(staged).st_mode & 0o777)
            with open(out, "wb") as f:
                f.write(b"\x00" * 2048)
            os.chmod(out, 0o644)  # world-readable, as the real tools leave it

            class _R:
                returncode = 0
            return _R()

        with tempfile.TemporaryDirectory() as td:
            conf = os.path.join(td, "day0.conf")
            with open(conf, "w") as f:
                f.write('system { root-authentication { '
                        'encrypted-password "$6$topsecret"; } }\n')
            out_iso = os.path.join(td, "day0-config.iso")
            old_umask = os.umask(0o022)  # force the world-readable default
            try:
                with mock.patch.object(mcd, "_iso_tool",
                                       return_value="xorriso"), \
                     mock.patch.object(mcd.subprocess, "run",
                                       side_effect=fake_run):
                    iso = mcd.build_config_drive(conf, out_iso, node_id=None,
                                                 validate=False)
                mode = os.stat(iso).st_mode & 0o777
            finally:
                os.umask(old_umask)
            return mode

    def test_iso_is_owner_only(self):
        staged = []
        mode = self._build(staged)
        self.assertEqual(
            mode & 0o077, 0,
            f"day-0 ISO must be owner-only, got {oct(mode)} (#4905-C)")
        self.assertEqual(mode, 0o600, f"expected 0o600, got {oct(mode)}")

    def test_staged_conf_is_owner_only(self):
        staged = []
        self._build(staged)
        self.assertEqual(len(staged), 1,
                         "expected exactly one staged xpf.conf")
        self.assertEqual(
            staged[0] & 0o077, 0,
            f"staged xpf.conf must be owner-only, got {oct(staged[0])} (#4905-C)")

    def test_check_config_warnings_are_printed(self):
        warning = "replace the published cluster PSK"

        def fake_run(argv, **_kwargs):
            if argv[1] == "check-config":
                return mock.Mock(
                    returncode=0,
                    stdout=f"PASS day0.conf\nwarning: {warning}\n",
                    stderr="",
                )
            out = argv[argv.index("-o") + 1]
            with open(out, "wb") as f:
                f.write(b"\x00" * 2048)
            return mock.Mock(returncode=0)

        with tempfile.TemporaryDirectory() as td:
            conf = os.path.join(td, "day0.conf")
            with open(conf, "w") as f:
                f.write("system { host-name day0; }\n")
            output = io.StringIO()
            with redirect_stdout(output), \
                 mock.patch.object(mcd, "find_xpfd",
                                   return_value="/usr/local/sbin/xpfd"), \
                 mock.patch.object(mcd, "_iso_tool",
                                   return_value="xorriso"), \
                 mock.patch.object(mcd.subprocess, "run",
                                   side_effect=fake_run):
                mcd.build_config_drive(
                    conf, os.path.join(td, "day0-config.iso"),
                    node_id=0, validate=True)
        self.assertIn(f"WARNING: {warning}", output.getvalue())


if __name__ == "__main__":
    unittest.main()
