#!/usr/bin/env python3
"""The day-0 ISO must never EXIST world-readable, not merely end up 0600 (#6764).

The ISO tools create the output file themselves, so its mode comes from the
process umask at CREATION time — a typical 0022 yields 0644. The chmod that
follows the build only narrows it afterwards, and the file already contains
xpf.conf from the moment the tool writes it. On a large image that window is the
whole build, and every co-located UID can `isoinfo -R -x /xpf.conf` the
root-authentication hash, the IKE pre-shared key, the SNMP community and the
DDNS tokens straight out of it.

The pre-existing #4905-C test cannot see this. Its fake explicitly does
`os.chmod(out, 0o644)` AFTER writing — it simulates the finished artifact and
asserts the post-build chmod narrows it. That passes whether or not the file was
ever reachable at 0644 during construction, which is the thing that matters.

This test observes the mode the file has AT THE MOMENT THE TOOL CREATES IT,
under a deliberately lax 0022 umask, and never chmods it in the fake. With the
umask guard removed the recorded mode is 0644 and this fails; the post-build
chmod cannot repair a window that has already closed.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

mcd = load_subject("make_config_drive", Path(__file__).with_name("make_config_drive.py"))


class ConfigDriveCreationUmaskTests(unittest.TestCase):
    def _build_recording_creation_mode(self):
        """Return the ISO's mode as it existed the instant the tool created it."""
        seen = []

        def fake_run(argv, check=False):
            out = argv[argv.index("-o") + 1]
            # Create it the way the real tools do: let the UMASK decide. No
            # explicit chmod here — that is the whole point of the test.
            with open(out, "wb") as f:
                f.write(b"\x00" * 2048)
            seen.append(os.stat(out).st_mode & 0o777)

        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "xpf.conf")
            with open(cfg, "w") as f:
                f.write("system { host-name t; }\n")
            out = os.path.join(td, "day0.iso")

            old = os.umask(0o022)  # the lax default that produces 0644
            try:
                with mock.patch.object(mcd.subprocess, "run", fake_run), \
                     mock.patch.object(mcd, "_iso_tool", lambda: "xorriso"):
                    mcd.build_config_drive(cfg, out, node_id=None, validate=False)
                final = os.stat(out).st_mode & 0o777
                # Sample the umask HERE, inside the block, before this test's
                # own finally restores it — otherwise the test repairs the very
                # leak it is meant to detect and a guard that never restores
                # passes. (Measured: it did.)
                umask_after = os.umask(0o022)
                os.umask(umask_after)
            finally:
                os.umask(old)

        self.assertEqual(len(seen), 1, "the ISO tool was not invoked exactly once")
        return seen[0], final, umask_after

    def test_iso_is_never_created_world_readable(self):
        creation_mode, final_mode, _ = self._build_recording_creation_mode()
        self.assertEqual(
            creation_mode & 0o077, 0,
            f"the ISO was CREATED mode {creation_mode:04o} under a 0022 umask. It already "
            "contains xpf.conf at that moment, so every co-located UID can read the day-0 "
            "secrets for the whole build; chmodding afterwards cannot close a window that "
            "has already been open")
        # And the finished artifact is still owner-only — the #4905-C property.
        self.assertEqual(
            final_mode & 0o077, 0,
            f"finished ISO mode {final_mode:04o}, want owner-only")

    def test_umask_is_restored_after_the_build(self):
        """The guard must not leak a 0077 umask into the rest of the process.

        umask is process-global. A build that left it at 0077 would silently
        narrow every file the caller creates afterwards — including ones a later
        step expects to be group-readable."""
        _, _, umask_after_build = self._build_recording_creation_mode()
        self.assertEqual(
            umask_after_build, 0o022,
            f"the build left the umask at {umask_after_build:04o}, not the caller's 0022. "
            "umask is process-global, so a leaked 0077 silently narrows every file the "
            "caller creates afterwards")


if __name__ == "__main__":
    unittest.main()
