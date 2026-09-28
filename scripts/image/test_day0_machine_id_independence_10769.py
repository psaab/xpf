#!/usr/bin/env python3
"""Machine-id independence of post-reset ssh regeneration (#10769 d05-F6 R2).

The factory-reset wipe installs a FRESH RANDOM /etc/machine-id instead of
truncating it (truncate would regenerate the same SMBIOS firmware UUID on
VMs, reproducing the prior DUID-EN). That rotation is safe for ssh ONLY
because post-reset key regeneration does not depend on first-boot
detection or machine-id state:

  * xpf-day0-config.service runs on a STAMP condition
    (ConditionPathExists=!/etc/xpf/.day0-config-applied — absent after a
    wipe), Before=ssh.service, with no ConditionFirstBoot or machine-id
    gating;
  * the xpf-day0-config script regenerates keys on KEY ABSENCE
    (ls /etc/ssh/ssh_host_*_key), never consulting machine-id.

RED on revert: gate the unit on first-boot/machine-id state (or make the
script consult it) and these asserts flip — a present fresh machine-id
would then skip regeneration and strand sshd without host keys.
"""

from __future__ import annotations

import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_UNIT = _HERE / "xpf-day0-config.service"
_SCRIPT = _HERE / "xpf-day0-config"


class TestDay0MachineIdIndependence10769(unittest.TestCase):
    def test_unit_has_no_machine_id_firstboot_gate(self):
        unit = _UNIT.read_text()
        self.assertNotIn("ConditionFirstBoot", unit)
        self.assertNotIn("machine-id", unit)
        self.assertIn("ConditionPathExists=!/etc/xpf/.day0-config-applied", unit)
        self.assertIn("Before=", unit)
        before = [ln for ln in unit.splitlines() if ln.startswith("Before=")]
        self.assertTrue(any("ssh.service" in ln for ln in before),
                        "day-0 unit must order before ssh.service")

    def test_script_regenerates_on_key_absence_only(self):
        script = _SCRIPT.read_text()
        self.assertIn("ssh_host_*_key", script)
        self.assertNotIn("machine-id", script)


if __name__ == "__main__":
    unittest.main()
