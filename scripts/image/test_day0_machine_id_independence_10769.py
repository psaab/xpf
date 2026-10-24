#!/usr/bin/env python3
"""Machine-id independence of post-reset ssh regeneration (#10769, #16445).

The factory-reset wipe installs a FRESH RANDOM /etc/machine-id instead of
truncating it (truncate would regenerate the same SMBIOS firmware UUID on
VMs, reproducing the prior DUID-EN). That rotation is safe for ssh ONLY
because post-reset key regeneration does not depend on first-boot
detection or machine-id state. Since #16445 it also must not depend on
the day-0 loader: a failed/interrupted reset leaves its pending marker
on the loader's stamp path, so the loader is condition-skipped on the
very boot that needs the keys back. The contract is therefore:

  * xpf-ssh-hostkeys.service regenerates on KEY ABSENCE alone
    (ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key), Before=
    ssh.service, runs ssh-keygen -A, with no ConditionFirstBoot,
    machine-id, or day-0 stamp gating, and is shipped by both the .deb
    (debian/rules) and the baked image (bake.py);
  * xpf-day0-config.service stays gated on the day-0 stamp (the twin:
    with the pending marker present the loader is still skipped) and
    neither the unit nor the script regenerates host keys any more.

RED on revert: gate the regenerator on first-boot/machine-id/stamp
state, drop either shipping path, or move regeneration back into the
day-0 loader, and these asserts flip -- a present fresh machine-id (or
the pending marker) would then skip regeneration and strand sshd
without host keys.
"""

from __future__ import annotations

import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
_DAY0_UNIT = _HERE / "xpf-day0-config.service"
_DAY0_SCRIPT = _HERE / "xpf-day0-config"
_REGEN_UNIT = _HERE / "xpf-ssh-hostkeys.service"
_RULES = _ROOT / "debian" / "rules"
_BAKE = _HERE / "bake.py"


def _directives(text: str) -> str:
    """Unit directives only: comments naming a forbidden gate to explain
    why it is absent must not trip the absence asserts."""
    return "\n".join(ln for ln in text.splitlines()
                    if ln.strip() and not ln.lstrip().startswith(("#", ";")))


class TestDay0MachineIdIndependence10769(unittest.TestCase):
    def test_regen_unit_gated_on_key_absence_only(self):
        unit = _directives(_REGEN_UNIT.read_text())
        self.assertNotIn("ConditionFirstBoot", unit)
        self.assertNotIn("machine-id", unit)
        self.assertNotIn(".day0-config-applied", unit)
        self.assertIn(
            "ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key", unit)
        self.assertIn("ExecStart=/usr/bin/ssh-keygen -A", unit)
        before = [ln for ln in unit.splitlines()
                  if ln.startswith("Before=")]
        self.assertTrue(any("ssh.service" in ln for ln in before),
                        "regen unit must order before ssh.service")

    def test_regen_unit_shipped_by_deb_and_bake(self):
        rules = _RULES.read_text()
        self.assertIn("cp scripts/image/xpf-ssh-hostkeys.service "
                      "debian/xpf.xpf-ssh-hostkeys.service", rules)
        self.assertIn("--name=xpf-ssh-hostkeys", rules)
        bake = _BAKE.read_text()
        self.assertIn("xpf-ssh-hostkeys.service:/usr/lib/systemd/system",
                      bake)
        self.assertIn("systemctl enable xpf-ssh-hostkeys.service", bake)

    def test_day0_loader_no_longer_regenerates(self):
        unit = _directives(_DAY0_UNIT.read_text())
        # Twin: the loader keeps its stamp gate and its xpfd ordering,
        # and no longer claims the ssh ordering or the keygen job.
        self.assertIn("ConditionPathExists=!/etc/xpf/.day0-config-applied",
                      unit)
        self.assertNotIn("ssh.service", unit)
        script = _DAY0_SCRIPT.read_text()
        self.assertNotIn("ssh-keygen", script)
        self.assertNotIn("regen_ssh_host_keys", script)
        self.assertNotIn("machine-id", script)


if __name__ == "__main__":
    unittest.main()
