#!/usr/bin/env python3
"""Regression tests for the #16804 networkd foreign-rule drop-in.

systemd-networkd's default ManageForeignRoutingPolicyRules=yes deletes
every xpf ip rule on `networkctl reconfigure` and on networkd restart.
The drop-in etc/systemd/networkd.conf.d/xpf.conf disables that cleanup;
it must ship in the baked image AND in the .deb (staged under
/usr/lib/systemd/networkd.conf.d), from the one repo source so the two
cannot drift.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
bake = load_subject("bake", HERE / "bake.py")
RULES = ROOT / "debian" / "rules"
SOURCE = ROOT / "etc" / "systemd" / "networkd.conf.d" / "xpf.conf"


class NetworkdDropinTests(unittest.TestCase):
    def test_source_dropin_disables_foreign_rule_cleanup(self):
        text = SOURCE.read_text()
        self.assertIn("[Network]", text)
        self.assertIn("ManageForeignRoutingPolicyRules=no", text)

    def test_bake_copies_dropin_into_image(self):
        self.assertEqual(bake.NETWORKD_CONF_PATH, str(SOURCE))
        calls = []
        with patch.object(bake, "run", side_effect=lambda argv: calls.append(argv)):
            bake.virt_customize("appliance.qcow2", "xpf.deb")
        argv = calls[0]
        needle = f"{SOURCE}:/etc/systemd/networkd.conf.d"
        self.assertIn(needle, argv)

    def test_debian_rules_stages_dropin_under_usr_lib(self):
        rules = RULES.read_text()
        # Join backslash-continued logical lines before matching.
        logical = rules.replace("\\\n", " ")
        self.assertIn("etc/systemd/networkd.conf.d/xpf.conf", logical)
        self.assertIn(
            "debian/xpf/usr/lib/systemd/networkd.conf.d/xpf.conf", logical)


if __name__ == "__main__":
    unittest.main()
