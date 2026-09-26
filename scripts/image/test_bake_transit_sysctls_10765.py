#!/usr/bin/env python3
"""Regression tests for appliance transit sysctl ownership (#10765 F7)."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

_SPEC = importlib.util.spec_from_file_location(
    "bake", Path(__file__).with_name("bake.py")
)
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)


class ApplianceTransitSysctlTests(unittest.TestCase):
    def test_bake_sysctl_dropin_does_not_enable_transit_forwarding(self):
        calls = []
        with patch.object(bake, "run", side_effect=lambda argv: calls.append(argv)):
            bake.virt_customize("appliance.qcow2", "xpf.deb")

        argv = calls[0]
        conf_path = "/etc/sysctl.d/99-xpf.conf:"
        sysctl_arg = next(
            value for flag, value in zip(argv, argv[1:])
            if flag == "--write" and value.startswith(conf_path)
        )
        sysctl_conf = sysctl_arg[len(conf_path):]
        self.assertIn("net.core.bpf_jit_enable=1\n", sysctl_conf)
        self.assertIn("net.ipv6.conf.all.accept_ra=0\n", sysctl_conf)
        self.assertIn("net.ipv6.conf.default.accept_ra=0\n", sysctl_conf)
        self.assertNotIn("net.ipv4.ip_forward=", sysctl_conf)
        self.assertNotIn("net.ipv6.conf.all.forwarding=", sysctl_conf)


if __name__ == "__main__":
    unittest.main()
