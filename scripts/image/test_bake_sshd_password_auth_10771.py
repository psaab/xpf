#!/usr/bin/env python3
"""Regression for factory sshd password-auth posture (#10771 g3-F3)."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_SPEC = importlib.util.spec_from_file_location(
    "bake", Path(__file__).with_name("bake.py")
)
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)


class FactorySSHDPasswordAuthTests(unittest.TestCase):
    def test_baked_dropin_overrides_canonical_password_auth_setting(self):
        sshd = shutil.which("sshd") or "/usr/sbin/sshd"
        ssh_keygen = shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen"
        if not Path(sshd).is_file() or not Path(ssh_keygen).is_file():
            self.skipTest("OpenSSH sshd and ssh-keygen are required")

        calls = []
        with patch.object(bake, "run", side_effect=lambda argv: calls.append(argv)):
            bake.virt_customize("appliance.qcow2", "xpf.deb")

        prefix = "/etc/ssh/sshd_config.d/10-xpf-factory.conf:"
        dropins = [
            value[len(prefix):]
            for flag, value in zip(calls[0], calls[0][1:])
            if flag == "--write" and value.startswith(prefix)
        ]
        self.assertEqual(len(dropins), 1, "bake must write exactly one factory sshd drop-in")

        with tempfile.TemporaryDirectory() as root:
            config_dir = Path(root) / "sshd_config.d"
            config_dir.mkdir()
            host_key = Path(root) / "ssh_host_ed25519_key"
            subprocess.run(
                [ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)],
                check=True,
                capture_output=True,
                text=True,
            )
            main_config = Path(root) / "sshd_config"
            main_config.write_text(
                f"Include {config_dir}/*.conf\n"
                f"HostKey {host_key}\n"
                f"PidFile {root}/sshd.pid\n",
                encoding="utf-8",
            )
            cloudimg = config_dir / "60-cloudimg-settings.conf"
            cloudimg.write_text("PasswordAuthentication yes\n", encoding="utf-8")

            def effective_password_authentication():
                result = subprocess.run(
                    [sshd, "-T", "-f", str(main_config)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                settings = [
                    line for line in result.stdout.splitlines()
                    if line.startswith("passwordauthentication ")
                ]
                self.assertEqual(len(settings), 1, "sshd -T must report PasswordAuthentication")
                return settings[0]

            # Bind the fixture to the Canonical drop-in being the setting owner
            # without xpf's earlier-sorting factory pin.
            self.assertEqual(effective_password_authentication(), "passwordauthentication yes")

            (config_dir / "10-xpf-factory.conf").write_text(dropins[0], encoding="utf-8")
            self.assertEqual(effective_password_authentication(), "passwordauthentication no")


if __name__ == "__main__":
    unittest.main()
