#!/usr/bin/env python3
"""Behavioral Tier-1 gate reactions for cohort #10770 / #10772.

Each negative reading enters the real Harness assertion method and must raise
SystemExit through validate.fail; pure-verdict tests and call-site scans cannot
prove that reaction. The paired passing readings prove each fixture is otherwise
usable, so an unrelated earlier failure cannot satisfy a negative cell.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import shutil
import types
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("validate", _HERE / "validate.py")
validate = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(validate)

_KVER = "7.0.0-15-generic"
_EFIBOOTMGR = "\n".join((
    "BootCurrent: 0003",
    "Timeout: 0 seconds",
    "BootOrder: 0003,0004",
    "Boot0003* xpf-A\tHD(1,GPT,1234)/File(\\EFI\\xpf-A\\shimx64.efi)",
    "Boot0004* xpf-B\tHD(1,GPT,1234)/File(\\EFI\\xpf-B\\shimx64.efi)",
)) + "\n"


def _result(stdout="", returncode=0, stderr=""):
    return types.SimpleNamespace(stdout=stdout, returncode=returncode,
                                 stderr=stderr)


def _esp_output(missing_b_shim=False):
    lines = []
    for slot in validate._AB_SLOTS:
        for filename in validate._AB_SLOT_FILES:
            missing = (missing_b_shim and slot == "xpf-B" and
                       filename == "shimx64.efi")
            state = "MISSING" if missing else "present"
            lines.append(f"FILE {slot} {filename} {state}")
        lines.append(f'SEL {slot} set xpf_slot_kernel="vmlinuz-{_KVER}"')
        lines.append(f'SEL {slot} set xpf_slot_initrd="initrd.img-{_KVER}"')
    return "\n".join(lines) + "\n"


class GateReactionTests(unittest.TestCase):
    def setUp(self):
        self.harness = validate.Harness("unused.qcow2", "unused.tar.gz",
                                        "unused-net", False, verify_sig=False)
        self.addCleanup(shutil.rmtree, self.harness.work, ignore_errors=True)

    def _expect_gate_failure(self, call):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                call()
        self.assertEqual(raised.exception.code, 1)
        return stderr.getvalue()

    def _exercise_ab(self, branch):
        status = {
            "xpf-uefi-slots.service": {
                "ExecMainStatus": "1" if branch == "registration-oneshot" else "0",
                "ActiveState": "failed" if branch == "registration-oneshot" else "active",
                "Result": "exit-code" if branch == "registration-oneshot" else "success",
            },
            "xpf-kernel-promote.service": {
                "ExecMainStatus": "1" if branch == "promotion-oneshot" else "0",
                "ActiveState": "failed" if branch == "promotion-oneshot" else "active",
                "Result": "exit-code" if branch == "promotion-oneshot" else "success",
            },
        }

        def show_unit(_inst, unit, prop):
            return status[unit][prop]

        def guest(_inst, *cmd, **_kwargs):
            if cmd[:2] == ("uname", "-r"):
                return _result(_KVER)
            if cmd[:2] == ("sh", "-c") and cmd[2] == validate._AB_SLOT_ESP_PROBE:
                return _result(_esp_output(
                    missing_b_shim=branch == "esp-staging"))
            if cmd[0] == "efibootmgr":
                if branch == "efibootmgr-command":
                    # The command fails, but the captured text is valid: if the
                    # command-failure reaction is neutered, no later gate masks it.
                    return _result(_EFIBOOTMGR, 1, "temporary error")
                if branch == "slot-registration":
                    return _result(_EFIBOOTMGR.replace(
                        "Boot0004* xpf-B\tHD(1,GPT,1234)/File(\\EFI\\xpf-B\\shimx64.efi)\n", ""))
                return _result(_EFIBOOTMGR)
            if cmd[0] == "journalctl":
                return _result("captured unit journal\n")
            raise AssertionError(f"unexpected guest command: {cmd!r}")

        def guest_sh(_inst, command):
            if "no armed kernel candidate recorded" in command:
                return branch != "ordinary-boot-log"
            return True

        output = io.StringIO()
        with mock.patch.object(self.harness, "_wait"), \
                mock.patch.object(self.harness, "_show_unit", side_effect=show_unit), \
                mock.patch.object(validate, "guest", side_effect=guest), \
                mock.patch.object(validate, "guest_sh", side_effect=guest_sh), \
                contextlib.redirect_stdout(output):
            self.harness.assert_ab_kernel_channel("guest")
        return output.getvalue()

    def test_image_seal_bad_identity_fails_and_sealed_inventory_passes(self):
        def run_seal(bad):
            def fake_run(argv, **_kwargs):
                if argv[0] == "virt-ls":
                    names = "ssh_host_ed25519_key\n" if bad and argv[-1] == "/etc/ssh" else ""
                    return _result(names)
                if argv[0] == "virt-cat":
                    return _result("")
                raise AssertionError(f"unexpected command: {argv!r}")

            output = io.StringIO()
            with mock.patch.object(self.harness, "freeze_artifacts"), \
                    mock.patch.object(validate.shutil, "which", return_value="/usr/bin/tool"), \
                    mock.patch.object(validate.subprocess, "run", side_effect=fake_run), \
                    contextlib.redirect_stdout(output):
                self.harness.assert_image_sealed()
            return output.getvalue()

        failure = self._expect_gate_failure(lambda: run_seal(True))
        self.assertIn("image is NOT sealed", failure)
        self.assertIn("image seal verified", run_seal(False))

    def test_day0_permission_failure_fails_and_root_mode_600_passes(self):
        def run_assertion(stat):
            output = io.StringIO()
            with mock.patch.object(validate, "guest", return_value=_result(stat)), \
                    contextlib.redirect_stdout(output):
                self.harness.assert_day0_conf_perms("guest")
            return output.getvalue()

        failure = self._expect_gate_failure(
            lambda: run_assertion("644 root:root regular file"))
        self.assertIn("day-0 config permission assertion FAILED", failure)
        self.assertIn("mode 600", run_assertion("600 root:root regular file"))

    def test_secure_boot_off_fails_and_enabled_passes(self):
        def run_assertion(efivar):
            def guest(_inst, *cmd, **_kwargs):
                script = cmd[2]
                if script.startswith("od "):
                    return _result(efivar)
                if script.startswith("command -v mokutil"):
                    return _result("")
                if script.startswith("cat /sys/kernel/security/lockdown"):
                    return _result("")
                raise AssertionError(f"unexpected guest probe: {script!r}")

            output = io.StringIO()
            with mock.patch.object(validate, "guest", side_effect=guest), \
                    contextlib.redirect_stdout(output):
                self.harness.assert_secure_boot("guest")
            return output.getvalue()

        failure = self._expect_gate_failure(lambda: run_assertion("0"))
        self.assertIn("Secure Boot assertion FAILED", failure)
        self.assertIn("ENABLED", run_assertion("1"))

    def test_unheld_kernel_fails_and_all_packages_held_passes(self):
        packages = "linux-image-7.0.0-15-generic\nlinux-modules-7.0.0-15-generic\n"

        def run_assertion(held):
            # Route by the probe command; the first query enumerates packages,
            # and the second query returns apt-mark's hold list.
            def guest(_inst, *cmd, **_kwargs):
                output = (packages if cmd[2] == validate._INSTALLED_KERNEL_PKGS_PROBE
                          else held)
                return _result(output)

            output = io.StringIO()
            with mock.patch.object(validate, "guest", side_effect=guest), \
                    contextlib.redirect_stdout(output):
                self.harness.assert_kernel_hold("guest")
            return output.getvalue()

        failure = self._expect_gate_failure(
            lambda: run_assertion("linux-image-7.0.0-15-generic\n"))
        self.assertIn("kernel hold assertion FAILED", failure)
        self.assertIn("all 2 installed kernel packages held",
                      run_assertion(packages))

    def test_each_ab_channel_failure_reaction_exits_and_all_good_passes(self):
        expected = {
            "registration-oneshot": "A/B slot registration:",
            "esp-staging": "A/B slot ESP staging FAILED",
            "efibootmgr-command": "efibootmgr failed in the guest",
            "slot-registration": "A/B slot registration FAILED in-guest",
            "promotion-oneshot": "promotion gate:",
            "ordinary-boot-log": "ordinary-boot path",
        }
        for branch, message in expected.items():
            with self.subTest(branch=branch):
                failure = self._expect_gate_failure(lambda b=branch: self._exercise_ab(b))
                self.assertIn(message, failure)
        output = self._exercise_ab("all-good")
        self.assertIn("promotion gate ran clean on this ordinary boot", output)


if __name__ == "__main__":
    unittest.main()
