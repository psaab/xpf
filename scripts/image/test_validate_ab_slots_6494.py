#!/usr/bin/env python3
"""Hermetic unit tests for the #1930 LANE-1 A/B slot assertions the Tier-1
gate gained in #6494.

validate.py's scenario A cannot run without a hypervisor and a real baked
qcow2, but the verdicts it hinges on are pure functions over captured command
output and ARE testable without one — the _qemu_img_verdict idiom already in
the file:

  - `_efibootmgr_slot_verdict` — both A/B slots registered exactly once, each
    with its own signed shim loader, both reachable in BootOrder.
  - `_oneshot_clean_verdict` — the registration + promotion oneshots RAN and
    exited 0, with "never ran" distinguished from "ran and failed".

RED on revert: relax any of the three slot properties, or stop distinguishing
a skipped oneshot from a failed one, and an assertion here flips.

The efibootmgr samples are the real output shape: an entry line is
"BootXXXX[*]<space>LABEL<TAB>loader-path", where the label is followed by a TAB
and the path, NOT line-end. Anchoring a label match at $ is the exact miss that
created duplicate slots live during #1930, so the duplicate case below is a
regression fixture, not a hypothetical.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("validate", _HERE / "validate.py")
validate = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(validate)


def _efibootmgr(order="0003,0004,0000", entries=None):
    """Render efibootmgr output with a BootOrder and the given entry lines."""
    if entries is None:
        entries = [
            "Boot0003* xpf-A\tHD(1,GPT,1234)/File(\\EFI\\xpf-A\\shimx64.efi)",
            "Boot0004* xpf-B\tHD(1,GPT,1234)/File(\\EFI\\xpf-B\\shimx64.efi)",
            "Boot0000* ubuntu\tHD(1,GPT,1234)/File(\\EFI\\ubuntu\\shimx64.efi)",
        ]
    head = ["BootCurrent: 0003", "Timeout: 0 seconds", f"BootOrder: {order}"]
    return "\n".join(head + entries) + "\n"


class EfibootmgrSlotVerdictTests(unittest.TestCase):
    def test_both_slots_registered_once_and_in_bootorder_passes(self):
        ok, reason = validate._efibootmgr_slot_verdict(_efibootmgr())
        self.assertTrue(ok, reason)

    def test_missing_slot_fails(self):
        # The bake staged the ESP dirs but the in-guest oneshot never created
        # the entry: the whole #6494 failure mode.
        out = _efibootmgr(entries=[
            "Boot0003* xpf-A\tHD(1,GPT,1234)/File(\\EFI\\xpf-A\\shimx64.efi)",
            "Boot0000* ubuntu\tHD(1,GPT,1234)/File(\\EFI\\ubuntu\\shimx64.efi)",
        ])
        ok, reason = validate._efibootmgr_slot_verdict(out)
        self.assertFalse(ok)
        self.assertIn("xpf-B", reason)
        self.assertIn("NOT registered", reason)

    def test_neither_slot_registered_fails_naming_both(self):
        out = _efibootmgr(entries=[
            "Boot0000* ubuntu\tHD(1,GPT,1234)/File(\\EFI\\ubuntu\\shimx64.efi)",
        ])
        ok, reason = validate._efibootmgr_slot_verdict(out)
        self.assertFalse(ok)
        self.assertIn("xpf-A", reason)
        self.assertIn("xpf-B", reason)

    def test_duplicate_slot_fails(self):
        # The #1930 live bug: a label guard anchored at $ never matched, so
        # every boot created another entry. A duplicated slot makes BootNext
        # ambiguous.
        out = _efibootmgr(order="0003,0005,0004", entries=[
            "Boot0003* xpf-A\tHD(1,GPT,1234)/File(\\EFI\\xpf-A\\shimx64.efi)",
            "Boot0005* xpf-A\tHD(1,GPT,1234)/File(\\EFI\\xpf-A\\shimx64.efi)",
            "Boot0004* xpf-B\tHD(1,GPT,1234)/File(\\EFI\\xpf-B\\shimx64.efi)",
        ])
        ok, reason = validate._efibootmgr_slot_verdict(out)
        self.assertFalse(ok)
        self.assertIn("registered 2 times", reason)

    def test_right_label_wrong_loader_path_fails(self):
        # A stale/foreign entry that shares the LABEL but chainloads something
        # else must NOT count as registered (r1 Codex High on xpf-uefi-slots).
        out = _efibootmgr(entries=[
            "Boot0003* xpf-A\tHD(1,GPT,1234)/File(\\EFI\\ubuntu\\shimx64.efi)",
            "Boot0004* xpf-B\tHD(1,GPT,1234)/File(\\EFI\\xpf-B\\shimx64.efi)",
        ])
        ok, reason = validate._efibootmgr_slot_verdict(out)
        self.assertFalse(ok)
        self.assertIn("loader path", reason)

    def test_registered_but_absent_from_bootorder_fails(self):
        # A slot the firmware will never reach is not usable by the channel.
        out = _efibootmgr(order="0000")
        ok, reason = validate._efibootmgr_slot_verdict(out)
        self.assertFalse(ok)
        self.assertIn("BootOrder", reason)

    def test_no_bootorder_line_fails(self):
        out = "\n".join([
            "BootCurrent: 0003",
            "Boot0003* xpf-A\tHD(1,GPT,1234)/File(\\EFI\\xpf-A\\shimx64.efi)",
            "Boot0004* xpf-B\tHD(1,GPT,1234)/File(\\EFI\\xpf-B\\shimx64.efi)",
        ]) + "\n"
        ok, reason = validate._efibootmgr_slot_verdict(out)
        self.assertFalse(ok)
        self.assertIn("BootOrder", reason)

    def test_bare_path_form_without_File_wrapper_passes(self):
        # efibootmgr renders the loader either as File(\EFI\..) or bare; both
        # are the same registration, and the shell guard accepts both.
        out = _efibootmgr(entries=[
            "Boot0003* xpf-A\tHD(1,GPT,1234)/\\EFI\\xpf-A\\shimx64.efi",
            "Boot0004* xpf-B\tHD(1,GPT,1234)/\\EFI\\xpf-B\\shimx64.efi",
        ])
        ok, reason = validate._efibootmgr_slot_verdict(out)
        self.assertTrue(ok, reason)

    def test_bootorder_id_case_is_ignored(self):
        # efibootmgr prints hex ids; firmware/tooling case can differ between
        # the entry line and the BootOrder list. A case mismatch is not an
        # unreachable slot, and treating it as one would false-fail a good bake.
        out = _efibootmgr(order="000a,0000", entries=[
            "Boot000A* xpf-A\tHD(1,GPT,1234)/File(\\EFI\\xpf-A\\shimx64.efi)",
            "Boot000B* xpf-B\tHD(1,GPT,1234)/File(\\EFI\\xpf-B\\shimx64.efi)",
        ])
        ok, reason = validate._efibootmgr_slot_verdict(out)
        # xpf-B is genuinely absent from BootOrder here; xpf-A must NOT be.
        self.assertFalse(ok)
        self.assertNotIn("xpf-A: registered", reason)
        self.assertIn("xpf-B", reason)

    def test_empty_output_fails_rather_than_passing_vacuously(self):
        # An efibootmgr that printed nothing must not read as "all good".
        ok, _ = validate._efibootmgr_slot_verdict("")
        self.assertFalse(ok)


class BootCurrentSlotVerdictTests(unittest.TestCase):
    def test_bootcurrent_for_xpf_slot_passes(self):
        ok, reason = validate._efibootmgr_bootcurrent_slot_verdict(
            _efibootmgr(), "xpf-A")
        self.assertTrue(ok, reason)

    def test_bootcurrent_for_fallback_entry_fails(self):
        out = _efibootmgr().replace("BootCurrent: 0003", "BootCurrent: 0000")
        ok, reason = validate._efibootmgr_bootcurrent_slot_verdict(out, "xpf-A")
        self.assertFalse(ok)
        self.assertIn("firmware did not boot through", reason)

    def test_missing_bootcurrent_fails(self):
        out = _efibootmgr().replace("BootCurrent: 0003\n", "")
        ok, reason = validate._efibootmgr_bootcurrent_slot_verdict(out, "xpf-A")
        self.assertFalse(ok)
        self.assertIn("no valid BootCurrent", reason)

    def test_multiline_bootcurrent_value_is_not_accepted(self):
        out = _efibootmgr().replace("BootCurrent: 0003", "BootCurrent:\n0003")
        ok, reason = validate._efibootmgr_bootcurrent_slot_verdict(out, "xpf-A")
        self.assertFalse(ok)
        self.assertIn("no valid BootCurrent", reason)

    def test_wrong_slot_label_or_loader_cannot_match_bootcurrent(self):
        out = _efibootmgr(entries=[
            "Boot0003* xpf-A\tHD(1,GPT,1234)/File(\\EFI\\ubuntu\\shimx64.efi)",
            "Boot0004* xpf-B\tHD(1,GPT,1234)/File(\\EFI\\xpf-B\\shimx64.efi)",
        ])
        ok, reason = validate._efibootmgr_bootcurrent_slot_verdict(out, "xpf-A")
        self.assertFalse(ok)
        self.assertIn("no unique entry", reason)


class OneshotCleanVerdictTests(unittest.TestCase):
    def test_clean_run_passes(self):
        ok, reason = validate._oneshot_clean_verdict("u", "0", "active", "success")
        self.assertTrue(ok, reason)

    def test_nonzero_exit_fails(self):
        ok, reason = validate._oneshot_clean_verdict("u", "1", "failed", "exit-code")
        self.assertFalse(ok)

    def test_never_ran_is_distinguished_from_failed(self):
        # A Condition-skipped unit (never enabled, or ConditionPathExists
        # /boot/efi did not hold) is a DIFFERENT bake defect from a non-zero
        # exit, and collapsing them sends the next person to the wrong place.
        ok, reason = validate._oneshot_clean_verdict("u", "0", "inactive", "")
        self.assertFalse(ok)
        self.assertIn("never ran", reason)

        ok, reason = validate._oneshot_clean_verdict("u", "1", "failed", "exit-code")
        self.assertFalse(ok)
        self.assertNotIn("never ran", reason)

    def test_timeout_result_fails(self):
        # TimeoutStartSec=20 tripping is a real, non-hypothetical outcome for
        # xpf-uefi-slots (a stuck efibootmgr), and it exits with Result=timeout.
        ok, reason = validate._oneshot_clean_verdict("u", "0", "failed", "timeout")
        self.assertFalse(ok)
        self.assertIn("timeout", reason)


class ScenarioWiringTests(unittest.TestCase):
    def test_scenario_a_calls_the_ab_assertion(self):
        """The verdicts can be perfect and prove nothing if scenario A never
        calls them. Structural, and RED the moment the call is dropped."""
        src = (_HERE / "validate.py").read_text()
        body = src.split("def scenario_a(self):", 1)[1].split("def scenario_b(self):", 1)[0]
        self.assertIn("self.assert_ab_kernel_channel(", body,
                      "scenario A does not assert the #1930 A/B kernel channel "
                      "— the Tier-1 gate would sign a manifest for an image "
                      "whose kernel can never be upgraded in place (#6494)")

        self.assertIn("self.assert_ab_slot_boot(", body,
                      "scenario A never boots through an xpf UEFI entry")
        self.assertLess(body.index("self.assert_ab_kernel_channel("),
                        body.index("self.assert_ab_slot_boot("))

    def test_harness_exposes_the_assertion(self):
        self.assertTrue(hasattr(validate.Harness, "assert_ab_kernel_channel"))

    def test_harness_exposes_the_slot_boot_assertion(self):
        self.assertTrue(hasattr(validate.Harness, "assert_ab_slot_boot"))


if __name__ == "__main__":
    unittest.main()
