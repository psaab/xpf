#!/usr/bin/env python3
"""Hermetic unit tests for the Secure Boot posture the Tier-1 gate gained in
#6497.

The production appliance posture is UEFI Secure Boot ON (test/incus/setup.sh
sets `security.secureboot: "true"` "to match the production posture (#1943)"),
but the gate proved nothing about it: the incus scenarios INHERITED SB from the
incus default rather than setting it, and the plain-QEMU leg deliberately
preferred a NON-secboot OVMF and had no SB-on variant at all. A default flip, a
profile override, or a hypervisor without the MS db silently degraded the whole
gate to SB-off and still passed.

Two pure functions carry the fix, and both are testable without a hypervisor:

  - `_secureboot_verdict` — is SB actually ON, given the guest's three
    readings? The interesting cases are the ones where a reading is MISSING for
    a reason that is not "SB is off".
  - `_qemu_firmware_choice` — pick an SB-enforcing OVMF pair when the host has
    one; otherwise report the SB-off fallback AS a fallback.

RED on revert: make an unobservable posture pass, let mokutil's absence read as
"off", drop the explicit `security.secureboot=true`, or restore the SB-off
firmware preference, and an assertion here flips.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_HERE = Path(__file__).resolve().parent
validate = load_subject("validate", _HERE / "validate.py")


class SecureBootVerdictTests(unittest.TestCase):
    def test_efivar_one_passes(self):
        # `od -An -t u1 -j 4 -N 1` renders the flag byte with leading spaces.
        ok, reason = validate._secureboot_verdict("           1", "", "")
        self.assertTrue(ok, reason)
        self.assertIn("ENABLED", reason)

    def test_efivar_zero_fails(self):
        ok, reason = validate._secureboot_verdict("           0", "", "")
        self.assertFalse(ok)
        self.assertIn("DISABLED", reason)

    def test_efivar_zero_beats_an_active_lockdown(self):
        # lockdown can be forced from the cmdline, so it must never OVERRIDE a
        # definite "off" from the firmware. A gate that let it would pass an
        # SB-off boot on a box with lockdown=integrity in the cmdline.
        ok, reason = validate._secureboot_verdict("0", "", "none [integrity] confidentiality")
        self.assertFalse(ok)

    def test_mokutil_disabled_fails_even_without_the_efivar(self):
        ok, _ = validate._secureboot_verdict("", "SecureBoot disabled", "")
        self.assertFalse(ok)

    def test_mokutil_enabled_passes_when_the_efivar_is_unreadable(self):
        ok, reason = validate._secureboot_verdict("", "SecureBoot enabled", "")
        self.assertTrue(ok, reason)

    def test_missing_mokutil_is_not_read_as_secure_boot_off(self):
        # mokutil is NOT in bake.py's RUNTIME_PACKAGES. An assertion that
        # required it would turn a package-set change into a fake Secure Boot
        # "regression" — and, worse, would train the next person to ignore it.
        ok, reason = validate._secureboot_verdict("1", "", "")
        self.assertTrue(ok, reason)

    def test_lockdown_alone_corroborates_when_nothing_else_is_readable(self):
        ok, reason = validate._secureboot_verdict("", "", "none [integrity] confidentiality")
        self.assertTrue(ok, reason)
        ok, reason = validate._secureboot_verdict("", "", "none integrity [confidentiality]")
        self.assertTrue(ok, reason)

    def test_inactive_lockdown_alone_does_not_pass(self):
        ok, _ = validate._secureboot_verdict("", "", "[none] integrity confidentiality")
        self.assertFalse(ok)

    def test_no_readings_at_all_FAILS_rather_than_passing(self):
        # The core of #6497: an unobserved posture is not a satisfied one. A
        # gate that cannot see the property it exists to assert has not
        # asserted it, and passing there is how SB-off shipped green.
        ok, reason = validate._secureboot_verdict("", "", "")
        self.assertFalse(ok)
        self.assertIn("could not observe", reason)


class QemuFirmwareChoiceTests(unittest.TestCase):
    """`find` is injected, so the preference order is asserted independently of
    which OVMF packages this test host happens to have installed."""

    @staticmethod
    def _finder(present):
        def find(candidates):
            for c in candidates:
                if c in present:
                    return c
            return None
        return find

    def test_sb_enforcing_pair_is_preferred_when_available(self):
        present = set(validate._OVMF_SECBOOT_CODE_CANDIDATES[:1]) \
            | set(validate._OVMF_MS_VARS_CANDIDATES[:1]) \
            | set(validate._OVMF_CODE_CANDIDATES[:1]) \
            | set(validate._OVMF_VARS_CANDIDATES[:1])
        code, varsf, sb, reason = validate._qemu_firmware_choice(self._finder(present))
        self.assertTrue(sb, reason)
        self.assertIn("secboot", code + varsf)
        self.assertNotIn(code, validate._OVMF_CODE_CANDIDATES)

    def test_falls_back_to_sb_off_and_REPORTS_it(self):
        # The #6497 defect was not the fallback — it was presenting the
        # fallback as bootability proof without saying SB was off.
        present = set(validate._OVMF_CODE_CANDIDATES[:1]) \
            | set(validate._OVMF_VARS_CANDIDATES[:1])
        code, varsf, sb, reason = validate._qemu_firmware_choice(self._finder(present))
        self.assertIsNotNone(code)
        self.assertIsNotNone(varsf)
        self.assertFalse(sb)
        self.assertIn("SB-OFF", reason)

    def test_secboot_code_without_ms_vars_is_not_claimed_as_enforcing(self):
        # A secboot CODE build with plain VARS has no MS db: the shim would not
        # verify, and calling it "enforcing" would be a false claim.
        present = set(validate._OVMF_SECBOOT_CODE_CANDIDATES[:1]) \
            | set(validate._OVMF_CODE_CANDIDATES[:1]) \
            | set(validate._OVMF_VARS_CANDIDATES[:1])
        _, _, sb, _ = validate._qemu_firmware_choice(self._finder(present))
        self.assertFalse(sb)

    def test_ms_vars_without_a_secboot_code_build_is_not_claimed_as_enforcing(self):
        # A non-secboot CODE build IGNORES Secure Boot even with MS keys
        # present, so this pair enforces nothing.
        present = set(validate._OVMF_MS_VARS_CANDIDATES[:1]) \
            | set(validate._OVMF_CODE_CANDIDATES[:1]) \
            | set(validate._OVMF_VARS_CANDIDATES[:1])
        _, _, sb, _ = validate._qemu_firmware_choice(self._finder(present))
        self.assertFalse(sb)

    def test_no_firmware_at_all_returns_none(self):
        code, varsf, sb, reason = validate._qemu_firmware_choice(self._finder(set()))
        self.assertIsNone(code)
        self.assertIsNone(varsf)
        self.assertFalse(sb)
        self.assertIn("no usable OVMF", reason)


class WiringTests(unittest.TestCase):
    """The verdicts can be perfect and prove nothing if the scenarios do not
    set the posture and call them. Structural, and RED the moment either goes."""

    SRC = (_HERE / "validate.py").read_text()

    def test_launch_sets_secureboot_explicitly(self):
        body = self.SRC.split("def launch(self", 1)[1].split("\n    def ", 1)[0]
        self.assertIn("security.secureboot=true", body,
                      "launch() does not set security.secureboot explicitly — "
                      "the gate would INHERIT the posture it exists to prove, "
                      "and a default flip would degrade every scenario to "
                      "SB-off while still passing (#6497)")

    def test_scenario_a_asserts_secure_boot(self):
        body = self.SRC.split("def scenario_a(self):", 1)[1].split("\n    def ", 1)[0]
        self.assertIn("self.assert_secure_boot(", body,
                      "scenario A does not assert Secure Boot state (#6497)")

    def test_qemu_leg_uses_the_firmware_chooser(self):
        body = self.SRC.split("def scenario_qemu(self):", 1)[1]
        self.assertIn("_qemu_firmware_choice(", body,
                      "the QEMU leg does not go through the SB-preferring "
                      "firmware chooser — it is SB-off-only again (#6497)")

    def test_harness_exposes_the_assertion(self):
        self.assertTrue(hasattr(validate.Harness, "assert_secure_boot"))


if __name__ == "__main__":
    unittest.main()
