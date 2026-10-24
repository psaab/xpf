#!/usr/bin/env python3
"""Hermetic unit tests for the #6498 Tier-1 first-boot substrate assertions.

#6494 taught the Tier-1 gate to check that the #1930 A/B slots are REGISTERED
in the guest's firmware. #6498 covers the two halves of the LANE-1 substrate
that registration alone does not prove:

  - `_ab_slot_esp_verdict` — each slot's ESP dir is fully STAGED
    (shimx64.efi + grubx64.efi + xpf.selector) and its selector names the
    RUNNING kernel. A slot can register cleanly and still be a dead boot entry
    if its selector points at a kernel the image does not ship — and that only
    surfaces during a rollback, the one moment the channel exists for.
  - `_kernel_hold_verdict` — every installed KERNEL package is in
    `apt-mark showhold` on the BOOTED image. bake.py verifies the hold inside
    virt-customize, before virt-sysprep / sparsify / export / first boot;
    nothing re-read it afterwards.

Both are pure functions over captured command output, in the
`_qemu_img_verdict` idiom, so the acceptance criteria are asserted without a
hypervisor or a baked qcow2.

WHY THE HOLD ENUMERATION IS NOT THE LITERAL `linux-*`: #6498's acceptance
criterion says "every installed linux-* package appears in apt-mark showhold".
That assertion REDS every valid image — `linux-base` is a hard dependency of
linux-image-*-generic, and `linux-libc-dev` / `linux-sysctl-defaults` /
`linux-perf` are installed alongside it; none are kernel packages and bake.py
deliberately holds none of them. The property the criterion reaches for is "the
kernel cannot move under the verifier-gated shim .o", so the gate enumerates
exactly the set bake.py holds — and the drift canary at the bottom binds those
two enumerations together, because a gate that enumerated a DIFFERENT set than
the bake holds would either red on a good image or certify an unprotected one.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_HERE = Path(__file__).resolve().parent
validate = load_subject("validate", _HERE / "validate.py")

KVER = "7.0.0-15-generic"


def _esp(slots=("xpf-A", "xpf-B"), files=None, selector=None, kver=KVER):
    """Render the in-guest ESP probe's line protocol.

    `files` maps slot -> the subset of _AB_SLOT_FILES that is PRESENT (default:
    all three). `selector` maps slot -> the verbatim selector lines (default:
    the pair bake.py seeds).
    """
    files = files or {}
    selector = selector or {}
    out = []
    for slot in slots:
        have = files.get(slot, list(validate._AB_SLOT_FILES))
        for f in validate._AB_SLOT_FILES:
            out.append(f"FILE {slot} {f} " + ("present" if f in have else "MISSING"))
        if "xpf.selector" in have:
            lines = selector.get(slot, [
                f'set xpf_slot_kernel="vmlinuz-{kver}"',
                f'set xpf_slot_initrd="initrd.img-{kver}"',
            ])
            out += [f"SEL {slot} {l}" for l in lines]
    return "\n".join(out) + "\n"


class AbSlotEspVerdictTests(unittest.TestCase):
    def test_fully_staged_both_slots_passes(self):
        ok, reason = validate._ab_slot_esp_verdict(_esp(), KVER)
        self.assertTrue(ok, reason)

    def test_missing_shim_in_one_slot_fails_and_names_it(self):
        # The bake's slot-staging fragment broke: register_slot() would see no
        # shimx64.efi, return 1, and never call efibootmgr for this slot.
        out = _esp(files={"xpf-B": ["grubx64.efi", "xpf.selector"]})
        ok, reason = validate._ab_slot_esp_verdict(out, KVER)
        self.assertFalse(ok)
        self.assertIn("xpf-B", reason)
        self.assertIn("shimx64.efi", reason)

    def test_missing_grub_fails(self):
        out = _esp(files={"xpf-A": ["shimx64.efi", "xpf.selector"]})
        ok, reason = validate._ab_slot_esp_verdict(out, KVER)
        self.assertFalse(ok)
        self.assertIn("grubx64.efi", reason)

    def test_missing_selector_is_reported_once_not_three_times(self):
        # One defect, one diagnosis: a slot with no selector file must not
        # ALSO be reported for each selector variable it therefore lacks.
        out = _esp(files={"xpf-A": ["shimx64.efi", "grubx64.efi"]})
        ok, reason = validate._ab_slot_esp_verdict(out, KVER)
        self.assertFalse(ok)
        self.assertIn("xpf.selector", reason)
        self.assertNotIn("xpf_slot_kernel", reason)

    def test_selector_naming_a_kernel_the_image_does_not_ship_fails(self):
        # The registration succeeds and the oneshot exits 0 — nothing ELSE in
        # the gate notices. This slot boots into a vmlinuz that is not there,
        # which is discovered during a rollback.
        ok, reason = validate._ab_slot_esp_verdict(_esp(kver="7.0.0-22-generic"),
                                                   KVER)
        self.assertFalse(ok)
        self.assertIn("xpf_slot_kernel", reason)
        self.assertIn("7.0.0-22-generic", reason)

    def test_selector_with_stale_initrd_only_still_fails(self):
        # Only the initrd half drifted (a partial edit of the seeding printf).
        out = _esp(selector={"xpf-B": [
            f'set xpf_slot_kernel="vmlinuz-{KVER}"',
            'set xpf_slot_initrd="initrd.img-6.18.0-1-generic"',
        ]})
        ok, reason = validate._ab_slot_esp_verdict(out, KVER)
        self.assertFalse(ok)
        self.assertIn("xpf_slot_initrd", reason)

    def test_selector_missing_a_variable_fails(self):
        out = _esp(selector={"xpf-A": [f'set xpf_slot_kernel="vmlinuz-{KVER}"']})
        ok, reason = validate._ab_slot_esp_verdict(out, KVER)
        self.assertFalse(ok)
        self.assertIn("xpf_slot_initrd", reason)

    def test_unquoted_selector_is_judged_on_its_value_not_its_punctuation(self):
        out = _esp(selector={"xpf-A": [
            f"set xpf_slot_kernel=vmlinuz-{KVER}",
            f"set xpf_slot_initrd=initrd.img-{KVER}",
        ]})
        ok, reason = validate._ab_slot_esp_verdict(out, KVER)
        self.assertTrue(ok, reason)

    def test_only_one_slot_staged_fails(self):
        # One slot is as unavailable as none: the channel refuses to arm
        # unless BOTH are registered.
        ok, reason = validate._ab_slot_esp_verdict(_esp(slots=("xpf-A",)), KVER)
        self.assertFalse(ok)
        self.assertIn("xpf-B", reason)

    def test_empty_probe_output_fails_rather_than_passing_vacuously(self):
        ok, reason = validate._ab_slot_esp_verdict("", KVER)
        self.assertFalse(ok)
        self.assertIn("xpf-A", reason)
        self.assertIn("xpf-B", reason)


class KernelHoldVerdictTests(unittest.TestCase):
    INSTALLED = ("linux-image-7.0.0-15-generic\nlinux-modules-7.0.0-15-generic\n"
                 "linux-modules-extra-7.0.0-15-generic\nlinux-generic\n")

    def test_all_installed_kernel_packages_held_passes(self):
        ok, reason = validate._kernel_hold_verdict(self.INSTALLED, self.INSTALLED)
        self.assertTrue(ok, reason)

    def test_one_unheld_package_fails_and_names_it(self):
        held = self.INSTALLED.replace("linux-modules-extra-7.0.0-15-generic\n", "")
        ok, reason = validate._kernel_hold_verdict(self.INSTALLED, held)
        self.assertFalse(ok)
        self.assertIn("linux-modules-extra-7.0.0-15-generic", reason)

    def test_unrelated_extra_holds_do_not_mask_a_missing_one(self):
        # A pre-existing unrelated hold must not be counted toward the kernel
        # set — this is the exact masking bake.py's per-package verify exists
        # to prevent, re-asserted on the booted image.
        held = self.INSTALLED.replace("linux-generic\n", "") + "frr\nsome-other-pkg\n"
        ok, reason = validate._kernel_hold_verdict(self.INSTALLED, held)
        self.assertFalse(ok)
        self.assertIn("linux-generic", reason)

    def test_superset_of_holds_still_passes(self):
        ok, reason = validate._kernel_hold_verdict(
            self.INSTALLED, self.INSTALLED + "frr\n")
        self.assertTrue(ok, reason)

    def test_empty_enumeration_fails_rather_than_passing_vacuously(self):
        # "all zero of them are held" is the pass that would argue against
        # anyone ever re-examining the property. bake.py's own hold fragment
        # collapsed to an empty enumeration TWICE during #1926.
        ok, reason = validate._kernel_hold_verdict("", "linux-generic\n")
        self.assertFalse(ok)
        self.assertIn("vacuous", reason)

    def test_whitespace_only_enumeration_is_also_empty(self):
        ok, _ = validate._kernel_hold_verdict("   \n \n", "linux-generic\n")
        self.assertFalse(ok)

    def test_nothing_held_at_all_fails(self):
        ok, reason = validate._kernel_hold_verdict(self.INSTALLED, "")
        self.assertFalse(ok)
        self.assertIn("4 of 4", reason)


class BakeAgreementCanaryTests(unittest.TestCase):
    """The gate must agree with the BAKE about what it is asserting.

    These bind the two copies rather than one of them: a divergence between
    what bake.py stages/holds and what validate.py asserts is ALWAYS a bug —
    the gate would either red on a good image or certify a broken one — so the
    agreement itself is the property under test.
    """

    BAKE = (_HERE / "bake.py").read_text(encoding="utf-8")

    def test_hold_globs_match_bake_pys_enumeration(self):
        i = self.BAKE.index("dpkg-query -W -f=")
        window = self.BAKE[i:i + 600]
        globs = tuple(re.findall(r'"(linux-[A-Za-z0-9*-]+)"', window))
        self.assertEqual(globs, validate._KERNEL_PKG_GLOBS,
                         "validate.py's kernel-package enumeration has drifted "
                         "from bake.py's apt-mark hold fragment: the gate would "
                         "assert a different set than the bake protects")

    def test_selector_variables_match_bake_pys_seeding(self):
        for var, prefix in validate._SELECTOR_VARS.items():
            self.assertIn(f'set {var}="{prefix}%s"', self.BAKE,
                          f"bake.py no longer seeds {var}={prefix}<kver> — the "
                          "selector assertion is asserting a variable the bake "
                          "does not write")

    def test_slot_files_match_bake_pys_staging(self):
        i = self.BAKE.index("staged A/B slots seeded at kernel")
        window = self.BAKE[max(0, i - 900):i]
        for f in validate._AB_SLOT_FILES:
            self.assertIn(f, window,
                          f"bake.py's slot-staging fragment no longer mentions "
                          f"{f} — the ESP assertion requires a file the bake "
                          "does not stage")


class WiringTests(unittest.TestCase):
    """A pure verdict nothing CALLS asserts nothing. These pin the call sites,
    so deleting an assertion from the scenario reds here rather than silently
    restoring the #6498 gap with every unit test still green."""

    SRC = (_HERE / "validate.py").read_text(encoding="utf-8")

    def _body(self, name):
        return self.SRC.split(f"def {name}(self", 1)[1].split("\n    def ", 1)[0]

    def test_scenario_a_asserts_the_kernel_hold(self):
        self.assertIn("self.assert_kernel_hold(", self._body("scenario_a"))

    def test_ab_channel_assertion_checks_the_esp_staging(self):
        self.assertIn("_ab_slot_esp_verdict(", self._body("assert_ab_kernel_channel"))

    def test_kernel_hold_assertion_uses_the_verdict(self):
        self.assertIn("_kernel_hold_verdict(", self._body("assert_kernel_hold"))

    def test_esp_staging_is_asserted_before_the_nvram_state(self):
        # Diagnosis order: an UNSTAGED slot must not be reported as "the
        # oneshot did not register it" — that points at the wrong half of the
        # channel (register_slot returns 1 without ever calling efibootmgr).
        body = self._body("assert_ab_kernel_channel")
        self.assertLess(body.index("_ab_slot_esp_verdict("),
                        body.index("_efibootmgr_slot_verdict("))


if __name__ == "__main__":
    unittest.main()
