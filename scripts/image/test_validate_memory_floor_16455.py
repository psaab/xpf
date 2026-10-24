#!/usr/bin/env python3
"""Hermetic unit tests for the Tier-1 memory floor (#16455).

validate.py boots the baked image in a 2 GiB incus VM (launch()). The
pre-#16455 image carried vm.nr_hugepages = 1440 (2.8 GiB) in
/etc/sysctl.d, applied at boot: the guest OOM-killed, so the gate
either failed downstream or ran unrepresentatively, and the documented
4 GiB appliance kept only ~620 MiB before any service started.

Scenario A now asserts, from ONE /proc/meminfo read in the guest:
HugePages_Total <= 90 (the default-ring pool bake.DEFAULT_HUGEPAGES)
AND MemAvailable >= 1 GiB. Both properties are decided by the pure
`_memory_floor_verdict`, tested here without a hypervisor.

RED on revert: drop the assert from scenario A, raise the bound back
toward 1440, or let an unobserved reading pass, and a cell here flips.
The shipped-side bound is cross-pinned against bake.py and the repo
conf so the gate cannot silently follow a raised default.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_HERE = Path(__file__).resolve().parent
validate = load_subject("validate", _HERE / "validate.py")
bake = load_subject("bake", _HERE / "bake.py")

# A plausible post-boot 2 GiB guest meminfo with the FIXED pool.
FIXED_MEMINFO = """\
MemTotal:        2048000 kB
MemFree:         1200000 kB
MemAvailable:    1500000 kB
Buffers:           20000 kB
Cached:           300000 kB
HugePages_Total:       90
HugePages_Free:        72
HugePages_Rsvd:         0
HugePages_Surp:         0
Hugepagesize:       2048 kB
"""

# The pre-#16455 guest: the kernel could only carve 849 of the 1440
# requested pages out of 2 GiB, and almost nothing was left.
PREFIX_MEMINFO = """\
MemTotal:        2048000 kB
MemFree:           40000 kB
MemAvailable:     120000 kB
Buffers:            4000 kB
Cached:            60000 kB
HugePages_Total:      849
HugePages_Free:       849
HugePages_Rsvd:         0
HugePages_Surp:         0
Hugepagesize:       2048 kB
"""


class MemoryFloorVerdictTests(unittest.TestCase):
    def test_fixed_pool_passes(self):
        ok, reason = validate._memory_floor_verdict(FIXED_MEMINFO, 90)
        self.assertTrue(ok, reason)
        self.assertIn("HugePages_Total=90", reason)

    def test_prefix_pool_fails_on_hugepages_total(self):
        # The exact demonstrated defect: even the PARTIAL 849-page
        # allocation the 2 GiB guest managed is 9x the default pool.
        ok, reason = validate._memory_floor_verdict(PREFIX_MEMINFO, 90)
        self.assertFalse(ok)
        self.assertIn("HugePages_Total=849", reason)
        self.assertIn("1440", reason)

    def test_full_large_pool_fails_even_with_memory_available(self):
        # A 4 GiB appliance shape: pool fully allocated, MemAvailable
        # still above the (2 GiB-VM-calibrated) floor -- the pool bound
        # alone must catch it, because the acceptance is "at most what
        # ring 1024 needs", not "enough memory left on THIS size".
        text = FIXED_MEMINFO.replace("HugePages_Total:       90",
                                     "HugePages_Total:     1440")
        ok, reason = validate._memory_floor_verdict(text, 90)
        self.assertFalse(ok)
        self.assertIn("HugePages_Total=1440", reason)

    def test_low_mem_available_fails_even_with_small_pool(self):
        text = FIXED_MEMINFO.replace("MemAvailable:    1500000 kB",
                                     "MemAvailable:     500000 kB")
        ok, reason = validate._memory_floor_verdict(text, 90)
        self.assertFalse(ok)
        self.assertIn("below", reason)

    def test_boundary_values_pass(self):
        text = FIXED_MEMINFO.replace(
            "MemAvailable:    1500000 kB",
            f"MemAvailable:    {validate.MEM_AVAILABLE_FLOOR_KIB} kB")
        ok, reason = validate._memory_floor_verdict(text, 90)
        self.assertTrue(ok, reason)

    def test_one_page_over_the_pool_fails(self):
        text = FIXED_MEMINFO.replace("HugePages_Total:       90",
                                     "HugePages_Total:       91")
        ok, _ = validate._memory_floor_verdict(text, 90)
        self.assertFalse(ok)

    def test_unobserved_readings_fail(self):
        for text in ("", "MemTotal:        2048000 kB\n",
                     FIXED_MEMINFO.replace("HugePages_Total:       90\n", ""),
                     FIXED_MEMINFO.replace("MemAvailable:    1500000 kB\n", ""),
                     "HugePages_Total: lots\nMemAvailable: plenty kB\n"):
            with self.subTest(text=text[:30]):
                ok, reason = validate._memory_floor_verdict(text, 90)
                self.assertFalse(ok)
                self.assertIn("could not observe", reason)

    def test_zero_pool_passes_the_bound(self):
        # No pool at all is within "at most what ring 1024 needs" --
        # undersize only costs the advisory-THP fallback at large
        # rings, never correctness at the default.
        text = FIXED_MEMINFO.replace("HugePages_Total:       90",
                                     "HugePages_Total:        0")
        ok, reason = validate._memory_floor_verdict(text, 90)
        self.assertTrue(ok, reason)


class MemoryFloorWiringTests(unittest.TestCase):
    SRC = (_HERE / "validate.py").read_text()

    def test_scenario_a_asserts_the_floor(self):
        body = self.SRC.split("def scenario_a(self):", 1)[1].split(
            "\n    def ", 1)[0]
        self.assertIn("self.assert_memory_floor(", body)

    def test_gate_bound_matches_the_shipped_default(self):
        # The literal 90 in validate.py, bake's DEFAULT_HUGEPAGES, and
        # the repo conf's effective pool must agree; raising any one
        # without the others is the #16455 regression shape.
        self.assertEqual(bake.DEFAULT_HUGEPAGES, 90)
        self.assertEqual(bake.effective_hugepages(), 90)
        body = self.SRC.split("def assert_memory_floor(self, inst):", 1)[1]
        self.assertIn("_memory_floor_verdict(meminfo, 90)", body)


if __name__ == "__main__":
    unittest.main()
