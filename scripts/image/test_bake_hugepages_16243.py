#!/usr/bin/env python3
"""Regression tests for the UMEM hugepage provisioning path (#16243).

The code side was already done: UMEM tries MAP_HUGETLB first, reports
`hugepage_backed` per binding, and sizes the pool at 80 x 2 MiB pages per
binding (umem_sizing_contract_tests). The measured rig defect was purely
provisioning: etc/sysctl.d/99-xpf-hugepages.conf existed in the repo but
NO path installed it -- not the bake, not the .deb, not any deploy tool --
so a ring-entries 16384 rig booted with HugePages_Total=0 and reported
`Hugepage-backed bindings: 0/30`.

These tests pin the bake half of the fix: virt_customize must write the
conf, verbatim from the repo file (single source of truth), and the value
must still cover the reference topology at the pinned 80 pages/binding.
"""

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

CONF_PATH_PREFIX = "/etc/sysctl.d/99-xpf-hugepages.conf:"


def _hugepages_write(argv):
    return next(
        value for flag, value in zip(argv, argv[1:])
        if flag == "--write" and value.startswith(CONF_PATH_PREFIX)
    )[len(CONF_PATH_PREFIX):]


class BakeHugepagesTests(unittest.TestCase):
    def test_bake_installs_hugepages_conf_verbatim_from_repo(self):
        calls = []
        with patch.object(bake, "run", side_effect=lambda argv: calls.append(argv)):
            bake.virt_customize("appliance.qcow2", "xpf.deb")

        shipped = _hugepages_write(calls[0])
        repo_conf = Path(bake.HUGEPAGES_CONF_PATH).read_text()
        self.assertEqual(
            shipped, repo_conf,
            "bake must ship etc/sysctl.d/99-xpf-hugepages.conf verbatim; "
            "a divergent copy would drift from the operator-edited file",
        )

    def test_effective_pool_covers_reference_topology(self):
        # hugepages_conf() itself must reject anything whose EFFECTIVE
        # (last uncommented exact-key) value is short -- the parse is the
        # guard, not a search for any positive line (review 16260).
        self.assertIn("vm.nr_hugepages = 1440", bake.hugepages_conf())

    def test_hugepages_conf_rejects_ineffective_reservations(self):
        cases = {
            "no assignment": "# no reservation here\n",
            "comment only": "# vm.nr_hugepages = 1440\n",
            "zero": "vm.nr_hugepages = 0\n",
            "wrong key": "vm.nr_hugepages_mempolicy = 1440\n",
            "trailing zero override":
                "vm.nr_hugepages = 1440\nvm.nr_hugepages = 0\n",
            "trailing short override":
                "vm.nr_hugepages = 1440\nvm.nr_hugepages = 600\n",
            "slash-form zero override":
                "vm.nr_hugepages = 1440\nvm/nr_hugepages = 0\n",
            "slash-form alone, short":
                "vm/nr_hugepages = 600\n",
            "leading-minus zero override":
                "vm.nr_hugepages = 1440\n-vm.nr_hugepages = 0\n",
            "leading-minus slash-form short override":
                "vm.nr_hugepages = 1440\n-vm/nr_hugepages = 600\n",
            "under reference pool": "vm.nr_hugepages = 600\n",
            "non-integer": "vm.nr_hugepages = lots\n",
            "slash-form non-integer": "vm/nr_hugepages = lots\n",
            "leading-slash zero override":
                "vm.nr_hugepages = 1440\n/vm/nr_hugepages = 0\n",
            # First-separator rule: '/vm.nr_hugepages' keeps its dot
            # (literal dotted filename under /proc/sys) — it never
            # assigns vm.nr_hugepages, so alone it is no reservation,
            # and after a zero it cannot rescue the pool.
            "leading-slash dotted key alone is not the knob":
                "/vm.nr_hugepages = 2400\n",
            "leading-slash dotted key cannot rescue a zero":
                "vm.nr_hugepages = 0\n/vm.nr_hugepages = 2400\n",
            # ...while a LEADING DOT does alias (separators swap).
            "leading-dot zero override":
                "vm.nr_hugepages = 1440\n.vm.nr_hugepages = 0\n",
            "backslash is not a separator":
                "vm.nr_hugepages = 0\nvm\\nr_hugepages = 2400\n",
            "bare negative-match suppresses assignment":
                "vm.nr_hugepages = 1440\n-vm.nr_hugepages\n",
            "bare negative-match slash form suppresses":
                "vm.nr_hugepages = 1440\n-vm/nr_hugepages\n",
            "glob key cannot be evaluated":
                "vm.nr_hugepages = 1440\nvm.* = 0\n",
            "trailing inline comment is part of the value":
                "vm.nr_hugepages = 1440 # pages\n",
            # path_simplify PRESERVES internal '..' (systemd then
            # rejects the write); it must not alias the knob.
            "internal dotdot alone is not the knob":
                "vm/../vm/nr_hugepages = 2400\n",
            "internal dotdot cannot rescue a zero":
                "vm.nr_hugepages = 0\nvm/../vm/nr_hugepages = 2400\n",
            # parse_file consumes ONE '-'; '--key' keys on '-key'.
            "double-minus alone is not the knob":
                "--vm.nr_hugepages = 2400\n",
            "double-minus cannot rescue a zero":
                "vm.nr_hugepages = 0\n--vm.nr_hugepages = 2400\n",
            # Kernel base-0 integers (proc_doulongvec_minmax):
            # 01440 is octal 800; the rest the kernel rejects outright
            # while Python's int() would have accepted them.
            "zero-padded octal is 800 not 1440":
                "vm.nr_hugepages = 01440\n",
            "underscore separator": "vm.nr_hugepages = 1_440\n",
            "leading plus": "vm.nr_hugepages = +1440\n",
            "full-width digits": "vm.nr_hugepages = １４４０\n",
            "negative": "vm.nr_hugepages = -1440\n",
            "hex below pool": "vm.nr_hugepages = 0x100\n",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(SystemExit, msg=name):
                    bake.hugepages_conf(text)

    def test_hugepages_conf_accepts_effective_pool_despite_noise(self):
        text = ("# vm.nr_hugepages = 0\n"
                "vm.nr_hugepages_mempolicy = 0\n"
                "vm.nr_hugepages = 2400\n")
        self.assertEqual(bake.hugepages_conf(text), text)

    def test_hugepages_conf_accepts_sysctl_normalized_forms(self):
        # sysctl accepts the slash form, the leading '-' (ignore-errors,
        # still applied), and no spaces around '='. A valid pool written
        # that way is a valid pool (fail-closed must not false-positive).
        for text in ("vm/nr_hugepages = 2400\n",
                     "-vm.nr_hugepages = 2400\n",
                     "vm.nr_hugepages=1440\n",
                     # A dash/slash override that RAISES the pool is the
                     # effective value too.
                     "vm.nr_hugepages = 600\n-vm/nr_hugepages = 2400\n"):
            with self.subTest(text=text):
                self.assertEqual(bake.hugepages_conf(text), text)

    def test_hugepages_conf_accepts_kernel_integer_forms(self):
        # Base-0 forms the KERNEL accepts at/above the pool: hex and
        # octal spellings of sufficient values are real reservations.
        for text in ("vm.nr_hugepages = 0x5A0\n",      # 1440 hex
                     "vm.nr_hugepages = 02640\n",      # 1440 octal
                     "vm.nr_hugepages = 2400\n"):
            with self.subTest(text=text):
                self.assertEqual(bake.hugepages_conf(text), text)

    def test_hugepages_conf_accepts_leading_slash_and_resumed_forms(self):
        for text in ("/vm/nr_hugepages = 2400\n",
                     # First-separator rule, other direction: a leading
                     # dot swaps separators, so this IS the knob.
                     ".vm.nr_hugepages = 2400\n",
                     # A dotted-filename key alongside a valid pool is
                     # an unrelated (inert) entry, not an override.
                     "vm.nr_hugepages = 1440\n/vm.nr_hugepages = 0\n",
                     # A bare directive suppresses only until a later
                     # real assignment replaces it again.
                     "vm.nr_hugepages = 600\n-vm.nr_hugepages\n"
                     "vm.nr_hugepages = 2400\n",
                     # Suppressing an unrelated key changes nothing.
                     "vm.nr_hugepages = 1440\n-net.ipv4.ip_forward\n"):
            with self.subTest(text=text):
                self.assertEqual(bake.hugepages_conf(text), text)

    def test_kernel_forms_stop_virt_customize_before_run(self):
        # Real-loader boundary (review 16260): ineffective spellings
        # must abort virt_customize before run() is ever called — not
        # via a mocked hugepages_conf.
        bad = ("vm.nr_hugepages = 01440\n",
               "vm/../vm/nr_hugepages = 2400\n",
               "--vm.nr_hugepages = 2400\n")
        for text in bad:
            with self.subTest(text=text):
                calls = []
                with patch.object(bake, "open",
                                  unittest.mock.mock_open(read_data=text),
                                  create=True):
                    with patch.object(
                            bake, "run",
                            side_effect=lambda argv: calls.append(argv)):
                        with self.assertRaises(SystemExit):
                            bake.virt_customize("appliance.qcow2", "xpf.deb")
                self.assertEqual(calls, [])

    def test_invalid_conf_stops_virt_customize_before_run(self):
        # The write argument is built through hugepages_conf(); a bad
        # repo conf must abort argument construction, before any
        # virt-customize invocation reaches run().
        calls = []
        with patch.object(bake, "hugepages_conf",
                          side_effect=SystemExit("bad pool")):
            with patch.object(bake, "run",
                              side_effect=lambda argv: calls.append(argv)):
                with self.assertRaises(SystemExit):
                    bake.virt_customize("appliance.qcow2", "xpf.deb")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
