#!/usr/bin/env python3
"""Regression tests for the UMEM hugepage provisioning path (#16243/#16455).

#16243: UMEM tries MAP_HUGETLB first and sizes the pool at 80 x 2 MiB
pages per binding at ring-entries 16384, but NO provisioning path
installed etc/sysctl.d/99-xpf-hugepages.conf, so a ring-16384 rig
booted with HugePages_Total=0. The fix shipped the 1440-page pool on
every path.

#16455: that shipped default was itself the defect. 1440 pages is
2.8 GiB, withheld at boot on every baked image regardless of the
committed ring-entries (the default 1024 needs ~10 MiB per binding, no
large pool), and the .deb's /usr/lib/sysctl.d payload was applied by
systemd's file trigger at package-install time on foreign hosts. The
fix: the repo conf ships ONLY the default-ring pool (90 = 5 pages x 18
reference bindings), the bake refuses any other shipped default, rig
images size up explicitly with --hugepages N, and the .deb installs no
sysctl.d file at all.

These tests pin all three halves. The #16243 consumer-model cases from
review 16260 are kept, re-based on the 90-page default: any spelling
whose EFFECTIVE (last surviving, kernel-parsed) value is not the
required pool for the path under test must die at bake time.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

bake = load_subject("bake", Path(__file__).with_name("bake.py"))

CONF_PATH_PREFIX = "/etc/sysctl.d/99-xpf-hugepages.conf:"
RULES = Path(__file__).resolve().parents[2] / "debian" / "rules"


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

    def test_shipped_default_is_exactly_the_default_ring_pool(self):
        # The #16455 acceptance bound, at the bake gate: the effective
        # pool of the shipped conf is what ring-entries 1024 needs on
        # the reference topology (5 pages x 18 bindings) -- NOT the
        # 1440-page large-ring pool. On the pre-fix tree the repo conf
        # reads 1440 and this assertion (and hugepages_conf's equality
        # gate) fails.
        self.assertEqual(bake.effective_hugepages(), 90)
        self.assertEqual(bake.DEFAULT_HUGEPAGES, 90)
        self.assertIn("vm.nr_hugepages = 90", bake.hugepages_conf())
        self.assertLessEqual(bake.effective_hugepages() * 2, 180)  # MiB

    def test_hugepages_conf_rejects_the_old_large_ring_default(self):
        # Direct regression cell for #16455: the exact pre-fix shipped
        # value must refuse to bake as a default. (On the pre-fix tree
        # hugepages_conf() REQUIRED >= 1440, so this was the accepted
        # -- indeed mandated -- input.)
        with self.assertRaises(SystemExit):
            bake.hugepages_conf("vm.nr_hugepages = 1440\n")

    def test_hugepages_conf_rejects_ineffective_reservations(self):
        cases = {
            "no assignment": "# no reservation here\n",
            "comment only": "# vm.nr_hugepages = 1440\n",
            "zero": "vm.nr_hugepages = 0\n",
            "wrong key": "vm.nr_hugepages_mempolicy = 1440\n",
            "the old 1440 default": "vm.nr_hugepages = 1440\n",
            "above the default pool": "vm.nr_hugepages = 600\n",
            "just above the default pool": "vm.nr_hugepages = 91\n",
            "just below the default pool": "vm.nr_hugepages = 89\n",
            "trailing zero override":
                "vm.nr_hugepages = 90\nvm.nr_hugepages = 0\n",
            "trailing large override":
                "vm.nr_hugepages = 90\nvm.nr_hugepages = 1440\n",
            "slash-form zero override":
                "vm.nr_hugepages = 90\nvm/nr_hugepages = 0\n",
            "slash-form alone, large":
                "vm/nr_hugepages = 1440\n",
            "leading-minus zero override":
                "vm.nr_hugepages = 90\n-vm.nr_hugepages = 0\n",
            "leading-minus slash-form large override":
                "vm.nr_hugepages = 90\n-vm/nr_hugepages = 1440\n",
            "non-integer": "vm.nr_hugepages = lots\n",
            "slash-form non-integer": "vm/nr_hugepages = lots\n",
            "leading-slash zero override":
                "vm.nr_hugepages = 90\n/vm/nr_hugepages = 0\n",
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
                "vm.nr_hugepages = 90\n.vm.nr_hugepages = 0\n",
            "backslash is not a separator":
                "vm.nr_hugepages = 0\nvm\\nr_hugepages = 2400\n",
            "bare negative-match suppresses assignment":
                "vm.nr_hugepages = 90\n-vm.nr_hugepages\n",
            "bare negative-match slash form suppresses":
                "vm.nr_hugepages = 90\n-vm/nr_hugepages\n",
            "glob key cannot be evaluated":
                "vm.nr_hugepages = 90\nvm.* = 0\n",
            "trailing inline comment is part of the value":
                "vm.nr_hugepages = 90 # pages\n",
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
            # 0132 is octal 90 -- accepted below as a positive control;
            # these spellings parse to something else, or not at all.
            "octal spelling of a different value":
                "vm.nr_hugepages = 01440\n",
            "underscore separator": "vm.nr_hugepages = 1_440\n",
            "leading plus": "vm.nr_hugepages = +90\n",
            "full-width digits": "vm.nr_hugepages = ９０\n",
            "negative": "vm.nr_hugepages = -90\n",
            "hex below pool": "vm.nr_hugepages = 0x10\n",
            "hex of the old pool": "vm.nr_hugepages = 0x5A0\n",
            # Lexical gate: consumers are byte-oriented. NBSP anywhere
            # (value, key, or before a rescuing line), a Unicode line
            # separator inside a comment, or any non-ASCII/control byte
            # must refuse — Python's Unicode strip/splitlines would
            # otherwise invent an effective reservation.
            "NBSP before value": "vm.nr_hugepages = \u00a090\n",
            "NBSP before key": "\u00a0vm.nr_hugepages = 90\n",
            "NBSP rescue after zero":
                "vm.nr_hugepages = 0\n\u00a0vm.nr_hugepages = 90\n",
            "U+2028 inside comment hides assignment":
                "# copied comment\u2028vm.nr_hugepages = 90\n",
            "control byte in file": "vm.nr_hugepages = 90\x0b\n",
            # Kernel token length: 21 chars consumed = EINVAL
            # (proc_get_long TMPBUFLEN=22), even for octal 90.
            "21-char zero-padded octal": "vm.nr_hugepages = " + "0" * 18 + "132\n",
            # Sibling pool mutator: mempolicy shares the default
            # hstate pool under CONFIG_NUMA and applies in file order.
            "trailing mempolicy shrinks pool":
                "vm.nr_hugepages = 90\nvm.nr_hugepages_mempolicy = 0\n",
            "mempolicy before pool still refused":
                "vm.nr_hugepages_mempolicy = 0\nvm.nr_hugepages = 90\n",
            "slash-form mempolicy refused":
                "vm.nr_hugepages = 90\nvm/nr_hugepages_mempolicy = 5\n",
            # systemd line grammar: CR is a line ending too
            # (read_line_full), so CR-separated entries are real
            # lines at boot and must not hide from validation.
            "CR-separated zero override":
                "vm.nr_hugepages = 90\rvm.nr_hugepages = 0\n",
            "CR-separated bare suppressor":
                "vm.nr_hugepages = 90\r-vm.nr_hugepages\n",
            "CR-separated mempolicy":
                "vm.nr_hugepages = 90\rvm.nr_hugepages_mempolicy = 0\n",
            "CR-only file with wrong pool":
                "vm.nr_hugepages = 600\r",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(SystemExit, msg=name):
                    bake.hugepages_conf(text)

    def test_hugepages_conf_accepts_effective_pool_despite_noise(self):
        text = ("# vm.nr_hugepages = 0\n"
                "vm.unrelated_knob = 0\n"
                "vm.nr_hugepages = 90\n")
        self.assertEqual(bake.hugepages_conf(text), text)

    def test_hugepages_conf_accepts_ascii_crlf_and_spacing(self):
        # Positive controls for the lexical gate: CRLF line endings,
        # tabs, and ordinary ASCII spacing are consumer-valid.
        for text in ("vm.nr_hugepages = 90\r\n",
                     # CR alone is a line ending: two valid CR-separated
                     # lines, and a CRLF file, parse as at boot.
                     "vm.unrelated_knob = 0\rvm.nr_hugepages = 90\r",
                     "vm.nr_hugepages = 90\r\nvm.unrelated_knob = 0\r\n",
                     "\tvm.nr_hugepages\t=\t90 \n",
                     "vm.nr_hugepages = " + "0" * 17 + "132\n"):  # 20-char octal 90
            with self.subTest(text=text):
                self.assertEqual(bake.hugepages_conf(text), text)

    def test_hugepages_conf_accepts_sysctl_normalized_forms(self):
        # sysctl accepts the slash form, the leading '-' (ignore-errors,
        # still applied), and no spaces around '='. A valid pool written
        # that way is a valid pool (fail-closed must not false-positive).
        for text in ("vm/nr_hugepages = 90\n",
                     "-vm.nr_hugepages = 90\n",
                     "vm.nr_hugepages=90\n",
                     # A dash/slash override that RESTORES the pool is
                     # the effective value too.
                     "vm.nr_hugepages = 600\n-vm/nr_hugepages = 90\n"):
            with self.subTest(text=text):
                self.assertEqual(bake.hugepages_conf(text), text)

    def test_hugepages_conf_accepts_kernel_integer_forms(self):
        # Base-0 forms the KERNEL accepts at the default pool: hex and
        # octal spellings of 90 are real reservations of 90 pages.
        for text in ("vm.nr_hugepages = 0x5A\n",       # 90 hex
                     "vm.nr_hugepages = 0132\n",       # 90 octal
                     "vm.nr_hugepages = 90\n"):
            with self.subTest(text=text):
                self.assertEqual(bake.hugepages_conf(text), text)

    def test_hugepages_conf_accepts_leading_slash_and_resumed_forms(self):
        for text in ("/vm/nr_hugepages = 90\n",
                     # First-separator rule, other direction: a leading
                     # dot swaps separators, so this IS the knob.
                     ".vm.nr_hugepages = 90\n",
                     # A dotted-filename key alongside a valid pool is
                     # an unrelated (inert) entry, not an override.
                     "vm.nr_hugepages = 90\n/vm.nr_hugepages = 0\n",
                     # A bare directive suppresses only until a later
                     # real assignment replaces it again.
                     "vm.nr_hugepages = 600\n-vm.nr_hugepages\n"
                     "vm.nr_hugepages = 90\n",
                     # Suppressing an unrelated key changes nothing.
                     "vm.nr_hugepages = 90\n-net.ipv4.ip_forward\n"):
            with self.subTest(text=text):
                self.assertEqual(bake.hugepages_conf(text), text)

    def test_kernel_forms_stop_virt_customize_before_run(self):
        # Real-loader boundary (review 16260): ineffective spellings
        # must abort virt_customize before run() is ever called — not
        # via a mocked hugepages_conf.
        bad = ("vm.nr_hugepages = 01440\n",
               "vm/../vm/nr_hugepages = 2400\n",
               "--vm.nr_hugepages = 2400\n",
               # The pre-#16455 shipped file itself, verbatim value.
               "vm.nr_hugepages = 1440\n")
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


class HugepagesOverrideTests(unittest.TestCase):
    """The --hugepages rig path (#16455): explicit, sized, effective."""

    def test_override_renders_the_requested_effective_pool(self):
        for pages in (1440, 2400):
            with self.subTest(pages=pages):
                rendered = bake.hugepages_conf(pages=pages)
                self.assertEqual(bake.effective_hugepages(rendered), pages)
                repo = Path(bake.HUGEPAGES_CONF_PATH).read_text()
                # Only the value token changes; the rest of the file
                # (header, formula, warnings) is byte-identical.
                self.assertEqual(
                    rendered.replace(f"vm.nr_hugepages = {pages}",
                                       "vm.nr_hugepages = 90"),
                    repo)

    def test_override_rewrites_the_effective_line_not_a_shadowed_one(self):
        # Later line wins at boot: rewriting the FIRST (shadowed)
        # assignment would leave the effective pool at 90 while the
        # bake believed it had provisioned 1440.
        text = "vm.nr_hugepages = 600\nvm.nr_hugepages = 90\n"
        rendered = bake.hugepages_conf(text, pages=1440)
        self.assertEqual(rendered,
                         "vm.nr_hugepages = 600\nvm.nr_hugepages = 1440\n")
        self.assertEqual(bake.effective_hugepages(rendered), 1440)

    def test_override_below_the_large_ring_floor_refuses(self):
        # 600 was the old one-NIC shortfall (#7497); an override in
        # (default, 1440) is neither the default pool nor a large-ring
        # pool and must not bake.
        for pages in (91, 600, 1439):
            with self.subTest(pages=pages):
                with self.assertRaises(SystemExit):
                    bake.hugepages_conf(pages=pages)

    def test_bake_with_override_writes_the_rig_pool(self):
        calls = []
        with patch.object(bake, "run", side_effect=lambda argv: calls.append(argv)):
            bake.virt_customize("appliance.qcow2", "xpf.deb", hugepages=2400)
        self.assertEqual(
            bake.effective_hugepages(_hugepages_write(calls[0])), 2400)

    def test_parse_hugepages_arg(self):
        self.assertEqual(bake.parse_hugepages_arg("1440"), 1440)
        self.assertEqual(bake.parse_hugepages_arg("90"), 90)
        for bad in ("", "abc", "0x5A0", "+1440", "-1440", "1440 ",
                    " 1440", "1_440", "89", "0"):
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    bake.parse_hugepages_arg(bad)


class DebShipsNoSysctlTests(unittest.TestCase):
    """#16455: `apt install` on an unmarked host must not move the pool.

    debian/rules is the .deb's file list in practice; a sysctl.d
    payload there is applied by systemd's file trigger at install
    time. This cell reads the rules as make logical lines and refuses
    any install line that stages a sysctl.d file.
    """

    def test_debian_rules_installs_no_sysctl_d_payload(self):
        rules = RULES.read_text()
        # Join backslash-continued logical lines before matching.
        logical = rules.replace("\\\n", " ")
        offenders = [
            line.strip() for line in logical.splitlines()
            if "sysctl.d" in line
            and ("install" in line or line.strip().startswith("cp "))
            and not line.strip().startswith("#")
            and not line.strip().startswith("@#")
        ]
        self.assertEqual(
            offenders, [],
            "debian/rules must not stage any sysctl.d payload (#16455): "
            "systemd applies /usr/lib/sysctl.d at package-install time, "
            "so the .deb would rewrite a foreign host's hugepage pool "
            "the moment apt finishes (#10733)")

    def test_debian_rules_never_names_the_hugepages_conf_as_payload(self):
        rules = RULES.read_text()
        payload_lines = [
            line for line in rules.splitlines()
            if "99-xpf-hugepages.conf" in line
            and not line.lstrip().startswith("#")
            and not line.lstrip().startswith("@#")
        ]
        self.assertEqual(payload_lines, [])


if __name__ == "__main__":
    unittest.main()
