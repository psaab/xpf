#!/usr/bin/env python3
"""Hermetic unit tests for `guest_absent` (#7424 row 2).

The four negative assertions in scenarios A and C -- "the factory boot
installed no config" and "the REJECT wrote nothing" -- were written as

    if guest(inst, <existence probe>, check=False).returncode == 0:
        fail(...)

which fails OPEN. (Written without the literal tokens so the census below can
stay a clean zero-occurrence check rather than whitelisting its own docs.) `incus exec` exits non-zero both when the in-guest `test -e`
finds nothing AND when incus could not run the command at all (instance not
running, agent not up, connection refused). Only `== 0` was tested, so a
transport failure was indistinguishable from absence and scored as PASS.

The middle row of the table below is the one that matters and the one no
previous test could express: a check that could not observe its property must
not report that the property holds. Testing only PRESENT and ABSENT would leave
the fail-open exactly as it was, because the old code got both of those right.

RED on revert: restoring the `returncode == 0` form makes
`test_transport_failure_is_not_absence` pass silently (the helper would return
True), so that cell is the fail-on-revert pin.
"""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_HERE = Path(__file__).resolve().parent
validate = load_subject("validate", _HERE / "validate.py")


def _completed(rc, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["incus"], returncode=rc,
                                       stdout=stdout, stderr=stderr)


class GuestAbsentTests(unittest.TestCase):
    def test_guest_says_absent(self):
        with mock.patch.object(validate, "_default_run",
                               return_value=_completed(0, "XPF_ABSENT\n")):
            self.assertTrue(validate.guest_absent("inst", "/etc/xpf/xpf.conf"))

    def test_guest_says_present(self):
        with mock.patch.object(validate, "_default_run",
                               return_value=_completed(0, "XPF_PRESENT\n")):
            self.assertFalse(validate.guest_absent("inst", "/etc/xpf/xpf.conf"))

    def test_transport_failure_is_not_absence(self):
        """The whole point. incus itself failed, so nothing was observed.

        The pre-#7424 form returned "absent" here, which is how the central
        negative claims of scenarios A and C could pass without the guest ever
        being reached.
        """
        with mock.patch.object(
                validate, "_default_run",
                return_value=_completed(1, "", "Error: instance is not running")):
            with self.assertRaises(SystemExit) as cm:
                validate.guest_absent("inst", "/etc/xpf/xpf.conf")
            self.assertNotEqual(cm.exception.code, 0)

    def test_empty_output_with_zero_rc_is_not_absence(self):
        """rc=0 but no token: the shell ran and produced nothing recognisable.

        Distinct from the transport case, and equally not evidence of absence.
        A helper keyed only on the return code would accept this.
        """
        with mock.patch.object(validate, "_default_run",
                               return_value=_completed(0, "")):
            with self.assertRaises(SystemExit):
                validate.guest_absent("inst", "/etc/xpf/xpf.conf")

    def test_path_is_shell_quoted(self):
        """A path is interpolated into a `sh -c` snippet, so it must be quoted.

        Not hypothetical hygiene: without quoting, a path containing a space
        makes `[ -e a b ]` a syntax error, which produces no token -- so the
        check would fail loudly rather than silently, but it would fail on a
        legitimate input.
        """
        captured = {}

        def _capture(argv, **kw):
            captured["argv"] = argv
            return _completed(0, "XPF_ABSENT\n")

        with mock.patch.object(validate, "_default_run", side_effect=_capture):
            validate.guest_absent("inst", "/etc/xpf/a file")
        script = captured["argv"][-1]
        self.assertIn("'/etc/xpf/a file'", script)


class CallSiteTests(unittest.TestCase):
    def test_no_negative_assertion_still_uses_the_returncode_form(self):
        """The four sites must route through the helper.

        A helper nobody calls fixes nothing, and this is the check a future
        edit re-introducing the old form has to defeat.

        The pattern is deliberately narrow. An earlier draft forbade the
        literal `"test", "-e"` outright and red on five sites that are
        CORRECT: the positive assertions compare `!= 0`, so a transport
        failure makes them fail CLOSED. Only the `== 0` comparison -- "the
        probe exited zero, therefore the file is there, therefore anything
        else means it is not" -- is the fail-open shape. Forbidding the whole
        idiom would have forced the correct sites to churn to satisfy a test,
        which is the census warning on a valid input rather than finding a
        defect.
        """
        src = (_HERE / "validate.py").read_text()
        # Calls wrap across lines; normalise before matching.
        flat = re.sub(r"\s+", " ", src)
        offenders = re.findall(
            r'guest\([^()]*"test", "-e"[^()]*\)\.returncode == 0', flat)
        self.assertEqual(
            offenders, [],
            "a negative existence assertion is still comparing an in-guest "
            "probe's return code against 0, which cannot distinguish absence "
            "from an unobserved check (#7424): " + repr(offenders))
        # #16196: +1 module def, +1 Harness bound-method def, +1 bound
        # delegation, +4 scenario call sites (now self.guest_absent).
        self.assertEqual(src.count("guest_absent("), 7,
                         "expected module def + bound def/delegation + 4 call sites")

    def test_the_census_still_permits_the_fail_closed_positive_form(self):
        """Guard the guard: the `!= 0` sites must remain permissible.

        Without this, someone tightening the census above to the bare literal
        would red five correct call sites and the natural "fix" is to churn
        them. This pins that the census is about the COMPARISON, not the idiom.
        """
        flat = re.sub(r"\s+", " ", (_HERE / "validate.py").read_text())
        positives = re.findall(
            r'guest\([^()]*"test", "-e"[^()]*\)\.returncode != 0', flat)
        self.assertGreater(
            len(positives), 0,
            "expected the fail-closed positive assertions to still exist; if "
            "they are gone this guard is no longer testing anything")


if __name__ == "__main__":
    unittest.main()
