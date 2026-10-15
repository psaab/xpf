#!/usr/bin/env python3
"""Hermetic unit tests for the #7347 skip ledger.

`scripts/image/validate.py` is the gate `bake.py`'s `finalize_artifacts` runs
STRICTLY BEFORE `sign_step` (#4017). Scenario Q returned early when `qemu-img`
was absent, `main()` ran the scenarios for effect and returned 0 regardless,
and `bake.py` reads exit 0 as a pass — so on a host without qemu-utils the
whole structural probe was skipped and the artifact was still minisigned
`validated: true`.

**A scenario that returns is indistinguishable from one that asserted**, and
here the difference was laundered through a signature: `publish.py` and
`xpf-deploy.py fetch` verify the signature and read a signed image as a
validated one. That is why this is worse than a gate that fails open into a log
line — downstream has no way to tell.

This is the SECOND vacuous gate found in the signing path. #6547 was the first
(the seal was never asserted), fixed in #7317, which set the posture this
follows: *"a security gate that skips itself when its tool is absent is the
vacuous-gate shape this check exists to remove."*

Two things these tests are careful about:

  * THE GATE IS CALIBRATED ON KNOWN-BAD INPUT BEFORE ANY GREEN IS TRUSTED.
    `test_missing_qemu_img_fails` strips qemu-img from PATH and asserts the
    scenario EXITS rather than returning — proving the gate fails when the tool
    is absent, not merely that it passes when present. A gate that has only
    ever been observed passing has not been observed at all.

  * FATAL vs TOLERATED IS A MEASURED CLASSIFICATION, NOT A GUESS. It is decided
    by one question: does bake.py guarantee the tool on a real bake host?
    `test_fatal_classification_matches_bake_requirements` reads bake.py's own
    preflight and pins the answer, so the classification cannot drift away from
    the thing that justifies it.
"""

from __future__ import annotations

import importlib.util
import io
import os
import shutil
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


validate = _load("validate")


class _Recorder:
    """The minimum surface scenario_qemu touches for the skip paths.

    Deliberately NOT a real Harness: constructing one makes a tempdir and takes
    a run-ownership token, none of which this behaviour depends on. Binding to
    the real `skip` method rather than reimplementing it is the point — a test
    that reimplements the thing under test measures the reimplementation.
    """

    def __init__(self, qcow2="/nonexistent.qcow2"):
        self.qcow2 = qcow2
        self.skipped = []

    skip = validate.Harness.skip


class MissingToolIsAFailureTests(unittest.TestCase):
    def test_missing_qemu_img_fails(self):
        """KNOWN-BAD INPUT. With qemu-img off PATH the gate must EXIT, not skip.

        Before #7347 this returned None and the run went on to exit 0, so the
        artifact was signed with no structural evidence.
        """
        h = _Recorder()
        empty = str(_HERE / "_no_such_bin_dir_7347")
        old = os.environ.get("PATH", "")
        os.environ["PATH"] = empty
        try:
            self.assertIsNone(shutil.which("qemu-img"),
                              "calibration precondition failed: qemu-img is still "
                              "resolvable, so this cell is not exercising the "
                              "missing-tool path at all")
            buf = io.StringIO()
            with self.assertRaises(SystemExit) as cm, redirect_stdout(buf):
                validate.Harness.scenario_qemu(h)
        finally:
            os.environ["PATH"] = old
        self.assertEqual(cm.exception.code, 1,
                         "a missing qemu-img must FAIL the gate (#7347)")
        self.assertEqual(h.skipped, [],
                         "qemu-img absence must be a hard fail, not a recorded "
                         "skip — a recorded skip is survivable with --allow-skip "
                         "and this one must never be")

    def test_control_qemu_img_present_does_not_take_the_missing_tool_path(self):
        """POSITIVE CONTROL. Without it, a scenario_qemu that raised
        unconditionally would pass the cell above while measuring nothing."""
        if shutil.which("qemu-img") is None:
            self.skipTest("qemu-img not installed on this host")
        h = _Recorder(qcow2=str(_HERE / "_definitely_not_a_qcow2_7347"))
        buf = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stdout(buf):
            validate.Harness.scenario_qemu(h)
        # It still exits — the file is not a qcow2 — but for the RIGHT reason.
        # The distinction is the whole point: same exit code, different cause.
        self.assertNotIn("qemu-img not found", buf.getvalue() + " ",
                         "with qemu-img present the gate must fail on the IMAGE, "
                         "not report the tool missing")


class SkipLedgerTests(unittest.TestCase):
    def test_a_fatal_skip_is_recorded_and_named(self):
        h = _Recorder()
        buf = io.StringIO()
        with redirect_stdout(buf):
            validate.Harness.skip(h, "X/leg", "because reasons", fatal=True)
        self.assertEqual(len(h.skipped), 1)
        what, reason, fatal = h.skipped[0]
        self.assertEqual((what, fatal), ("X/leg", True))
        self.assertIn("because reasons", reason)
        self.assertIn("FATAL", buf.getvalue(),
                      "a fatal skip must SAY so where an operator reads the log")

    def test_a_tolerated_skip_is_recorded_but_not_marked_fatal(self):
        h = _Recorder()
        buf = io.StringIO()
        with redirect_stdout(buf):
            validate.Harness.skip(h, "Q/boot-leg", "no kvm", fatal=False)
        self.assertEqual(h.skipped[0][2], False)
        self.assertNotIn("FATAL", buf.getvalue())

    def test_a_skip_is_never_silent(self):
        """The defect class in one assertion: a skip that produces no output is
        the thing that made scenario Q's return indistinguishable from a pass."""
        h = _Recorder()
        buf = io.StringIO()
        with redirect_stdout(buf):
            validate.Harness.skip(h, "Q/boot-leg", "no kvm", fatal=False)
        self.assertIn("SKIP", buf.getvalue())
        self.assertIn("Q/boot-leg", buf.getvalue())


class ClassificationMatchesTheBakeTests(unittest.TestCase):
    """FATAL vs TOLERATED must stay tied to what bake.py actually guarantees."""

    def test_fatal_classification_matches_bake_requirements(self):
        bake_src = (_HERE / "bake.py").read_text()

        # qemu-img IS require()d by the bake preflight, so its absence cannot
        # happen on a legitimate bake host -- which is what makes failing on it
        # safe rather than disruptive.
        self.assertIn('("qemu-img", "apt-get install qemu-utils")', bake_src,
                      "bake.py no longer require()s qemu-img. The #7347 hard "
                      "fail was justified BY that requirement; if the bake no "
                      "longer guarantees the tool, failing on it will break "
                      "legitimate bakes and the classification must be revisited")

        # /dev/kvm is only a WARNING there, so a TCG bake host is SUPPORTED and
        # the boot leg genuinely cannot run on it. That is why the boot leg is
        # fatal=False and why this fix deliberately departs from #7347's
        # "exit non-zero if ANY scenario SKIPped".
        self.assertIn("no /dev/kvm access", bake_src,
                      "bake.py no longer treats a missing /dev/kvm as a mere "
                      "warning. If KVM became required, the Q boot leg should "
                      "be reclassified fatal=True")

    def test_docstring_and_code_agree_about_always(self):
        """#7347 also found the file contradicting itself: the module docstring
        sold the structural probe as running `(always)` while the code comment
        1500 lines later said `always runs when qemu-img is present`. The code
        was the wrong half; both must now state the same posture."""
        src = (_HERE / "validate.py").read_text()
        self.assertNotIn("always runs when qemu-img is present", src,
                         "the code comment still claims the probe is gated on "
                         "the tool being present, which #7347 made untrue")
        self.assertIn("a missing qemu-img FAILS the gate rather", src,
                      "the module docstring must state the missing-tool posture")


class SkipVerdictTests(unittest.TestCase):
    """The DECISION, exercised without incus, a network or six VM boots.

    Each row states what the ledger holds and what the gate must do about it.
    The middle row is the one that matters: a ledger carrying ONLY tolerated
    skips must still exit 0, or a TCG bake host — a supported configuration —
    breaks. Without that row a verdict of "any skip fails" would pass every
    other cell here.
    """

    FATAL = ("Q/thing", "tool gone", True)
    OK = ("Q/boot-leg", "no kvm", False)

    def test_no_skips_passes(self):
        code, lines = validate._skip_verdict([], allow_skip=False)
        self.assertEqual(code, 0)
        self.assertTrue(any("no legs skipped" in x for x in lines))

    def test_only_tolerated_skips_still_passes(self):
        code, lines = validate._skip_verdict([self.OK], allow_skip=False)
        self.assertEqual(code, 0,
                         "a tolerated skip must not fail the gate — /dev/kvm is "
                         "only a WARNING in bake.py's preflight, so a TCG bake "
                         "host is supported and must keep baking")
        self.assertTrue(any("Q/boot-leg" in x for x in lines),
                        "a tolerated skip must still be NAMED; invisibility is "
                        "the defect being fixed, not the fatality")
        self.assertFalse(any("FATAL" in x for x in lines))

    def test_a_fatal_skip_fails(self):
        code, lines = validate._skip_verdict([self.OK, self.FATAL], allow_skip=False)
        self.assertEqual(code, 1)
        self.assertTrue(any("REFUSING to report success" in x for x in lines))

    def test_allow_skip_downgrades_a_fatal_skip(self):
        code, lines = validate._skip_verdict([self.FATAL], allow_skip=True)
        self.assertEqual(code, 0)
        self.assertTrue(any("Do not sign an artifact validated this way" in x
                            for x in lines),
                        "the escape hatch must say what it just permitted")

    def test_allow_skip_does_not_hide_the_skip(self):
        _, lines = validate._skip_verdict([self.FATAL], allow_skip=True)
        self.assertTrue(any("Q/thing" in x for x in lines))


class BakeDoesNotPassTheEscapeHatchTests(unittest.TestCase):
    """--allow-skip exists for dev runs. The signing path must never use it."""

    def test_bake_does_not_pass_allow_skip(self):
        bake_src = (_HERE / "bake.py").read_text()
        self.assertIn("validate.py", bake_src,
                      "bake.py no longer invokes validate.py; this guard is "
                      "measuring nothing")
        self.assertNotIn("--allow-skip", bake_src,
                         "bake.py passes --allow-skip, which re-opens exactly "
                         "the hole #7347 closed: a skipped leg would again "
                         "reach sign_step as a pass")


class BootLegClassificationTests(unittest.TestCase):
    """The boot leg must record a TOLERATED skip, behaviourally.

    This cell exists because the mutation matrix caught its absence: flipping
    the boot leg's `fatal=False` to `fatal=True` left every other test in this
    file green. That flip would fail every bake on a TCG host — a configuration
    bake.py explicitly supports, since /dev/kvm is only a WARNING in its
    preflight — so the classification being unbound was the most load-bearing
    gap in the change.

    It runs the REAL scenario_qemu against a real, conforming qcow2 with
    qemu-system-x86_64 removed from PATH but qemu-img kept. That is the exact
    shape of a TCG bake host: the structural probe passes, the boot leg cannot
    run. A source scan for `fatal=False` would also have caught the mutation,
    but it would not prove the structural probe still PASSES on such a host,
    which is the half that matters to whoever is baking.
    """

    def test_boot_leg_skip_is_tolerated_not_fatal(self):
        if shutil.which("qemu-img") is None:
            self.skipTest("qemu-img not installed on this host")
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            qcow = str(Path(d) / "probe.qcow2")
            # Sparse: a 20 GiB virtual size clears BAKE_MIN_BYTES (8 GiB) for
            # about 200 KiB of actual disk.
            size = validate.BAKE_MIN_BYTES + (1 << 30)
            subprocess.run(["qemu-img", "create", "-f", "qcow2", qcow, str(size)],
                           check=True, capture_output=True)

            # A PATH holding qemu-img and nothing else: the TCG-host shape.
            binz = Path(d) / "bin"
            binz.mkdir()
            os.symlink(shutil.which("qemu-img"), binz / "qemu-img")

            h = _Recorder(qcow2=qcow)
            old = os.environ.get("PATH", "")
            os.environ["PATH"] = str(binz)
            try:
                self.assertIsNotNone(shutil.which("qemu-img"),
                                     "precondition: qemu-img must stay reachable")
                self.assertIsNone(shutil.which("qemu-system-x86_64"),
                                  "precondition failed: qemu-system-x86_64 is still "
                                  "reachable, so this cell is not exercising the "
                                  "TCG-host path")
                buf = io.StringIO()
                with redirect_stdout(buf):
                    validate.Harness.scenario_qemu(h)
            finally:
                os.environ["PATH"] = old

        out = buf.getvalue()
        self.assertIn("structural probe OK", out,
                      "the structural probe must still PASS on a TCG host — that "
                      "is the whole point of classifying the boot leg tolerated "
                      "rather than skipping the scenario wholesale")
        self.assertEqual(len(h.skipped), 1, f"expected exactly one skip, got {h.skipped}")
        what, _reason, fatal = h.skipped[0]
        self.assertEqual(what, "Q/boot-leg")
        self.assertFalse(fatal,
                         "the boot leg must be a TOLERATED skip. bake.py treats a "
                         "missing /dev/kvm as a WARNING, not a require(), so a TCG "
                         "bake host is supported and marking this fatal would fail "
                         "every bake on one (#7347)")
        # #13205: the gate reports R/W accessibility, not mere existence.
        # A present-but-unusable /dev/kvm must be distinguished from a usable
        # device so operators can tell why the boot leg skipped.
        self.assertIn("/dev/kvm", _reason)
        self.assertIn("kvm_access=", _reason)


class KvmAccessGate13205Tests(unittest.TestCase):
    def test_kvm_unwritable_takes_skip_with_access_wording(self):
        """Present but R/W-denied /dev/kvm must skip, not launch QEMU.

        Master probes os.path.exists, so it proceeds past the gate and
        QEMU dies with accel=kvm permission denied (#13205, bake.py:1276
        already probes os.access R|W).
        """
        if shutil.which("qemu-img") is None or shutil.which("qemu-system-x86_64") is None:
            self.skipTest("qemu tools not installed")
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            qcow = str(Path(d) / "probe.qcow2")
            size = validate.BAKE_MIN_BYTES + (1 << 30)
            subprocess.run(["qemu-img", "create", "-f", "qcow2", qcow, str(size)],
                           check=True, capture_output=True)
            h = _Recorder(qcow2=qcow)
            real_access, real_popen = os.access, validate.subprocess.Popen
            def fake_access(p, m):
                return False if p == "/dev/kvm" else real_access(p, m)
            def checked_popen(argv, *args, **kwargs):
                if argv[0] == shutil.which("qemu-system-x86_64"):
                    raise AssertionError("QEMU must not launch without /dev/kvm R/W access")
                return real_popen(argv, *args, **kwargs)
            validate.os.access = fake_access
            validate.subprocess.Popen = checked_popen
            try:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    validate.Harness.scenario_qemu(h)
            finally:
                validate.os.access, validate.subprocess.Popen = real_access, real_popen
        self.assertEqual(len(h.skipped), 1, f"expected KVM skip, got {h.skipped}")
        self.assertIn("kvm_access=False", h.skipped[0][1],
                      "skip reason must reflect os.access R|W, not exists (#13205)")
        self.assertFalse(h.skipped[0][2])


class QemuOnlyIncusBypass13205Tests(unittest.TestCase):
    def _drive(self, scenario):
        calls = []
        class Rec:
            def __init__(self, *a, **k):
                self.skipped = []
            def __getattr__(self, n):
                def rec(*a, **k):
                    calls.append(n)
                return rec
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            q, m = Path(d) / "i.qcow2", Path(d) / "m.tar.gz"
            q.write_bytes(b""); m.write_bytes(b"")
            oh, orx, oa = validate.Harness, validate.maybe_reexec_incus_admin, sys.argv
            validate.Harness = Rec
            validate.maybe_reexec_incus_admin = lambda: calls.append("maybe_reexec")
            sys.argv = ["validate.py", "--qcow2", str(q), "--metadata", str(m), scenario]
            try:
                rc = validate.main()
            finally:
                validate.Harness, validate.maybe_reexec_incus_admin, sys.argv = oh, orx, oa
        self.assertEqual(rc, 0)
        return calls

    def test_q_only_skips_incus_but_keeps_signature_verification(self):
        calls = self._drive("q")
        self.assertNotIn("ensure_network", calls, "q-only must not create Incus network (#13205)")
        self.assertNotIn("import_image", calls, "q-only must not import multi-GB image (#13205)")
        self.assertIn("verify_signatures", calls,
                      "q-only must still verify signed manifest explicitly; it "
                      "only ran inside import_image before (#13205)")
        self.assertIn("scenario_qemu", calls)

    def test_non_q_still_uses_incus(self):
        calls = self._drive("a")
        self.assertIn("ensure_network", calls)
        self.assertIn("import_image", calls)
        self.assertIn("scenario_a", calls)


if __name__ == "__main__":
    unittest.main()
