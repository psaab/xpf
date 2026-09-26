#!/usr/bin/env python3
"""Hermetic unit tests for the #6547 image-seal gate.

`scripts/image/validate.py` is the gate `bake.py`'s `finalize_artifacts` runs
STRICTLY BEFORE `sign_step` (#4017). It asserted NOTHING about image sealing,
so a clone-identity regression shipped SIGNED and passed the publish gate.

The acute risk was bounded — bake's `run()` is `subprocess.run(argv,
check=True)`, so an outright `virt-sysprep` failure raises. The real exposure
is DRIFT: the `--enable` list was a hand-maintained string literal, and the
identity purge is a `rm -rf ... 2>/dev/null || true` whose failure is swallowed
by construction. Nothing would have caught a member falling out of either, or
the step being refactored away. The consequence is fleet-wide shared SSH host
keys, machine-id and SNMPv3 EngineID.

Two things these tests are careful about:

  * THE VERDICT IS CALIBRATED ON KNOWN-BAD INPUT BEFORE ANY GREEN IS TRUSTED.
    Each identity gets its own failing case, asserting the reason names both
    the path and the seal step that produced it — a verdict that passes a
    sealed image proves nothing until it is shown to reject an unsealed one.

  * A MISSING OBSERVATION IS A FAILURE, NOT A PASS. The single most likely way
    for this gate to go vacuous again is for the inventory read to come back
    empty (unreadable image, renamed path, tool change) and for the verdict to
    read "nothing found" as "nothing present". `test_unobserved_check_fails`
    pins the opposite.

The last class binds the gate to the bake. `_SEAL_IDENTITY_CHECKS` entries name
the seal step that produces their outcome; those names must all exist in
`bake.SYSPREP_ENABLE_OPS` or `bake.SYSPREP_PURGE_PATHS`. That is the
acceptance-criterion test in its runnable form: remove one `--enable` member
from the bake and this file goes RED, without needing a VM or a real image.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


validate = _load("validate")
bake = _load("bake")


def sealed_inventory():
    """The inventory a correctly sealed image produces: every 'absent' glob
    matches nothing, and /etc/machine-id is present but zero-length (which is
    what virt-sysprep's machine-id op leaves behind — it truncates rather than
    deletes)."""
    found = {c["glob"]: [] for c in validate._SEAL_IDENTITY_CHECKS}
    found["/etc/machine-id"] = ["/etc/machine-id"]
    found["/etc/machine-id:size"] = 0
    return found


class SealVerdictTests(unittest.TestCase):
    def test_sealed_image_passes(self):
        ok, reason = validate._image_seal_verdict(sealed_inventory())
        self.assertTrue(ok, reason)

    def test_absent_machine_id_also_passes(self):
        # virt-sysprep truncates; a deleted file is equally sealed and must
        # not be a false red.
        found = sealed_inventory()
        found["/etc/machine-id"] = []
        found.pop("/etc/machine-id:size")
        ok, reason = validate._image_seal_verdict(found)
        self.assertTrue(ok, reason)

    def test_populated_machine_id_fails(self):
        found = sealed_inventory()
        found["/etc/machine-id:size"] = 32
        ok, reason = validate._image_seal_verdict(found)
        self.assertFalse(ok)
        self.assertIn("/etc/machine-id", reason)
        self.assertIn("machine-id", reason)

    def test_shipped_ssh_host_key_fails(self):
        found = sealed_inventory()
        found["/etc/ssh/ssh_host_*"] = [
            "/etc/ssh/ssh_host_ed25519_key",
            "/etc/ssh/ssh_host_ed25519_key.pub",
        ]
        ok, reason = validate._image_seal_verdict(found)
        self.assertFalse(ok)
        self.assertIn("ssh_host_ed25519_key", reason)
        self.assertIn("ssh-hostkeys", reason)

    def test_shipped_snmp_engine_id_fails(self):
        found = sealed_inventory()
        found["/var/lib/xpf/snmp-engine-id"] = ["/var/lib/xpf/snmp-engine-id"]
        ok, reason = validate._image_seal_verdict(found)
        self.assertFalse(ok)
        self.assertIn("snmp-engine-id", reason)

    def test_shipped_engineboots_fails(self):
        found = sealed_inventory()
        found["/var/lib/xpf/snmp-engineboots"] = ["/var/lib/xpf/snmp-engineboots"]
        ok, reason = validate._image_seal_verdict(found)
        self.assertFalse(ok)
        self.assertIn("snmp-engineboots", reason)

    def test_shipped_random_seed_fails(self):
        found = sealed_inventory()
        found["/var/lib/systemd/random-seed"] = ["/var/lib/systemd/random-seed"]
        ok, reason = validate._image_seal_verdict(found)
        self.assertFalse(ok)
        self.assertIn("random-seed", reason)

    def test_unobserved_check_fails(self):
        """A glob with NO entry in the inventory must FAIL. This is the
        vacuous-gate guard: an unreadable image, a renamed path, or a tool
        change that returns nothing must not read as 'nothing present'."""
        for c in validate._SEAL_IDENTITY_CHECKS:
            with self.subTest(glob=c["glob"]):
                found = sealed_inventory()
                found.pop(c["glob"])
                found.pop(f"{c['glob']}:size", None)
                ok, reason = validate._image_seal_verdict(found)
                self.assertFalse(ok, f"{c['glob']} unobserved but verdict passed")
                self.assertIn("NOT OBSERVED", reason)

    def test_empty_inventory_fails(self):
        ok, reason = validate._image_seal_verdict({})
        self.assertFalse(ok)
        self.assertIn("NOT OBSERVED", reason)

    def test_every_failure_is_reported_not_just_the_first(self):
        found = sealed_inventory()
        found["/etc/ssh/ssh_host_*"] = ["/etc/ssh/ssh_host_rsa_key"]
        found["/var/lib/systemd/random-seed"] = ["/var/lib/systemd/random-seed"]
        ok, reason = validate._image_seal_verdict(found)
        self.assertFalse(ok)
        self.assertIn("ssh_host_rsa_key", reason)
        self.assertIn("random-seed", reason)


class SealBakeAgreementTests(unittest.TestCase):
    """The gate's identity table and the bake's seal must not drift apart.

    This is the acceptance-criterion test: removing one `--enable` member from
    bake.py makes it RED, with no VM and no real image.
    """

    def test_every_identity_check_is_sealed_by_the_bake(self):
        ops = set(bake.SYSPREP_ENABLE_OPS)
        purged = set(bake.SYSPREP_PURGE_PATHS)
        for c in validate._SEAL_IDENTITY_CHECKS:
            with self.subTest(glob=c["glob"]):
                sealed_by = c["sealed_by"]
                self.assertTrue(
                    sealed_by in ops or sealed_by in purged,
                    f"{c['glob']} claims to be sealed by {sealed_by!r}, but the "
                    "bake neither enables that virt-sysprep operation nor "
                    "purges that path — the seal and the gate that verifies it "
                    "have drifted apart")

    def test_dropping_an_enable_member_is_detected(self):
        """Calibration of the agreement check itself: with `ssh-hostkeys`
        removed from the bake, the check must report the ssh host-key entry as
        unsealed. Without this, a green agreement test proves only that the
        assertion runs, not that it can fail."""
        ops = set(bake.SYSPREP_ENABLE_OPS) - {"ssh-hostkeys"}
        purged = set(bake.SYSPREP_PURGE_PATHS)
        unsealed = [c["glob"] for c in validate._SEAL_IDENTITY_CHECKS
                    if c["sealed_by"] not in ops and c["sealed_by"] not in purged]
        self.assertEqual(unsealed, ["/etc/ssh/ssh_host_*"])

    def test_dropping_a_purge_path_is_detected(self):
        ops = set(bake.SYSPREP_ENABLE_OPS)
        purged = set(bake.SYSPREP_PURGE_PATHS) - {"/var/lib/systemd/random-seed"}
        unsealed = [c["glob"] for c in validate._SEAL_IDENTITY_CHECKS
                    if c["sealed_by"] not in ops and c["sealed_by"] not in purged]
        self.assertEqual(unsealed, ["/var/lib/systemd/random-seed"])

    def test_bake_still_purges_the_factory_state_paths(self):
        """The purge tuple also carries the non-identity factory-state paths.
        They are not part of the clone-identity verdict, but silently losing
        them ships a committed config inside the golden image."""
        for p in ("/etc/xpf/.configdb", "/etc/xpf/xpf.conf",
                  "/etc/xpf/.day0-config-applied",
                  "/etc/xpf/.day0-config-rejected", "/etc/xpf/.root-grown"):
            self.assertIn(p, bake.SYSPREP_PURGE_PATHS)


class SealWiringTests(unittest.TestCase):
    """The gate must actually be CALLED, and called before anything boots.

    A test that only asserts `Harness.assert_image_sealed` EXISTS is exactly
    the vacuous shape #6547 is about: deleting the one line in `main()` that
    calls it leaves the method, its verdict function and every unit test above
    green while the gate asserts nothing again. These drive the real `main()`
    against a recording Harness double and bind the CALL SITE.
    """

    def _drive_main(self, scenario):
        calls = []

        class RecordingHarness:
            def __init__(self, *a, **kw):
                # #7347: main() now reads the skip LEDGER after running the
                # scenarios. __getattr__ below answers EVERY attribute with a
                # recording callable, so without a real list here `h.skipped`
                # comes back as a function and _skip_verdict raises
                # TypeError: 'function' object is not iterable.
                #
                # Modelling it is the right fix rather than making the verdict
                # tolerant of a non-list: a double is a stand-in for Harness,
                # and Harness genuinely has this attribute now. A verdict that
                # shrugged at the wrong type would also shrug on the real gate.
                self.skipped = []

            def __getattr__(self, name):
                def record(*a, **kw):
                    calls.append(name)
                return record

        with tempfile.TemporaryDirectory() as d:
            qcow = Path(d) / "img.qcow2"
            meta = Path(d) / "meta.tar.gz"
            qcow.write_bytes(b"")
            meta.write_bytes(b"")
            orig_harness = validate.Harness
            orig_reexec = validate.maybe_reexec_incus_admin
            orig_argv = sys.argv
            validate.Harness = RecordingHarness
            validate.maybe_reexec_incus_admin = lambda: None
            sys.argv = ["validate.py", "--qcow2", str(qcow),
                        "--metadata", str(meta), scenario]
            try:
                rc = validate.main()
            finally:
                validate.Harness = orig_harness
                validate.maybe_reexec_incus_admin = orig_reexec
                sys.argv = orig_argv
        self.assertEqual(rc, 0)
        return calls

    def test_main_calls_the_seal_gate(self):
        calls = self._drive_main("all")
        self.assertIn("assert_image_sealed", calls,
                      "main() never calls the image-seal gate — it is dead "
                      "code and the artifact is signed unverified")

    def test_seal_gate_runs_before_the_image_is_imported_or_booted(self):
        calls = self._drive_main("all")
        seal = calls.index("assert_image_sealed")
        self.assertLess(seal, calls.index("import_image"),
                        f"seal gate must precede the image import: {calls}")
        for scenario_method in validate.SCENARIO_METHODS.values():
            self.assertLess(seal, calls.index(scenario_method),
                            f"seal gate must precede {scenario_method}: {calls}")

    def test_seal_gate_runs_for_a_single_scenario_run_too(self):
        """It is a pre-scenario step, not a scenario, so `validate.py … b`
        is gated by it as well — otherwise a targeted re-run would sign an
        unverified artifact."""
        for key, method in validate.SCENARIO_METHODS.items():
            with self.subTest(scenario=key):
                calls = self._drive_main(key)
                self.assertIn("assert_image_sealed", calls)
                self.assertLess(calls.index("assert_image_sealed"),
                                calls.index(method))

    def test_cleanup_still_runs(self):
        """Negative control on the driver itself: if the harness double were
        never exercised these assertions would be vacuous."""
        calls = self._drive_main("a")
        self.assertIn("cleanup", calls)
        self.assertIn("ensure_network", calls)


if __name__ == "__main__":
    unittest.main()
