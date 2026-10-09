#!/usr/bin/env python3
"""Gate-boundary fixture: the bake gate must run the FULL scenario set (#12209).

bake.validation_gate_step(False, ...) runs validate.py with the "all" tail so
every registered scenario (validate.SCENARIO_ORDER) boots before the bake set
becomes eligible for signing. A single scenario key ("a".."q") is ALSO valid
argv (validate.py accepts it and dispatches just that leg), so an `all` -> `a`
regression still runs a green subset and still returns True — and the ordering
tests assert the argv prefix and the qcow2/metadata paths but never the tail,
so the mutant escapes them.

This fixture closes the gap BEHAVIORALLY, not by asserting command text:

  - FakeValidateGate stubs bake.subprocess.run but calls the REAL
    validate.main() with a RecordingHarness in place of Incus/QEMU. It
    records the selected scenarios and the scenario methods actually
    dispatched by the validator; the narrowing mutant still returns 0 for
    the successful `a` leg, and the kill comes from recorded coverage.
  - GateCoverageFixture.withhold_unless_full() refuses to stamp provenance
    unless the executed set covers the full required set; only then does the
    REAL bake.record_validation_success flip the sidecar to `validated: true`.

RED on mutant: with bake.py's "all" tail narrowed to "a", the gate runs one
leg, coverage is incomplete, and the provenance assertion goes RED — while
test_bake_sign_ordering.py stays green. GREEN on the real gate: full coverage
earns `validated: true` on the sidecar.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_HERE = Path(__file__).resolve().parent

_SPEC_BAKE = importlib.util.spec_from_file_location("bake", _HERE / "bake.py")
bake = importlib.util.module_from_spec(_SPEC_BAKE)
assert _SPEC_BAKE.loader is not None
_SPEC_BAKE.loader.exec_module(bake)

# validate.py's own top-level imports (make_config_drive, sign) resolve via the
# sys.path inserts it performs at import time.
_SPEC_VALIDATE = importlib.util.spec_from_file_location(
    "validate", _HERE / "validate.py")
validate = importlib.util.module_from_spec(_SPEC_VALIDATE)
assert _SPEC_VALIDATE.loader is not None
_SPEC_VALIDATE.loader.exec_module(validate)


def required_scenarios():
    """The authoritative full-set ledger: the real registry order.

    The live registry is the runtime ledger; a contract test below pins the
    current required set so additions prompt an explicit full-gate review.
    """
    return list(validate.SCENARIO_ORDER)


def resolve_selection(argv):
    """Resolve the validator CLI selection using its actual scenario registry.

    The validator's real main() performs dispatch; this expected selection is
    recorded independently so tests can compare it with invoked Harness legs.
    """
    tail = argv[-1]
    if tail == "all":
        return list(validate.SCENARIO_ORDER)
    if tail in validate.SCENARIO_METHODS:
        return [tail]
    raise AssertionError(f"unresolvable gate argv tail: {tail!r} in {argv!r}")


def validate_argv(qcow2, metadata, scenario):
    """Construct a real validator CLI invocation for the fake subprocess."""
    return [
        bake.sys.executable, os.fspath(_HERE / "validate.py"),
        "--qcow2", os.fspath(qcow2),
        "--metadata", os.fspath(metadata),
        scenario,
    ]



class ScenarioFailure(RuntimeError):
    """A fake guest leg failed while the real validator was dispatching."""


class RecordingHarness:
    """No-VM harness: keep validate.main's real scenario dispatch observable."""

    instances = []
    fail_scenarios = set()
    _scenario_keys = {
        method: key for key, method in validate.SCENARIO_METHODS.items()
    }

    def __init__(self, qcow2, metadata, net, keep, verify_sig):
        self.executed = []
        self.skipped = []
        type(self).instances.append(self)

    def freeze_artifacts(self):
        pass

    def assert_image_sealed(self):
        pass

    def ensure_network(self):
        pass

    def import_image(self):
        pass

    def cleanup(self):
        pass

    def __getattr__(self, name):
        key = self._scenario_keys.get(name)
        if key is None:
            raise AttributeError(name)

        def execute_scenario():
            self.executed.append(key)
            if key in self.fail_scenarios:
                raise ScenarioFailure(f"scenario {key} failed")

        return execute_scenario


class FakeValidateGate:
    """Run real validate.main() while replacing only its hypervisor Harness."""

    def __init__(self, fail_scenarios=()):
        self.fail_scenarios = set(fail_scenarios)
        self.seen_argv = []
        self.selected = []
        self.executed = []
        self.succeeded = []

    def run(self, argv, **kwargs):
        self.seen_argv.append(list(argv))
        self.selected.extend(resolve_selection(argv))
        RecordingHarness.instances.clear()
        RecordingHarness.fail_scenarios = self.fail_scenarios
        with (
            patch.object(validate, "Harness", RecordingHarness),
            patch.object(validate, "maybe_reexec_incus_admin"),
            patch.object(validate.sys, "argv", argv[1:]),
        ):
            try:
                returncode = validate.main()
            except ScenarioFailure:
                returncode = 1

        for harness in RecordingHarness.instances:
            self.executed.extend(harness.executed)
        if returncode == 0:
            self.succeeded.extend(self.executed)
        return SimpleNamespace(returncode=returncode)


class GateCoverageFixture:
    """Withholds signed provenance unless the FULL required set succeeded."""

    def __init__(self, gate):
        self.gate = gate
        self.required = required_scenarios()

    def missing(self):
        return [k for k in self.required if k not in self.gate.succeeded]

    def full_set_succeeded(self):
        return not self.missing()

    def withhold_unless_full(self, manifest, sums, files, snapshot):
        """Stamp `validated: true` ONLY on full-set success; else refuse.

        Returns True when provenance was stamped. On a narrowed or failed
        gate the sidecar remains `validated: false` and is not signable.
        """
        if not self.full_set_succeeded():
            return False
        bake.record_validation_success(manifest, sums, files, snapshot)
        return True


def _write_bake_set(temp):
    """Mirror ValidationProvenanceTests._write_fixture: unvalidated sidecar,
    checksum manifest, and hash-time snapshot over the four-file bake set."""
    names = bake.sign.bake_set_basenames("test")
    files = [os.path.join(temp, name) for name in names]
    for path in files:
        Path(path).write_text("artifact\n")
    manifest = files[2]
    sums = os.path.join(temp, "xpf-test.SHA256SUMS")
    Path(manifest).write_text("version: test\nvalidated: false\n")
    snapshot = bake.snapshot_manifest_inputs(files)
    bake.sign.write_manifest(sums, files, recorded_hashes=snapshot)
    return files, manifest, sums, snapshot


def _write_validator_inputs(temp):
    """Create existing paths for validate.main's argument preflight."""
    qcow = Path(temp, "frozen.qcow2")
    metadata = Path(temp, "frozen-metadata.tar.gz")
    qcow.write_text("qcow fixture")
    metadata.write_text("metadata fixture")
    return str(qcow), str(metadata)


class SelectionResolutionTests(unittest.TestCase):
    def test_all_expands_to_full_registry_order(self):
        self.assertEqual(
            resolve_selection(["validate.py", "--qcow2", "q", "--metadata",
                               "m", "all"]),
            list(validate.SCENARIO_ORDER))

    def test_single_key_resolves_to_that_leg_only(self):
        self.assertEqual(
            resolve_selection(["validate.py", "--qcow2", "q", "--metadata",
                               "m", "a"]),
            ["a"])

    def test_required_set_tracks_registry(self):
        # Fail-closed ledger: the required set IS the registry order, and the
        # registry still carries the legs this gate was written against.
        self.assertEqual(required_scenarios(), ["a", "b", "c", "d", "e", "q"])
        for key in required_scenarios():
            self.assertIn(key, validate.SCENARIO_METHODS)


class GateBoundaryTests(unittest.TestCase):
    def test_full_gate_earns_validated_true(self):
        gate = FakeValidateGate()
        with tempfile.TemporaryDirectory() as temp:
            qcow, metadata = _write_validator_inputs(temp)
            with patch.object(bake.subprocess, "run", side_effect=gate.run):
                self.assertTrue(
                    bake.validation_gate_step(False, qcow, metadata))
            fixture = GateCoverageFixture(gate)
            files, manifest, sums, snapshot = _write_bake_set(temp)
            # On an all->a mutant this coverage boundary withholds provenance;
            # the test fails here, while the sidecar remains validated:false.
            self.assertTrue(
                fixture.withhold_unless_full(manifest, sums, files, snapshot),
                f"gate narrowed or failed: missing {fixture.missing()}; "
                f"provenance is {Path(manifest).read_text()!r}")
            self.assertIn("validated: true\n", Path(manifest).read_text())
        # Behavioral, not command-text: selected keys must match scenario
        # methods actually dispatched successfully by validate.main().
        self.assertEqual(gate.selected, required_scenarios())
        self.assertEqual(gate.executed, required_scenarios())
        self.assertEqual(gate.succeeded, required_scenarios())

    def test_single_scenario_success_withholds_validated_true(self):
        # Negative control: a narrowed gate that SUCCEEDS (rc 0) must still
        # be refused provenance — this is the branch the mutant exercises.
        gate = FakeValidateGate()
        with tempfile.TemporaryDirectory() as temp:
            qcow, metadata = _write_validator_inputs(temp)
            gate.run(validate_argv(qcow, metadata, "a"))
            fixture = GateCoverageFixture(gate)
            self.assertEqual(gate.selected, ["a"])
            self.assertEqual(gate.executed, ["a"])
            self.assertEqual(gate.succeeded, ["a"])
            files, manifest, sums, snapshot = _write_bake_set(temp)
            with patch.object(bake, "record_validation_success") as record:
                self.assertFalse(
                    fixture.withhold_unless_full(
                        manifest, sums, files, snapshot))
                record.assert_not_called()
            self.assertIn("validated: false\n", Path(manifest).read_text())

    def test_failed_full_selection_withholds_validated_true(self):
        # Full selection alone is insufficient: a failed guest leg cannot
        # earn provenance, even if several earlier legs passed.
        gate = FakeValidateGate(fail_scenarios={"e"})
        with tempfile.TemporaryDirectory() as temp:
            qcow, metadata = _write_validator_inputs(temp)
            gate.run(validate_argv(qcow, metadata, "all"))
            self.assertEqual(gate.selected, required_scenarios())
            self.assertEqual(gate.executed, ["a", "b", "c", "d", "e"])
            self.assertEqual(gate.succeeded, [])
            fixture = GateCoverageFixture(gate)
            files, manifest, sums, snapshot = _write_bake_set(temp)
            with patch.object(bake, "record_validation_success") as record:
                self.assertFalse(
                    fixture.withhold_unless_full(
                        manifest, sums, files, snapshot))
                record.assert_not_called()
            self.assertIn("validated: false\n", Path(manifest).read_text())


if __name__ == "__main__":
    unittest.main()
