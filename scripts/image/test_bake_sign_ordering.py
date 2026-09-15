#!/usr/bin/env python3
"""Unit tests for the #4017 bake step ordering: VALIDATE before SIGN.

The appliance bake (scripts/image/bake.py) must run the in-guest
verify-dataplane validation gate BEFORE it minisign-signs the checksum
manifest. The signature is a trust artifact — downstream publish
(scripts/dist/publish.py) and operators read a signed image as a
validated one (#1864 secure-boot chain) — so a bake that fails validation
must NOT leave a signed .minisig behind (fable-161 F-092).

These tests drive bake.finalize_artifacts() with injected validate/sign
steps and assert the sign step never runs when validation fails. On
revert (sign ordered before validate) the failure-path tests go RED: the
sign step runs and a .minisig is produced despite the validation failure.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "bake", Path(__file__).with_name("bake.py")
)
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)


class FinalizeOrderingTests(unittest.TestCase):
    """finalize_artifacts must call validate_step, then sign_step, and must
    never reach sign_step if validate_step aborts."""

    def test_success_signs_after_validation(self):
        calls = []
        bake.finalize_artifacts(
            validate_step=lambda: calls.append("validate"),
            sign_step=lambda: calls.append("sign"),
        )
        # Order is load-bearing: validate strictly precedes sign.
        self.assertEqual(calls, ["validate", "sign"])

    def test_validation_exception_skips_sign(self):
        calls = []

        def validate():
            calls.append("validate")
            raise RuntimeError("gate failed")

        def sign():
            calls.append("sign")

        with self.assertRaises(RuntimeError):
            bake.finalize_artifacts(validate_step=validate, sign_step=sign)
        self.assertIn("validate", calls)
        # RED on revert (sign ordered before validate): "sign" would appear.
        self.assertNotIn("sign", calls)

    def test_validation_die_is_nonzero_and_skips_sign(self):
        """A real gate failure aborts via bake.die() -> SystemExit non-zero,
        BEFORE signing. Mirrors validation_gate_step()'s die() on rc != 0."""
        calls = []

        def validate():
            calls.append("validate")
            bake.die("validation gate FAILED — artifacts are NOT publishable")

        def sign():
            calls.append("sign")

        with self.assertRaises(SystemExit) as ctx:
            bake.finalize_artifacts(validate_step=validate, sign_step=sign)
        # die() passes a message string to sys.exit -> non-zero process exit.
        self.assertIsNotNone(ctx.exception.code)
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertNotIn("sign", calls)


class NoSignedArtifactOnValidationFailureTests(unittest.TestCase):
    """End-to-end ordering check against the filesystem: a validation
    failure must leave NO signed output. The sign_step here actually writes
    a .minisig into the out dir, so a revert (sign-before-validate) leaves
    the file on disk and the assertion goes RED."""

    def _sign_step(self, out_dir, recorded):
        def _sign():
            recorded.append("sign")
            # Simulate sign.sign_manifest producing the trust artifact.
            Path(out_dir, "xpf-test.SHA256SUMS.minisig").write_text("sig\n")
        return _sign

    def test_failed_validation_leaves_no_minisig(self):
        with tempfile.TemporaryDirectory() as out_dir:
            recorded = []

            def validate():
                bake.die("validation gate FAILED")

            with self.assertRaises(SystemExit) as ctx:
                bake.finalize_artifacts(
                    validate_step=validate,
                    sign_step=self._sign_step(out_dir, recorded),
                )
            self.assertNotEqual(ctx.exception.code, 0)
            self.assertNotIn("sign", recorded)
            minisigs = [f for f in os.listdir(out_dir) if f.endswith(".minisig")]
            # RED on revert: sign runs first and leaves a signed artifact.
            self.assertEqual(minisigs, [], f"unexpected signed artifact: {minisigs}")

    def test_passing_validation_signs_after(self):
        with tempfile.TemporaryDirectory() as out_dir:
            recorded = []
            bake.finalize_artifacts(
                validate_step=lambda: recorded.append("validate"),
                sign_step=self._sign_step(out_dir, recorded),
            )
            self.assertEqual(recorded, ["validate", "sign"])
            self.assertTrue(
                os.path.isfile(os.path.join(out_dir, "xpf-test.SHA256SUMS.minisig"))
            )


class ValidationGateStepTests(unittest.TestCase):
    """--skip-validate downgrades the gate to a warning (no die), so a bake
    can proceed to sign; the default path dies non-zero on gate failure."""

    def test_skip_validate_does_not_die(self):
        # Should return without raising; qcow/meta paths are unused when skipped.
        bake.validation_gate_step(True, "/nonexistent.qcow2", "/nonexistent.meta")


class RuntimePackageSyncTests(unittest.TestCase):
    """#4172: frr-pythontools (provider of /usr/lib/frr/frr-reload.py, the
    daemon's primary FRR reload path) MUST appear in BOTH the bake's
    RUNTIME_PACKAGES and the xpf-appliance metapackage Depends, kept in sync
    per the bake.py comment. Missing it silently degrades every appliance's
    FRR reload to the additive `vtysh -f` fallback (stale-config removal
    never converges). RED on revert: dropping it from either list fails
    here."""

    @staticmethod
    def _appliance_depends():
        control = Path(__file__).resolve().parents[2] / "debian" / "control"
        text = control.read_text()
        stanza = text.split("Package: xpf-appliance", 1)[1]
        # Depends runs until the next control field at column 0 (Description:).
        depends = stanza.split("Depends:", 1)[1].split("\nDescription:", 1)[0]
        pkgs = set()
        for entry in depends.split(","):
            tok = entry.strip()
            if tok:
                # Drop any version constraint / arch qualifier after the name.
                pkgs.add(tok.split()[0])
        return pkgs

    def test_frr_pythontools_in_runtime_packages(self):
        self.assertIn(
            "frr-pythontools", bake.RUNTIME_PACKAGES,
            "frr-pythontools missing from bake RUNTIME_PACKAGES "
            "(#4172: /usr/lib/frr/frr-reload.py provider)")

    def test_frr_pythontools_in_appliance_depends(self):
        self.assertIn(
            "frr-pythontools", self._appliance_depends(),
            "frr-pythontools missing from xpf-appliance Depends in "
            "debian/control (#4172; keep in sync with RUNTIME_PACKAGES)")

    def test_frr_present_as_baseline(self):
        # Guard the split/parse logic itself: `frr` must resolve in both
        # lists, so a false-negative parse can't mask a real regression.
        self.assertIn("frr", bake.RUNTIME_PACKAGES)
        self.assertIn("frr", self._appliance_depends())

    def test_perl_base_in_runtime_packages(self):
        # #9921 F-147: perl-base (with Fcntl) backs xpf-day0-config's
        # O_NOFOLLOW medium read. Essential, so present by packaging
        # invariant — pinned explicitly in both lists so the boot path's
        # dependency is declared.
        self.assertIn(
            "perl-base", bake.RUNTIME_PACKAGES,
            "perl-base missing from bake RUNTIME_PACKAGES "
            "(#9921 F-147: safe_read_medium provider)")

    def test_perl_base_in_appliance_depends(self):
        self.assertIn(
            "perl-base", self._appliance_depends(),
            "perl-base missing from xpf-appliance Depends in "
            "debian/control (#9921 F-147; keep in sync with RUNTIME_PACKAGES)")


if __name__ == "__main__":
    unittest.main()
