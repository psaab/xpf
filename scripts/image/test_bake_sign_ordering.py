#!/usr/bin/env python3
"""Unit tests for the #4017 bake step ordering: VALIDATE before SIGN.

The appliance bake (scripts/image/bake.py) must run the in-guest
verify-dataplane validation gate BEFORE it minisign-signs the checksum
manifest. The signature is a trust artifact — downstream publish
(scripts/dist/publish.py) and operators read a signed image as a
validated one (#1864 secure-boot chain) — so a bake that fails validation
must NOT leave a signed .minisig behind (fable-161 F-092).

These unit tests drive bake.finalize_artifacts() with injected validate/sign
steps. A main() integration case also stubs external tools but exercises the
real validation return-code check and main() wiring, proving a failed gate
cannot reach signing. --skip-validate still runs the standalone offline seal
check, and the bake's direct signer enforces the same provenance refusal as
the sign-manifest CLI.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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
    """--skip-validate still performs the offline seal check and leaves
    provenance unvalidated; the default path runs the full gate."""

    def test_skip_validate_runs_seal_only_and_returns_false(self):
        with patch.object(bake.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0)) as run:
            self.assertFalse(
                bake.validation_gate_step(
                    True, "/frozen/image.qcow2", "/frozen/metadata.tar.gz"))

        cmd = run.call_args.args[0]
        self.assertEqual(cmd[:2], [bake.sys.executable,
                                   os.path.join(bake.HERE, "validate.py")])
        self.assertEqual(cmd[cmd.index("--qcow2") + 1], "/frozen/image.qcow2")
        self.assertEqual(cmd[cmd.index("--metadata") + 1],
                         "/frozen/metadata.tar.gz")
        self.assertIn("--seal-only", cmd)

    def test_failed_seal_gate_aborts_skip_validate_bake(self):
        with patch.object(bake.subprocess, "run",
                          return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(SystemExit) as ctx:
                bake.validation_gate_step(True, "/qcow", "/metadata")
        self.assertIn("image seal gate FAILED", str(ctx.exception))

    def test_successful_validation_returns_true(self):
        with patch.object(bake.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0)):
            self.assertTrue(
                bake.validation_gate_step(False, "/qcow", "/metadata"))


class ValidationProvenanceTests(unittest.TestCase):
    @staticmethod
    def _write_fixture(temp):
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

    def test_success_updates_sidecar_and_only_its_snapshot_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            files, manifest, sums, snapshot = self._write_fixture(temp)
            before = dict(snapshot)

            bake.record_validation_success(manifest, sums, files, snapshot)

            self.assertIn("validated: true\n", Path(manifest).read_text())
            recorded = bake.sign.parse_manifest(sums)
            self.assertEqual(recorded, snapshot)
            for name, digest in before.items():
                if name != os.path.basename(manifest):
                    self.assertEqual(snapshot[name], digest)

    def test_gate_window_sidecar_drift_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            files, manifest, sums, snapshot = self._write_fixture(temp)
            tampered = Path(manifest).read_text().replace(
                "version: test", "version: tampered")
            Path(manifest).write_text(tampered)

            with self.assertRaises(SystemExit) as ctx:
                bake.record_validation_success(manifest, sums, files, snapshot)

            self.assertIn("drifted during validation", str(ctx.exception))
            self.assertEqual(Path(manifest).read_text(), tampered)
            self.assertEqual(bake.sign.parse_manifest(sums), snapshot)

    def test_gate_window_checksum_drift_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            files, manifest, sums, snapshot = self._write_fixture(temp)
            tampered = dict(snapshot)
            tampered["xpf-test.pkgs"] = "f" * 64
            bake.sign.write_manifest(sums, files, recorded_hashes=tampered)

            with self.assertRaises(SystemExit) as ctx:
                bake.record_validation_success(manifest, sums, files, snapshot)

            self.assertIn("checksum manifest", str(ctx.exception))
            self.assertIn("validated: false\n", Path(manifest).read_text())


    def test_skip_validate_cannot_sign_via_bake_direct_signer(self):
        with tempfile.TemporaryDirectory() as temp:
            _, _, sums, snapshot = self._write_fixture(temp)
            with (
                patch.dict(os.environ, {"XPF_SIGN_SECKEY": "/unused"}),
                patch.object(bake.sign, "assert_bake_set",
                             wraps=bake.sign.assert_bake_set) as gate,
                patch.object(bake.sign, "require_minisign") as require_minisign,
            ):
                with self.assertRaises(SystemExit) as ctx:
                    bake.sign_manifest_step_from_snapshot(
                        temp, sums, "test", snapshot, temp)

            self.assertIn("validated='false'", str(ctx.exception))
            gate.assert_called_once()
            require_minisign.assert_not_called()
            self.assertFalse(os.path.exists(sums + ".minisig"))


class MainValidationGateTests(unittest.TestCase):
    """The actual bake main path must treat validate.py's nonzero rc as fatal."""

    def test_failed_validation_command_prevents_signing(self):
        with tempfile.TemporaryDirectory() as temp:
            out_dir = os.path.join(temp, "dist")
            os.makedirs(out_dir)
            version = "0.0.10+g123456789abc"
            deb = Path(temp, f"xpf_{version}_amd64.deb")
            deb.write_text("stub")
            cached = os.path.join(temp, "base.img")
            args = SimpleNamespace(
                version=version,
                out=out_dir,
                skip_build=True,
                skip_validate=False,
                keep_work=False,
            )
            subprocess_calls = []
            sign_calls = []

            def run(argv, **kwargs):
                if argv[0] == "dpkg-deb":
                    staged_xpfd = Path(argv[3], "usr/local/share/xpf/staged/xpfd")
                    staged_xpfd.parent.mkdir(parents=True)
                    staged_xpfd.write_text("stub")
                    staged_xpfd.chmod(0o755)
                elif argv[0] == "virt-sparsify":
                    Path(argv[-1]).write_text("qcow")
                elif argv[0] == "tar":
                    Path(argv[argv.index("-czf") + 1]).write_text("metadata")

            def out_text(argv):
                if argv[0] == "dpkg-deb" and argv[1] == "-f":
                    return version + "\n"
                if argv[-1] == "version":
                    return "xpfd release (commit 123456789abc, built test)\n"
                if argv[0] == "virt-filesystems":
                    return "/dev/sda1 1 ext4 2\n"
                if argv[0] == "virt-cat":
                    return "unused by mocked inventory parser"
                if argv[0] == "git":
                    raise subprocess.CalledProcessError(128, argv)
                if argv[-1] == "protocol-versions":
                    return "ha-protocol-version=1\n"
                raise AssertionError(f"unexpected out_text command: {argv}")

            def subprocess_run(argv, **kwargs):
                subprocess_calls.append(argv)
                return SimpleNamespace(returncode=1)

            def sign(out_dir, sums, ver, snapshot, work):
                sign_calls.append(ver)
                Path(out_dir, f"xpf-{ver}.SHA256SUMS.minisig").write_text("sig\n")

            with (
                patch.object(bake.argparse.ArgumentParser, "parse_args",
                             return_value=args),
                patch.object(bake, "require"),
                patch.object(bake, "ensure_memlock"),
                patch.object(bake, "run", side_effect=run),
                patch.object(bake, "out_text", side_effect=out_text),
                patch.object(bake, "fetch_base",
                             return_value=("jammy", "https://example", "base.img",
                                           cached, "a" * 64, True)),
                patch.object(bake.image_inventory, "parse",
                             return_value=("6.18.0", ["xpf=1"])),
                patch.object(bake.subprocess, "run", side_effect=subprocess_run),
                patch.object(bake, "sign_manifest_step_from_snapshot",
                             side_effect=sign),
                patch("glob.glob", return_value=[str(deb)]),
                patch.dict(os.environ, {"XDG_CACHE_HOME": temp}),
            ):
                with self.assertRaises(SystemExit) as ctx:
                    bake.main()

            self.assertNotEqual(ctx.exception.code, 0)
            validate_cmd = subprocess_calls[-1]
            self.assertEqual(validate_cmd[0], bake.sys.executable)
            self.assertEqual(validate_cmd[1], os.path.join(bake.HERE, "validate.py"))
            self.assertEqual(validate_cmd[2], "--qcow2")
            self.assertEqual(validate_cmd[4], "--metadata")
            self.assertEqual(sign_calls, [])
            self.assertEqual(
                [name for name in os.listdir(out_dir) if name.endswith(".minisig")],
                [],
            )
            # A failed gate must leave no provenance that can be re-signed as
            # validated. RED on revert: bake previously wrote this as true
            # from `not --skip-validate`, before running the gate.
            sidecar = Path(out_dir, f"xpf-{version}.manifest")
            self.assertIn("validated: false\n", sidecar.read_text())
            with self.assertRaises(bake.sign.SignError):
                bake.sign.assert_bake_set(
                    os.path.join(out_dir, f"xpf-{version}.SHA256SUMS"),
                    [os.path.join(out_dir, name)
                     for name in bake.sign.bake_set_basenames(version)])


            version = "0.0.10+g123456789abc"
            deb = Path(temp, f"xpf_{version}_amd64.deb")
            deb.write_text("stub")
            cached = os.path.join(temp, "base.img")
            args = SimpleNamespace(
                version=version,
                out=out_dir,
                skip_build=True,
                skip_validate=True,
                keep_work=False,
            )
            subprocess_calls = []

            def run(argv, **kwargs):
                if argv[0] == "dpkg-deb":
                    staged_xpfd = Path(argv[3], "usr/local/share/xpf/staged/xpfd")
                    staged_xpfd.parent.mkdir(parents=True)
                    staged_xpfd.write_text("stub")
                    staged_xpfd.chmod(0o755)
                elif argv[0] == "virt-sparsify":
                    Path(argv[-1]).write_text("qcow")
                elif argv[0] == "tar":
                    Path(argv[argv.index("-czf") + 1]).write_text("metadata")

            def out_text(argv):
                if argv[0] == "dpkg-deb" and argv[1] == "-f":
                    return version + "\n"
                if argv[-1] == "version":
                    return "xpfd release (commit 123456789abc, built test)\n"
                if argv[0] == "virt-filesystems":
                    return "/dev/sda1 1 ext4 2\n"
                if argv[0] == "virt-cat":
                    return "unused by mocked inventory parser"
                if argv[0] == "git":
                    raise subprocess.CalledProcessError(128, argv)
                if argv[-1] == "protocol-versions":
                    return "ha-protocol-version=1\n"
                raise AssertionError(f"unexpected out_text command: {argv}")

            def subprocess_run(argv, **kwargs):
                subprocess_calls.append(argv)
                return SimpleNamespace(returncode=0)

            with (
                patch.object(bake.argparse.ArgumentParser, "parse_args",
                             return_value=args),
                patch.object(bake, "require"),
                patch.object(bake, "ensure_memlock"),
                patch.object(bake, "run", side_effect=run),
                patch.object(bake, "out_text", side_effect=out_text),
                patch.object(bake, "fetch_base",
                             return_value=("jammy", "https://example", "base.img",
                                           cached, "a" * 64, True)),
                patch.object(bake.image_inventory, "parse",
                             return_value=("6.18.0", ["xpf=1"])),
                patch.object(bake.subprocess, "run", side_effect=subprocess_run),
                patch("glob.glob", return_value=[str(deb)]),
                patch.dict(os.environ, {"XDG_CACHE_HOME": temp,
                                        "XPF_SIGN_SECKEY": "/unused"}),
            ):
                with self.assertRaises(SystemExit) as ctx:
                    bake.main()

            self.assertIn("validated='false'", str(ctx.exception))
            seal_cmd = subprocess_calls[-1]
            self.assertIn("--seal-only", seal_cmd)
            self.assertNotIn("all", seal_cmd)
            self.assertFalse(
                any(name.endswith(".minisig") for name in os.listdir(out_dir)))
            sidecar = Path(out_dir, f"xpf-{version}.manifest")
            self.assertIn("validated: false\n", sidecar.read_text())


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
